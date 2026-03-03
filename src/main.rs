// =============================================================================
// ssh_guardian — SSH 暴力破解防护守护进程
// 支持：Debian 10 + UFW + systemd
// =============================================================================

mod config;
mod state;
mod log_watcher;
mod ban_manager;
mod logger;

use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::thread;
use nix::sys::signal::{self, Signal, SigHandler};
use nix::unistd::Pid;

use config::Config;
use state::StateDb;
use log_watcher::LogWatcher;
use ban_manager::BanManager;
use logger::GuardianLogger;

static mut RUNNING: bool = true;

extern "C" fn handle_signal(_: libc::c_int) {
    unsafe { RUNNING = false; }
}

fn main() {
    // ── 注册信号处理 ──────────────────────────────────────────────────────────
    unsafe {
        signal::signal(Signal::SIGTERM, SigHandler::Handler(handle_signal)).ok();
        signal::signal(Signal::SIGINT,  SigHandler::Handler(handle_signal)).ok();
    }

    // ── 加载配置 ──────────────────────────────────────────────────────────────
    let config = Config::load();

    // ── 初始化日志器 ──────────────────────────────────────────────────────────
    let glog = GuardianLogger::new(&config.log_file)
        .expect("无法初始化日志文件");
    let glog = Arc::new(Mutex::new(glog));

    {
        let mut l = glog.lock().unwrap();
        l.info("════════════════════════════════════════");
        l.info("  SSH Guardian 启动");
        l.info(&format!("  auth.log      : {}", config.auth_log));
        l.info(&format!("  失败阈值      : {} 次 / {} 秒", config.fail_threshold, config.time_window_secs));
        l.info(&format!("  初始封禁时长  : {} 秒", config.ban_duration_secs));
        l.info(&format!("  永久封禁阈值  : {} 次", config.max_ban_count));
        l.info(&format!("  状态数据库    : {}", config.state_file));
        l.info("════════════════════════════════════════");
    }

    // ── 初始化状态数据库 ──────────────────────────────────────────────────────
    let state_db = StateDb::load(&config.state_file)
        .unwrap_or_else(|e| {
            glog.lock().unwrap().warn(&format!("状态文件加载失败（将使用空状态）: {}", e));
            StateDb::new()
        });
    let state_db = Arc::new(Mutex::new(state_db));

    // ── 初始化组件 ────────────────────────────────────────────────────────────
    let ban_manager = BanManager::new(
        Arc::clone(&state_db),
        Arc::clone(&glog),
        config.clone(),
    );
    let ban_manager = Arc::new(Mutex::new(ban_manager));

    let log_watcher = LogWatcher::new(
        Arc::clone(&ban_manager),
        Arc::clone(&glog),
        config.clone(),
    );

    // ── 启动 auth.log 监听线程 ────────────────────────────────────────────────
    let watcher_handle = {
        let mut watcher = log_watcher;
        thread::spawn(move || {
            watcher.run();
        })
    };

    // ── 主循环：定期执行解禁检查 ──────────────────────────────────────────────
    glog.lock().unwrap().info("主循环启动，每60秒检查一次到期封禁");

    loop {
        if unsafe { !RUNNING } {
            break;
        }

        // 到期解禁检查
        {
            let mut bm = ban_manager.lock().unwrap();
            bm.check_expired_bans();
        }

        // 保存状态
        {
            let db = state_db.lock().unwrap();
            let cfg_path = &config.state_file;
            if let Err(e) = db.save(cfg_path) {
                glog.lock().unwrap().error(&format!("状态保存失败: {}", e));
            }
        }

        // 每60秒检查一次
        for _ in 0..60 {
            if unsafe { !RUNNING } { break; }
            thread::sleep(Duration::from_secs(1));
        }
    }

    // ── 优雅退出 ──────────────────────────────────────────────────────────────
    {
        let mut l = glog.lock().unwrap();
        l.info("收到退出信号，正在保存状态并退出...");
    }

    {
        let db = state_db.lock().unwrap();
        db.save(&config.state_file).ok();
    }

    glog.lock().unwrap().info("SSH Guardian 已退出");
}
