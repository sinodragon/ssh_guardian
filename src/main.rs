// =============================================================================
// ssh_guardian — SSH 暴力破解防护守护进程
// 支持：Debian 10 + UFW + systemd
// =============================================================================

mod ban_manager;
mod config;
mod ipc;
mod log_watcher;
mod logger;
mod patterns;
mod state;

use ban_manager::BanManager;
use chrono::Utc;
use config::Config;
use log_watcher::LogWatcher;
use logger::GuardianLogger;
#[cfg(unix)]
use nix::sys::signal::{self, SigHandler, Signal};
use state::StateDb;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

#[cfg(unix)]
static mut RUNNING: bool = true;

#[cfg(unix)]
extern "C" fn handle_signal(_: libc::c_int) {
    unsafe {
        RUNNING = false;
    }
}

#[cfg(unix)]
static mut RELOAD_LOG: bool = false;

#[cfg(unix)]
extern "C" fn handle_sighup(_: libc::c_int) {
    unsafe {
        RELOAD_LOG = true;
    }
}

fn main() {
    // ── 注册信号处理 ──────────────────────────────────────────────────────────
    #[cfg(unix)]
    unsafe {
        signal::signal(Signal::SIGTERM, SigHandler::Handler(handle_signal)).ok();
        signal::signal(Signal::SIGINT, SigHandler::Handler(handle_signal)).ok();
        signal::signal(Signal::SIGHUP, SigHandler::Handler(handle_sighup)).ok();
    }

    // ── 加载配置 ──────────────────────────────────────────────────────────────
    let config = Config::load();

    // ── 初始化日志器 ──────────────────────────────────────────────────────────
    let glog = GuardianLogger::new(&config.log_file).expect("无法初始化日志文件");
    let glog = Arc::new(Mutex::new(glog));

    {
        let mut l = glog.lock().unwrap();
        l.info("════════════════════════════════════════");
        l.info("  SSH Guardian 启动");
        l.info(&format!("  版本          : {}", env!("CARGO_PKG_VERSION")));
        l.info(&format!("  auth.log      : {}", config.auth_log));
        l.info(&format!(
            "  失败阈值      : {} 次 / {} 秒",
            config.fail_threshold, config.time_window_secs
        ));
        l.info(&format!(
            "  初始封禁时长  : {} 秒",
            config.ban_duration_secs
        ));
        l.info(&format!("  永久封禁阈值  : {} 次", config.max_ban_count));
        l.info(&format!("  状态数据库    : {}", config.state_file));
        l.info(&format!("  SSH端口       : {}", config.ssh_port));
        l.info(&format!(
            "  event清理间隔 : {} 秒",
            config.event_cleanup_interval_secs
        ));
        l.info(&format!(
            "  record清理间隔: {} 秒",
            config.record_cleanup_interval_secs
        ));
        l.info("════════════════════════════════════════");
    }

    // ── 初始化状态数据库 ──────────────────────────────────────────────────────
    let state_db = StateDb::load(&config.state_file).unwrap_or_else(|e| {
        glog.lock()
            .unwrap()
            .warn(&format!("状态文件加载失败（将使用空状态）: {}", e));
        StateDb::new()
    });
    let state_db = Arc::new(Mutex::new(state_db));

    // ── 记录本次启动时间 ──────────────────────────────────────────────────────
    {
        let mut db = state_db.lock().unwrap();
        db.start_time = Some(Utc::now());
        db.save(&config.state_file).ok();
    }

    // ── 构建正则表达式（全局共享）────────────────────────────────────────────
    let patterns = Arc::new(patterns::build_patterns());
    let pattern_configs = Arc::new(patterns::build_pattern_configs());

    // ── 初始化组件 ────────────────────────────────────────────────────────────
    let ban_manager = BanManager::new(Arc::clone(&state_db), Arc::clone(&glog), config.clone());
    let ban_manager = Arc::new(Mutex::new(ban_manager));

    let log_watcher = LogWatcher::new(
        Arc::clone(&ban_manager),
        Arc::clone(&glog),
        config.clone(),
        Arc::clone(&patterns),
        Arc::clone(&pattern_configs),
    );

    // ── 启动 auth.log 监听线程 ────────────────────────────────────────────────
    let _watcher_handle = {
        let mut watcher = log_watcher;
        thread::spawn(move || {
            watcher.run();
        })
    };

    // ── 启动 IPC 监听线程 ─────────────────────────────────────────────────────
    let _ipc_handle = {
        let ipc_ban_manager = Arc::clone(&ban_manager);
        let ipc_state_db = Arc::clone(&state_db);
        let ipc_glog = Arc::clone(&glog);
        let ipc_config = config.clone();
        let ipc_pattern = Arc::clone(&patterns);
        let ipc_pattern_configs = Arc::clone(&pattern_configs);
        thread::spawn(move || {
            ipc::listen(
                ipc_ban_manager,
                ipc_state_db,
                ipc_glog,
                ipc_config,
                ipc_pattern,
                ipc_pattern_configs,
            );
        })
    };

    // ── 主循环：定期执行解禁检查 ──────────────────────────────────────────────
    glog.lock()
        .unwrap()
        .info("主循环启动，每60秒检查一次到期封禁");

    let mut last_event_cleanup = std::time::Instant::now();
    let mut last_record_cleanup = std::time::Instant::now();

    loop {
        #[cfg(unix)]
        if unsafe { !RUNNING } {
            break;
        }

        #[cfg(unix)]
        if unsafe { RELOAD_LOG } {
            unsafe {
                RELOAD_LOG = false;
            }
            match GuardianLogger::new(&config.log_file) {
                Ok(new_logger) => {
                    let mut logger = glog.lock().unwrap();
                    *logger = new_logger;
                    logger.info("收到 SIGHUP，日志文件已重新打开");
                }
                Err(e) => eprintln!("重新打开日志文件失败: {}", e),
            }
        }

        // 到期解禁检查
        {
            let mut bm = ban_manager.lock().unwrap();
            bm.check_expired_bans();
        }

        if last_event_cleanup.elapsed().as_secs() >= config.event_cleanup_interval_secs {
            // 清理 fail_events
            let mut db = state_db.lock().unwrap();
            let cleaned = db.cleanup_expired_events(config.time_window_secs);
            glog.lock().unwrap().info(&format!(
                "执行 fail_events 清理：清理 {} 条，剩余 {} 个IP",
                cleaned,
                db.fail_events.len()
            ));
            last_event_cleanup = std::time::Instant::now();
        }

        if last_record_cleanup.elapsed().as_secs() >= config.record_cleanup_interval_secs {
            // 清理 records
            let mut db = state_db.lock().unwrap();
            let cleaned = db.cleanup_inactive_records(config.record_retain_days);
            glog.lock().unwrap().info(&format!(
                "执行 records 清理：清理 {} 条，剩余 {} 个IP",
                cleaned,
                db.records.len()
            ));
            last_record_cleanup = std::time::Instant::now();
        }

        // 保存状态
        {
            let mut db = state_db.lock().unwrap();
            if db.dirty {
                let cfg_path = &config.state_file;
                if let Err(e) = db.save(cfg_path) {
                    glog.lock().unwrap().error(&format!("状态保存失败: {}", e));
                } else {
                    db.dirty = false;
                }
            }
        }

        // 每60秒检查一次
        for _ in 0..60 {
            #[cfg(unix)]
            if unsafe { !RUNNING || RELOAD_LOG } {
                break;
            }
            thread::sleep(Duration::from_secs(1));
        }
    }

    // ── 优雅退出 ──────────────────────────────────────────────────────────────
    {
        let mut l = glog.lock().unwrap();
        l.info("收到退出信号，正在保存状态并退出...");
    }

    // 退出时无条件保存，确保最新状态保存到文件，不依赖 dirty 标记
    {
        let mut db = state_db.lock().unwrap();
        db.last_shutdown = Some(Utc::now());
        db.save(&config.state_file).ok();
    }

    glog.lock().unwrap().info("SSH Guardian 已退出");
}
