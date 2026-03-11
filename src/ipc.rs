use crate::ban_manager::BanManager;
use crate::config::Config;
use crate::logger::GuardianLogger;
use crate::patterns::{scan_history_range, HistoryFailRecord, PatternConfig};
use crate::state::{IpRecord, StateDb};
use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::sync::{Arc, Mutex};

pub const SOCKET_PATH: &str = "/var/run/ssh_guardian.sock";

struct IpcContext<'a> {
    ban_manager: &'a Arc<Mutex<BanManager>>,
    state_db: &'a Arc<Mutex<StateDb>>,
    logger: &'a Arc<Mutex<GuardianLogger>>,
    config: &'a Config,
    patterns: &'a [Regex],
    pattern_configs: &'a [PatternConfig],
}

#[derive(Serialize, Deserialize)]
pub enum Command {
    Status,
    ListBanned,
    ListTracked,
    Unban { ip: String },
    Ban { ip: String },
    AddWhitelist { ip: String },
    ScanHistory,
}

#[derive(Serialize, Deserialize)]
pub enum Response {
    Status {
        banned: Vec<IpRecord>,
        tracked: Vec<(String, usize)>,
        total_records: usize,
    },
    Banned {
        records: Vec<IpRecord>,
    },
    Tracked {
        records: Vec<(String, usize)>,
    },
    Ok {
        message: String,
    },
    Err {
        message: String,
    },
    HistoryScan {
        // 新增
        from: Option<DateTime<Utc>>, // 扫描起始时间
        to: Option<DateTime<Utc>>,   // 扫描结束时间（服务启动时间）
        records: Vec<HistoryFailRecord>,
    },
}

pub fn listen(
    ban_manager: Arc<Mutex<BanManager>>,
    state_db: Arc<Mutex<StateDb>>,
    logger: Arc<Mutex<GuardianLogger>>,
    config: Config,
    patterns: Arc<Vec<Regex>>,
    pattern_configs: Arc<Vec<PatternConfig>>,
) {
    let _ = fs::remove_file(SOCKET_PATH);

    let listener = match UnixListener::bind(SOCKET_PATH) {
        Ok(l) => l,
        Err(e) => {
            logger
                .lock()
                .unwrap()
                .error(&format!("IPC socket 绑定失败: {}", e));
            return;
        }
    };

    fs::set_permissions(SOCKET_PATH, PermissionsExt::from_mode(0o600)).ok();
    logger
        .lock()
        .unwrap()
        .info(&format!("IPC socket 已就绪: {}", SOCKET_PATH));

    let ctx = IpcContext {
        ban_manager: &ban_manager,
        state_db: &state_db,
        logger: &logger,
        config: &config,
        patterns: &patterns,
        pattern_configs: &pattern_configs,
    };

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                let mut line = String::new();
                if BufReader::new(&stream).read_line(&mut line).is_err() {
                    continue;
                }

                let response = match serde_json::from_str::<Command>(line.trim()) {
                    Ok(cmd) => handle_command(cmd, &ctx),
                    Err(e) => Response::Err {
                        message: format!("命令解析失败: {}", e),
                    },
                };

                let json = serde_json::to_string(&response).unwrap_or_default();
                let _ = stream.write_all(json.as_bytes());
                let _ = stream.write_all(b"\n");
            }
            Err(e) => {
                logger.lock().unwrap().warn(&format!("IPC 连接错误: {}", e));
            }
        }
    }
}

fn handle_command(cmd: Command, ctx: &IpcContext) -> Response {
    match cmd {
        Command::Status => {
            let db = ctx.state_db.lock().unwrap();
            let banned = db
                .records
                .values()
                .filter(|r| r.is_currently_banned())
                .cloned()
                .collect();
            let tracked = db
                .fail_events
                .iter()
                .map(|(ip, events)| (ip.clone(), events.len()))
                .collect();
            Response::Status {
                banned,
                tracked,
                total_records: db.records.len(),
            }
        }

        Command::ListBanned => {
            let db = ctx.state_db.lock().unwrap();
            let records = db
                .records
                .values()
                .filter(|r| r.is_currently_banned())
                .cloned()
                .collect();
            Response::Banned { records }
        }

        Command::ListTracked => {
            let db = ctx.state_db.lock().unwrap();
            let records = db
                .fail_events
                .iter()
                .map(|(ip, events)| (ip.clone(), events.len()))
                .collect();
            Response::Tracked { records }
        }

        Command::Unban { ip } => {
            let result = ctx.ban_manager.lock().unwrap().manual_unban(&ip);
            match result {
                Ok(_) => {
                    ctx.logger
                        .lock()
                        .unwrap()
                        .info(&format!("sgctl 手动解禁 IP={}", ip));
                    Response::Ok {
                        message: format!("已解禁 {}", ip),
                    }
                }
                Err(e) => Response::Err { message: e },
            }
        }

        Command::Ban { ip } => {
            let result = ctx.ban_manager.lock().unwrap().manual_ban(&ip);
            match result {
                Ok(_) => {
                    ctx.logger
                        .lock()
                        .unwrap()
                        .info(&format!("sgctl 手动封禁 IP={}", ip));
                    Response::Ok {
                        message: format!("已封禁 {}", ip),
                    }
                }
                Err(e) => Response::Err { message: e },
            }
        }

        Command::AddWhitelist { ip } => {
            // 白名单写入配置文件需要重新加载，这里只记录日志提示
            // 实际白名单持久化需要修改 config.json，重启服务后生效
            ctx.logger
                .lock()
                .unwrap()
                .info(&format!("sgctl 请求添加白名单 IP={}（需重启服务生效）", ip));
            Response::Ok {
                message: format!(
                    "请手动将 {} 添加到 /etc/ssh_guardian/config.json 的 whitelist 字段，重启服务后生效",
                    ip
                ),
            }
        }

        Command::ScanHistory => {
            // 获取扫描时间范围
            let (from, to) = {
                let db = ctx.state_db.lock().unwrap();
                (db.last_shutdown, db.start_time)
            };

            let records = scan_history_range(
                &ctx.config.auth_log,
                from,
                to,
                ctx.config,
                ctx.patterns,
                ctx.pattern_configs,
            );

            ctx.logger.lock().unwrap().info(&format!(
                "sgctl 请求历史扫描，发现 {} 个IP有失败记录",
                records.len()
            ));

            Response::HistoryScan { from, to, records }
        }
    }
}
