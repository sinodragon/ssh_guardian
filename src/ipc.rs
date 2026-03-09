use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use crate::ban_manager::BanManager;
use crate::logger::GuardianLogger;
use crate::state::{IpRecord, StateDb};

pub const SOCKET_PATH: &str = "/var/run/ssh_guardian.sock";

#[derive(Serialize, Deserialize)]
pub enum Command {
    Status,
    ListBanned,
    ListTracked,
    Unban { ip: String },
    Ban { ip: String },
    AddWhitelist { ip: String },
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
}

pub fn listen(
    ban_manager: Arc<Mutex<BanManager>>,
    state_db: Arc<Mutex<StateDb>>,
    logger: Arc<Mutex<GuardianLogger>>,
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

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                let mut line = String::new();
                if BufReader::new(&stream).read_line(&mut line).is_err() {
                    continue;
                }

                let response = match serde_json::from_str::<Command>(line.trim()) {
                    Ok(cmd) => handle_command(cmd, &ban_manager, &state_db, &logger),
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

fn handle_command(
    cmd: Command,
    ban_manager: &Arc<Mutex<BanManager>>,
    state_db: &Arc<Mutex<StateDb>>,
    logger: &Arc<Mutex<GuardianLogger>>,
) -> Response {
    match cmd {
        Command::Status => {
            let db = state_db.lock().unwrap();
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
            let db = state_db.lock().unwrap();
            let records = db
                .records
                .values()
                .filter(|r| r.is_currently_banned())
                .cloned()
                .collect();
            Response::Banned { records }
        }

        Command::ListTracked => {
            let db = state_db.lock().unwrap();
            let records = db
                .fail_events
                .iter()
                .map(|(ip, events)| (ip.clone(), events.len()))
                .collect();
            Response::Tracked { records }
        }

        Command::Unban { ip } => {
            let result = ban_manager.lock().unwrap().manual_unban(&ip);
            match result {
                Ok(_) => {
                    logger
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
            let result = ban_manager.lock().unwrap().manual_ban(&ip);
            match result {
                Ok(_) => {
                    logger
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
            logger
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
    }
}
