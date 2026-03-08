// log_watcher.rs — 实时监听 auth.log，解析 SSH 登录失败事件
use regex::Regex;
use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::ban_manager::BanManager;
use crate::config::Config;
use crate::logger::GuardianLogger;

struct PatternConfig {
    ip_group: usize,
    user_group: Option<usize>,
    port_group: Option<usize>,
    default_user: &'static str,
}

pub struct LogWatcher {
    ban_manager: Arc<Mutex<BanManager>>,
    logger: Arc<Mutex<GuardianLogger>>,
    config: Config,
    patterns: Vec<Regex>,
    pattern_configs: Vec<PatternConfig>,
}

/// 解析出的 SSH 失败登录事件
#[derive(Debug)]
struct FailedLogin {
    ip: String,
    user: String,
    port: Option<u16>,
}

impl LogWatcher {
    pub fn new(
        ban_manager: Arc<Mutex<BanManager>>,
        logger: Arc<Mutex<GuardianLogger>>,
        config: Config,
    ) -> Self {
        LogWatcher {
            ban_manager,
            logger,
            config,
            patterns: Self::build_patterns(),
            pattern_configs: Self::build_pattern_configs(),
        }
    }

    pub fn run(&mut self) {
        self.logger
            .lock()
            .unwrap()
            .info(&format!("开始监听 auth.log: {}", self.config.auth_log));

        // 打开文件，定位到末尾（只处理新增内容）
        let mut file = match File::open(&self.config.auth_log) {
            Ok(f) => f,
            Err(e) => {
                self.logger
                    .lock()
                    .unwrap()
                    .error(&format!("无法打开 {}: {}", self.config.auth_log, e));
                return;
            }
        };

        // 定位到文件末尾，只读新增内容
        if let Err(e) = file.seek(SeekFrom::End(0)) {
            self.logger
                .lock()
                .unwrap()
                .warn(&format!("seek 失败: {}", e));
        }

        let mut reader = BufReader::new(file);
        let mut eof_count = 0u32;

        loop {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) => {
                    // 没有新内容，等待后重试
                    thread::sleep(Duration::from_millis(500));
                    eof_count += 1;

                    if eof_count % 10 != 0 {
                        continue;
                    }
                    eof_count = 0;

                    // 检查文件是否被日志轮转（inode 变化）
                    // 简单处理：每次 Ok(0) 时重新 open
                    let current_path = self.config.auth_log.clone();
                    if let Ok(new_file) = File::open(&current_path) {
                        // 用新文件替换 reader
                        let inner = reader.get_mut();
                        // 检查新旧文件是否相同（通过 metadata）
                        #[cfg(unix)]
                        if let (Ok(old_meta), Ok(new_meta)) =
                            (inner.metadata(), new_file.metadata())
                        {
                            use std::os::unix::fs::MetadataExt;
                            if old_meta.ino() != new_meta.ino() {
                                self.logger
                                    .lock()
                                    .unwrap()
                                    .info("检测到 auth.log 日志轮转，重新打开文件");
                                reader = BufReader::new(new_file);
                            }
                        }
                    }
                    continue;
                }
                Ok(_) => {
                    eof_count = 0;
                    let line = line.trim_end().to_string();
                    if line.is_empty() {
                        continue;
                    }

                    if let Some(event) =
                        Self::parse_line(&line, &self.patterns, &self.pattern_configs)
                    {
                        let mut bm = self.ban_manager.lock().unwrap();
                        bm.record_failure(&event.ip, &event.user, event.port);
                    }
                }
                Err(e) => {
                    self.logger
                        .lock()
                        .unwrap()
                        .error(&format!("读取 auth.log 错误: {}", e));
                    thread::sleep(Duration::from_secs(2));
                }
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 构建解析正则组
    // ─────────────────────────────────────────────────────────────────────────
    fn build_patterns() -> Vec<Regex> {
        vec![
            // Failed password for <user> from <ip> port <port>
            Regex::new(r"Failed password for (?:invalid user )?(\S+) from ([\d.]+) port (\d+)")
                .unwrap(),
            // Failed password for invalid user <user> from <ip> port <port>
            // (已被上面的可选 group 覆盖)

            // Invalid user <user> from <ip> port <port>
            Regex::new(r"Invalid user (\S+) from ([\d.]+)(?:\s+port\s+(\d+))?").unwrap(),
            // pam_unix authentication failure ... rhost=<ip>  user=<user>
            Regex::new(r"authentication failure;.*rhost=([\d.]+).*user=(\S+)").unwrap(),
            // BREAK-IN ATTEMPT from <ip>
            Regex::new(r"BREAK-IN ATTEMPT from ([\d.]+)").unwrap(),
            // Did not receive identification string from <ip>
            Regex::new(r"Did not receive identification string from ([\d.]+)").unwrap(),
            // Connection closed by <ip> port <port> [preauth]
            Regex::new(r"Connection closed by ([\d.]+) port (\d+) \[preauth]").unwrap(),
            // Disconnecting invalid user <user> <ip> port <port>
            Regex::new(r"Disconnecting invalid user (\S+) ([\d.]+) port (\d+)").unwrap(),
        ]
    }

    fn build_pattern_configs() -> Vec<PatternConfig> {
        vec![
            // Failed password: user=1, ip=2, port=3
            PatternConfig {
                ip_group: 2,
                user_group: Some(1),
                port_group: Some(3),
                default_user: "unknown",
            },
            // Invalid user: user=1, ip=2, port=3
            PatternConfig {
                ip_group: 2,
                user_group: Some(1),
                port_group: Some(3),
                default_user: "unknown",
            },
            // pam_unix: ip=1, user=2
            PatternConfig {
                ip_group: 1,
                user_group: Some(2),
                port_group: None,
                default_user: "unknown",
            },
            // BREAK-IN ATTEMPT: ip=1
            PatternConfig {
                ip_group: 1,
                user_group: None,
                port_group: None,
                default_user: "unknown",
            },
            // Did not receive: ip=1
            PatternConfig {
                ip_group: 1,
                user_group: None,
                port_group: None,
                default_user: "unknown",
            },
            // Connection closed: ip=1, port=2
            PatternConfig {
                ip_group: 1,
                user_group: None,
                port_group: Some(2),
                default_user: "preauth",
            },
            // Disconnecting invalid user: user=1, ip=2, port=3
            PatternConfig {
                ip_group: 2,
                user_group: Some(1),
                port_group: Some(3),
                default_user: "unknown",
            },
        ]
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 解析单行日志
    // ─────────────────────────────────────────────────────────────────────────
    fn parse_line(
        line: &str,
        patterns: &[Regex],
        configs: &[PatternConfig],
    ) -> Option<FailedLogin> {
        // 仅处理包含 sshd 的行
        if !line.contains("sshd") {
            return None;
        }

        for (pattern, cfg) in patterns.iter().zip(configs.iter()) {
            if let Some(caps) = pattern.captures(line) {
                let ip = caps.get(cfg.ip_group).map_or("", |m| m.as_str());
                if ip.is_empty() {
                    continue;
                }
                let user = cfg
                    .user_group
                    .and_then(|g| caps.get(g))
                    .map_or(cfg.default_user, |m| m.as_str());
                let port = cfg
                    .port_group
                    .and_then(|g| caps.get(g))
                    .and_then(|m| m.as_str().parse().ok());
                return Some(FailedLogin {
                    ip: ip.to_string(),
                    user: user.to_string(),
                    port,
                });
            }
        }

        None
    }
}
