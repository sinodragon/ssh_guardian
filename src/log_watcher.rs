// log_watcher.rs — 实时监听 auth.log，解析 SSH 登录失败事件
use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::thread;
use regex::Regex;

use crate::config::Config;
use crate::ban_manager::BanManager;
use crate::logger::GuardianLogger;

pub struct LogWatcher {
    ban_manager: Arc<Mutex<BanManager>>,
    logger:      Arc<Mutex<GuardianLogger>>,
    config:      Config,
}

/// 解析出的 SSH 失败登录事件
#[derive(Debug)]
struct FailedLogin {
    ip:   String,
    user: String,
    port: Option<u16>,
}

impl LogWatcher {
    pub fn new(
        ban_manager: Arc<Mutex<BanManager>>,
        logger:      Arc<Mutex<GuardianLogger>>,
        config:      Config,
    ) -> Self {
        LogWatcher { ban_manager, logger, config }
    }

    pub fn run(&mut self) {
        // 构建 SSH 失败日志正则表达式组
        let patterns = Self::build_patterns();

        self.logger.lock().unwrap().info(&format!(
            "开始监听 auth.log: {}", self.config.auth_log
        ));

        // 打开文件，定位到末尾（只处理新增内容）
        let mut file = match File::open(&self.config.auth_log) {
            Ok(f)  => f,
            Err(e) => {
                self.logger.lock().unwrap().error(&format!(
                    "无法打开 {}: {}", self.config.auth_log, e
                ));
                return;
            }
        };

        // 定位到文件末尾，只读新增内容
        if let Err(e) = file.seek(SeekFrom::End(0)) {
            self.logger.lock().unwrap().warn(&format!("seek 失败: {}", e));
        }

        let mut reader = BufReader::new(file);

        loop {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) => {
                    // 没有新内容，等待后重试
                    thread::sleep(Duration::from_millis(500));

                    // 检查文件是否被日志轮转（inode 变化）
                    // 简单处理：每次 Ok(0) 时重新 open
                    let current_path = self.config.auth_log.clone();
                    if let Ok(new_file) = File::open(&current_path) {
                        // 用新文件替换 reader
                        let inner = reader.get_mut();
                        // 检查新旧文件是否相同（通过 metadata）
                        if let (Ok(old_meta), Ok(new_meta)) = (
                            inner.metadata(),
                            new_file.metadata(),
                        ) {
                            use std::os::unix::fs::MetadataExt;
                            if old_meta.ino() != new_meta.ino() {
                                self.logger.lock().unwrap().info(
                                    "检测到 auth.log 日志轮转，重新打开文件"
                                );
                                reader = BufReader::new(new_file);
                            }
                        }
                    }
                    continue;
                }
                Ok(_) => {
                    let line = line.trim_end().to_string();
                    if line.is_empty() { continue; }

                    if let Some(event) = Self::parse_line(&line, &patterns) {
                        let mut bm = self.ban_manager.lock().unwrap();
                        bm.record_failure(&event.ip, &event.user, event.port);
                    }
                }
                Err(e) => {
                    self.logger.lock().unwrap().error(&format!("读取 auth.log 错误: {}", e));
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
            Regex::new(
                r"Failed password for (?:invalid user )?(\S+) from ([\d\.]+) port (\d+)"
            ).unwrap(),

            // Failed password for invalid user <user> from <ip> port <port>
            // (已被上面的可选 group 覆盖)

            // Invalid user <user> from <ip> port <port>
            Regex::new(
                r"Invalid user (\S+) from ([\d\.]+)(?:\s+port\s+(\d+))?"
            ).unwrap(),

            // pam_unix authentication failure ... rhost=<ip>  user=<user>
            Regex::new(
                r"authentication failure;.*rhost=([\d\.]+).*user=(\S+)"
            ).unwrap(),

            // BREAK-IN ATTEMPT from <ip>
            Regex::new(
                r"BREAK-IN ATTEMPT from ([\d\.]+)"
            ).unwrap(),

            // Did not receive identification string from <ip>
            Regex::new(
                r"Did not receive identification string from ([\d\.]+)"
            ).unwrap(),

            // Connection closed by <ip> port <port> [preauth]
            Regex::new(
                r"Connection closed by ([\d\.]+) port (\d+) \[preauth\]"
            ).unwrap(),

            // Disconnecting invalid user <user> <ip> port <port>
            Regex::new(
                r"Disconnecting invalid user (\S+) ([\d\.]+) port (\d+)"
            ).unwrap(),
        ]
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 解析单行日志
    // ─────────────────────────────────────────────────────────────────────────
    fn parse_line(line: &str, patterns: &[Regex]) -> Option<FailedLogin> {
        // 仅处理包含 sshd 的行
        if !line.contains("sshd") {
            return None;
        }

        // 模式1: Failed password for [invalid user] <user> from <ip> port <port>
        if let Some(caps) = patterns[0].captures(line) {
            let user = caps.get(1).map_or("unknown", |m| m.as_str());
            let ip   = caps.get(2).map_or("", |m| m.as_str());
            let port = caps.get(3).and_then(|m| m.as_str().parse().ok());
            if !ip.is_empty() {
                return Some(FailedLogin { ip: ip.to_string(), user: user.to_string(), port });
            }
        }

        // 模式2: Invalid user <user> from <ip>
        if let Some(caps) = patterns[1].captures(line) {
            let user = caps.get(1).map_or("unknown", |m| m.as_str());
            let ip   = caps.get(2).map_or("", |m| m.as_str());
            let port = caps.get(3).and_then(|m| m.as_str().parse().ok());
            if !ip.is_empty() {
                return Some(FailedLogin { ip: ip.to_string(), user: user.to_string(), port });
            }
        }

        // 模式3: pam_unix ... rhost=<ip> ... user=<user>
        if let Some(caps) = patterns[2].captures(line) {
            let ip   = caps.get(1).map_or("", |m| m.as_str());
            let user = caps.get(2).map_or("unknown", |m| m.as_str());
            if !ip.is_empty() {
                return Some(FailedLogin { ip: ip.to_string(), user: user.to_string(), port: None });
            }
        }

        // 模式4: BREAK-IN ATTEMPT from <ip>
        if let Some(caps) = patterns[3].captures(line) {
            let ip = caps.get(1).map_or("", |m| m.as_str());
            if !ip.is_empty() {
                return Some(FailedLogin { ip: ip.to_string(), user: "unknown".to_string(), port: None });
            }
        }

        // 模式5: Did not receive identification string from <ip>
        if let Some(caps) = patterns[4].captures(line) {
            let ip = caps.get(1).map_or("", |m| m.as_str());
            if !ip.is_empty() {
                return Some(FailedLogin { ip: ip.to_string(), user: "unknown".to_string(), port: None });
            }
        }

        // 模式6: Connection closed by <ip> port <port> [preauth]
        if let Some(caps) = patterns[5].captures(line) {
            let ip   = caps.get(1).map_or("", |m| m.as_str());
            let port = caps.get(2).and_then(|m| m.as_str().parse().ok());
            if !ip.is_empty() {
                return Some(FailedLogin { ip: ip.to_string(), user: "preauth".to_string(), port });
            }
        }

        // 模式7: Disconnecting invalid user <user> <ip> port <port>
        if let Some(caps) = patterns[6].captures(line) {
            let user = caps.get(1).map_or("unknown", |m| m.as_str());
            let ip   = caps.get(2).map_or("", |m| m.as_str());
            let port = caps.get(3).and_then(|m| m.as_str().parse().ok());
            if !ip.is_empty() {
                return Some(FailedLogin { ip: ip.to_string(), user: user.to_string(), port });
            }
        }

        None
    }
}
