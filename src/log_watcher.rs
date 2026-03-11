// log_watcher.rs — 实时监听 auth.log，解析 SSH 登录失败事件
use crate::ban_manager::BanManager;
use crate::config::Config;
use crate::ipc::HistoryFailRecord;
use crate::logger::GuardianLogger;
use crate::patterns::PatternConfig;
use chrono::{DateTime, Datelike, Utc};
use regex::Regex;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

pub struct LogWatcher {
    ban_manager: Arc<Mutex<BanManager>>,
    logger: Arc<Mutex<GuardianLogger>>,
    config: Config,
    patterns: Arc<Vec<Regex>>,
    pattern_configs: Arc<Vec<PatternConfig>>,
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
        patterns: Arc<Vec<Regex>>,
        pattern_configs: Arc<Vec<PatternConfig>>,
    ) -> Self {
        LogWatcher {
            ban_manager,
            logger,
            config,
            patterns,
            pattern_configs,
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

    /// 扫描指定时间范围内的历史失败记录，返回按IP聚合的结果
    pub fn scan_history_range(
        auth_log: &str,
        from: Option<DateTime<Utc>>,
        to: Option<DateTime<Utc>>,
        config: &Config,
        patterns: &[Regex],
        pattern_configs: &[PatternConfig],
    ) -> Vec<HistoryFailRecord> {
        let file = match File::open(auth_log) {
            Ok(f) => f,
            Err(_) => return vec![],
        };

        // 用 HashMap 按IP聚合
        let mut aggregated: HashMap<String, HistoryFailRecord> = HashMap::new();

        for line in BufReader::new(file).lines() {
            let line = match line {
                Ok(l) => l,
                Err(_) => continue,
            };

            // 解析行时间戳
            let line_time = match Self::parse_line_time(&line) {
                Some(t) => t,
                None => continue,
            };

            // 过滤时间范围
            if let Some(from_time) = from {
                if line_time < from_time {
                    continue;
                }
            }
            if let Some(to_time) = to {
                if line_time > to_time {
                    continue;
                }
            }

            // 解析失败登录事件
            let event = match Self::parse_line(&line, patterns, pattern_configs) {
                Some(e) => e,
                None => continue,
            };

            // 过滤白名单
            if config.is_whitelisted(&event.ip) {
                continue;
            }

            // 按IP聚合
            let record = aggregated
                .entry(event.ip.clone())
                .or_insert_with(|| HistoryFailRecord {
                    ip: event.ip.clone(),
                    fail_count: 0,
                    first_seen: line_time,
                    last_seen: line_time,
                    users: vec![],
                });

            record.fail_count += 1;
            record.last_seen = line_time;
            if !record.users.contains(&event.user) {
                record.users.push(event.user.clone());
            }
        }

        // 按失败次数降序排列
        let mut results: Vec<HistoryFailRecord> = aggregated.into_values().collect();
        results.sort_by(|a, b| b.fail_count.cmp(&a.fail_count));
        results
    }

    /// 解析单行日志的时间戳
    fn parse_line_time(line: &str) -> Option<DateTime<Utc>> {
        if line.len() < 15 {
            return None;
        }
        let time_str = &line[..15];
        let year = Utc::now().year();
        let full = format!("{} {}", year, time_str);
        chrono::NaiveDateTime::parse_from_str(&full, "%Y %b %d %H:%M:%S")
            .ok()
            .map(|t| {
                let ts = t.and_utc();
                // 跨年处理：解析结果超过当前时间说明是上一年
                if ts > Utc::now() {
                    let last_year = format!("{} {}", year - 1, time_str);
                    chrono::NaiveDateTime::parse_from_str(&last_year, "%Y %b %d %H:%M:%S")
                        .ok()
                        .map(|t| t.and_utc())
                        .unwrap_or(ts)
                } else {
                    ts
                }
            })
    }
}
