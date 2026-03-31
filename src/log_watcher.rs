// log_watcher.rs — 实时监听 auth.log，解析 SSH 登录失败事件
use crate::ban_manager::BanManager;
use crate::config::Config;
use crate::logger::GuardianLogger;
use crate::patterns::{parse_line, PatternConfig};
use regex::Regex;
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
                    if let Ok(latest_file) = File::open(&current_path) {
                        // 用新文件替换 reader
                        let current_file = reader.get_ref();
                        // 检查新旧文件是否相同（通过 metadata）
                        #[cfg(unix)]
                        if let (Ok(current_meta), Ok(latest_meta)) =
                            (current_file.metadata(), latest_file.metadata())
                        {
                            use std::os::unix::fs::MetadataExt;
                            if current_meta.ino() != latest_meta.ino() {
                                self.logger
                                    .lock()
                                    .unwrap()
                                    .info("检测到 auth.log 日志轮转，重新打开文件");
                                reader = BufReader::new(latest_file);
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

                    if let Some(event) = parse_line(&line, &self.patterns, &self.pattern_configs) {
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
}
