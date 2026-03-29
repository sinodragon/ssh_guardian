// logger.rs — 结构化文件日志
use chrono::Local;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::Path;

pub struct GuardianLogger {
    writer: BufWriter<File>,
}

impl GuardianLogger {
    pub fn new(path: &str) -> Result<Self, std::io::Error> {
        if let Some(parent) = Path::new(path).parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(GuardianLogger {
            writer: BufWriter::new(file),
        })
    }

    fn write_line(&mut self, level: &str, msg: &str) {
        let ts = Local::now().format("%Y-%m-%d %H:%M:%S");
        let line = format!("[{}] [{:<5}] {}\n", ts, level, msg);
        let _ = self.writer.write_all(line.as_bytes());
        let _ = self.writer.flush();
        // 同时输出到 stderr（systemd journald 会收集）
        eprint!("{}", line);
    }

    pub fn info(&mut self, msg: &str) {
        self.write_line("INFO", msg);
    }

    pub fn warn(&mut self, msg: &str) {
        self.write_line("WARN", msg);
    }

    pub fn error(&mut self, msg: &str) {
        self.write_line("ERROR", msg);
    }

    pub fn ban(&mut self, ip: &str, duration_secs: Option<u64>, ban_count: u32, fail_count: u32) {
        let duration_str = match duration_secs {
            Some(s) => format!("{}秒 ({}小时{}分)", s, s / 3600, (s % 3600) / 60),
            None => "永久".to_string(),
        };
        self.write_line(
            "BAN",
            &format!(
                "封禁 IP={} | 时长={} | 累计封禁次数={} | 触发失败次数={}",
                ip, duration_str, ban_count, fail_count
            ),
        );
    }

    pub fn unban(&mut self, ip: &str, ban_count: u32, reason: &str) {
        self.write_line(
            "UNBAN",
            &format!(
                "解禁 IP={} | 历史封禁次数={} | 原因={}",
                ip, ban_count, reason
            ),
        );
    }

    pub fn fail_detected(
        &mut self,
        ip: &str,
        user: &str,
        count: u32,
        threshold: u32,
        total_fails: u32,
        total_threshold: u32,
    ) {
        self.write_line(
            "FAIL",
            &format!(
                "登录失败 IP={} | 用户={} | 窗口内失败次数={}/{} | 总失败次数={}/{}",
                ip, user, count, threshold, total_fails, total_threshold
            ),
        );
    }

    pub fn perm_ban(&mut self, ip: &str, ban_count: u32) {
        self.write_line(
            "PERM",
            &format!("永久封禁 IP={} | 累计达到 {} 次封禁上限", ip, ban_count),
        );
    }
}
