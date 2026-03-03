// config.rs — 配置管理
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    /// SSH 认证日志路径
    pub auth_log: String,
    /// 失败次数阈值（在 time_window_secs 内达到此值则触发封禁）
    pub fail_threshold: u32,
    /// 统计时间窗口（秒）
    pub time_window_secs: u64,
    /// 初始封禁时长（秒）
    pub ban_duration_secs: u64,
    /// 累计封禁达到此次数后永久封禁
    pub max_ban_count: u32,
    /// SSH 监听端口（用于日志分析时过滤）
    pub ssh_port: u16,
    /// 状态数据库文件路径
    pub state_file: String,
    /// 日志文件路径
    pub log_file: String,
    /// 白名单 IP 列表（不会被封禁）
    pub whitelist: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            auth_log: "/var/log/auth.log".to_string(),
            fail_threshold: 5,
            time_window_secs: 600,   // 10 分钟
            ban_duration_secs: 3600, // 1 小时
            max_ban_count: 3,
            ssh_port: 22,
            state_file: "/var/lib/ssh_guardian/state.json".to_string(),
            log_file: "/var/log/ssh_guardian.log".to_string(),
            whitelist: vec!["127.0.0.1".to_string(), "::1".to_string()],
        }
    }
}

impl Config {
    const CONFIG_PATH: &'static str = "/etc/ssh_guardian/config.json";

    pub fn load() -> Self {
        if Path::new(Self::CONFIG_PATH).exists() {
            match fs::read_to_string(Self::CONFIG_PATH) {
                Ok(content) => match serde_json::from_str(&content) {
                    Ok(cfg) => return cfg,
                    Err(e) => eprintln!("配置文件解析失败，使用默认配置: {}", e),
                },
                Err(e) => eprintln!("配置文件读取失败，使用默认配置: {}", e),
            }
        }
        Config::default()
    }

    /// 判断 IP 是否在白名单中，同时过滤私有地址
    pub fn is_whitelisted(&self, ip: &str) -> bool {
        if self.whitelist.iter().any(|w| w == ip) {
            return true;
        }
        // 过滤常见私有/本地地址段
        if ip.starts_with("127.")
            || ip.starts_with("10.")
            || ip.starts_with("::1")
            || ip == "localhost"
        {
            return true;
        }
        if ip.starts_with("192.168.") {
            return true;
        }
        // 172.16.0.0/12
        if let Some(second) = ip.strip_prefix("172.") {
            if let Some(octet_str) = second.split('.').next() {
                if let Ok(octet) = octet_str.parse::<u8>() {
                    if (16..=31).contains(&octet) {
                        return true;
                    }
                }
            }
        }
        false
    }
}
