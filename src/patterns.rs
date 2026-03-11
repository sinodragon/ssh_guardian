use crate::config::Config;
use chrono::{DateTime, Datelike, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};

pub struct PatternConfig {
    pub ip_group: usize,
    pub user_group: Option<usize>,
    pub port_group: Option<usize>,
    pub default_user: &'static str,
}

pub fn build_patterns() -> Vec<Regex> {
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

pub fn build_pattern_configs() -> Vec<PatternConfig> {
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

/// 解析出的 SSH 失败登录事件
#[derive(Debug)]
pub struct FailedLogin {
    pub ip: String,
    pub user: String,
    pub port: Option<u16>,
}

// 单条历史失败记录
#[derive(Serialize, Deserialize)]
pub struct HistoryFailRecord {
    pub ip: String,
    pub fail_count: u32,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub users: Vec<String>, // 尝试过的用户名列表
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
        let line_time = match parse_line_time(&line) {
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
        let event = match parse_line(&line, patterns, pattern_configs) {
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

// ─────────────────────────────────────────────────────────────────────────
// 解析单行日志
// ─────────────────────────────────────────────────────────────────────────
pub fn parse_line(
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
