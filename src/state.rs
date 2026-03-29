// state.rs — 持久化状态数据库
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// 单个 IP 的封禁记录
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IpRecord {
    pub ip: String,
    /// 累计封禁次数
    pub ban_count: u32,
    /// 当前封禁到期时间；None 表示当前未被封禁（或永久封禁）
    pub ban_until: Option<DateTime<Utc>>,
    /// 是否永久封禁
    pub permanent: bool,
    /// 首次检测时间
    pub first_seen: DateTime<Utc>,
    /// 最近一次封禁时间
    pub last_banned: Option<DateTime<Utc>>,
    /// 最近一次触发封禁时统计到的失败次数
    pub last_fail_count: u32,
}

impl IpRecord {
    pub fn new(ip: &str) -> Self {
        IpRecord {
            ip: ip.to_string(),
            ban_count: 0,
            ban_until: None,
            permanent: false,
            first_seen: Utc::now(),
            last_banned: None,
            last_fail_count: 0,
        }
    }

    /// 判断当前是否处于封禁状态
    pub fn is_active_ban(&self) -> bool {
        if self.permanent {
            return true;
        }
        if let Some(until) = self.ban_until {
            return Utc::now() < until;
        }
        false
    }

    /// 剩余封禁秒数（已解禁或永久封禁时返回 None）
    #[allow(dead_code)]
    pub fn remaining_secs(&self) -> Option<i64> {
        if self.permanent {
            return None;
        }
        if let Some(until) = self.ban_until {
            let remaining = (until - Utc::now()).num_seconds();
            if remaining > 0 {
                return Some(remaining);
            }
        }
        None
    }
}

/// 失败登录事件（用于时间窗口统计）
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FailEvent {
    pub time: DateTime<Utc>,
    pub user: String,
    pub port: Option<u16>,
}

/// 完整状态数据库
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct StateDb {
    /// IP -> 封禁记录
    pub records: HashMap<String, IpRecord>,
    /// IP -> 最近失败事件列表（用于时间窗口统计）
    pub fail_events: HashMap<String, Vec<FailEvent>>,
    pub last_shutdown: Option<DateTime<Utc>>,
    pub start_time: Option<DateTime<Utc>>,
    #[serde(skip)]
    pub dirty: bool,
}

impl StateDb {
    pub fn new() -> Self {
        StateDb::default()
    }

    pub fn load(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let content = fs::read_to_string(path)?;
        let db: StateDb = serde_json::from_str(&content)?;
        Ok(db)
    }

    pub fn save(&self, path: &str) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(parent) = Path::new(path).parent() {
            fs::create_dir_all(parent)?;
        }
        let content = serde_json::to_string_pretty(self)?;
        // 原子写入：先写临时文件再 rename
        let tmp = format!("{}.tmp", path);
        fs::write(&tmp, &content)?;
        fs::rename(&tmp, path)?;
        Ok(())
    }

    /// 获取或创建 IP 记录
    pub fn get_or_create(&mut self, ip: &str) -> &mut IpRecord {
        self.dirty = true; // 该方法返回的 IP 记录用于更新状态数据，所以设置为 dirty
        self.records
            .entry(ip.to_string())
            .or_insert_with(|| IpRecord::new(ip))
    }

    /// 添加失败事件
    pub fn add_fail_event(&mut self, ip: &str, user: &str, port: Option<u16>) {
        let events = self
            .fail_events
            .entry(ip.to_string())
            .or_insert_with(Vec::new);
        events.push(FailEvent {
            time: Utc::now(),
            user: user.to_string(),
            port,
        });
        self.dirty = true;
    }

    /// 获取时间窗口内的失败次数，并清理过期事件
    pub fn fail_count_in_window(&mut self, ip: &str, window_secs: u64) -> u32 {
        let cutoff = Utc::now() - chrono::Duration::seconds(window_secs as i64);
        if let Some(events) = self.fail_events.get_mut(ip) {
            events.retain(|e| e.time > cutoff);
            let count = events.len() as u32;
            if count == 0 {
                self.fail_events.remove(ip);
                self.dirty = true;
            }
            count
        } else {
            0
        }
    }

    /// 清理某IP的失败事件（封禁后重置）
    pub fn clear_fail_events(&mut self, ip: &str) {
        self.fail_events.remove(ip);
        self.dirty = true;
    }

    /// 获取所有当前临时封禁中的记录（用于到期检查）
    pub fn expired_temp_bans(&self) -> Vec<IpRecord> {
        self.records
            .values()
            .filter(|r| r.ban_until.is_some() && !r.is_active_ban())
            .cloned()
            .collect()
    }

    /// 清理所有 IP 中已过期的失败事件，返回清理的条目数
    pub fn cleanup_expired_events(&mut self, window_secs: u64) -> usize {
        let cutoff = Utc::now() - chrono::Duration::seconds(window_secs as i64);
        let mut cleaned = 0;

        self.fail_events.retain(|_ip, events| {
            let before = events.len();
            events.retain(|e| e.time > cutoff);
            cleaned += before - events.len();
            // 事件全部过期则移除该 IP 的条目
            !events.is_empty()
        });
        if cleaned > 0 {
            self.dirty = true;
        }

        cleaned
    }

    /// 清理长期未活跃的历史记录（非永久封禁、已解禁、且超过保留期）
    pub fn cleanup_inactive_records(&mut self, retain_days: i64) -> usize {
        let cutoff = Utc::now() - chrono::Duration::days(retain_days);
        let before = self.records.len();

        self.records.retain(|_ip, record| {
            // 永久封禁记录永远保留
            if record.permanent {
                return true;
            }
            // 当前仍在封禁中，保留
            if record.is_active_ban() {
                return true;
            }
            // 最近有过封禁行为且未超过保留期，保留
            if let Some(last) = record.last_banned {
                return last > cutoff;
            }
            // 从未被封禁过（只有失败记录但未达阈值），超过窗口期则清理
            record.first_seen > cutoff
        });

        if before != self.records.len() {
            self.dirty = true;
        }

        before - self.records.len()
    }
}
