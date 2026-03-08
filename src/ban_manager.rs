// ban_manager.rs — UFW 封禁 / 解禁管理
use chrono::Utc;
use std::process::Command;
use std::sync::{Arc, Mutex};

use crate::config::Config;
use crate::logger::GuardianLogger;
use crate::state::{IpRecord, StateDb};

pub struct BanManager {
    state_db: Arc<Mutex<StateDb>>,
    logger: Arc<Mutex<GuardianLogger>>,
    config: Config,
    ssh_port: String,
}

impl BanManager {
    pub fn new(
        state_db: Arc<Mutex<StateDb>>,
        logger: Arc<Mutex<GuardianLogger>>,
        config: Config,
    ) -> Self {
        let ssh_port = config.ssh_port.to_string();
        BanManager {
            state_db,
            logger,
            config,
            ssh_port,
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 公开接口：记录一次失败登录，并决定是否封禁
    // ─────────────────────────────────────────────────────────────────────────
    pub fn record_failure(&mut self, ip: &str, user: &str, port: Option<u16>) {
        if self.config.is_whitelisted(ip) {
            return;
        }

        let fail_count = {
            let mut db = self.state_db.lock().unwrap();
            // 1. 添加失败事件
            db.add_fail_event(ip, user, port);
            // 2. 统计窗口内失败次数
            db.fail_count_in_window(ip, self.config.time_window_secs)
        };

        // 3. 记录日志
        {
            let mut log = self.logger.lock().unwrap();
            log.fail_detected(ip, user, fail_count, self.config.fail_threshold);
        }

        // 4. 未达阈值，不处理
        if fail_count <= self.config.fail_threshold {
            return;
        }

        // 5. 判断是否已在封禁中
        let already_banned = {
            let db = self.state_db.lock().unwrap();
            db.records
                .get(ip)
                .map(|r| r.is_currently_banned())
                .unwrap_or(false)
        };

        if already_banned {
            // 封禁期间再次触发，仅记录，不重置计时
            let mut log = self.logger.lock().unwrap();
            log.warn(&format!(
                "IP={} 在封禁期间继续尝试登录（窗口内失败 {} 次），跳过重复处理",
                ip, fail_count
            ));
            return;
        }

        // 6. 计算新封禁参数
        let (new_ban_count, duration_secs, permanent) = {
            let db = self.state_db.lock().unwrap();
            let ban_count = db.records.get(ip).map(|r| r.ban_count).unwrap_or(0);
            let new_count = ban_count + 1;
            if new_count >= self.config.max_ban_count {
                (new_count, 0u64, true)
            } else {
                // 封禁时长按 2^(n-1) 倍增长
                let multiplier = 2u64.pow(new_count - 1);
                let duration = self.config.ban_duration_secs * multiplier;
                (new_count, duration, false)
            }
        };

        // 7. 执行封禁
        self.do_ban(ip, new_ban_count, duration_secs, permanent, fail_count);

        // 8. 封禁后清除失败事件（避免重复计数）
        {
            let mut db = self.state_db.lock().unwrap();
            db.clear_fail_events(ip);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 检查并执行到期解禁
    // ─────────────────────────────────────────────────────────────────────────
    pub fn check_expired_bans(&mut self) {
        let expired: Vec<IpRecord> = {
            let db = self.state_db.lock().unwrap();
            db.active_temp_bans()
                .into_iter()
                .filter(|r| {
                    if let Some(until) = r.ban_until {
                        Utc::now() >= until
                    } else {
                        false
                    }
                })
                .collect()
        };

        for record in expired {
            self.do_unban(&record.ip, record.ban_count, "封禁到期自动解禁");
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 内部：调用 UFW 封禁并更新状态
    // ─────────────────────────────────────────────────────────────────────────
    fn do_ban(
        &mut self,
        ip: &str,
        ban_count: u32,
        duration_secs: u64,
        permanent: bool,
        fail_count: u32,
    ) {
        // 先检查是否已有 UFW 规则（避免重复）
        if self.ufw_rule_exists(ip) {
            // 规则存在但仍检测到失败，说明规则未正确生效
            // 先删除旧规则，重新插入到第1位确保优先匹配
            self.logger.lock().unwrap().warn(&format!(
                "IP={} UFW 规则已存在但仍检测到失败，删除旧规则并重新插入",
                ip
            ));
            if let Err(e) = self.ufw_delete(ip) {
                self.logger
                    .lock()
                    .unwrap()
                    .error(&format!("IP={} 删除旧规则失败: {}", ip, e));
                // 删除失败则放弃本次封禁，避免状态混乱
                return;
            }
        }

        match self.ufw_deny(ip) {
            Ok(_) => {
                if permanent {
                    self.logger.lock().unwrap().perm_ban(ip, ban_count);
                } else {
                    self.logger
                        .lock()
                        .unwrap()
                        .ban(ip, Some(duration_secs), ban_count, fail_count);
                }
            }
            Err(e) => {
                self.logger
                    .lock()
                    .unwrap()
                    .error(&format!("UFW 封禁 IP={} 失败: {}", ip, e));
                return;
            }
        }

        // 更新状态数据库
        let ban_until = if permanent {
            None
        } else {
            Some(Utc::now() + chrono::Duration::seconds(duration_secs as i64))
        };

        let mut db = self.state_db.lock().unwrap();
        let record = db.get_or_create(ip);
        record.ban_count = ban_count;
        record.ban_until = ban_until;
        record.permanent = permanent;
        record.last_banned = Some(Utc::now());
        record.last_fail_count = fail_count;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 内部：调用 UFW 解禁并更新状态
    // ─────────────────────────────────────────────────────────────────────────
    fn do_unban(&mut self, ip: &str, ban_count: u32, reason: &str) {
        match self.ufw_delete(ip) {
            Ok(_) => {
                self.logger.lock().unwrap().unban(ip, ban_count, reason);
            }
            Err(e) => {
                self.logger.lock().unwrap().warn(&format!(
                    "UFW 删除规则 IP={} 失败（可能已不存在）: {}",
                    ip, e
                ));
            }
        }

        // 更新状态（保留 ban_count，清空 ban_until）
        let mut db = self.state_db.lock().unwrap();
        if let Some(record) = db.records.get_mut(ip) {
            record.ban_until = None;
            record.permanent = false;
        }
        db.dirty = true;

        // 立即保存，解禁是关键状态变更
        if let Err(e) = db.save(&self.config.state_file) {
            self.logger
                .lock()
                .unwrap()
                .error(&format!("解禁后状态保存失败 IP={}: {}", ip, e));
        } else {
            db.dirty = false;
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // UFW 命令封装
    // ─────────────────────────────────────────────────────────────────────────
    fn ufw_deny(&self, ip: &str) -> Result<(), String> {
        let output = Command::new("ufw")
            .args([
                "insert",
                "1",
                "deny",
                "proto",
                "tcp",
                "from",
                ip,
                "to",
                "any",
                "port",
                &self.ssh_port,
                "comment",
                "ssh_guardian",
            ])
            .output()
            .map_err(|e| format!("执行 ufw 失败: {}", e))?;

        if output.status.success() {
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(format!("ufw deny 返回错误: {}", stderr.trim()))
        }
    }

    fn ufw_delete(&self, ip: &str) -> Result<(), String> {
        // ufw 删除规则：先查询编号，再按编号删除（避免交互确认问题）
        // 或直接使用 "ufw delete deny from <ip>"
        let output = Command::new("ufw")
            .args([
                "delete",
                "deny",
                "proto",
                "tcp",
                "from",
                ip,
                "to",
                "any",
                "port",
                &self.ssh_port,
            ])
            .output()
            .map_err(|e| format!("执行 ufw 失败: {}", e))?;

        if output.status.success() {
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // 规则不存在也视为成功（可能已手动删除）
            if stderr.contains("Could not delete") || stderr.contains("doesn't exist") {
                Ok(())
            } else {
                Err(format!("ufw delete 返回错误: {}", stderr.trim()))
            }
        }
    }

    fn ufw_rule_exists(&self, ip: &str) -> bool {
        let output = Command::new("ufw").args(["status"]).output();

        match output {
            Ok(o) => {
                let stdout = String::from_utf8_lossy(&o.stdout);
                let port = &self.ssh_port;
                stdout
                    .lines()
                    .any(|line| line.contains(ip) && line.contains(port) && line.contains("DENY"))
            }
            Err(_) => false,
        }
    }
}
