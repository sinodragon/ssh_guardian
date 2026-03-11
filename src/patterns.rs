use regex::Regex;

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
