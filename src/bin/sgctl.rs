use chrono::{DateTime, Local, Utc};
use ssh_guardian::ipc::{Command, Response, SOCKET_PATH};
use ssh_guardian::patterns::HistoryFailRecord;
use ssh_guardian::state::IpRecord;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let cmd = match args.get(1).map(String::as_str) {
        Some("status") => Command::Status,
        Some("banned") => Command::ListBanned,
        Some("tracked") => Command::ListTracked,
        Some("unban") => {
            let ip = args.get(2).expect("用法: sgctl unban <IP>");
            Command::Unban { ip: ip.clone() }
        }
        Some("ban") => {
            let ip = args.get(2).expect("用法: sgctl ban <IP>");
            Command::Ban { ip: ip.clone() }
        }
        Some("scan") => Command::ScanHistory,
        _ => {
            eprintln!("用法:");
            eprintln!("  sgctl status          查看全部状态");
            eprintln!("  sgctl banned          列出封禁中的IP");
            eprintln!("  sgctl tracked         列出追踪中的IP");
            eprintln!("  sgctl unban <IP>      手动解禁");
            eprintln!("  sgctl ban   <IP>      手动封禁");
            eprintln!("  sgctl scan            扫描历史记录");
            std::process::exit(1);
        }
    };

    // 连接 socket 并发送命令
    let mut stream = UnixStream::connect(SOCKET_PATH).unwrap_or_else(|e| {
        eprintln!("无法连接到 ssh_guardian（服务是否正在运行？）: {}", e);
        std::process::exit(1);
    });

    let json = serde_json::to_string(&cmd).unwrap();
    stream.write_all(json.as_bytes()).ok();
    stream.write_all(b"\n").ok();

    // 读取响应并格式化输出
    let mut response = String::new();
    BufReader::new(&stream).read_line(&mut response).ok();

    match serde_json::from_str::<Response>(&response) {
        Ok(resp) => print_response(resp),
        Err(e) => eprintln!("响应解析失败: {}", e),
    }
}

fn print_response(resp: Response) {
    match resp {
        Response::Status {
            banned,
            tracked,
            total_records,
        } => {
            print_banned_list(&banned);
            print_tracked_list(&tracked);
            println!("───────────────────────────────────────");
            println!("  历史记录共 {} 条", total_records);
            println!("═══════════════════════════════════════");
        }
        Response::Banned { records } => print_banned_list(&records),
        Response::Tracked { records } => print_tracked_list(&records),
        Response::Ok { message } => println!("✓ {}", message),
        Response::Err { message } => eprintln!("✗ {}", message),
        Response::HistoryScan { from, to, records } => print_scan_history(from, to, &records),
    }
}

fn print_scan_history(
    from: Option<DateTime<Utc>>,
    to: Option<DateTime<Utc>>,
    records: &Vec<HistoryFailRecord>,
) {
    println!("════════════════════════════════════════════");
    println!("  历史扫描结果");
    println!("  扫描范围: {} → {}", fmt_time_opt(from), fmt_time_opt(to));
    println!("  发现 {} 个IP有失败记录", records.len());
    println!("────────────────────────────────────────────");

    if records.is_empty() {
        println!("  （无失败记录）");
    } else {
        println!(
            "  {:<18} {:>6}  {:<19}  {:<19}  {}",
            "IP", "失败", "首次", "最近", "尝试用户"
        );
        println!("  {}", "─".repeat(80));
        for r in records {
            println!(
                "  {:<18} {:>6}  {}  {}  {}",
                r.ip,
                r.fail_count,
                fmt_time(r.first_seen),
                fmt_time(r.last_seen),
                r.users.join(", "),
            );
        }
        println!("────────────────────────────────────────────");
        println!("  提示：使用 sgctl ban <IP> 手动封禁可疑IP");
    }
    println!("════════════════════════════════════════════");
}

fn print_tracked_list(tracked: &Vec<(String, usize)>) {
    println!("═══════════════════════════════════════");
    println!("  追踪中 ({} 个IP)", tracked.len());
    println!("───────────────────────────────────────");
    for (ip, count) in tracked {
        println!("  {} 失败 {} 次", ip, count);
    }
}

fn print_banned_list(banned: &Vec<IpRecord>) {
    println!("═══════════════════════════════════════");
    println!("  封禁中 ({} 个IP)", banned.len());
    println!("───────────────────────────────────────");
    for r in banned {
        if r.permanent {
            println!("  {} 永久封禁 (累计{}次)", r.ip, r.ban_count);
        } else if let Some(until) = r.ban_until {
            println!(
                "  {} 到期: {} (累计{}次)",
                r.ip,
                fmt_time(until),
                r.ban_count
            );
        }
    }
}

// 定义一个辅助函数统一处理转换
fn fmt_time(t: DateTime<Utc>) -> String {
    t.with_timezone(&Local)
        .format("%Y-%m-%d %H:%M:%S")
        .to_string()
}

fn fmt_time_opt(t: Option<DateTime<Utc>>) -> String {
    t.map(|t| fmt_time(t)).unwrap_or_else(|| "未知".to_string())
}
