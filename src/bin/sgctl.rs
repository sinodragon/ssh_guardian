use ssh_guardian::ipc::{Command, Response, SOCKET_PATH};
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
        _ => {
            eprintln!("用法:");
            eprintln!("  sgctl status          查看全部状态");
            eprintln!("  sgctl banned          列出封禁中的IP");
            eprintln!("  sgctl tracked         列出追踪中的IP");
            eprintln!("  sgctl unban <IP>      手动解禁");
            eprintln!("  sgctl ban   <IP>      手动封禁");
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
    }
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
                until.format("%Y-%m-%d %H:%M:%S"),
                r.ban_count
            );
        }
    }
}
