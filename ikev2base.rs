use std::env;
use std::io::{self, Write};
use std::process::Command;

#[derive(Debug)]
struct Config {
    netdatafrom: String,
    avoidfrom: Vec<String>,
    action: String,
}

fn usage() -> ! {
    eprintln!("Usage:");
    eprintln!("  ikev2_localpipe --netdatafrom <IP[:PORT]> [--avoidfrom <IP|IP:PORT|...>] <connectvpn|disconnectvpn|kill>");
    std::process::exit(1);
}

fn ask(prompt: &str) -> String {
    print!("{prompt}");
    io::stdout().flush().ok();
    let mut s = String::new();
    io::stdin().read_line(&mut s).ok();
    s.trim().to_string()
}

fn parse_args() -> Config {
    let args: Vec<String> = env::args().collect();
    if args.len() == 1 {
        usage();
    }

    let mut netdatafrom = String::new();
    let mut avoidfrom: Vec<String> = Vec::new();
    let mut action = String::new();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--netdatafrom" => {
                if i + 1 >= args.len() { usage(); }
                netdatafrom = args[i+1].clone();
                i += 2;
                continue;
            }
            "--avoidfrom" => {
                if i + 1 >= args.len() { usage(); }
                let parts = args[i+1]
                    .split('|')
                    .map(|s| s.split(':').next().unwrap_or("").to_string())
                    .filter(|s| !s.is_empty())
                    .collect::<Vec<_>>();
                avoidfrom.extend(parts);
                i += 2;
                continue;
            }
            "connectvpn" | "disconnectvpn" | "kill" => {
                action = args[i].clone();
            }
            _ => {}
        }
        i += 1;
    }

    if netdatafrom.is_empty() && action == "connectvpn" {
        netdatafrom = ask("Enter --netdatafrom (IP[:PORT]): ");
    }
    if avoidfrom.is_empty() && action == "connectvpn" {
        let a = ask("Enter --avoidfrom (optional, multiple with |): ");
        if !a.is_empty() {
            avoidfrom = a
                .split('|')
                .map(|s| s.split(':').next().unwrap_or("").to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }
    }

    if netdatafrom.is_empty() {
        eprintln!("[ERROR] --netdatafrom is required");
        usage();
    }
    if action.is_empty() {
        eprintln!("[ERROR] You must specify one action: connectvpn, disconnectvpn, or kill");
        usage();
    }

    // ensure netdatafrom IP is also in avoid list
    let nd_ip = netdatafrom.split(':').next().unwrap().to_string();
    avoidfrom.push(nd_ip);

    avoidfrom.sort();
    avoidfrom.dedup();

    Config {
        netdatafrom,
        avoidfrom,
        action,
    }
}

fn run_command(cmd: &mut Command, label: &str) {
    println!("[EXEC] {:?}", cmd);
    match cmd.status() {
        Ok(status) if status.success() => {
            println!("[OK] {}", label);
        }
        Ok(status) => {
            eprintln!("[WARN] {} failed exit code {:?}", label, status.code());
        }
        Err(e) => {
            eprintln!("[ERROR] cannot execute {}: {}", label, e);
        }
    }
}

#[cfg(target_os = "linux")]
async fn handle_linux(cfg: &Config) {
    use zbus::{Connection, Proxy};
    use zvariant::{Value, OwnedObjectPath};
    use std::collections::HashMap;

    let vpn_name = "ikev2-localhost-pipe";

    let connection = match Connection::system().await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[ERROR] cannot connect to system D-Bus: {e}");
            return;
        }
    };

    let nm = match Proxy::new(
        &connection,
        "org.freedesktop.NetworkManager",
        "/org/freedesktop/NetworkManager",
        "org.freedesktop.NetworkManager",
    ).await {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[ERROR] cannot create NM proxy: {e}");
            return;
        }
    };

    match cfg.action.as_str() {
        "connectvpn" => {
            let mut vpn = HashMap::new();
            vpn.insert("service-type", Value::from("org.freedesktop.NetworkManager.strongswan"));
            vpn.insert("address", Value::from("127.0.0.1"));
            vpn.insert("id", Value::from(vpn_name));
            vpn.insert("psk", Value::from("12"));

            let mut con = HashMap::new();
            let mut connection_section = HashMap::new();
            connection_section.insert("id", Value::from(vpn_name));
            connection_section.insert("type", Value::from("vpn"));
            con.insert("connection", connection_section);
            con.insert("vpn", vpn);

            let mut ipv4 = HashMap::new();
            ipv4.insert("never-default", Value::from(true));
            let routes4: Vec<String> = cfg.avoidfrom.iter().map(|ip| format!("{}/32", ip)).collect();
            ipv4.insert("routes", Value::from(routes4));
            con.insert("ipv4", ipv4);

            let mut ipv6 = HashMap::new();
            ipv6.insert("never-default", Value::from(true));
            let routes6: Vec<String> = cfg.avoidfrom.iter().map(|ip| format!("{}/128", ip)).collect();
            ipv6.insert("routes", Value::from(routes6));
            con.insert("ipv6", ipv6);

            match nm.call::<OwnedObjectPath>("AddConnection", &(con)).await {
                Ok(path) => {
                    println!("[INFO] Created VPN config: {:?}", path);
                    match nm.call::<OwnedObjectPath>(
                        "ActivateConnection",
                        &(path.clone(), OwnedObjectPath::from("/"), OwnedObjectPath::from("/")),
                    ).await
                    {
                        Ok(active) => {
                            println!("[INFO] VPN started: {:?}", active);
                        }
                        Err(e) => {
                            eprintln!("[ERROR] ActivateConnection failed: {e}");
                        }
                    }
                }
                Err(e) => {
                    eprintln!("[ERROR] AddConnection failed: {e}");
                }
            }
        }
        "disconnectvpn" => {
            match nm.get_property::<Vec<OwnedObjectPath>>("ActiveConnections").await {
                Ok(active_list) => {
                    for ac in active_list {
                        if let Ok(proxy_ac) = Proxy::new(
                            &connection,
                            "org.freedesktop.NetworkManager",
                            ac.as_str(),
                            "org.freedesktop.NetworkManager.Connection.Active",
                        )
                        .await
                        {
                            if let Ok(id) = proxy_ac.get_property::<String>("Id").await {
                                if id == vpn_name {
                                    println!("[INFO] Disconnecting VPN: {}", id);
                                    let _ = nm.call::<()>("DeactivateConnection", &(ac.clone())).await;
                                    break;
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!("[ERROR] cannot get ActiveConnections: {e}");
                }
            }
        }
        "kill" => {
            match nm.call::<Vec<OwnedObjectPath>>("ListConnections", &()).await {
                Ok(list) => {
                    for c in list {
                        if let Ok(cp) = Proxy::new(
                            &connection,
                            "org.freedesktop.NetworkManager",
                            c.as_str(),
                            "org.freedesktop.NetworkManager.Settings.Connection",
                        )
                        .await
                        {
                            if let Ok(settings) =
                                cp.call::<HashMap<String, HashMap<String, Value>>>("GetSettings", &()).await
                            {
                                if let Some(conn_section) = settings.get("connection") {
                                    if let Some(Value::Str(id)) = conn_section.get("id") {
                                        if id == vpn_name {
                                            println!("[INFO] Deleting VPN config: {}", id);
                                            let _ = cp.call::<()>("Delete", &()).await;
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!("[ERROR] ListConnections failed: {e}");
                }
            }
        }
        _ => usage(),
    }
}

#[cfg(target_os = "macos")]
fn handle_macos(cfg: &Config) {
    match cfg.action.as_str() {
        "connectvpn" => {
            run_command(&mut Command::new("scutil").args(&["--nc", "start", "ikev2-localhost-pipe"]), "macOS start VPN");
        }
        "disconnectvpn" => {
            run_command(&mut Command::new("scutil").args(&["--nc", "stop", "ikev2-localhost-pipe"]), "macOS stop VPN");
        }
        "kill" => {
            run_command(&mut Command::new("scutil").args(&["--nc", "stop", "ikev2-localhost-pipe"]), "macOS stop VPN");
            println!("[WARN] Please manually remove the VPN configuration (mobileconfig)");
        }
        _ => usage(),
    }
}

#[cfg(target_os = "windows")]
fn handle_windows(cfg: &Config) {
    let name = "ikev2-localhost-pipe";
    match cfg.action.as_str() {
        "connectvpn" => {
            run_command(&mut Command::new("powershell")
                .arg("-Command")
                .arg(format!("Add-VpnConnection -Name '{name}' -ServerAddress 'localhost' -TunnelType IKEv2 -SplitTunneling -Force")), "Windows create VPN connection");
            for ip in &cfg.avoidfrom {
                run_command(&mut Command::new("powershell")
                    .arg("-Command")
                    .arg(format!("Add-VpnConnectionRoute -ConnectionName '{name}' -DestinationPrefix '{ip}/32' -PassThru")), "Windows route avoid IPv4");
                run_command(&mut Command::new("powershell")
                    .arg("-Command")
                    .arg(format!("Add-VpnConnectionRoute -ConnectionName '{name}' -DestinationPrefix '{ip}/128' -PassThru")), "Windows route avoid IPv6");
            }
            run_command(&mut Command::new("powershell")
                .arg("-Command")
                .arg(format!("rasdial {name} 12")), "Windows dial VPN");
        }
        "disconnectvpn" => {
            run_command(&mut Command::new("powershell")
                .arg("-Command")
                .arg(format!("rasdial {name} /disconnect")), "Windows disconnect VPN");
        }
        "kill" => {
            run_command(&mut Command::new("powershell")
                .arg("-Command")
                .arg(format!("rasdial {name} /disconnect")), "Windows disconnect VPN");
            run_command(&mut Command::new("powershell")
                .arg("-Command")
                .arg(format!("Remove-VpnConnection -Name '{name}' -Force -PassThru")), "Windows delete VPN connection");
        }
        _ => usage(),
    }
}

#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() {
    let cfg = parse_args();
    println!("[CONFIG] {:?}", cfg);
    handle_linux(&cfg).await;
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn main() {
    let cfg = parse_args();
    println!("[CONFIG] {:?}", cfg);
    #[cfg(target_os = "macos")]
    handle_macos(&cfg);
    #[cfg(target_os = "windows")]
    handle_windows(&cfg);
}
