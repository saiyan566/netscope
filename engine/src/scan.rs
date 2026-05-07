use crate::types::{emit, EngineRequest, ScanEvent, Target};
use serde_json::json;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const COMMON_TCP_PORTS: &[u16] = &[
    22, 80, 443, 8080, 8443, 3389, 445, 139, 53, 25, 110, 143, 587, 993, 995, 21, 23, 123, 161,
    389, 636, 3306, 5432, 6379, 27017, 9200, 9300, 11211, 5900, 6000, 8000, 8888,
];

const COMMON_UDP_PORTS: &[u16] = &[53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514, 520, 1900, 4500, 5353, 11211];

#[derive(Clone, Copy)]
enum Transport {
    Tcp,
    Udp,
}

pub fn discover_hosts(request: &EngineRequest, targets: &[Target]) -> Vec<Target> {
    let methods = request.discovery_methods.join(",");
    if methods.contains("arp") || methods.contains("icmp") {
        emit(json!({
            "type": "warning",
            "message": "raw ARP/ICMP discovery is exposed in the interface; this MVP uses TCP fallback unless a future Linux privileged probe backend is enabled"
        }));
    }

    let ports = parse_ports_or_default(&request.tcp_ping_ports, &[22, 80, 443, 445, 3389], 5)
        .unwrap_or_else(|_| vec![22, 80, 443, 445, 3389]);
    let timeout = Duration::from_millis(request.timeout_ms.max(100));
    let mut up = Vec::new();

    for target in targets {
        let started = Instant::now();
        let mut found = false;
        let mut reason = String::from("no tcp liveness response");
        for port in &ports {
            if tcp_connect(target.ip, *port, timeout).is_some() {
                found = true;
                reason = format!("tcp/{port} accepted connection");
                break;
            }
        }
        if found {
            up.push(target.clone());
        }
        emit(json!({
            "type": "host",
            "target": target.original,
            "resolved_ip": target.ip.to_string(),
            "state": if found { "up" } else { "unknown" },
            "method": "tcp",
            "rtt_ms": started.elapsed().as_millis() as u64,
            "reason": reason
        }));
    }

    emit(json!({
        "type": "summary",
        "message": format!("host discovery complete: {} up or responsive, {} unknown", up.len(), targets.len().saturating_sub(up.len()))
    }));
    up
}

pub fn run_scan(request: &EngineRequest, targets: Vec<Target>) -> Vec<ScanEvent> {
    if targets.is_empty() {
        emit(json!({"type": "summary", "message": "no targets to scan"}));
        return Vec::new();
    }

    let selected_targets = if request.discover_hosts && !request.skip_host_discovery {
        let live = discover_hosts(request, &targets);
        if live.is_empty() {
            emit(json!({
                "type": "warning",
                "message": "host discovery did not identify responsive hosts; no port scans were launched"
            }));
        }
        live
    } else {
        targets
    };

    let tcp_ports = if request.tcp {
        parse_ports_or_default(&request.ports, COMMON_TCP_PORTS, request.top_ports)
            .unwrap_or_else(|err| {
                emit(json!({"type": "error", "message": err}));
                Vec::new()
            })
    } else {
        Vec::new()
    };
    let udp_ports = if request.udp {
        parse_ports_or_default(&request.udp_ports, COMMON_UDP_PORTS, request.top_udp)
            .unwrap_or_else(|err| {
                emit(json!({"type": "error", "message": err}));
                Vec::new()
            })
    } else {
        Vec::new()
    };

    let jobs_per_target = tcp_ports.len() + udp_ports.len();
    let job_count = selected_targets.len().saturating_mul(jobs_per_target);
    emit(json!({
        "type": "progress",
        "message": format!("queued {job_count} probes across {} targets", selected_targets.len())
    }));
    if job_count == 0 {
        emit(json!({"type": "summary", "message": "no probes selected"}));
        return Vec::new();
    }

    let targets = Arc::new(selected_targets);
    let tcp_ports = Arc::new(tcp_ports);
    let udp_ports = Arc::new(udp_ports);
    let next_job = Arc::new(AtomicUsize::new(0));
    let events = Arc::new(Mutex::new(Vec::new()));
    let worker_count = request.concurrency.clamp(1, 2048).min(job_count);
    let timeout = Duration::from_millis(request.timeout_ms.max(100));
    let per_worker_delay = rate_delay(request.rate, worker_count);
    let udp_retries = request.udp_retries.max(1);
    let ssh_audit = request.ssh_audit;

    let mut handles = Vec::new();
    for _ in 0..worker_count {
        let targets = Arc::clone(&targets);
        let tcp_ports = Arc::clone(&tcp_ports);
        let udp_ports = Arc::clone(&udp_ports);
        let next_job = Arc::clone(&next_job);
        let events = Arc::clone(&events);
        let handle = thread::spawn(move || loop {
            let index = next_job.fetch_add(1, Ordering::Relaxed);
            if index >= job_count {
                break;
            }
            if let Some(delay) = per_worker_delay {
                thread::sleep(delay);
            }
            let target_index = index / jobs_per_target;
            let port_index = index % jobs_per_target;
            let target = &targets[target_index];
            let event = if port_index < tcp_ports.len() {
                scan_probe(target, tcp_ports[port_index], Transport::Tcp, timeout, udp_retries, ssh_audit)
            } else {
                let udp_index = port_index - tcp_ports.len();
                scan_probe(target, udp_ports[udp_index], Transport::Udp, timeout, udp_retries, ssh_audit)
            };
            if let Some(event) = event {
                emit(serde_json::to_value(&event).unwrap_or_else(|_| json!({
                    "type": "error",
                    "message": "failed to serialize scan event"
                })));
                events.lock().expect("event lock poisoned").push(event);
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        let _ = handle.join();
    }

    let events = events.lock().expect("event lock poisoned").clone();
    emit(json!({
        "type": "summary",
        "message": format!("scan complete: {} responsive ports from {job_count} probes", events.len())
    }));
    events
}

fn scan_probe(
    target: &Target,
    port: u16,
    transport: Transport,
    timeout: Duration,
    udp_retries: usize,
    ssh_audit: bool,
) -> Option<ScanEvent> {
    match transport {
        Transport::Tcp => scan_tcp(target, port, timeout, ssh_audit),
        Transport::Udp => scan_udp(target, port, timeout, udp_retries),
    }
}

fn scan_tcp(target: &Target, port: u16, timeout: Duration, ssh_audit: bool) -> Option<ScanEvent> {
    let mut stream = tcp_connect(target.ip, port, timeout)?;
    let mut banner = String::new();
    let mut service = service_name(port, "tcp").to_string();

    let _ = stream.set_read_timeout(Some(Duration::from_millis(350)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(350)));

    if port == 22 || ssh_audit {
        let mut buf = [0u8; 256];
        if let Ok(n) = stream.read(&mut buf) {
            banner = String::from_utf8_lossy(&buf[..n]).trim().to_string();
            if banner.starts_with("SSH-") {
                service = "ssh".into();
                emit_ssh_service(target, port, &banner);
            }
        }
    } else if matches!(port, 80 | 8080 | 8000 | 8888) {
        let _ = stream.write_all(b"HEAD / HTTP/1.0\r\n\r\n");
        let mut buf = [0u8; 512];
        if let Ok(n) = stream.read(&mut buf) {
            banner = first_line(&String::from_utf8_lossy(&buf[..n]));
            if banner.starts_with("HTTP/") {
                service = "http".into();
            }
        }
    }

    Some(ScanEvent {
        event_type: "open_port".into(),
        target: target.original.clone(),
        resolved_ip: target.ip.to_string(),
        port,
        transport: "tcp".into(),
        state: "open".into(),
        reason: "connect accepted".into(),
        service,
        banner,
    })
}

fn emit_ssh_service(target: &Target, port: u16, banner: &str) {
    let protocol_version = banner
        .split('-')
        .nth(1)
        .unwrap_or("")
        .trim()
        .to_string();
    let server_id = banner
        .splitn(3, '-')
        .nth(2)
        .unwrap_or("")
        .trim()
        .to_string();
    emit(json!({
        "type": "service",
        "target": target.original,
        "resolved_ip": target.ip.to_string(),
        "port": port,
        "transport": "tcp",
        "service": "ssh",
        "banner": banner,
        "ssh": {
            "protocol_version": protocol_version,
            "server_id": server_id,
            "host_key_types": [],
            "kex_algorithms": [],
            "auth_methods": []
        }
    }));
}

fn scan_udp(target: &Target, port: u16, timeout: Duration, retries: usize) -> Option<ScanEvent> {
    let bind_addr = if target.ip.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let socket = UdpSocket::bind(bind_addr).ok()?;
    let _ = socket.set_read_timeout(Some(timeout));
    let _ = socket.set_write_timeout(Some(timeout));
    let addr = SocketAddr::new(target.ip, port);
    socket.connect(addr).ok()?;

    let payload = udp_probe(port);
    let mut buf = [0u8; 1024];
    for _ in 0..retries {
        let _ = socket.send(payload);
        match socket.recv(&mut buf) {
            Ok(n) => {
                let banner = printable(&buf[..n]);
                return Some(ScanEvent {
                    event_type: "open_port".into(),
                    target: target.original.clone(),
                    resolved_ip: target.ip.to_string(),
                    port,
                    transport: "udp".into(),
                    state: "open".into(),
                    reason: "udp response received".into(),
                    service: service_name(port, "udp").to_string(),
                    banner,
                });
            }
            Err(err) if err.kind() == std::io::ErrorKind::ConnectionRefused => {
                return None;
            }
            Err(_) => {}
        }
    }
    None
}

fn tcp_connect(ip: IpAddr, port: u16, timeout: Duration) -> Option<TcpStream> {
    let addr = SocketAddr::new(ip, port);
    TcpStream::connect_timeout(&addr, timeout).ok()
}

pub fn parse_ports_or_default(spec: &str, defaults: &[u16], top: usize) -> Result<Vec<u16>, String> {
    if spec.trim().is_empty() {
        return Ok(defaults.iter().copied().take(top.max(1)).collect());
    }
    let mut ports = Vec::new();
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((start, end)) = part.split_once('-') {
            let start = parse_port(start)?;
            let end = parse_port(end)?;
            if start > end {
                return Err(format!("invalid port range {part:?}"));
            }
            for port in start..=end {
                ports.push(port);
            }
        } else {
            ports.push(parse_port(part)?);
        }
    }
    ports.sort_unstable();
    ports.dedup();
    Ok(ports)
}

fn parse_port(value: &str) -> Result<u16, String> {
    let port: u16 = value
        .trim()
        .parse()
        .map_err(|_| format!("invalid port {value:?}"))?;
    if port == 0 {
        return Err("port 0 is not supported".into());
    }
    Ok(port)
}

fn rate_delay(rate: usize, workers: usize) -> Option<Duration> {
    if rate == 0 {
        return None;
    }
    let per_worker = (rate / workers.max(1)).max(1);
    Some(Duration::from_millis((1000 / per_worker).max(1) as u64))
}

fn service_name(port: u16, transport: &str) -> &'static str {
    match (transport, port) {
        ("tcp", 22) => "ssh",
        ("tcp", 80 | 8080 | 8000 | 8888) => "http",
        ("tcp", 443 | 8443) => "https",
        ("tcp", 21) => "ftp",
        ("tcp", 23) => "telnet",
        ("tcp", 25 | 587) => "smtp",
        ("tcp", 53) | ("udp", 53) => "dns",
        ("udp", 123) => "ntp",
        ("udp", 161) => "snmp",
        ("udp", 1900) => "ssdp",
        ("udp", 5353) => "mdns",
        ("tcp", 3306) => "mysql",
        ("tcp", 5432) => "postgres",
        ("tcp", 6379) => "redis",
        ("tcp", 9200 | 9300) => "elasticsearch",
        _ => "unknown",
    }
}

fn udp_probe(port: u16) -> &'static [u8] {
    match port {
        53 => b"\0\x01\x01\0\0\x01\0\0\0\0\0\0\x07example\x03com\0\0\x01\0\x01",
        123 => b"\x1b\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        161 => b"\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04\x70\x69\x6e\x67\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00",
        1900 => b"M-SEARCH * HTTP/1.1\r\nHOST:239.255.255.250:1900\r\nMAN:\"ssdp:discover\"\r\nMX:1\r\nST:ssdp:all\r\n\r\n",
        _ => b"\0",
    }
}

fn first_line(value: &str) -> String {
    value.lines().next().unwrap_or("").trim().to_string()
}

fn printable(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| {
            if b.is_ascii_graphic() || *b == b' ' {
                *b as char
            } else {
                '.'
            }
        })
        .collect::<String>()
        .chars()
        .take(160)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_port_ranges_and_dedupes() {
        let ports = parse_ports_or_default("22,80-82,22", &[], 0).unwrap();
        assert_eq!(ports, vec![22, 80, 81, 82]);
    }

    #[test]
    fn rejects_port_zero() {
        assert!(parse_ports_or_default("0", &[], 0).is_err());
    }
}
