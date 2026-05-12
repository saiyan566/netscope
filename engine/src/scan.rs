use crate::types::{emit, EngineRequest, ScanEvent, Target};
use rustls::client::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier, ServerName,
};
use rustls::{
    Certificate, ClientConfig, ClientConnection, DigitallySignedStruct, OwnedTrustAnchor,
    RootCertStore, SignatureScheme,
};
use serde_json::json;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant, SystemTime};
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::*;

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
    let service_detect = request.service_detect;
    let http_audit = request.http_audit;
    let tls_audit = request.tls_audit;

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
                scan_probe(
                    target,
                    tcp_ports[port_index],
                    Transport::Tcp,
                    timeout,
                    udp_retries,
                    ssh_audit,
                    service_detect,
                    http_audit,
                    tls_audit,
                )
            } else {
                let udp_index = port_index - tcp_ports.len();
                scan_probe(
                    target,
                    udp_ports[udp_index],
                    Transport::Udp,
                    timeout,
                    udp_retries,
                    ssh_audit,
                    service_detect,
                    http_audit,
                    tls_audit,
                )
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
    service_detect: bool,
    http_audit: bool,
    tls_audit: bool,
) -> Option<ScanEvent> {
    match transport {
        Transport::Tcp => scan_tcp(
            target,
            port,
            timeout,
            ssh_audit,
            service_detect,
            http_audit,
            tls_audit,
        ),
        Transport::Udp => scan_udp(target, port, timeout, udp_retries),
    }
}

fn scan_tcp(
    target: &Target,
    port: u16,
    timeout: Duration,
    ssh_audit: bool,
    service_detect: bool,
    http_audit: bool,
    tls_audit: bool,
) -> Option<ScanEvent> {
    let stream = tcp_connect(target.ip, port, timeout)?;
    let mut banner = String::new();
    let mut service = service_name(port, "tcp").to_string();

    if should_probe_service(port, ssh_audit, service_detect, http_audit, tls_audit) {
        let detected = probe_tcp_service(
            stream,
            target,
            port,
            timeout,
            ssh_audit,
            service_detect,
            http_audit,
            tls_audit,
        );
        if !detected.service.is_empty() {
            service = detected.service;
        }
        banner = detected.banner;
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

struct ServiceProbeResult {
    service: String,
    banner: String,
}

fn should_probe_service(
    port: u16,
    ssh_audit: bool,
    service_detect: bool,
    http_audit: bool,
    tls_audit: bool,
) -> bool {
    service_detect
        || http_audit
        || tls_audit
        || ssh_audit
        || matches!(port, 21 | 22 | 25 | 53 | 80 | 110 | 143 | 443 | 587 | 3306 | 5432 | 6379 | 8080 | 8443 | 3389)
}

fn probe_tcp_service(
    mut stream: TcpStream,
    target: &Target,
    port: u16,
    timeout: Duration,
    ssh_audit: bool,
    service_detect: bool,
    http_audit: bool,
    tls_audit: bool,
) -> ServiceProbeResult {
    let _ = stream.set_read_timeout(Some(Duration::from_millis(450)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(450)));

    if port == 22 || ssh_audit {
        if let Some(banner) = read_banner(&mut stream, 256) {
            if banner.starts_with("SSH-") {
                emit_ssh_service(target, port, &banner);
                return ServiceProbeResult { service: "ssh".into(), banner };
            }
            if !banner.is_empty() {
                return ServiceProbeResult { service: service_name(port, "tcp").into(), banner };
            }
        }
    }

    if matches!(port, 80 | 8080 | 8000 | 8888) || http_audit {
        if let Some(response) = http_probe(&mut stream, target, port, http_audit) {
            return ServiceProbeResult { service: "http".into(), banner: response };
        }
    }

    if matches!(port, 443 | 8443 | 465 | 993 | 995) {
        emit_service_detection(target, port, "https", "", "port-based", "common TLS service port");
        if tls_audit {
            emit_tls_audit(target, port, timeout);
        }
        return ServiceProbeResult { service: "https".into(), banner: String::new() };
    }

    if service_detect {
        match port {
            21 | 25 | 110 | 143 | 587 => {
                if let Some(banner) = read_banner(&mut stream, 512) {
                    let service = service_name(port, "tcp");
                    emit_service_detection(target, port, service, &banner, "banner", "server sent protocol banner");
                    return ServiceProbeResult { service: service.into(), banner };
                }
            }
            53 => {
                if let Some(banner) = dns_tcp_probe(&mut stream) {
                    emit_service_detection(target, port, "dns", &banner, "protocol", "DNS over TCP query received a response");
                    return ServiceProbeResult { service: "dns".into(), banner };
                }
            }
            3306 => {
                if let Some(banner) = read_banner(&mut stream, 512) {
                    emit_service_detection(target, port, "mysql", &banner, "banner", "database handshake banner observed");
                    return ServiceProbeResult { service: "mysql".into(), banner };
                }
            }
            5432 => {
                emit_service_detection(target, port, "postgres", "", "port-based", "common PostgreSQL service port");
                return ServiceProbeResult { service: "postgres".into(), banner: String::new() };
            }
            6379 => {
                if let Some(banner) = redis_ping_probe(&mut stream) {
                    emit_service_detection(target, port, "redis", &banner, "protocol", "Redis PING received a response");
                    return ServiceProbeResult { service: "redis".into(), banner };
                }
            }
            3389 => {
                emit_service_detection(target, port, "rdp", "", "port-based", "common RDP service port");
                return ServiceProbeResult { service: "rdp".into(), banner: String::new() };
            }
            _ => {}
        }
    }

    ServiceProbeResult { service: service_name(port, "tcp").into(), banner: String::new() }
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

fn emit_service_detection(
    target: &Target,
    port: u16,
    service: &str,
    banner: &str,
    confidence: &str,
    evidence: &str,
) {
    emit(json!({
        "type": "service",
        "target": target.original,
        "resolved_ip": target.ip.to_string(),
        "port": port,
        "transport": "tcp",
        "service": service,
        "service_name": service,
        "banner": banner,
        "confidence": confidence,
        "evidence": evidence
    }));
}

#[derive(Debug)]
struct NoCertificateVerification;

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &Certificate,
        _intermediates: &[Certificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: SystemTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &Certificate,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &Certificate,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
        ]
    }
}

fn emit_tls_audit(target: &Target, port: u16, timeout: Duration) {
    match tls_audit(target, port, timeout) {
        Ok(audit) => {
            emit(json!({
                "type": "tls",
                "target": target.original,
                "resolved_ip": target.ip.to_string(),
                "port": port,
                "transport": "tcp",
                "subject": audit.subject,
                "issuer": audit.issuer,
                "sans": audit.sans,
                "not_before": audit.not_before,
                "not_after": audit.not_after,
                "days_until_expiry": audit.days_until_expiry,
                "expired": audit.expired,
                "expiring_soon": audit.expiring_soon,
                "self_signed": audit.self_signed,
                "hostname_checked": audit.hostname_checked,
                "hostname_mismatch": audit.hostname_mismatch,
                "trust_valid": audit.trust_valid,
                "trust_error": audit.trust_error,
                "chain_length": audit.chain_length,
                "chain_subjects": audit.chain_subjects,
                "chain_issuers": audit.chain_issuers,
                "negotiated_tls_version": audit.protocol_version,
                "cipher_suite": audit.cipher_suite,
                "limitations": "trust validation uses the bundled Mozilla roots through rustls; cipher posture is based on one negotiated handshake, not exhaustive enumeration",
                "evidence": "TLS handshake completed and peer certificate metadata was parsed without authentication or exploit probes"
            }));
            if audit.expired {
                emit_tls_finding(target, port, "high", "TLS certificate is expired", "The certificate not_after date is in the past.", "Renew and deploy a valid certificate for this service.");
            } else if audit.expiring_soon {
                emit_tls_finding(target, port, "medium", "TLS certificate expires soon", "The certificate expires within 30 days.", "Renew the certificate before expiry and monitor certificate lifecycle.");
            }
            if audit.self_signed {
                emit_tls_finding(target, port, "medium", "TLS certificate appears self-signed", "The certificate subject and issuer match.", "Use a certificate issued by an approved CA for externally trusted services.");
            }
            if audit.hostname_mismatch {
                emit_tls_finding(target, port, "high", "TLS certificate hostname mismatch", "The requested host did not match the certificate SAN/CN identity.", "Deploy a certificate whose SANs cover the exposed hostname.");
            }
            if !audit.trust_valid {
                emit_tls_finding(target, port, "medium", "TLS certificate trust validation failed", &format!("Trust validation failed: {}", audit.trust_error), "Deploy a certificate chain trusted by the intended clients and include required intermediates.");
            }
            if audit.protocol_version.contains("TLSv1_0") || audit.protocol_version.contains("TLSv1_1") {
                emit_tls_finding(target, port, "high", "Legacy TLS protocol negotiated", &format!("Negotiated protocol: {}", audit.protocol_version), "Disable TLS 1.0/1.1 and require TLS 1.2 or newer.");
            }
        }
        Err(err) => emit(json!({
            "type": "tls",
            "target": target.original,
            "resolved_ip": target.ip.to_string(),
            "port": port,
            "transport": "tcp",
            "error": err,
            "evidence": "TLS audit attempted a standard client handshake but did not complete"
        })),
    }
}

#[derive(Debug)]
struct TLSAudit {
    subject: String,
    issuer: String,
    sans: Vec<String>,
    not_before: String,
    not_after: String,
    days_until_expiry: i64,
    expired: bool,
    expiring_soon: bool,
    self_signed: bool,
    hostname_checked: String,
    hostname_mismatch: bool,
    trust_valid: bool,
    trust_error: String,
    chain_length: usize,
    chain_subjects: Vec<String>,
    chain_issuers: Vec<String>,
    protocol_version: String,
    cipher_suite: String,
}

fn tls_audit(target: &Target, port: u16, timeout: Duration) -> Result<TLSAudit, String> {
    let server_name = tls_server_name(target)?;
    let expected_host = tls_expected_host(target);
    let config = ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
        .with_no_client_auth();
    let mut conn = ClientConnection::new(Arc::new(config), server_name)
        .map_err(|err| format!("failed to create TLS client: {err}"))?;
    let mut tcp = tcp_connect(target.ip, port, timeout)
        .ok_or_else(|| "failed to connect for TLS audit".to_string())?;
    let _ = tcp.set_read_timeout(Some(timeout));
    let _ = tcp.set_write_timeout(Some(timeout));
    while conn.is_handshaking() {
        conn.complete_io(&mut tcp)
            .map_err(|err| format!("TLS handshake failed: {err}"))?;
    }
    let protocol_version = conn
        .protocol_version()
        .map(|version| format!("{:?}", version))
        .unwrap_or_default();
    let cipher_suite = conn
        .negotiated_cipher_suite()
        .map(|suite| format!("{:?}", suite.suite()))
        .unwrap_or_default();
    let certs = conn
        .peer_certificates()
        .ok_or_else(|| "server did not provide peer certificates".to_string())?;
    if certs.is_empty() {
        return Err("server certificate chain was empty".to_string());
    }
    let (trust_valid, trust_error) = validate_tls_trust(target, port, timeout);
    parse_tls_certificates(
        certs,
        &expected_host,
        protocol_version,
        cipher_suite,
        trust_valid,
        trust_error,
    )
}

fn tls_server_name(target: &Target) -> Result<ServerName, String> {
    let host = tls_expected_host(target);
    ServerName::try_from(host.as_str())
        .or_else(|_| ServerName::try_from(target.ip.to_string().as_str()))
        .or_else(|_| ServerName::try_from("localhost"))
        .map_err(|_| "failed to construct TLS server name".to_string())
}

fn tls_expected_host(target: &Target) -> String {
    target
        .original
        .split('/')
        .next()
        .unwrap_or(target.original.as_str())
        .trim_matches('[')
        .trim_matches(']')
        .to_string()
}

fn validate_tls_trust(target: &Target, port: u16, timeout: Duration) -> (bool, String) {
    let server_name = match tls_server_name(target) {
        Ok(value) => value,
        Err(err) => return (false, err),
    };
    let mut roots = RootCertStore::empty();
    roots.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
        OwnedTrustAnchor::from_subject_spki_name_constraints(ta.subject, ta.spki, ta.name_constraints)
    }));
    let config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let mut conn = match ClientConnection::new(Arc::new(config), server_name) {
        Ok(value) => value,
        Err(err) => return (false, format!("failed to create verifying TLS client: {err}")),
    };
    let mut tcp = match tcp_connect(target.ip, port, timeout) {
        Some(value) => value,
        None => return (false, "failed to connect for trust validation".into()),
    };
    let _ = tcp.set_read_timeout(Some(timeout));
    let _ = tcp.set_write_timeout(Some(timeout));
    while conn.is_handshaking() {
        if let Err(err) = conn.complete_io(&mut tcp) {
            return (false, err.to_string());
        }
    }
    (true, String::new())
}

fn parse_tls_certificates(
    certs: &[Certificate],
    expected_host: &str,
    protocol_version: String,
    cipher_suite: String,
    trust_valid: bool,
    trust_error: String,
) -> Result<TLSAudit, String> {
    let first = certs
        .first()
        .ok_or_else(|| "server certificate chain was empty".to_string())?;
    let mut chain_subjects = Vec::new();
    let mut chain_issuers = Vec::new();
    for cert in certs {
        if let Ok((_, parsed)) = parse_x509_certificate(cert.0.as_slice()) {
            chain_subjects.push(parsed.subject().to_string());
            chain_issuers.push(parsed.issuer().to_string());
        }
    }
    let mut audit =
        parse_tls_certificate(first.0.as_slice(), expected_host, protocol_version, cipher_suite)?;
    audit.trust_valid = trust_valid;
    audit.trust_error = trust_error;
    audit.chain_length = certs.len();
    audit.chain_subjects = chain_subjects;
    audit.chain_issuers = chain_issuers;
    Ok(audit)
}

fn parse_tls_certificate(
    der: &[u8],
    expected_host: &str,
    protocol_version: String,
    cipher_suite: String,
) -> Result<TLSAudit, String> {
    let (_, cert) = parse_x509_certificate(der).map_err(|err| format!("failed to parse certificate: {err}"))?;
    let subject = cert.subject().to_string();
    let issuer = cert.issuer().to_string();
    let not_before_time = cert.validity().not_before;
    let not_after_time = cert.validity().not_after;
    let not_before = not_before_time.to_string();
    let not_after = not_after_time.to_string();
    let now = x509_parser::time::ASN1Time::now().timestamp();
    let days_until_expiry = (not_after_time.timestamp() - now) / 86_400;
    let expired = days_until_expiry < 0;
    let expiring_soon = !expired && days_until_expiry <= 30;
    let mut sans = Vec::new();
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for name in &san.value.general_names {
            match name {
                GeneralName::DNSName(value) => sans.push((*value).to_string()),
                GeneralName::IPAddress(value) => sans.push(format_ip_san(value)),
                _ => {}
            }
        }
    }
    let self_signed = subject == issuer;
    let hostname_match = certificate_hostname_matches(&sans, &subject, expected_host);
    Ok(TLSAudit {
        subject,
        issuer,
        sans,
        not_before,
        not_after,
        days_until_expiry,
        expired,
        expiring_soon,
        self_signed,
        hostname_checked: expected_host.to_string(),
        hostname_mismatch: !hostname_match,
        trust_valid: false,
        trust_error: String::new(),
        chain_length: 1,
        chain_subjects: Vec::new(),
        chain_issuers: Vec::new(),
        protocol_version,
        cipher_suite,
    })
}

fn certificate_hostname_matches(sans: &[String], subject: &str, expected_host: &str) -> bool {
    if expected_host.is_empty() {
        return true;
    }
    let expected = expected_host.trim_matches('.').to_ascii_lowercase();
    for san in sans {
        let san = san.trim_start_matches("ip:").to_ascii_lowercase();
        if dns_name_matches(&san, &expected) {
            return true;
        }
    }
    if sans.is_empty() {
        return subject.to_ascii_lowercase().contains(&format!("cn={expected}"))
            || subject.to_ascii_lowercase().contains(&format!("cn = {expected}"));
    }
    false
}

fn dns_name_matches(pattern: &str, host: &str) -> bool {
    if pattern == host {
        return true;
    }
    if let Some(suffix) = pattern.strip_prefix("*.") {
        return host.ends_with(&format!(".{suffix}"))
            && host.matches('.').count() == suffix.matches('.').count() + 1;
    }
    false
}

fn format_ip_san(value: &[u8]) -> String {
    match value.len() {
        4 => format!("ip:{}.{}.{}.{}", value[0], value[1], value[2], value[3]),
        16 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(value);
            format!("ip:{}", std::net::Ipv6Addr::from(octets))
        }
        _ => format!("ip:{}", printable(value)),
    }
}

fn emit_tls_finding(target: &Target, port: u16, severity: &str, title: &str, evidence: &str, remediation: &str) {
    emit(json!({
        "type": "finding",
        "target": target.original,
        "resolved_ip": target.ip.to_string(),
        "port": port,
        "transport": "tcp",
        "severity": severity,
        "title": title,
        "evidence": evidence,
        "remediation": remediation,
        "safe_validation": "Re-run netscope scan with --tls-audit or inspect the certificate with an approved TLS diagnostic tool.",
        "references": ["https://www.cisa.gov/resources-tools/resources/securing-remote-access"]
    }));
}

fn read_banner(stream: &mut TcpStream, limit: usize) -> Option<String> {
    let mut buf = vec![0u8; limit];
    match stream.read(&mut buf) {
        Ok(0) => None,
        Ok(n) => Some(printable(&buf[..n]).trim().to_string()),
        Err(_) => None,
    }
}

fn http_probe(stream: &mut TcpStream, target: &Target, port: u16, audit: bool) -> Option<String> {
    let method = if audit { "GET" } else { "HEAD" };
    let request = format!(
        "{method} / HTTP/1.0\r\nHost: {}\r\nUser-Agent: Netscope/0.3.0-beta\r\nConnection: close\r\n\r\n",
        target.original
    );
    let _ = stream.write_all(request.as_bytes());
    let mut buf = [0u8; 8192];
    let n = stream.read(&mut buf).ok()?;
    if n == 0 {
        return None;
    }
    let response = String::from_utf8_lossy(&buf[..n]).to_string();
    let status_line = first_line(&response);
    if !status_line.starts_with("HTTP/") {
        return None;
    }
    if audit {
        emit_http_audit(target, port, &response);
    } else {
        emit_service_detection(target, port, "http", &status_line, "protocol", "HTTP response status line observed");
    }
    Some(status_line)
}

fn emit_http_audit(target: &Target, port: u16, response: &str) {
    let status_code = response
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .unwrap_or(0);
    let headers = parse_http_headers(response);
    let title = page_title(response);
    let security_headers = json!({
        "strict_transport_security": headers.get("strict-transport-security").cloned().unwrap_or_default(),
        "content_security_policy": headers.get("content-security-policy").cloned().unwrap_or_default(),
        "x_frame_options": headers.get("x-frame-options").cloned().unwrap_or_default(),
        "x_content_type_options": headers.get("x-content-type-options").cloned().unwrap_or_default(),
        "referrer_policy": headers.get("referrer-policy").cloned().unwrap_or_default(),
        "permissions_policy": headers.get("permissions-policy").cloned().unwrap_or_default()
    });
    emit(json!({
        "type": "http_audit",
        "target": target.original,
        "resolved_ip": target.ip.to_string(),
        "port": port,
        "transport": "tcp",
        "status_code": status_code,
        "server": headers.get("server").cloned().unwrap_or_default(),
        "content_type": headers.get("content-type").cloned().unwrap_or_default(),
        "title": title,
        "security_headers": security_headers,
        "evidence": "single safe HTTP GET / response inspected; no crawling, fuzzing, authentication, or injection performed"
    }));
    emit_service_detection(target, port, "http", &format!("HTTP {status_code}"), "protocol", "HTTP response observed");
}

fn parse_http_headers(response: &str) -> std::collections::HashMap<String, String> {
    let mut headers = std::collections::HashMap::new();
    for line in response.lines().skip(1) {
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }
    headers
}

fn page_title(response: &str) -> String {
    let lower = response.to_ascii_lowercase();
    let Some(start) = lower.find("<title>") else {
        return String::new();
    };
    let body_start = start + "<title>".len();
    let Some(end) = lower[body_start..].find("</title>") else {
        return String::new();
    };
    response[body_start..body_start + end]
        .trim()
        .chars()
        .take(120)
        .collect()
}

fn dns_tcp_probe(stream: &mut TcpStream) -> Option<String> {
    let query = b"\0\x1d\0\x01\x01\0\0\x01\0\0\0\0\0\0\x07example\x03com\0\0\x01\0\x01";
    let _ = stream.write_all(query);
    let mut buf = [0u8; 512];
    match stream.read(&mut buf) {
        Ok(n) if n >= 4 => Some(format!("dns tcp response {} bytes", n)),
        _ => None,
    }
}

fn redis_ping_probe(stream: &mut TcpStream) -> Option<String> {
    let _ = stream.write_all(b"*1\r\n$4\r\nPING\r\n");
    let mut buf = [0u8; 128];
    match stream.read(&mut buf) {
        Ok(n) if n > 0 => Some(printable(&buf[..n]).trim().to_string()),
        _ => None,
    }
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
    use std::net::TcpListener;

    #[test]
    fn parses_port_ranges_and_dedupes() {
        let ports = parse_ports_or_default("22,80-82,22", &[], 0).unwrap();
        assert_eq!(ports, vec![22, 80, 81, 82]);
    }

    #[test]
    fn rejects_port_zero() {
        assert!(parse_ports_or_default("0", &[], 0).is_err());
    }

    #[test]
    fn extracts_http_title_and_headers() {
        let response = "HTTP/1.1 200 OK\r\nServer: example\r\nX-Frame-Options: DENY\r\n\r\n<html><title>Hello Netscope</title></html>";
        let headers = parse_http_headers(response);
        assert_eq!(headers.get("server").unwrap(), "example");
        assert_eq!(headers.get("x-frame-options").unwrap(), "DENY");
        assert_eq!(page_title(response), "Hello Netscope");
    }

    #[test]
    fn tls_parser_rejects_invalid_der() {
        let err = parse_tls_certificate(
            b"not a certificate",
            "example.com",
            "TLSv1_3".into(),
            "TLS_AES_128_GCM_SHA256".into(),
        )
        .unwrap_err();
        assert!(err.contains("failed to parse certificate"));
    }

    #[test]
    fn tls_parser_extracts_certificate_metadata() {
        let cert = decode_base64_fixture(LOCALHOST_TEST_CERT_B64);
        let audit = parse_tls_certificates(
            &[Certificate(cert)],
            "localhost",
            "TLSv1_3".into(),
            "TLS13_AES_256_GCM_SHA384".into(),
            false,
            "self-signed fixture".into(),
        )
        .unwrap();

        assert!(audit.subject.contains("localhost"));
        assert!(audit.issuer.contains("localhost"));
        assert_eq!(audit.sans, vec!["localhost"]);
        assert!(audit.self_signed);
        assert!(!audit.hostname_mismatch);
        assert_eq!(audit.hostname_checked, "localhost");
        assert_eq!(audit.chain_length, 1);
        assert_eq!(audit.chain_subjects.len(), 1);
        assert!(!audit.trust_valid);
        assert_eq!(audit.trust_error, "self-signed fixture");
        assert_eq!(audit.protocol_version, "TLSv1_3");
        assert_eq!(audit.cipher_suite, "TLS13_AES_256_GCM_SHA384");
    }

    #[test]
    fn tls_audit_reports_handshake_failure() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let _ = stream.write_all(b"not tls");
            }
        });
        let target = Target {
            original: "localhost".into(),
            ip: "127.0.0.1".parse().unwrap(),
        };
        let err = tls_audit(&target, port, Duration::from_millis(500)).unwrap_err();
        let _ = handle.join();
        assert!(err.contains("TLS handshake failed") || err.contains("failed"));
    }

    #[test]
    fn tls_hostname_matching_handles_dns_and_wildcards() {
        assert!(certificate_hostname_matches(
            &["example.com".into()],
            "",
            "example.com"
        ));
        assert!(certificate_hostname_matches(
            &["*.example.com".into()],
            "",
            "api.example.com"
        ));
        assert!(!certificate_hostname_matches(
            &["*.example.com".into()],
            "",
            "deep.api.example.com"
        ));
        assert!(!certificate_hostname_matches(
            &["www.example.com".into()],
            "",
            "api.example.com"
        ));
    }

    #[test]
    fn tls_server_name_handles_targets() {
        let target = Target {
            original: "example.com".into(),
            ip: "93.184.216.34".parse().unwrap(),
        };
        assert!(tls_server_name(&target).is_ok());
    }

    const LOCALHOST_TEST_CERT_B64: &str = "MIIC4DCCAcigAwIBAgIIS91d82c/U8MwDQYJKoZIhvcNAQELBQAwFDESMBAGA1UEAxMJbG9jYWxob3N0MB4XDTI2MDUxMDE2MDUxMFoXDTI2MDgwOTE2MDUxMFowFDESMBAGA1UEAxMJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyl7t25kSc7TLMOBbDRPbLThL68GS0XFFtWecEnqZxKOMgf3dh+8MXyng6AKQmiOYpHTqtdBgpVA2kKHPmQIIyGkfMhiEPMmn0w5ymdEwa9hcT70b2H/nRjmqN+IvSmr1PjHm/MND2O6zl95fK+b9V6jWflh+sj0lde4eS9RVAy06+4Pqw3e247x4+HWf1UQhth9sxCWXhHPoXVIljnojukfdJ1WY9HgI/xsoE/IOXRd5XJf/6UoXuaf1eC0wrpIP3hEU7ipE9Pb8AGXW5MnYQExORzhzuec8gxXD9Xc25YQ5c6D2gZlAMsBj+pgR1sh9K6gQ3Vtuf3dHzgpLRSUzlQIDAQABozYwNDAUBgNVHREEDTALgglsb2NhbGhvc3QwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwDQYJKoZIhvcNAQELBQADggEBALHru4QNr200otSXtc2L7KT23U3WV+O1KTCieP9oqhZE0QqSPBdW3xlQfVuk96z591YL9rR/eQSZ5eqBQ9V0XBNOSfAgn06Ad2onYz3daNp2Fxp58+3qkferan3REbvo+6GcXGvyLvtaJBK74Xhp5FIw+mQBXVbEBMuBlWZOdqj0GG3fWij+MToArKrMgTrE1PAkf8wDm+FQQiGHv0vLT8mpLggfAy4qXyBrRVB+e/uTITfBYVOO4BNnKnvk0Ji2FelKymjhlngop2vs7QmawFwrYfqzJY/7oPEeE9Ii62nL0cSyX2QHkCsyLqRQsTDL3n/MI2nVisN/lNJieRIxMmg=";

    fn decode_base64_fixture(input: &str) -> Vec<u8> {
        let mut out = Vec::new();
        let mut buffer = 0u32;
        let mut bits = 0u8;
        for byte in input.bytes().filter(|b| !b.is_ascii_whitespace()) {
            if byte == b'=' {
                break;
            }
            let value = match byte {
                b'A'..=b'Z' => byte - b'A',
                b'a'..=b'z' => byte - b'a' + 26,
                b'0'..=b'9' => byte - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                _ => panic!("invalid base64 fixture byte"),
            } as u32;
            buffer = (buffer << 6) | value;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push((buffer >> bits) as u8);
                buffer &= (1u32 << bits) - 1;
            }
        }
        out
    }
}
