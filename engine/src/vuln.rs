use crate::scan::run_scan;
use crate::targets::expand_targets;
use crate::types::{emit, EngineRequest, ScanEvent};
use serde_json::{json, Value};
use std::fs;

pub fn findings_from_scan_events(events: &[ScanEvent]) {
    for event in events {
        if event.state == "open" {
            emit_findings_for_event(event);
        }
    }
}

pub fn findings_from_input(request: &EngineRequest) -> Result<(), String> {
    if !request.input_file.is_empty() {
        let content = fs::read_to_string(&request.input_file)
            .map_err(|err| format!("failed to read input file {}: {err}", request.input_file))?;
        let mut count = 0usize;
        for line in content.lines() {
            let value: Value = match serde_json::from_str(line) {
                Ok(value) => value,
                Err(_) => continue,
            };
            if value.get("type").and_then(Value::as_str) != Some("open_port") {
                continue;
            }
            if let Ok(event) = serde_json::from_value::<ScanEvent>(value) {
                emit_findings_for_event(&event);
                count += 1;
            }
        }
        emit(json!({
            "type": "summary",
            "message": format!("vulnerability pass inspected {count} prior scan events")
        }));
        return Ok(());
    }

    let mut scan_request = request.clone();
    scan_request.command = "scan".into();
    scan_request.tcp = true;
    if scan_request.ports.trim().is_empty() {
        scan_request.ports = "22,23,80,8080,8000,8888,3306,5432,6379,9200,9300,27017".into();
    }
    if scan_request.udp && scan_request.udp_ports.trim().is_empty() {
        scan_request.udp_ports = "161,1900".into();
    }
    let targets = expand_targets(&scan_request)?;
    let events = run_scan(&scan_request, targets);
    let inspected = events.len();
    findings_from_scan_events(&events);
    emit(json!({
        "type": "summary",
        "message": format!("vulnerability pass inspected {inspected} responsive services")
    }));
    Ok(())
}

fn emit_findings_for_event(event: &ScanEvent) {
    match (event.transport.as_str(), event.port) {
        ("tcp", 22) => ssh_findings(event),
        ("tcp", 23) => finding(
            event,
            "telnet_exposed",
            "high",
            "Telnet service exposed",
            "Telnet sends credentials and session data without encryption.",
            "Disable Telnet and migrate administration to SSH with key-based access.",
            "Confirm service owner approval, then verify TCP/23 is closed or filtered after remediation.",
            &["https://www.cisa.gov/news-events/alerts/2017/10/16/security-tip-st04-015"],
        ),
        ("tcp", 80) | ("tcp", 8080) | ("tcp", 8000) | ("tcp", 8888) => finding(
            event,
            "plain_http_detected",
            "low",
            "Plain HTTP service detected",
            "The service responded on a cleartext HTTP port.",
            "Prefer HTTPS, redirect HTTP to HTTPS, and set HSTS where appropriate.",
            "Request the site over HTTP and confirm it redirects to HTTPS without exposing sensitive data.",
            &["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"],
        ),
        ("tcp", 6379) => exposed_datastore(
            event,
            "redis_exposed",
            "Redis service exposed",
            "Restrict Redis to trusted networks, require authentication where supported, and avoid binding it to public interfaces.",
        ),
        ("tcp", 9200) | ("tcp", 9300) => exposed_datastore(
            event,
            "elasticsearch_exposed",
            "Elasticsearch service exposed",
            "Restrict Elasticsearch to trusted networks and enforce authentication/TLS.",
        ),
        ("tcp", 27017) => exposed_datastore(
            event,
            "mongodb_exposed",
            "MongoDB service exposed",
            "Restrict MongoDB to trusted networks and require authentication/TLS.",
        ),
        ("tcp", 3306) => exposed_datastore(
            event,
            "mysql_exposed",
            "MySQL service exposed",
            "Restrict MySQL to application networks and enforce strong authentication/TLS.",
        ),
        ("tcp", 5432) => exposed_datastore(
            event,
            "postgresql_exposed",
            "PostgreSQL service exposed",
            "Restrict PostgreSQL to application networks and enforce strong authentication/TLS.",
        ),
        ("udp", 161) => finding(
            event,
            "snmp_responded",
            "medium",
            "SNMP service responded",
            "SNMP can expose sensitive operational metadata when reachable from untrusted networks.",
            "Restrict SNMP to management networks, use SNMPv3, and rotate community strings.",
            "From an approved management host, verify SNMPv3 is required and UDP/161 is filtered elsewhere.",
            &["https://www.cisa.gov/news-events/alerts/2017/06/05/simple-network-management-protocol-snmp-best-practices"],
        ),
        ("udp", 1900) => finding(
            event,
            "ssdp_responded",
            "medium",
            "SSDP service responded",
            "SSDP exposure can reveal devices and contribute to reflection traffic.",
            "Disable UPnP/SSDP where unnecessary and block UDP/1900 at network boundaries.",
            "Verify UDP/1900 is not reachable from unauthorized network segments.",
            &["https://www.cisa.gov/news-events/alerts/2014/01/17/udp-based-amplification-attacks"],
        ),
        _ => {}
    }
}

fn ssh_findings(event: &ScanEvent) {
    if event.banner.starts_with("SSH-1.") {
        finding(
            event,
            "ssh_legacy_protocol",
            "high",
            "Legacy SSH protocol detected",
            "The SSH banner indicates protocol version 1, which is obsolete and unsafe.",
            "Disable SSH protocol 1 and require SSH protocol 2 with modern algorithms.",
            "Run an approved SSH audit and confirm the banner starts with SSH-2.0.",
            &["https://www.cisa.gov/news-events/alerts/2017/10/16/security-tip-st04-017"],
        );
    } else {
        finding(
            event,
            "ssh_admin_surface",
            "info",
            "SSH administration surface detected",
            "SSH is reachable on this target. This is not a vulnerability by itself, but it is a sensitive administration surface.",
            "Limit SSH exposure with firewall rules, disable password login where possible, and use MFA or strong key controls.",
            "Confirm SSH is reachable only from approved administration networks.",
            &["https://www.cisa.gov/resources-tools/resources/securing-remote-access"],
        );
    }
}

fn exposed_datastore(event: &ScanEvent, code: &str, title: &str, remediation: &str) {
    finding(
        event,
        code,
        "medium",
        title,
        "A datastore or search service appears reachable. Exposure may be intended internally but should be tightly scoped.",
        remediation,
        "Verify the service is reachable only from approved application or administration networks.",
        &["https://www.cisa.gov/resources-tools/resources/secure-by-design"],
    );
}

fn finding(
    event: &ScanEvent,
    code: &str,
    severity: &str,
    title: &str,
    evidence: &str,
    remediation: &str,
    safe_validation: &str,
    references: &[&str],
) {
    emit(json!({
        "type": "finding",
        "finding_code": code,
        "target": event.target,
        "resolved_ip": event.resolved_ip,
        "port": event.port,
        "transport": event.transport,
        "service": event.service,
        "severity": severity,
        "title": title,
        "evidence": evidence,
        "remediation": remediation,
        "safe_validation": safe_validation,
        "references": references
    }));
}
