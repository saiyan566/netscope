use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::{self, Write};

#[derive(Debug, Deserialize, Clone)]
pub struct EngineRequest {
    pub command: String,
    #[serde(default)]
    pub targets: Vec<String>,
    #[serde(default)]
    pub target_file: String,
    #[serde(default)]
    pub excludes: Vec<String>,
    #[serde(default)]
    pub tcp: bool,
    #[serde(default)]
    pub udp: bool,
    #[serde(default)]
    pub ports: String,
    #[serde(default)]
    pub udp_ports: String,
    #[serde(default = "default_top_ports")]
    pub top_ports: usize,
    #[serde(default = "default_top_udp")]
    pub top_udp: usize,
    #[serde(default)]
    pub discover_hosts: bool,
    #[serde(default)]
    pub skip_host_discovery: bool,
    #[serde(default = "default_discovery_methods")]
    pub discovery_methods: Vec<String>,
    #[serde(default = "default_icmp_wait_ms")]
    pub icmp_wait_ms: u64,
    #[serde(default = "default_tcp_ping_ports")]
    pub tcp_ping_ports: String,
    #[serde(default = "default_arp_timeout_ms")]
    pub arp_timeout_ms: u64,
    #[serde(default = "default_udp_retries")]
    pub udp_retries: usize,
    #[serde(default)]
    pub rate: usize,
    #[serde(default = "default_concurrency")]
    pub concurrency: usize,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_memory_budget_mb")]
    pub memory_budget_mb: usize,
    #[serde(default)]
    pub ssh_audit: bool,
    #[serde(default)]
    pub service_detect: bool,
    #[serde(default)]
    pub http_audit: bool,
    #[serde(default)]
    pub tls_audit: bool,
    #[serde(default)]
    pub input_file: String,
    #[serde(default = "default_true")]
    pub subdomains: bool,
    #[serde(default)]
    pub wordlist: String,
    #[serde(default = "default_records")]
    pub records: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Target {
    pub original: String,
    pub ip: std::net::IpAddr,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanEvent {
    #[serde(rename = "type")]
    pub event_type: String,
    pub target: String,
    pub resolved_ip: String,
    pub port: u16,
    pub transport: String,
    pub state: String,
    pub reason: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub service: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub banner: String,
}

pub fn emit(value: Value) {
    let mut stdout = io::stdout().lock();
    let _ = serde_json::to_writer(&mut stdout, &value);
    let _ = stdout.write_all(b"\n");
}

fn default_top_ports() -> usize {
    100
}

fn default_top_udp() -> usize {
    20
}

fn default_discovery_methods() -> Vec<String> {
    vec!["arp".into(), "icmp".into(), "tcp".into()]
}

fn default_icmp_wait_ms() -> u64 {
    700
}

fn default_tcp_ping_ports() -> String {
    "22,80,443,445,3389".into()
}

fn default_arp_timeout_ms() -> u64 {
    700
}

fn default_udp_retries() -> usize {
    1
}

fn default_concurrency() -> usize {
    256
}

fn default_timeout_ms() -> u64 {
    900
}

fn default_memory_budget_mb() -> usize {
    150
}

fn default_true() -> bool {
    true
}

fn default_records() -> String {
    "A,AAAA,CNAME,MX,NS,TXT".into()
}
