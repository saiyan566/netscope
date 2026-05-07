use crate::types::{EngineRequest, Target};
use std::collections::HashSet;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};

const MAX_HOSTS_PER_MEMORY_MB: usize = 4096;
const MAX_SINGLE_EXPANSION: u64 = 1_000_000;

pub fn expand_targets(request: &EngineRequest) -> Result<Vec<Target>, String> {
    let mut specs = request.targets.clone();
    if !request.target_file.is_empty() {
        let content = fs::read_to_string(&request.target_file)
            .map_err(|err| format!("failed to read target file {}: {err}", request.target_file))?;
        for line in content.lines() {
            let trimmed = line.split('#').next().unwrap_or("").trim();
            if !trimmed.is_empty() {
                specs.push(trimmed.to_string());
            }
        }
    }
    if specs.is_empty() {
        return Ok(Vec::new());
    }

    let exclude_ips = expand_excludes(&request.excludes)?;
    let max_hosts = request.memory_budget_mb.max(1) * MAX_HOSTS_PER_MEMORY_MB;
    let mut seen = HashSet::new();
    let mut out = Vec::new();

    for spec in specs {
        for target in expand_one(&spec)? {
            if exclude_ips.contains(&target.ip) {
                continue;
            }
            if seen.insert(target.ip) {
                out.push(target);
                if out.len() > max_hosts {
                    return Err(format!(
                        "expanded target set exceeded memory budget guardrail ({max_hosts} hosts); split the scan or raise --memory-budget-mb"
                    ));
                }
            }
        }
    }
    Ok(out)
}

fn expand_excludes(specs: &[String]) -> Result<HashSet<IpAddr>, String> {
    let mut out = HashSet::new();
    for spec in specs {
        for target in expand_one(spec)? {
            out.insert(target.ip);
        }
    }
    Ok(out)
}

pub fn expand_one(spec: &str) -> Result<Vec<Target>, String> {
    let spec = spec.trim();
    if spec.is_empty() {
        return Ok(Vec::new());
    }
    if spec.contains('/') {
        return expand_cidr(spec);
    }
    if let Some((start, end)) = spec.split_once('-') {
        if start.trim().parse::<Ipv4Addr>().is_ok() && end.trim().parse::<Ipv4Addr>().is_ok() {
            return expand_range(spec, start.trim(), end.trim());
        }
    }
    if let Ok(ip) = spec.parse::<IpAddr>() {
        return Ok(vec![Target {
            original: spec.into(),
            ip,
        }]);
    }
    resolve_domain(spec)
}

fn expand_cidr(spec: &str) -> Result<Vec<Target>, String> {
    let (base, prefix) = spec
        .split_once('/')
        .ok_or_else(|| format!("invalid CIDR {spec:?}"))?;
    let base: Ipv4Addr = base
        .parse()
        .map_err(|_| format!("only IPv4 CIDR is supported in v1: {spec}"))?;
    let prefix: u32 = prefix
        .parse()
        .map_err(|_| format!("invalid CIDR prefix in {spec:?}"))?;
    if prefix > 32 {
        return Err(format!("invalid CIDR prefix in {spec:?}"));
    }

    let base_num = u32::from(base);
    let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
    let network = base_num & mask;
    let broadcast = network | !mask;

    let first = if prefix <= 30 {
        network.saturating_add(1)
    } else {
        network
    };
    let last = if prefix <= 30 {
        broadcast.saturating_sub(1)
    } else {
        broadcast
    };
    let count = u64::from(last.saturating_sub(first)) + 1;
    if count > MAX_SINGLE_EXPANSION {
        return Err(format!(
            "{spec} expands to {count} hosts; split the range into smaller scopes for low-memory scanning"
        ));
    }

    let mut out = Vec::new();
    for value in first..=last {
        out.push(Target {
            original: spec.into(),
            ip: IpAddr::V4(Ipv4Addr::from(value)),
        });
    }
    Ok(out)
}

fn expand_range(spec: &str, start: &str, end: &str) -> Result<Vec<Target>, String> {
    let start = u32::from(
        start
            .parse::<Ipv4Addr>()
            .map_err(|_| format!("invalid range start in {spec:?}"))?,
    );
    let end = u32::from(
        end.parse::<Ipv4Addr>()
            .map_err(|_| format!("invalid range end in {spec:?}"))?,
    );
    if start > end {
        return Err(format!("range start must be <= end in {spec:?}"));
    }
    let count = u64::from(end.saturating_sub(start)) + 1;
    if count > MAX_SINGLE_EXPANSION {
        return Err(format!(
            "{spec} expands to {count} hosts; split the range into smaller scopes for low-memory scanning"
        ));
    }
    let mut out = Vec::new();
    for value in start..=end {
        out.push(Target {
            original: spec.into(),
            ip: IpAddr::V4(Ipv4Addr::from(value)),
        });
    }
    Ok(out)
}

fn resolve_domain(spec: &str) -> Result<Vec<Target>, String> {
    let addr = format!("{spec}:0");
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    let addrs = addr
        .to_socket_addrs()
        .map_err(|err| format!("failed to resolve {spec}: {err}"))?;
    for socket in addrs {
        if seen.insert(socket.ip()) {
            out.push(Target {
                original: spec.into(),
                ip: socket.ip(),
            });
        }
    }
    if out.is_empty() {
        return Err(format!("no addresses resolved for {spec}"));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_ipv4_cidr_without_network_and_broadcast() {
        let out = expand_one("192.0.2.0/30").unwrap();
        let ips: Vec<String> = out.iter().map(|t| t.ip.to_string()).collect();
        assert_eq!(ips, vec!["192.0.2.1", "192.0.2.2"]);
    }

    #[test]
    fn expands_ipv4_range() {
        let out = expand_one("192.0.2.3-192.0.2.5").unwrap();
        assert_eq!(out.len(), 3);
        assert_eq!(out[0].ip.to_string(), "192.0.2.3");
        assert_eq!(out[2].ip.to_string(), "192.0.2.5");
    }
}
