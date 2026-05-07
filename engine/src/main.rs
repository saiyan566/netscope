mod scan;
mod targets;
mod types;
mod vuln;

use std::io::{self, Read};

use serde_json::json;

use crate::scan::{discover_hosts, run_scan};
use crate::targets::expand_targets;
use crate::types::{emit, EngineRequest};
use crate::vuln::{findings_from_input, findings_from_scan_events};

fn main() {
    if let Err(err) = run() {
        emit(json!({
            "type": "error",
            "message": err.to_string()
        }));
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut input = String::new();
    io::stdin()
        .read_to_string(&mut input)
        .map_err(|err| format!("failed to read request: {err}"))?;
    let request: EngineRequest =
        serde_json::from_str(&input).map_err(|err| format!("invalid request JSON: {err}"))?;

    match request.command.as_str() {
        "discover" => {
            let targets = expand_targets(&request)?;
            discover_hosts(&request, &targets);
            Ok(())
        }
        "scan" => {
            let targets = expand_targets(&request)?;
            let events = run_scan(&request, targets);
            findings_from_scan_events(&events);
            Ok(())
        }
        "vuln" => {
            findings_from_input(&request)?;
            Ok(())
        }
        other => Err(format!("unknown engine command {other:?}")),
    }
}
