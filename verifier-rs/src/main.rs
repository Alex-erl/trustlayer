//! `trustlayer-verify <bundle.json>` — re-check an exported TrustLayer evidence
//! bundle offline. Exit code: 0 = every offline check passed, 1 = a check
//! failed, 2 = usage / unreadable input.

use std::process::ExitCode;

use trustlayer_verify::{verify_bundle, Status};

const GREEN: &str = "\x1b[32m";
const RED: &str = "\x1b[31m";
const DIM: &str = "\x1b[2m";
const BOLD: &str = "\x1b[1m";
const RESET: &str = "\x1b[0m";

fn main() -> ExitCode {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("usage: trustlayer-verify <bundle.json>");
        return ExitCode::from(2);
    };

    let data = match std::fs::read_to_string(&path) {
        Ok(data) => data,
        Err(err) => {
            eprintln!("cannot read {path}: {err}");
            return ExitCode::from(2);
        }
    };

    let bundle: serde_json::Value = match serde_json::from_str(&data) {
        Ok(value) => value,
        Err(err) => {
            eprintln!("cannot parse {path}: {err}");
            return ExitCode::from(2);
        }
    };

    let report = verify_bundle(&bundle);

    println!("{BOLD}TrustLayer evidence — offline verification{RESET}");
    println!("{DIM}{path}{RESET}\n");

    for (name, check) in report.checks() {
        let mark = match check.status {
            Status::Ok => format!("{GREEN}✓{RESET}"),
            Status::Failed => format!("{RED}✗{RESET}"),
            Status::NotApplicable => format!("{DIM}–{RESET}"),
        };
        println!("  {mark} {name:<18} {DIM}{}{RESET}", check.detail);
    }

    if !report.anchors.is_empty() {
        println!("\n  {DIM}anchors (re-verify online on their own medium):{RESET}");
        for anchor in &report.anchors {
            println!("    {DIM}•{RESET} {} {DIM}— {}{RESET}", anchor.adapter, anchor.medium);
        }
    }

    if report.verified {
        println!("\n{GREEN}{BOLD}VERIFIED{RESET} — every self-contained check passed.");
        ExitCode::SUCCESS
    } else {
        println!("\n{RED}{BOLD}NOT VERIFIED{RESET} — one or more checks failed.");
        ExitCode::from(1)
    }
}
