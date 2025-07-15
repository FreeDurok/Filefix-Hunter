use winreg::enums::*;
use winreg::RegKey;
use colored::*;
use regex::Regex;
use serde::Serialize;
use std::fs::File;
use std::io::Write;
use std::env;

mod rules;
use rules::{get_keywords, get_patterns};

#[derive(Serialize)]
struct Finding {
    sid: String,
    username: String,
    name: String,
    value: String,
    suspicious: bool,
    matched: String,
}

fn print_help() {
    println!("{}", "
Usage:
    filefix-hunter [options]

Options:
    -h, --help            Show this message
    -f, --format <type>   Export format: json, csv or none (default: none)
    -o, --output <file>   Output file (default: typedpaths.json or typedpaths.csv)

Examples:
    filefix-hunter -f json -o output.json
    filefix-hunter --format=csv --output=report.csv

By default, no export is performed.
".yellow());
}

fn get_username_from_sid(sid: &str) -> Option<String> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let path = format!(r"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\{}", sid);
    if let Ok(key) = hklm.open_subkey_with_flags(&path, KEY_READ) {
        if let Ok(p) = key.get_value::<String, _>("ProfileImagePath") {
            return p.split('\\').last().map(ToString::to_string);
        }
    }
    None
}

fn is_suspicious(value: &str, keywords: &[&str], patterns: &[Regex]) -> Option<String> {
    let v = value.to_lowercase();
    for &kw in keywords {
        if v.contains(kw) {
            return Some(format!("keyword: {}", kw));
        }
    }
    for re in patterns {
        if re.is_match(&v) {
            return Some(format!("pattern: {}", re.as_str()));
        }
    }
    None
}

fn print_typed_paths_for_user(
    sid: &str,
    keywords: &[&str],
    patterns: &[Regex],
    hku: &RegKey,
    findings: &mut Vec<Finding>
) {
    let sub = r"Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths";
    let full = format!(r"{}\{}", sid, sub);
    if let Ok(sk) = hku.open_subkey_with_flags(&full, KEY_READ) {
        let user = get_username_from_sid(sid).unwrap_or_else(|| "Unknown".into());
        println!("\n{}", format!("HKEY_USERS\\{} = {}", sid, user).blue().bold());
        for (name, rv) in sk.enum_values().flatten() {
            if let winreg::RegValue { vtype: REG_SZ, ref bytes } = rv {
                let u16_data: Vec<u16> = bytes
                    .chunks(2)
                    .map(|c| u16::from_le_bytes([c[0], c.get(1).copied().unwrap_or(0)]))
                    .collect();
                let raw = String::from_utf16_lossy(&u16_data);
                let clean = raw.trim_end_matches('\u{0}').trim();

                let result = is_suspicious(clean, keywords, patterns);
                findings.push(Finding {
                    sid: sid.to_string(),
                    username: user.clone(),
                    name: name.to_string(),
                    value: clean.to_string(),
                    suspicious: result.is_some(),
                    matched: result.as_ref().map(|s| s.as_str()).unwrap_or("-").to_string(),
                });

                if result.is_some() {
                    println!("  [{}] {}", name.green(), clean.red().bold());
                } else {
                    println!("  [{}] {}", name.green(), clean.yellow());
                }
            }
        }
    }
}

fn export_findings(findings: &[Finding], mode: &str, path: &str) {
    let mut file = File::create(path).expect("Cannot create output file");
    match mode {
        "json" => {
            let data = serde_json::to_string_pretty(findings).unwrap();
            file.write_all(data.as_bytes()).unwrap();
            println!("✔ Exported to JSON at {}", path);
        }
        "csv" => {
            let mut wtr = csv::Writer::from_writer(file);
            for f in findings {
                wtr.serialize(f).unwrap();
            }
            wtr.flush().unwrap();
            println!("✔ Exported to CSV at {}", path);
        }
        _ => println!("Unsupported format: use 'json' or 'csv'"),
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut format = "none";
    let mut output = "";

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                print_help();
                return;
            }
            "-f" | "--format" => {
                if i+1 < args.len() {
                    format = &args[i+1];
                    if format == "csv" { output = "typedpaths.csv"; }
                    if format == "json" { output = "typedpaths.json"; }
                    i +=1;
                }
            }
            "-o" | "--output" => {
                if i+1 < args.len() {
                    output = &args[i+1];
                    i +=1;
                }
            }
            _ if args[i].starts_with("--format=") => {
                format = &args[i][9..];
            }
            _ if args[i].starts_with("--output=") => {
                output = &args[i][9..];
            }
            _ => {}
        }
        i += 1;
    }

    let keywords = get_keywords();
    let patterns = get_patterns();

    let hku = RegKey::predef(HKEY_USERS);
    let mut findings = Vec::new();

    for sid in hku.enum_keys().flatten() {
        print_typed_paths_for_user(&sid, &keywords, &patterns, &hku, &mut findings);
    }

    if format != "none" {
        if output.is_empty() {
            output = if format == "json" { "typedpaths.json" } else { "typedpaths.csv" };
        }
        export_findings(&findings, format, output);
    }
}
