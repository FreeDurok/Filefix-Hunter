# Filefix Hunter

![Rust](https://img.shields.io/badge/Rust-Programming%20Language-informational?style=flat&logo=rust)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

<p align="center">
  <img src=".img/Ransom Radar.png" alt="Ransom Radar Logo" width="300"/>
</p>


**filefix-hunter** is a forensic tool written in Rust for incident response. It enumerates TypedPaths entries in Windows registry to detect possible LOLBIN or filefix.exe exploitation traces.

<a href="https://ko-fi.com/durok" target="_blank">
  <img src="https://cdn.ko-fi.com/cdn/kofi5.png" alt="Buy Me a Coffee at ko-fi.com" height="40">
</a>

---

## 🚀 Purpose

- Scan all `HKEY_USERS\<SID>\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths` for each user.
- Look for suspicious commands, LOLBINs, known IOCs (Mimikatz, shellcode).
- Highlight suspicious entries (**red**) vs safe entries (**yellow**).
- Optionally export results to **JSON** or **CSV**.

---

## ⚠️ filefix Vulnerability

The **filefix** vulnerability exploits careless user behavior by getting them to paste malicious commands into Explorer’s address bar, leading to code execution with LOLBINs. More info [here](https://mrd0x.com/filefix-clickfix-alternative/).

---

## ⚙ Build

Requires the [Rust toolchain](https://www.rust-lang.org/tools/install):

```sh
cargo build --release
```

Binary at `target/release/filefix-hunter.exe`.

---

## 🚀 Usage

```sh
filefix-hunter [options]
```

Options:

* `-h, --help` : show help
* `-f, --format <json|csv|none>` : export format
* `-o, --output <file>` : output file name

Examples:

```sh
filefix-hunter -f json -o report.json
filefix-hunter --format=csv --output=report.csv
```

---

## 📝 Output

Terminal example:

```
HKEY_USERS\S-1-5-21-... = user
  [url1] rundll32.exe test.dll -> SUSPICIOUS
  [url2] Desktop               -> SAFE
```

JSON/CSV includes:

* `sid`, `username`, `name`, `value`
* `suspicious: true/false`
* `matched` reason

---

## 📝 License

MIT License

---
