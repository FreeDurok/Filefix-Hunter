use regex::Regex;

pub fn get_keywords() -> Vec<&'static str> {
    vec![
        "powershell", "cmd.exe", "mshta", "wscript", "cscript",
        "certutil", "bitsadmin", "rundll32", "regsvr32", "msiexec",
        "msbuild", "netsh", "net use", "net user", "net localgroup",
        "sc.exe", "sc", "schtasks", "wmic", "ftp", "tftp", "telnet",
        "curl", "wget", "invoke-webrequest", "invoke-expression", "iex", "ping",
        "whoami", "ipconfig", "arp", "nbtstat", "netstat", "tasklist",
        "taskkill", "findstr", "find", "tracert", "dsquery", "dsget",
        "driverquery", "gpresult", "logman", "wevtutil", "systeminfo",
        ".ps1", ".vbs", ".hta", ".bat", ".cmd", ".js", ".jse", ".wsf",
        ".msp", ".msc", "reg import", "reg add", "reg delete", "reg query",
        "invoke-mimikatz", "mimikatz", "downloadstring", "reflective",
        "shellcode", "base64", "-encodedcommand", "-enc", "-noprofile", "-windowstyle",
    ]
}

pub fn get_patterns() -> Vec<Regex> {
    vec![
        Regex::new(r"(?i)\.exe\b").unwrap(),
        Regex::new(r"(?i)\.dll\b").unwrap(),
        Regex::new(r"(?i)\.bat\b").unwrap(),
        Regex::new(r"(?i)\.cmd\b").unwrap(),
        Regex::new(r"(?i)\.ps1\b").unwrap(),
        Regex::new(r"(?i)\.vbs\b").unwrap(),
        Regex::new(r"(?i)\.hta\b").unwrap(),
        Regex::new(r"(?i)\.js\b").unwrap(),
        Regex::new(r"(?i)\.jse\b").unwrap(),
        Regex::new(r"(?i)\.wsf\b").unwrap(),
        Regex::new(r"(?i)\.msp\b").unwrap(),
        Regex::new(r"(?i)http[s]?://").unwrap(),
        Regex::new(r"(?i)ftp://").unwrap(),
        Regex::new(r"(?i)tftp://").unwrap(),
        Regex::new(r"(?i)telnet://").unwrap(),
        Regex::new(r"(?i)-encodedcommand").unwrap(),
        Regex::new(r"(?i)-enc\b").unwrap(),
        Regex::new(r"(?i)-bypass").unwrap(),
        Regex::new(r"(?i)downloadstring").unwrap(),
        Regex::new(r"(?i)reflective").unwrap(),
        Regex::new(r"(?i)mimikatz").unwrap(),
        Regex::new(r"(?i)shellcode").unwrap(),
        Regex::new(r"(?i)wevtutil.*clear-log").unwrap(),
        Regex::new(r"(?i)\\[\w\-]+\.dll").unwrap(),
    ]
}
