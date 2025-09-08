import re, json, pathlib, yaml, os

policy = yaml.safe_load(open("config/policy.yaml"))

patterns = {
    "telnet_vty": re.compile(r"line vty.*?\n(?: .*?\n)*?transport input (.*?)\n", re.DOTALL),
    "http_server": re.compile(r"^ip http server$", re.MULTILINE),
    "https_server": re.compile(r"^ip http secure-server$", re.MULTILINE),
    "banner_motd": re.compile(r"^banner motd ", re.MULTILINE),
    "service_pwd_enc": re.compile(r"^service password-encryption$", re.MULTILINE),
    "exec_timeout": re.compile(r"^line vty.*?\n(?: .*?\n)*?exec-timeout (\d+) (\d+)$", re.DOTALL | re.MULTILINE),
    "vty_access_class": re.compile(r"^line vty.*?\n(?: .*?\n)*?access-class ", re.DOTALL | re.MULTILINE),
    "snmp": re.compile(r"^snmp-server community (\S+) (RO|RW)(?: .*)?$", re.MULTILINE),
    "logging_host": re.compile(r"^logging host ", re.MULTILINE),
    "logging_buffer": re.compile(r"^logging buffered (\d+)", re.MULTILINE),
    "ntp_server": re.compile(r"^ntp server ", re.MULTILINE),
}

backup_dir = pathlib.Path("data/backups")
os.makedirs("data/reports", exist_ok=True)

results = {}

def meta(k):
    return policy.get("metadata", {}).get(k, {"title": k, "severity": "low", "control": "-"})

for cfg_file in backup_dir.glob("*.cfg"):
    name = cfg_file.stem
    cfg = cfg_file.read_text()

    checks = {}
    # SSH/Telnet
    m = patterns["telnet_vty"].search(cfg)
    transports = m.group(1).split() if m else []
    ssh_ok = ("ssh" in transports) if transports else False
    telnet_forbidden = ("telnet" not in transports) if transports else True
    checks["ssh_only"] = ssh_ok if policy["services"]["require_ssh"] else True
    checks["telnet_forbidden"] = telnet_forbidden if policy["services"]["forbid_telnet"] else True

    # HTTP/S
    checks["http_server_disabled"] = not patterns["http_server"].search(cfg) if policy["services"]["forbid_http_server"] else True
    checks["https_server_disabled"] = not patterns["https_server"].search(cfg) if not policy["services"].get("allow_https_server", False) else True

    # Banner + encryption
    checks["banner_present"] = bool(patterns["banner_motd"].search(cfg)) if policy["services"]["require_banner"] else True
    checks["pwd_encryption"] = bool(patterns["service_pwd_enc"].search(cfg)) if policy["services"]["require_password_encryption"] else True

    # Exec-timeout
    m = patterns["exec_timeout"].search(cfg)
    timeout_ok = False
    if m:
        minutes, seconds = int(m.group(1)), int(m.group(2))
        require = policy["services"]["require_exec_timeout_minutes"]
        timeout_ok = minutes <= require
    checks["exec_timeout_ok"] = timeout_ok

    # VTY ACL
    checks["vty_acl_present"] = bool(patterns["vty_access_class"].search(cfg)) if policy["services"]["vty_access_class_required"] else True

    # SNMP hygiene
    insecure_snmp = False
    for comm, mode in patterns["snmp"].findall(cfg):
        if comm.lower() in ("public", "private") or mode == "RW":
            insecure_snmp = True
    checks["snmp_secure"] = not insecure_snmp if policy["snmp"]["allow_v2c"] is False else True

    # Logging
    checks["remote_logging"] = bool(patterns["logging_host"].search(cfg)) if policy["logging"]["require_remote"] else True
    m = patterns["logging_buffer"].search(cfg)
    checks["buffer_logging"] = (m and int(m.group(1)) >= policy["logging"]["min_buffer_size"]) if policy["logging"]["require_buffered"] else True

    # NTP
    checks["ntp_present"] = bool(patterns["ntp_server"].search(cfg)) if policy["ntp"]["require_ntp"] else True

    # Score
    score = 100
    penalties = {
        "ssh_only": 10, "telnet_forbidden": 10, "http_server_disabled": 5,
        "https_server_disabled": 2, "banner_present": 5, "pwd_encryption": 5,
        "exec_timeout_ok": 5, "vty_acl_present": 8, "snmp_secure": 10,
        "remote_logging": 5, "buffer_logging": 3, "ntp_present": 3
    }
    for k, ok in checks.items():
        if not ok:
            score -= penalties.get(k, 3)
    score = max(score, 0)

    # Findings
    findings = []
    for k, ok in checks.items():
        if not ok:
            info = meta(k)
            findings.append({
                "key": k,
                "title": info.get("title", k),
                "severity": info.get("severity", "low"),
                "control": info.get("control", "-")
            })

    results[name] = {"score": score, "checks": checks, "findings": findings}

with open("data/reports/compliance.json", "w") as f:
    json.dump(results, f, indent=2)

print(json.dumps(results, indent=2))
