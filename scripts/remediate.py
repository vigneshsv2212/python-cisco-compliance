import json

data = json.load(open("data/reports/compliance.json"))

REMEDIATIONS = {
  "ssh_only": [
    "line vty 0 4",
    "transport input ssh",
    "exit"
  ],
  "telnet_forbidden": [
    "line vty 0 4",
    "transport input ssh",
    "exit"
  ],
  "http_server_disabled": ["no ip http server"],
  "https_server_disabled": ["no ip http secure-server"],
  "banner_present": ['banner motd ^CAuthorized Access Only^C'],
  "pwd_encryption": ["service password-encryption"],
  "exec_timeout_ok": [
    "line vty 0 4",
    "exec-timeout 10 0",
    "exit"
  ],
  "vty_acl_present": [
    "ip access-list standard MGMT",
    " permit 10.0.0.0 0.0.0.255",
    "exit",
    "line vty 0 4",
    "access-class MGMT in",
    "exit"
  ],
  "snmp_secure": [
    "no snmp-server community public",
    "no snmp-server community private"
  ],
  "remote_logging": ["logging host 198.51.100.10"],
  "buffer_logging": ["logging buffered 8192"],
  "ntp_present": ["ntp server 0.pool.ntp.org"]
}

for dev, r in data.items():
    to_fix = [f["key"] for f in r.get("findings", []) if f["key"] in REMEDIATIONS]
    if not to_fix:
        print(f"{dev}: No remediation needed ✅")
        continue
    print(f"\n{dev}: Suggested remediation (DRY-RUN) — {len(to_fix)} findings")
    cmds = []
    for k in to_fix:
        cmds.extend(REMEDIATIONS[k])
    # de-duplicate while preserving order
    out = []
    [out.append(c) for c in cmds if c not in out]
    for c in out:
        print("  ", c)
