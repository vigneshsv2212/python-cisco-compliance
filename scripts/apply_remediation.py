# scripts/apply_remediation.py
import os, json, yaml, argparse
from dotenv import load_dotenv
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException

load_dotenv()

def expand(v):
    """Expand ${VAR} from environment for devices.yaml."""
    return os.getenv(v[2:-1], "") if isinstance(v, str) and v.startswith("${") and v.endswith("}") else v

# ---- Load inventory and compliance results ----
inv = yaml.safe_load(open("config/devices.yaml"))
common = {k: expand(v) if isinstance(v, str) else v for k, v in inv.get("common", {}).items()}
devices = inv.get("devices", [])

data = json.load(open("data/reports/compliance.json"))

# ---- Remediation library (IOS commands) ----
REMEDIATIONS = {
    "ssh_only": ["line vty 0 4", "transport input ssh", "exit"],
    "telnet_forbidden": ["line vty 0 4", "transport input ssh", "exit"],
    "http_server_disabled": ["no ip http server"],
    "https_server_disabled": ["no ip http secure-server"],
    "banner_present": ['banner motd ^CAuthorized Access Only^C'],
    "pwd_encryption": ["service password-encryption"],
    "exec_timeout_ok": ["line vty 0 4", "exec-timeout 10 0", "exit"],
    "vty_acl_present": [
        "ip access-list standard MGMT",
        " permit 10.0.0.0 0.0.0.255",
        "exit",
        "line vty 0 4",
        "access-class MGMT in",
        "exit",
    ],
    "snmp_secure": ["no snmp-server community public", "no snmp-server community private"],
    "remote_logging": ["logging host 198.51.100.10"],
    "buffer_logging": ["logging buffered 8192"],
    "ntp_present": ["ntp server 0.pool.ntp.org"],
}

# ---- Args ----
parser = argparse.ArgumentParser()
parser.add_argument("--apply", action="store_true", help="Actually push commands to devices")
parser.add_argument("--allow", nargs="*", default=[], help="Only act on these device names")
parser.add_argument("--export", action="store_true", help="Export commands to data/remediation/<device>.txt")
args = parser.parse_args()

os.makedirs("data/remediation", exist_ok=True)

def uniq(seq):
    out = []
    [out.append(x) for x in seq if x not in out]
    return out

for dev in devices:
    name = dev.get("name", "(unnamed)")
    if name not in data:
        print(f"{name}: no compliance data — run compliance_check.py first")
        continue
    if args.allow and name not in args.allow:
        print(f"{name}: skipped (not in allow list)")
        continue

    # Build command list for failed findings
    to_fix = [f["key"] for f in data[name].get("findings", []) if f["key"] in REMEDIATIONS]
    if not to_fix:
        print(f"{name}: compliant ✅")
        continue

    cmds = []
    for k in to_fix:
        cmds.extend(REMEDIATIONS[k])
    cmds = uniq(cmds)

    mode_label = "APPLY" if args.apply else "DRY-RUN"
    print(f"\n{name}: {mode_label} — {len(to_fix)} findings, {len(cmds)} cmds")
    for c in cmds:
        print("  ", c)

    # Always export if requested
    if args.export:
        path = f"data/remediation/{name}.txt"
        with open(path, "w") as f:
            f.write("\n".join(cmds) + "\n")
        print(f"{name}: commands exported → {path}")

    # Stop here if not applying
    if not args.apply:
        continue

    # Apply mode (requires reachable device)
    params = {**common, **{k: expand(v) if isinstance(v, str) else v for k, v in dev.items()}}
    params.pop("name", None)  # Netmiko doesn't accept 'name'
    try:
        conn = ConnectHandler(**params)
        if params.get("secret"):
            conn.enable()
        out = conn.send_config_set(cmds)
        print(f"{name}: applied.\n---\n{out}\n---")
        conn.disconnect()
    except (NetmikoTimeoutException, NetmikoAuthenticationException) as e:
        print(f"{name}: APPLY failed ({e.__class__.__name__}). Tip: use --export or fix device reachability/creds.")
