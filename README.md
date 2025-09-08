# 🛡️ Python Cisco Compliance Toolkit A Python-based toolkit that **audits Cisco IOS configuration files**, generates **HTML compliance reports**, and exports **remediation commands** to fix misconfigurations. This project demonstrates how automation can bridge the gap between **network engineering** and **security compliance**. --- ## ✨ Features ### Audit Engine - Parses Cisco configs (.cfg) against a YAML-defined security baseline (policy.yaml). - Detects issues like Telnet enabled, weak SNMP, missing banners, or improper logging. - Outputs device scores and results in JSON (compliance.json). ### Report Generator - Creates a clean, professional **HTML dashboard** with: - Device scores - ✔ / ✖ compliance checks - Severity ratings (**High / Medium / Low**) - CIS/NIST control mappings for each rule ### Remediation Engine - Exports .txt scripts per device with the **exact Cisco IOS commands** needed to fix issues. - Safe by default (export mode only) → no live device required. - Upgrade path: Netmiko integration for pushing changes directly to routers/switches. --- ## 📂 Project Structure
bash
python-cisco-compliance/
├── config/
│   ├── devices.yaml       # Device inventory (demo uses 127.0.0.1 placeholders)
│   └── policy.yaml        # Security baseline (rules + CIS/NIST mapping)
├── data/
│   ├── backups/           # Cisco config files (.cfg)
│   ├── reports/           # JSON + HTML compliance reports
│   └── remediation/       # Exported IOS command scripts
├── scripts/
│   ├── compliance_check.py   # Audit engine
│   ├── generate_report.py    # HTML report generator
│   ├── remediate.py          # Dry-run remediation
│   └── apply_remediation.py  # Export/Apply remediation (Netmiko ready)
├── requirements.txt
└── README.md