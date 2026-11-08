#!/usr/bin/env python3
"""
Log Analyzer Agent
==================
Paper : A Multi-Agent System for Cybersecurity Threat Detection and Correlation
        Using Large Language Models
        IEEE Access, DOI: 10.1109/ACCESS.2025.3602681  (Section III-C)

Paper Architecture — Section III-C:
  Stage 1: Pre-processing & Normalization  (ELK-style field extraction)
  Stage 2: Signature-Based Detection       (Suricata-style regex rules)
  Stage 3: LLM Contextual Interpretation   (LLaMA 3.3-70B via Groq, Chain-of-Thought)
  Stage 4: Decision Fusion                 (3-source: regex + LLM + confidence)
  Stage 5: Structured Report               (risk verdict, IOCs, mitigations)

How to use:
    # Standalone
    python log_analyzer_agent.py --api-key gsk_... --log "Apr 6 sshd: Failed password..."

    # As a module (called by task_dispatcher)
    from agents.log_analyzer_agent import log_analyzer_agent, initialize_log_agent
    initialize_log_agent(groq_api_key="gsk_...")
    result = log_analyzer_agent(log_content="Apr 6 ...")
"""

# ── Auto-install ──────────────────────────────────────────────────────────────
import subprocess, sys

REQUIRED = {"groq": "groq"}
for _imp, _pkg in REQUIRED.items():
    try:
        __import__(_imp)
    except ImportError:
        print(f"  [INSTALL] {_pkg} ...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", _pkg, "--quiet"])
        print(f"  [OK]      {_pkg}")

# ── Standard library ──────────────────────────────────────────────────────────
import re
import os
import json
import time
import argparse
from datetime import datetime, timezone
from typing import Optional

# ── Third-party ───────────────────────────────────────────────────────────────
from groq import Groq

# ── Shared memory module ──────────────────────────────────────────────────────
import sys as _sys, os as _os
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
try:
    from agent_memory import get_memory as _get_memory
    _MEMORY_AVAILABLE = True
except ImportError:
    _MEMORY_AVAILABLE = False

# ══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ══════════════════════════════════════════════════════════════════════════════
LLM_MODEL         = "llama-3.3-70b-versatile"
MAX_TOKENS        = 600
TEMPERATURE       = 0.1
CALL_DELAY        = 1.5          # seconds between Groq calls
HIGH_CONF         = 0.75         # LLM confidence threshold for direct use
MED_CONF          = 0.55         # medium — use if regex also agrees

_groq_client: Optional[Groq] = None


# ══════════════════════════════════════════════════════════════════════════════
# PUBLIC INIT  (called by task_dispatcher before routing)
# ══════════════════════════════════════════════════════════════════════════════

def initialize_log_agent(groq_api_key: str) -> None:
    """
    Load the Groq client.
    Call this once before calling log_analyzer_agent().
    """
    global _groq_client
    _groq_client = Groq(api_key=groq_api_key)
    print("  [OK] Log Analyzer Agent initialized.")


# ══════════════════════════════════════════════════════════════════════════════
# STAGE 1 — PRE-PROCESSING & NORMALIZATION
# Paper: "logs from various sources … analyzed and normalized using the ELK stack
#         … fields such as timestamps, IP addresses and user IDs are extracted"
# ══════════════════════════════════════════════════════════════════════════════

# Field-extraction patterns (ELK Logstash grok-equivalent in pure regex)
_RE_IPV4      = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
_RE_PORT      = re.compile(r"\bport\s+(\d{1,5})\b", re.I)
_RE_USER      = re.compile(r"\b(?:user|for)\s+(\w+)", re.I)
_RE_TIMESTAMP = re.compile(
    r"\b(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\b|"          # syslog
    r"(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2})"            # ISO-8601
)
_RE_PROCESS   = re.compile(r"\b(\w+)\[(\d+)\]:")              # process[pid]:
_RE_HTTP_CODE = re.compile(r"\s(\d{3})\s")                    # HTTP status
_RE_URL       = re.compile(r"https?://[^\s\"'<>]+")


def normalize_log(raw: str) -> dict:
    """
    Stage 1 — Parse raw log text into structured fields.
    Mirrors Logstash grok parsing described in the paper.
    """
    norm = {
        "raw":            raw[:2000],
        "src_ip":         "N/A",
        "dst_ip":         "N/A",
        "src_port":       "N/A",
        "dst_port":       "N/A",
        "username":       "N/A",
        "process":        "N/A",
        "proto":          "unknown",
        "http_status":    "N/A",
        "urls":           [],
        "alert_sig":      "",
        "events":         [],
        "timestamp_norm": datetime.now(timezone.utc).isoformat(),
    }

    ips = _RE_IPV4.findall(raw)
    if ips:
        norm["src_ip"] = ips[0]
    if len(ips) >= 2:
        norm["dst_ip"] = ips[1]

    ports = _RE_PORT.findall(raw)
    if ports:
        norm["dst_port"] = ports[0]

    users = _RE_USER.findall(raw)
    if users:
        norm["username"] = users[0]

    proc_m = _RE_PROCESS.search(raw)
    if proc_m:
        norm["process"] = f"{proc_m.group(1)}[{proc_m.group(2)}]"

    norm["urls"] = _RE_URL.findall(raw)[:5]

    low = raw.lower()
    if "ssh"   in low: norm["proto"] = "TCP/SSH"
    elif "ftp" in low: norm["proto"] = "TCP/FTP"
    elif "http" in low or "80" in low or "443" in low: norm["proto"] = "TCP/HTTP"
    elif "udp" in low: norm["proto"] = "UDP"
    elif "icmp" in low: norm["proto"] = "ICMP"

    http_m = _RE_HTTP_CODE.search(raw)
    if http_m:
        norm["http_status"] = http_m.group(1)

    # Detected event markers
    event_patterns = [
        ("ssh_brute_force",   re.compile(r"failed password", re.I)),
        ("ssh_accepted",      re.compile(r"accepted password|publickey", re.I)),
        ("privilege_escalate",re.compile(r"sudo.*ran|sudo.*exec|su -", re.I)),
        ("port_scan",         re.compile(r"nmap|masscan|syn scan|port\s*scan", re.I)),
        ("web_brute_force",   re.compile(r"brute.?force", re.I)),
        ("sql_injection",     re.compile(r"sql.?inject|union.select|or\s+1=1|xp_cmd", re.I)),
        ("xss",               re.compile(r"<script|xss|cross.?site.?script", re.I)),
        ("ddos",              re.compile(r"ddos|syn.?flood|denial.?of.?service", re.I)),
        ("c2_beacon",         re.compile(r"botnet|c2\s|command.?control|beacon", re.I)),
        ("lateral_movement",  re.compile(r"lateral|psexec|wmi|pass.?the.?hash", re.I)),
        ("exfiltration",      re.compile(r"exfil|data.?transfer|outbound.*large", re.I)),
        ("heartbleed",        re.compile(r"heartbleed|tls.*bleed", re.I)),
    ]
    for name, pat in event_patterns:
        m = pat.search(raw)
        if m:
            norm["events"].append({"type": name, "match": m.group(0)[:60]})

    # Build alert_sig summary
    norm["alert_sig"] = "; ".join(e["type"] for e in norm["events"]) if norm["events"] else raw[:100]

    return norm


# ══════════════════════════════════════════════════════════════════════════════
# STAGE 2 — SIGNATURE-BASED DETECTION  (Suricata-equivalent regex rules)
# Paper: "signature-based detection system powered by Suricata … uses
#         well-maintained community and proprietary rule sets to detect
#         signatures of known threats"
# 16 rules derived from CIC-IDS2017 attack taxonomy used in the paper
# ══════════════════════════════════════════════════════════════════════════════

SIGNATURE_RULES = [
    # Rule format: (compiled_regex, label, severity)
    (re.compile(r"ddos|distributed.denial|syn.flood",           re.I), "DDoS",                    "CRITICAL"),
    (re.compile(r"dos hulk|hulk",                               re.I), "DoS-Hulk",                "HIGH"),
    (re.compile(r"goldeneye",                                   re.I), "DoS-GoldenEye",            "HIGH"),
    (re.compile(r"slowloris",                                   re.I), "DoS-Slowloris",            "HIGH"),
    (re.compile(r"slowhttptest|slow.http",                      re.I), "DoS-SlowHTTPTest",         "HIGH"),
    (re.compile(r"\bdos\b(?!.?hulk|.?golden|.?slow)",          re.I), "DoS-Generic",              "HIGH"),
    (re.compile(r"brute.?force",                                re.I), "Web-BruteForce",           "HIGH"),
    (re.compile(r"ftp.?patator|ftp.*brute",                    re.I), "FTP-Patator",              "HIGH"),
    (re.compile(r"failed password.*root|ssh.?patator|ssh.*brute|potential\s+ssh", re.I),
                                                                       "SSH-Patator",              "HIGH"),
    (re.compile(r"sql.?inject|sqli|union.select|xp_cmd|or\s+1=1", re.I), "SQLInjection",          "CRITICAL"),
    (re.compile(r"\bxss\b|cross.?site.?script|<script",        re.I), "XSS",                     "HIGH"),
    (re.compile(r"port.?scan|nmap|masscan|et scan|syn.?scan",  re.I), "PortScan",                "MEDIUM"),
    (re.compile(r"\bbot\b|botnet|c2\b|command.?control|beacon", re.I), "Bot-C2",                 "CRITICAL"),
    (re.compile(r"heartbleed|tls.*bleed",                       re.I), "Heartbleed",              "CRITICAL"),
    (re.compile(r"infiltrat|lateral|exfil",                    re.I), "Infiltration",             "CRITICAL"),
    (re.compile(r"accepted password|login success|session opened", re.I), "NormalAuth",           "LOW"),
]


def signature_detect(raw: str) -> tuple[str, str]:
    """
    Stage 2 — Apply 16 Suricata-style signature rules.
    Returns (label, severity).  "Unknown"/"UNKNOWN" if no match.
    """
    for pattern, label, severity in SIGNATURE_RULES:
        if pattern.search(raw):
            return label, severity
    return "Unknown", "UNKNOWN"


# ══════════════════════════════════════════════════════════════════════════════
# STAGE 3 — LLM CONTEXTUAL INTERPRETATION
# Paper: "invokes its third, most innovative layer: contextual interpretation
#         using an LLM … LLaMA 3.3-70B accessible via the Groq API.
#         The LLM receives sequences of suspicious log entries enriched with
#         metadata … follows a predefined prompt structure … chain-of-thought"
# ══════════════════════════════════════════════════════════════════════════════

_SYSTEM_PROMPT = """You are an expert SOC analyst specializing in log-based intrusion detection.
You receive structured log entries and must classify the attack type using chain-of-thought reasoning.

Available attack classes:
DDoS | DoS-Hulk | DoS-GoldenEye | DoS-Slowloris | DoS-SlowHTTPTest | DoS-Generic
Web-BruteForce | FTP-Patator | SSH-Patator | SQLInjection | XSS
PortScan | Bot-C2 | Heartbleed | Infiltration | Benign | Unknown

Respond ONLY with valid JSON, no markdown, no preamble:
{
  "step1_normalization": "<what fields and patterns you see>",
  "step2_signature":     "<which rules or patterns match>",
  "step3_context":       "<broader behavioral interpretation>",
  "step4_verdict":       "<final reasoning>",
  "attack_type":         "<one class from the list above>",
  "severity":            "<CRITICAL|HIGH|MEDIUM|LOW|NONE>",
  "confidence":          <0.0-1.0>,
  "ioc":                 "<primary indicator: IP, domain, signature, port>",
  "explanation":         "<1-2 sentence human-readable summary>",
  "mitigation":          "<concrete immediate action for the SOC analyst>"
}"""


def _build_llm_prompt(norm: dict, sig_label: str) -> str:
    return f"""Analyze this security log entry using chain-of-thought reasoning.

=== RAW LOG ===
{norm['raw'][:800]}

=== EXTRACTED FIELDS (Stage 1 Normalization) ===
  Source IP    : {norm['src_ip']}
  Dest IP      : {norm['dst_ip']}
  Dest Port    : {norm['dst_port']}
  Username     : {norm['username']}
  Process      : {norm['process']}
  Protocol     : {norm['proto']}
  HTTP Status  : {norm['http_status']}
  URLs found   : {norm['urls'][:3]}
  Alert Sig    : {norm['alert_sig']}
  Events       : {json.dumps([e['type'] for e in norm['events']])}

=== STAGE 2 SIGNATURE RESULT ===
  Signature match: {sig_label}

Now apply chain-of-thought (steps 1-4) and produce the JSON verdict."""


def call_llm(norm: dict, sig_label: str) -> dict:
    """
    Stage 3 — Send enriched log to LLaMA 3.3-70B via Groq.
    Returns parsed JSON dict or error fallback.
    """
    if _groq_client is None:
        return {
            "attack_type": sig_label if sig_label != "Unknown" else "Unknown",
            "severity":    "UNKNOWN",
            "confidence":  0.0,
            "ioc":         norm["src_ip"],
            "explanation": "LLM not initialized — call initialize_log_agent() first.",
            "mitigation":  "Manual review required.",
        }

    prompt = _build_llm_prompt(norm, sig_label)

    for attempt in range(3):
        try:
            time.sleep(CALL_DELAY)
            resp = _groq_client.chat.completions.create(
                model=LLM_MODEL,
                messages=[
                    {"role": "system", "content": _SYSTEM_PROMPT},
                    {"role": "user",   "content": prompt},
                ],
                temperature=TEMPERATURE,
                max_tokens=MAX_TOKENS,
            )
            raw_resp = resp.choices[0].message.content.strip()
            # Strip markdown fences if present
            raw_resp = re.sub(r"^```(?:json)?\n?", "", raw_resp)
            raw_resp = re.sub(r"\n?```$", "", raw_resp)
            result = json.loads(raw_resp)
            result["confidence"] = float(result.get("confidence", 0.5))
            return result

        except json.JSONDecodeError:
            # Try to extract JSON block
            m = re.search(r"\{.*\}", raw_resp, re.DOTALL)
            if m:
                try:
                    result = json.loads(m.group(0))
                    result["confidence"] = float(result.get("confidence", 0.5))
                    return result
                except Exception:
                    pass

        except Exception as e:
            err = str(e)
            if "429" in err or "rate_limit" in err.lower():
                wait = 30 * (attempt + 1)
                print(f"  [WARN] Rate limit (attempt {attempt+1}/3) — sleeping {wait}s ...")
                time.sleep(wait)
            else:
                print(f"  [WARN] LLM error (attempt {attempt+1}): {err[:100]}")
                time.sleep(2 ** attempt)

    # Exhausted retries — fall back to signature label
    return {
        "attack_type": sig_label if sig_label != "Unknown" else "Unknown",
        "severity":    "MEDIUM",
        "confidence":  0.0,
        "ioc":         norm["src_ip"],
        "explanation": "LLM unavailable after 3 retries — signature fallback used.",
        "mitigation":  "Manual review required.",
    }


# ══════════════════════════════════════════════════════════════════════════════
# STAGE 4 — 3-SOURCE DECISION FUSION
# Paper: "Decision Engine … fuses outputs from Suricata (signature),
#         LLM (semantic), and contextual metadata into a final verdict"
# Fusion priority:
#   1. LLM confidence ≥ HIGH_CONF  →  use LLM directly
#   2. LLM confidence ≥ MED_CONF AND agrees with signature  →  use LLM
#   3. LLM confidence ≥ MED_CONF alone  →  use LLM (flag for review)
#   4. Signature matched  →  use signature
#   5. Nothing matched    →  "Unknown"
# ══════════════════════════════════════════════════════════════════════════════

_SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0, "UNKNOWN": 0}
_ACTION_MAP = {
    "CRITICAL": "BLOCK",
    "HIGH":     "QUARANTINE",
    "MEDIUM":   "INVESTIGATE",
    "LOW":      "MONITOR",
    "NONE":     "ALLOW",
    "UNKNOWN":  "REVIEW",
}


def fuse_decision(sig_label: str, sig_severity: str, llm: dict) -> dict:
    """
    Stage 4 — Fuse signature + LLM into final verdict.
    """
    llm_label    = llm.get("attack_type", "Unknown")
    llm_severity = llm.get("severity", "UNKNOWN").upper()
    conf         = float(llm.get("confidence", 0.0))

    if conf >= HIGH_CONF:
        final_label    = llm_label
        final_severity = llm_severity
        basis          = "LLM_HIGH_CONFIDENCE"

    elif conf >= MED_CONF and llm_label == sig_label:
        final_label    = llm_label
        final_severity = llm_severity
        basis          = "LLM_SIGNATURE_AGREE"

    elif conf >= MED_CONF:
        final_label    = llm_label + " [review]"
        final_severity = llm_severity
        basis          = "LLM_MED_CONF"

    elif sig_label != "Unknown":
        final_label    = sig_label
        final_severity = sig_severity
        basis          = "SIGNATURE_ONLY"

    else:
        final_label    = "Unknown"
        final_severity = "UNKNOWN"
        basis          = "UNRESOLVED"

    clean_label = final_label.replace(" [review]", "")
    action      = _ACTION_MAP.get(final_severity, "REVIEW")

    return {
        "final_label":         clean_label,
        "final_label_flagged": final_label,
        "final_severity":      final_severity,
        "recommended_action":  action,
        "decision_basis":      basis,
        "signature_label":     sig_label,
        "signature_severity":  sig_severity,
        "llm_label":           llm_label,
        "llm_confidence":      conf,
    }


# ══════════════════════════════════════════════════════════════════════════════
# STAGE 5 — STRUCTURED REPORT GENERATION
# Paper: "structured report describing each host … threat narrative,
#         evidence traces, and actionable recommendations"
# ══════════════════════════════════════════════════════════════════════════════

def build_report(norm: dict, sig_label: str, sig_severity: str,
                 llm: dict, decision: dict, elapsed: float) -> dict:
    return {
        # ── Core verdict ─────────────────────────────────────────────
        "agent":              "LogAnalyzerAgent",
        "final_label":        decision["final_label"],
        "final_severity":     decision["final_severity"],
        "recommended_action": decision["recommended_action"],
        "risk_verdict":       decision["final_label"],

        # ── Stage breakdown ──────────────────────────────────────────
        "stage1_normalized_fields": {
            "src_ip":      norm["src_ip"],
            "dst_ip":      norm["dst_ip"],
            "dst_port":    norm["dst_port"],
            "username":    norm["username"],
            "process":     norm["process"],
            "proto":       norm["proto"],
            "alert_sig":   norm["alert_sig"],
            "events":      norm["events"],
        },
        "stage2_signature": {
            "label":    sig_label,
            "severity": sig_severity,
        },
        "stage3_llm": {
            "attack_type":   llm.get("attack_type", "N/A"),
            "severity":      llm.get("severity", "N/A"),
            "confidence":    llm.get("confidence", 0.0),
            "step1":         llm.get("step1_normalization", ""),
            "step2":         llm.get("step2_signature", ""),
            "step3":         llm.get("step3_context", ""),
            "step4":         llm.get("step4_verdict", ""),
            "explanation":   llm.get("explanation", ""),
            "mitigation":    llm.get("mitigation", ""),
            "ioc":           llm.get("ioc", norm["src_ip"]),
        },
        "stage4_decision_basis": decision["decision_basis"],

        # ── Analyst outputs ──────────────────────────────────────────
        "explanation":        llm.get("explanation", ""),
        "mitigation":         llm.get("mitigation", ""),
        "ioc":                llm.get("ioc", norm["src_ip"]),

        # ── Metadata ─────────────────────────────────────────────────
        "processing_time_sec": round(elapsed, 2),
        "timestamp_utc":       norm["timestamp_norm"],
    }


# ══════════════════════════════════════════════════════════════════════════════
# MAIN AGENT ENTRY POINT
# Called by the Task Dispatcher and directly for standalone use
# ══════════════════════════════════════════════════════════════════════════════

def log_analyzer_agent(log_content: str, verbose: bool = True) -> dict:
    """
    Full log analysis pipeline following paper Section III-C.

    Parameters
    ----------
    log_content : str  — raw log text (syslog, auth.log, web access log, etc.)
    verbose     : bool — print stage-by-stage progress

    Returns
    -------
    dict with keys: agent, final_label, final_severity, recommended_action,
    stage1_normalized_fields, stage2_signature, stage3_llm, stage4_decision_basis,
    explanation, mitigation, ioc, processing_time_sec, timestamp_utc
    """
    start = time.time()

    if verbose:
        print("\n" + "=" * 64)
        print("  LOG ANALYZER AGENT  (Paper Section III-C)")
        print("=" * 64)

    # Stage 1 — Normalize
    if verbose: print("\n  [1/4] Pre-processing & Normalization ...")
    norm = normalize_log(log_content)
    if verbose:
        print(f"        src_ip  : {norm['src_ip']}")
        print(f"        proto   : {norm['proto']}")
        print(f"        events  : {[e['type'] for e in norm['events']]}")

    # Stage 2 — Signature detection
    if verbose: print("  [2/4] Signature-based detection (Suricata rules) ...")
    sig_label, sig_severity = signature_detect(log_content)
    if verbose: print(f"        Signature : {sig_label}  [{sig_severity}]")

    # Stage 3 — LLM contextual interpretation
    if verbose: print(f"  [3/4] LLM contextual interpretation ({LLM_MODEL} via Groq) ...")
    llm = call_llm(norm, sig_label)
    if verbose:
        print(f"        LLM label      : {llm.get('attack_type')}")
        print(f"        LLM confidence : {llm.get('confidence', 0):.2f}")

    # Stage 4 — Decision fusion
    if verbose: print("  [4/4] 3-source decision fusion ...")
    decision = fuse_decision(sig_label, sig_severity, llm)
    if verbose: print(f"        Final verdict  : {decision['final_label']}  [{decision['final_severity']}]")
    if verbose: print(f"        Basis          : {decision['decision_basis']}")

    elapsed = time.time() - start
    report  = build_report(norm, sig_label, sig_severity, llm, decision, elapsed)

    if verbose:
        icons = {"CRITICAL": "🚨", "HIGH": "⚠️ ", "MEDIUM": "🔶", "LOW": "✅", "NONE": "✅"}
        icon  = icons.get(report["final_severity"], "❓")
        print("\n" + "=" * 64)
        print(f"  {icon} VERDICT    : {report['final_label']}")
        print(f"  📊 SEVERITY   : {report['final_severity']}")
        print(f"  🎯 ACTION     : {report['recommended_action']}")
        print(f"  🔑 IOC        : {report['ioc']}")
        print(f"  ⏱️  TIME       : {elapsed:.2f}s")
        print(f"\n  💬 Explanation : {report['explanation']}")
        print(f"  🛡️  Mitigation  : {report['mitigation']}")
        print("=" * 64)

    # ── Save to shared memory module (memory/log/) ────────────────────────────
    if _MEMORY_AVAILABLE:
        try:
            saved_path = _get_memory().save_log_report(report)
            print(f"  [MEMORY] Log report saved -> {saved_path}")
        except Exception as _mem_err:
            print(f"  [MEMORY] Log save failed: {_mem_err}")
    else:
        print("  [MEMORY] Skipped — agent_memory module not found")

    return report


# ══════════════════════════════════════════════════════════════════════════════
# STANDALONE ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Log Analyzer Agent  (Paper Section III-C)"
    )
    parser.add_argument("--api-key", required=True,
                        help="Groq API key (starts with gsk_)")
    parser.add_argument("--log", default=None,
                        help="Log text to analyze (default: built-in SSH brute-force sample)")
    args = parser.parse_args()

    initialize_log_agent(args.api_key)

    sample = args.log or (
        "Apr 06 14:22:01 srv01 sshd[1234]: Failed password for root "
        "from 192.168.56.103 port 54321 ssh2\n"
        "Apr 06 14:22:04 srv01 sshd[1235]: Failed password for root "
        "from 192.168.56.103 port 54322 ssh2\n"
        "Apr 06 14:22:07 srv01 sshd[1236]: Failed password for root "
        "from 192.168.56.103 port 54323 ssh2\n"
        "Apr 06 14:22:15 srv01 sudo:  root : TTY=pts/0 ; "
        "PWD=/root ; USER=root ; COMMAND=/bin/bash"
    )

    result = log_analyzer_agent(sample)
    print("\n=== JSON REPORT ===")
    print(json.dumps(result, indent=2))
