#!/usr/bin/env python3
"""
Task Dispatcher Agent  —  Unified File-Upload GUI Edition
==========================================================
Paper : A Multi-Agent System for Cybersecurity Threat Detection and Correlation
        Using Large Language Models
        IEEE Access, DOI: 10.1109/ACCESS.2025.3602681  (Section III-A)

Paper Architecture — Section III-A:
  The Task Dispatcher is the central entry point and orchestrator.
  It performs in order:
    1. Input validation   — checks completeness, metadata, formatting
    2. Task classification — content-based (regex/heuristic) first,
                             then LLM fallback (LLaMA 3.3-70B)
    3. Request Indexing   — UUID, serial, UTC timestamp, session, campaign tag
    4. Routing            — dispatches to the correct domain agent

  GUI redesign:
    - Single unified "Upload & Analyze" tab (NOT one tab per agent)
    - File upload supports: .txt, .log, .json, .eml, .csv (plus raw paste)
    - TaskDispatcher reads file content and classifies it automatically
    - All three agents (Email / IP / Log) are called through the same button

How to run:
    python task_dispatcher_gui.py
    python task_dispatcher_gui.py --cli --api-key gsk_...
"""

# ── Auto-install ───────────────────────────────────────────────────────────────
import subprocess, sys

REQUIRED = {"groq": "groq"}
for _imp, _pkg in REQUIRED.items():
    try:
        __import__(_imp)
    except ImportError:
        print(f"  [INSTALL] {_pkg} ...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", _pkg, "--quiet"])
        print(f"  [OK]      {_pkg}")

# ── Standard library ───────────────────────────────────────────────────────────
import re
import os
import csv
import io
import sys
import uuid
import json
import time
import argparse
import threading
import ipaddress
from datetime import datetime, timezone
from collections import defaultdict
from pathlib import Path
from groq import Groq

# Add agents folder to path so imports always work
# NOTE: Must be done BEFORE any threading starts to avoid Windows
#       transactional filesystem error (OSError WinError 6714).
#       Python's import system caches sys.path entries per-thread on
#       Windows; inserting the path here — in the main thread — ensures
#       the agents directory is visible to every worker thread.
_AGENTS_DIR = Path(__file__).parent / "agents"
_AGENTS_DIR_STR = str(_AGENTS_DIR.resolve())          # resolved absolute path
if _AGENTS_DIR_STR not in sys.path:
    sys.path.insert(0, _AGENTS_DIR_STR)

# Pre-import agents eagerly in the main thread.
# This populates sys.modules so worker threads never need to walk the
# filesystem under a Windows transaction context (fixes WinError 6714).
_EMAIL_AGENT_MODULE   = None
_IP_AGENT_MODULE      = None
_LOG_AGENT_MODULE     = None
_PREIMPORT_ERRORS: dict = {}

def _preimport_agents():
    """Called once at startup (main thread) to warm sys.modules."""
    global _EMAIL_AGENT_MODULE, _IP_AGENT_MODULE, _LOG_AGENT_MODULE
    try:
        import email_verification_agent as _m
        _EMAIL_AGENT_MODULE = _m
    except Exception as _e:
        _PREIMPORT_ERRORS["email"] = str(_e)
    for _mod in ("ip_range_analyzer_agent", "ipanalyzer"):
        try:
            _IP_AGENT_MODULE = __import__(_mod)
            break
        except Exception:
            pass
    if _IP_AGENT_MODULE is None:
        _PREIMPORT_ERRORS["ip"] = "ip_range_analyzer_agent.py not found"
    try:
        import log_analyzer_agent as _m2
        _LOG_AGENT_MODULE = _m2
    except Exception as _e2:
        _PREIMPORT_ERRORS["log"] = str(_e2)

_preimport_agents()

# KeyManager: multi-key rotation (3–9 keys)
from key_manager import KeyManager, build_key_manager

# ── Correlation Agent (Section III-E) ────────────────────────────────────────
try:
    from correlation_agent import CorrelationAgent, agent_result_to_report
    _CORRELATION_AVAILABLE = True
except ImportError:
    _CORRELATION_AVAILABLE = False
    print("  [WARN] correlation_agent.py not found — correlation disabled")

# Session-level store: accumulates routing results for correlation
# {session_id: [routing_result_dict, ...]}
_SESSION_ROUTING_RESULTS: dict = {}
_SESSION_LOCK = threading.Lock()

# ══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ══════════════════════════════════════════════════════════════════════════════
DEFAULT_GROQ_KEY = os.environ.get("GROQ_API_KEY", "")
GROQ_MODEL       = "llama-3.3-70b-versatile"

# Supported file extensions and their MIME-like category
SUPPORTED_EXTENSIONS = {
    ".txt":  "text",
    ".log":  "log",
    ".eml":  "email",
    ".json": "json",
    ".csv":  "csv",
}

# ══════════════════════════════════════════════════════════════════════════════
# TASK TYPE DEFINITIONS   (Paper Section III-A)
# ══════════════════════════════════════════════════════════════════════════════
class TaskType:
    EMAIL   = "EMAIL"
    IP      = "IP"
    LOG     = "LOG"
    UNKNOWN = "UNKNOWN"


# ══════════════════════════════════════════════════════════════════════════════
# REQUEST INDEX REGISTRY  (thread-safe)
# ══════════════════════════════════════════════════════════════════════════════
class IndexRegistry:
    def __init__(self):
        self._lock     = threading.Lock()
        self._counters = defaultdict(int)
        self._store    = {}

    def _today(self) -> str:
        return datetime.now(timezone.utc).strftime("%Y%m%d")

    def next_serial(self, task_type: str) -> str:
        with self._lock:
            key = (task_type, self._today())
            self._counters[key] += 1
            return f"{task_type}-{self._today()}-{self._counters[key]:04d}"

    def register(self, envelope: dict) -> None:
        with self._lock:
            self._store[envelope["request_id"]] = envelope

    def get(self, request_id: str):
        return self._store.get(request_id)

    def all_envelopes(self) -> list:
        return list(self._store.values())

    def by_type(self, task_type: str) -> list:
        return [e for e in self._store.values() if e["task_type"] == task_type]

    def by_session(self, session_id: str) -> list:
        return [e for e in self._store.values() if e["session_id"] == session_id]

    def summary(self) -> dict:
        out = defaultdict(list)
        for env in self._store.values():
            out[env["task_type"]].append({
                "serial":    env["serial_number"],
                "id":        env["request_id"],
                "timestamp": env["timestamp_utc"],
                "status":    env["routing_status"],
                "campaign":  env["campaign_tag"],
                "source":    env.get("source_file", "manual"),
            })
        return dict(out)


INDEX_REGISTRY = IndexRegistry()


# ══════════════════════════════════════════════════════════════════════════════
# INDEX ENVELOPE BUILDER
# ══════════════════════════════════════════════════════════════════════════════
def build_envelope(task_type: str, session_id: str,
                   raw_preview: str, campaign_tag: str = None,
                   source_file: str = "manual") -> dict:
    env = {
        "request_id":    str(uuid.uuid4()),
        "serial_number": INDEX_REGISTRY.next_serial(task_type),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "task_type":     task_type,
        "session_id":    session_id,
        "campaign_tag":  campaign_tag or "untagged",
        "raw_preview":   raw_preview[:120],
        "routing_status": "QUEUED",
        "source_file":   source_file,
    }
    INDEX_REGISTRY.register(env)
    return env


# ══════════════════════════════════════════════════════════════════════════════
# FILE CONTENT PARSER
# Reads a file path and returns (raw_text, detected_format, parsed_data)
# ══════════════════════════════════════════════════════════════════════════════
def parse_file_content(file_path: str) -> tuple:
    """
    Returns (raw_text: str, fmt: str, structured: dict | None)
    fmt is one of: 'text', 'log', 'email', 'json', 'csv'
    structured holds parsed JSON/CSV data (None for text/log/email)
    """
    path   = Path(file_path)
    suffix = path.suffix.lower()

    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        return "", "text", None, f"Read error: {e}"

    # ── JSON ──────────────────────────────────────────────────────────────────
    if suffix == ".json":
        try:
            parsed = json.loads(raw)
            return raw, "json", parsed, None
        except json.JSONDecodeError as e:
            # Still pass the raw text — classifier will handle it
            return raw, "json", None, f"JSON parse warning: {e}"

    # ── CSV ───────────────────────────────────────────────────────────────────
    if suffix == ".csv":
        try:
            reader = csv.DictReader(io.StringIO(raw))
            rows   = list(reader)
            return raw, "csv", {"rows": rows, "headers": reader.fieldnames}, None
        except Exception as e:
            return raw, "csv", None, f"CSV parse warning: {e}"

    # ── EML (email) ───────────────────────────────────────────────────────────
    if suffix == ".eml":
        return raw, "email", None, None

    # ── LOG ───────────────────────────────────────────────────────────────────
    if suffix == ".log":
        return raw, "log", None, None

    # ── TXT: may be anything — return raw, let classifier decide ──────────────
    return raw, "text", None, None


# ══════════════════════════════════════════════════════════════════════════════
# CONTENT-AWARE CLASSIFIER
# Inspects raw text (and optional parsed structure) to determine task type.
# This is the core intelligence that maps file content → agent.
# ══════════════════════════════════════════════════════════════════════════════

# Compiled regex patterns (ordered by specificity)
_RE_EMAIL_HEADERS = re.compile(
    r"^(From|To|Subject|Date|MIME-Version|Content-Type|Received|X-Mailer"
    r"|Return-Path|Reply-To|Delivered-To)\s*:",
    re.IGNORECASE | re.MULTILINE
)
_RE_EMAIL_ADDR   = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}", re.IGNORECASE)
_RE_PHISH_WORDS  = re.compile(
    r"\b(phish|spam|verify\s+your\s+account|click\s+here|urgent|suspicious\s+activity"
    r"|password\s+reset|login\s+immediately|account\s+locked|credential)\b",
    re.IGNORECASE
)
_RE_IP_ADDR      = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")
_RE_CIDR         = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}\b")
_RE_IP_SCAN_WORDS = re.compile(
    r"\b(nmap|scan|port\s*\d+|open\s+port|closed\s+port|filtered|service\s+detection"
    r"|host\s+discovery|ping\s+sweep|cidr|ip\s+range|masscan|shodan)\b",
    re.IGNORECASE
)
_RE_LOG_TIMESTAMP = re.compile(
    r"(\b(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}"
    r"|\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}"          # ISO-8601
    r"|\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})"             # Apache CLF
)
_RE_LOG_SEVERITY = re.compile(
    r"\b(ERROR|WARN(?:ING)?|INFO|DEBUG|CRITICAL|NOTICE|ALERT|EMERG|FATAL"
    r"|sshd|sudo|kernel|auth|failed\s+password|accepted\s+password"
    r"|cron|systemd|su\[|PAM|audit)\b",
    re.IGNORECASE
)
_RE_EVE_JSON     = re.compile(r'"event_type"\s*:\s*"(alert|flow|http|dns|tls|smtp|ssh|fileinfo)"', re.IGNORECASE)
_RE_SURICATA_ALERT = re.compile(r'"alert"\s*:\s*\{', re.IGNORECASE)


def _score_content(raw: str, fmt: str, structured) -> dict:
    """
    Return scoring dict {EMAIL: int, IP: int, LOG: int}.
    Higher score → more likely that task type.
    """
    scores = {TaskType.EMAIL: 0, TaskType.IP: 0, TaskType.LOG: 0}
    text   = raw[:12000]  # cap for speed

    # ── Format hints ─────────────────────────────────────────────────────────
    if fmt == "email":
        scores[TaskType.EMAIL] += 30
    if fmt == "log":
        scores[TaskType.LOG] += 20
    if fmt == "csv":
        # CSV with IP columns → IP agent; with log-like columns → LOG
        if structured and structured.get("headers"):
            headers_lower = [h.lower() for h in structured["headers"] if h]
            if any(h in ("src_ip", "dst_ip", "source_ip", "dest_ip", "ip",
                         "target", "ip_address") for h in headers_lower):
                scores[TaskType.IP] += 25
            if any(h in ("event_type", "alert", "severity", "category",
                         "log_source", "message", "event") for h in headers_lower):
                scores[TaskType.LOG] += 20
    if fmt == "json":
        if structured:
            # Suricata EVE JSON
            if isinstance(structured, dict):
                if "event_type" in structured:
                    scores[TaskType.LOG] += 30
                if "alert" in structured:
                    scores[TaskType.LOG] += 25
                if "src_ip" in structured or "dest_ip" in structured:
                    scores[TaskType.IP] += 15
                    scores[TaskType.LOG] += 10
                # Email-related JSON keys
                if any(k in structured for k in ("from", "to", "subject",
                                                   "email_content", "sender")):
                    scores[TaskType.EMAIL] += 30
            elif isinstance(structured, list) and structured:
                first = structured[0]
                if isinstance(first, dict):
                    if "event_type" in first:
                        scores[TaskType.LOG] += 30
                    if any(k in first for k in ("src_ip", "dest_ip")):
                        scores[TaskType.IP] += 15
                        scores[TaskType.LOG] += 10

    # ── Email signals ────────────────────────────────────────────────────────
    header_matches = len(_RE_EMAIL_HEADERS.findall(text))
    scores[TaskType.EMAIL] += min(header_matches * 8, 40)

    email_addrs = len(_RE_EMAIL_ADDR.findall(text))
    scores[TaskType.EMAIL] += min(email_addrs * 3, 18)

    phish_words = len(_RE_PHISH_WORDS.findall(text))
    scores[TaskType.EMAIL] += min(phish_words * 5, 20)

    if re.search(r"^(From|Subject)\s*:", text, re.IGNORECASE | re.MULTILINE):
        scores[TaskType.EMAIL] += 15

    # ── IP / Scan signals ────────────────────────────────────────────────────
    ip_hits = _RE_IP_ADDR.findall(text)
    # Only count valid IPs
    valid_ips = [m for m in ip_hits if all(0 <= int(o) <= 255 for o in m)]
    ip_count  = len(valid_ips)
    # Many IPs in a scan context → IP agent; a few in a log → LOG
    scores[TaskType.IP] += min(ip_count * 2, 20)

    cidr_hits = len(_RE_CIDR.findall(text))
    scores[TaskType.IP] += min(cidr_hits * 10, 30)

    scan_hits = len(_RE_IP_SCAN_WORDS.findall(text))
    scores[TaskType.IP] += min(scan_hits * 8, 32)

    # ── Log signals ───────────────────────────────────────────────────────────
    ts_hits = len(_RE_LOG_TIMESTAMP.findall(text))
    scores[TaskType.LOG] += min(ts_hits * 3, 30)

    sev_hits = len(_RE_LOG_SEVERITY.findall(text))
    scores[TaskType.LOG] += min(sev_hits * 4, 32)

    eve_hits = len(_RE_EVE_JSON.findall(text))
    scores[TaskType.LOG] += min(eve_hits * 10, 40)

    if _RE_SURICATA_ALERT.search(text):
        scores[TaskType.LOG] += 20

    # ── Disambiguate: emails typically have few IP lines, logs have many ──────
    # If IP count is low (≤ 3) and email score is already leading, reduce IP
    if ip_count <= 3 and scores[TaskType.EMAIL] >= scores[TaskType.IP]:
        scores[TaskType.IP] = max(0, scores[TaskType.IP] - 10)

    return scores


def classify_content(raw: str, fmt: str, structured,
                     groq_client: "Groq | None" = None) -> tuple:
    """
    Returns (task_type: str, method: str, scores: dict).
    method is 'heuristic' or 'llm'.
    """
    scores = _score_content(raw, fmt, structured)
    best   = max(scores, key=scores.get)
    best_v = scores[best]
    second = sorted(scores.values(), reverse=True)[1]

    # Confident if best score ≥ 15 AND leads by ≥ 10 over second
    if best_v >= 15 and (best_v - second) >= 10:
        return best, "heuristic", scores

    # Ambiguous — fall back to LLM
    if groq_client is not None:
        llm_type = _llm_classify_content(raw, fmt, groq_client)
        if llm_type != TaskType.UNKNOWN:
            return llm_type, "llm", scores

    # Last resort: pick highest score even if ambiguous
    if best_v > 0:
        return best, "heuristic-low-confidence", scores

    return TaskType.UNKNOWN, "none", scores


def _llm_classify_content(raw: str, fmt: str, groq_client: "Groq") -> str:
    """LLaMA 3.3-70B fallback: classify ambiguous content."""
    snippet = raw[:800].replace("\n", " ")
    prompt  = (
        f"You are a cybersecurity task classifier.\n"
        f"File format hint: {fmt}\n"
        f"Content snippet:\n{snippet}\n\n"
        f"Determine the security analysis task type. Reply with ONE word only: EMAIL, IP, or LOG."
    )
    try:
        resp = groq_client.chat.completions.create(
            model=GROQ_MODEL,
            messages=[
                {"role": "system", "content": "Reply with exactly one word: EMAIL, IP, or LOG."},
                {"role": "user",   "content": prompt},
            ],
            temperature=0.0,
            max_tokens=5,
        )
        v = resp.choices[0].message.content.strip().upper()
        if v in (TaskType.EMAIL, TaskType.IP, TaskType.LOG):
            return v
    except Exception as e:
        print(f"  [WARN] LLM classifier failed: {e}")
    return TaskType.UNKNOWN


# ══════════════════════════════════════════════════════════════════════════════
# PAYLOAD BUILDER
# Converts raw file text + format into a typed payload dict for each agent.
# ══════════════════════════════════════════════════════════════════════════════

def build_email_payload(raw: str, fmt: str, structured) -> dict:
    payload = {"email_content": raw}
    # Try to extract From/Subject from raw headers
    sender_m  = re.search(r"^From\s*:\s*(.+)$", raw, re.IGNORECASE | re.MULTILINE)
    subject_m = re.search(r"^Subject\s*:\s*(.+)$", raw, re.IGNORECASE | re.MULTILINE)
    if sender_m:
        payload["sender"]  = sender_m.group(1).strip()
    if subject_m:
        payload["subject"] = subject_m.group(1).strip()
    if fmt == "json" and isinstance(structured, dict):
        payload.update({k: v for k, v in structured.items()
                        if k in ("sender", "from", "subject", "to",
                                 "email_content", "body", "headers", "urls")})
    return payload


def build_ip_payload(raw: str, fmt: str, structured) -> dict:
    # Find the first valid IP or CIDR in the content
    cidr_m = _RE_CIDR.search(raw)
    if cidr_m:
        return {"target": cidr_m.group(0)}
    ip_hits = _RE_IP_ADDR.findall(raw)
    for m in ip_hits:
        ip_str = ".".join(m)
        try:
            ipaddress.ip_address(ip_str)
            return {"target": ip_str}
        except ValueError:
            pass
    if fmt == "json" and isinstance(structured, dict):
        for k in ("target", "ip_address", "src_ip", "dest_ip"):
            if k in structured:
                return {"target": str(structured[k])}
    if fmt == "csv" and structured and structured.get("rows"):
        first = structured["rows"][0]
        for k in ("target", "ip_address", "src_ip", "dest_ip"):
            if k in first:
                return {"target": str(first[k])}
    return {"target": raw.strip()[:50]}


def build_log_payload(raw: str, fmt: str, structured) -> dict:
    return {"log_content": raw}


_PAYLOAD_BUILDERS = {
    TaskType.EMAIL: build_email_payload,
    TaskType.IP:    build_ip_payload,
    TaskType.LOG:   build_log_payload,
}


# ══════════════════════════════════════════════════════════════════════════════
# PHASE 1 — INPUT VALIDATION
# ══════════════════════════════════════════════════════════════════════════════

def validate_email(data: dict):
    if not data.get("email_content") and not data.get("sender"):
        return False, "Email task requires 'email_content' or 'sender'."
    if "email_content" in data and not isinstance(data["email_content"], str):
        return False, "'email_content' must be a string."
    return True, "OK"


def validate_ip(data: dict):
    target = data.get("target", "").strip()
    if not target:
        return False, "IP task requires 'target' field (IP or CIDR)."
    try:
        ipaddress.ip_network(target, strict=False)
        return True, "OK"
    except ValueError:
        pass
    try:
        ipaddress.ip_address(target)
        return True, "OK"
    except ValueError:
        return False, f"Invalid IP/CIDR: '{target}'."


def validate_log(data: dict):
    if not data.get("log_content") and not data.get("log_file_path"):
        return False, "Log task requires 'log_content' or 'log_file_path'."
    if "log_content" in data and not isinstance(data["log_content"], str):
        return False, "'log_content' must be a string."
    return True, "OK"


_VALIDATORS = {
    TaskType.EMAIL: validate_email,
    TaskType.IP:    validate_ip,
    TaskType.LOG:   validate_log,
}

# Key sets for legacy dict-based heuristic (manual text input)
_EMAIL_KEYS = {"email_content", "sender", "subject", "headers", "body", "urls"}
_IP_KEYS    = {"target", "ip_range", "cidr", "ip_address"}
_LOG_KEYS   = {"log_content", "log_file_path", "log_lines", "syslog"}


# ══════════════════════════════════════════════════════════════════════════════
# PHASE 2 — OLD HEURISTIC (kept for dict-based manual input fallback)
# ══════════════════════════════════════════════════════════════════════════════

def _heuristic_classify(data: dict) -> str:
    if "task_type" in data:
        v = str(data["task_type"]).upper()
        if v in (TaskType.EMAIL, TaskType.IP, TaskType.LOG):
            return v
    keys = set(data.keys())
    if keys & _EMAIL_KEYS: return TaskType.EMAIL
    if keys & _IP_KEYS:    return TaskType.IP
    if keys & _LOG_KEYS:   return TaskType.LOG
    raw = json.dumps(data).lower()
    if re.search(r"\b(phishing|spam|subject|from:|to:|mime)\b", raw): return TaskType.EMAIL
    if re.search(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|cidr|nmap|port)\b", raw): return TaskType.IP
    if re.search(r"\b(auth\.log|syslog|failed|sudo|cron|kernel|ssh)\b", raw): return TaskType.LOG
    return TaskType.UNKNOWN


def _llm_classify(data: dict, groq_client: Groq) -> str:
    prompt = (
        "You are a cybersecurity task classifier.\n"
        "Given this JSON payload, determine what type of security analysis is needed.\n"
        "Reply with EXACTLY one word: EMAIL, IP, or LOG.\n\n"
        f"Payload:\n{json.dumps(data, indent=2)[:600]}\n\nClassification:"
    )
    try:
        resp = groq_client.chat.completions.create(
            model=GROQ_MODEL,
            messages=[
                {"role": "system", "content": "Reply with exactly one word: EMAIL, IP, or LOG."},
                {"role": "user",   "content": prompt},
            ],
            temperature=0.0,
            max_tokens=5,
        )
        v = resp.choices[0].message.content.strip().upper()
        if v in (TaskType.EMAIL, TaskType.IP, TaskType.LOG):
            return v
    except Exception as e:
        print(f"  [WARN] LLM classifier failed: {e}")
    return TaskType.UNKNOWN


def classify_task(data: dict, groq_client: Groq) -> str:
    t = _heuristic_classify(data)
    if t == TaskType.UNKNOWN:
        print("  [INFO] Heuristic inconclusive — calling LLM classifier ...")
        t = _llm_classify(data, groq_client)
    return t


# ══════════════════════════════════════════════════════════════════════════════
# PHASE 3 — AGENT IMPORTS  (lazy, graceful fallback)
# ══════════════════════════════════════════════════════════════════════════════

def _import_email_agent():
    # Use pre-imported module (main-thread import avoids WinError 6714)
    if _EMAIL_AGENT_MODULE is not None:
        try:
            return (_EMAIL_AGENT_MODULE.email_verification_agent,
                    _EMAIL_AGENT_MODULE.initialize, None)
        except AttributeError as e:
            return None, None, str(e)
    err = _PREIMPORT_ERRORS.get("email", "email_verification_agent not loaded")
    return None, None, err


def _import_ip_agent():
    if _IP_AGENT_MODULE is not None:
        try:
            return _IP_AGENT_MODULE.ip_range_analyzer_agent, None
        except AttributeError:
            pass
    err = _PREIMPORT_ERRORS.get("ip", "ip_range_analyzer_agent not found")
    return None, err


def _import_log_agent():
    if _LOG_AGENT_MODULE is not None:
        try:
            return (_LOG_AGENT_MODULE.log_analyzer_agent,
                    _LOG_AGENT_MODULE.initialize_log_agent, None)
        except AttributeError as e:
            return None, None, str(e)
    err = _PREIMPORT_ERRORS.get("log", "log_analyzer_agent not loaded")
    return None, None, err


# ══════════════════════════════════════════════════════════════════════════════
# PHASE 4 — ROUTING
# ══════════════════════════════════════════════════════════════════════════════

def _dict_to_email_text(payload: dict) -> str:
    body    = str(payload.get("email_content", ""))
    sender  = payload.get("sender",  "unknown@unknown.com")
    subject = payload.get("subject", "(no subject)")
    headers = payload.get("headers", {})
    lines = [f"From: {sender}", f"Subject: {subject}"]
    if isinstance(headers, dict):
        for k, v in headers.items():
            lines.append(f"{k}: {v}")
    lines.append("")
    lines.append(body)
    for url in payload.get("urls", []):
        lines.append(url)
    return "\n".join(lines)


def route_email(payload: dict, groq_api_key: str) -> dict:
    print("  [ROUTE] → Email Verification Agent")
    agent_fn, init_fn, err = _import_email_agent()
    if err:
        print(f"  [WARN] {err}")
        return {"agent": "EmailVerificationAgent", "status": "STUB",
                "result": None, "error": err}

    # ── Initialize email agent with paths relative to this script ───────
    import email_verification_agent as _eva
    if init_fn and _eva._faiss_index is None:
        _here = Path(__file__).parent
        vdb   = _here / "email_vdb.index"
        txts  = _here / "train_email_texts.npy"
        lbls  = _here / "train_email_labels.npy"
        if vdb.exists() and txts.exists() and lbls.exists():
            print("  [INIT] Initializing Email Verification Agent...")
            init_fn(
                groq_api_key      = groq_api_key,
                vdb_index_path    = str(vdb),
                train_texts_path  = str(txts),
                train_labels_path = str(lbls),
            )
        else:
            print("  [WARN] FAISS index files not found — email agent will run without vector DB")
            print(f"         Expected: {vdb}")
    # ─────────────────────────────────────────────────────────────────────

    try:
        email_text = _dict_to_email_text(payload)
        result = agent_fn(email_text, verbose=True)
        return {"agent": "EmailVerificationAgent", "status": "COMPLETED", "result": result}
    except Exception as e:
        print(f"  [ERR] Email agent: {e}")
        return {"agent": "EmailVerificationAgent", "status": "ERROR",
                "result": None, "error": str(e)}


def route_ip(payload: dict, groq_api_key: str) -> dict:
    print("  [ROUTE] → IP Range Analyzer Agent")
    agent_fn, err = _import_ip_agent()
    if err:
        print(f"  [WARN] {err}")
        return {"agent": "IPRangeAnalyzerAgent", "status": "STUB",
                "result": None, "error": err}
    try:
        result = agent_fn(
            target=payload.get("target", ""),
            run_accuracy_test=payload.get("run_accuracy_test", False),
        )
        return {"agent": "IPRangeAnalyzerAgent", "status": "COMPLETED", "result": result}
    except Exception as e:
        print(f"  [ERR] IP agent: {e}")
        return {"agent": "IPRangeAnalyzerAgent", "status": "ERROR",
                "result": None, "error": str(e)}


def route_log(payload: dict, groq_api_key: str) -> dict:
    print("  [ROUTE] → Log Analyzer Agent")
    agent_fn, init_fn, err = _import_log_agent()
    if err:
        print(f"  [WARN] {err}")
        return {"agent": "LogAnalyzerAgent", "status": "STUB",
                "result": None, "error": err}
    try:
        if init_fn:
            init_fn(groq_api_key=groq_api_key)
        log_text = payload.get("log_content", "") or payload.get("log_file_path", "")
        result = agent_fn(log_content=log_text, verbose=True)
        return {"agent": "LogAnalyzerAgent", "status": "COMPLETED", "result": result}
    except Exception as e:
        print(f"  [ERR] Log agent: {e}")
        return {"agent": "LogAnalyzerAgent", "status": "ERROR",
                "result": None, "error": str(e)}


_ROUTERS = {
    TaskType.EMAIL: route_email,
    TaskType.IP:    route_ip,
    TaskType.LOG:   route_log,
}


# ══════════════════════════════════════════════════════════════════════════════
# TASK DISPATCHER CORE CLASS
# ══════════════════════════════════════════════════════════════════════════════

class TaskDispatcherAgent:
    """
    Central orchestrator.  Paper Section III-A + Request Indexing extension.

    Two dispatch entry points:
      dispatch()      — classic dict-based (manual text input, legacy CLI)
      dispatch_file() — file-based: parse → classify content → route

    Supports 3–9 Groq API keys with automatic rotation on rate-limit (429).
    Pass a list of keys to __init__ to enable multi-key mode.
    """

    def __init__(self, groq_api_key: str = DEFAULT_GROQ_KEY,
                 api_keys: list = None):
        # ── Key manager setup ────────────────────────────────────────────
        if api_keys and len(api_keys) >= 2:
            # Multi-key mode: 3–9 keys (we accept 2+ for flexibility)
            self.key_manager = build_key_manager(api_keys)
            self.api_key     = self.key_manager.current_key()
            _n = len(api_keys)
            print(f"  [INIT] Multi-key mode: {_n} key(s) loaded (auto-rotation on 429)")
        else:
            self.key_manager = build_key_manager([groq_api_key])
            self.api_key     = groq_api_key

        self.groq_client = Groq(api_key=self.api_key)
        self.session_id  = str(uuid.uuid4())[:8].upper()
        print(f"  [INIT] Task Dispatcher ready  |  Session: {self.session_id}")

    def _rotate_key_on_error(self, exc: Exception) -> bool:
        """Rotate API key if error is a rate-limit (429). Returns True if rotated."""
        err_str = str(exc).lower()
        if "429" in str(exc) or "rate_limit" in err_str or "rate limit" in err_str:
            new_key = self.key_manager.rotate() if self.key_manager else None
            if new_key:
                self.api_key = new_key
                self.groq_client = Groq(api_key=new_key)
                print(f"  [KEY] Rate limit hit — rotated to next key ({new_key[:12]}…)")
                return True
            print("  [KEY] All API keys exhausted — waiting for cooldown…")
        return False

    def _route_with_rotation(self, router_fn, augmented: dict, max_retries: int = 9) -> dict:
        """Call a router function, auto-rotating keys on 429 errors."""
        for attempt in range(max_retries):
            try:
                return router_fn(augmented, self.api_key)
            except Exception as exc:
                if self._rotate_key_on_error(exc) and attempt < max_retries - 1:
                    time.sleep(1.5)
                    continue
                raise
        return router_fn(augmented, self.api_key)

    # ── File-based dispatch (new unified entry point) ─────────────────────────
    def dispatch_file(self, file_path: str,
                      campaign_tag: str = None,
                      override_type: str = None) -> dict:
        """
        Read a file, classify its content, build the correct payload,
        and route to the appropriate agent — all automatically.

        Parameters
        ----------
        file_path     : path to .txt / .log / .eml / .json / .csv file
        campaign_tag  : optional analyst label
        override_type : force EMAIL | IP | LOG (skip classifier)
        """
        SEP = "-" * 64
        print(f"\n{SEP}")
        print(f"  TASK DISPATCHER — File Upload")
        print(f"  File: {file_path}")
        print(SEP)

        # ── Parse ──────────────────────────────────────────────────────────
        print("  [1/5] Parsing file ...")
        raw, fmt, structured, parse_err = parse_file_content(file_path)
        if parse_err:
            print(f"  [WARN] {parse_err}")
        if not raw.strip():
            return self._fail({}, TaskType.UNKNOWN, campaign_tag,
                               "File is empty or could not be read.",
                               source_file=Path(file_path).name)

        print(f"        Format detected : {fmt}  |  Length: {len(raw):,} chars")

        # ── Classify ───────────────────────────────────────────────────────
        print("  [2/5] Classifying content ...")
        if override_type and override_type.upper() in (TaskType.EMAIL, TaskType.IP, TaskType.LOG):
            resolved = override_type.upper()
            method   = "manual override"
            scores   = {}
        else:
            resolved, method, scores = classify_content(raw, fmt, structured, self.groq_client)

        print(f"        Task type : {resolved}  ({method})")
        if scores:
            print(f"        Scores    : " + "  ".join(f"{k}={v}" for k, v in scores.items()))

        if resolved == TaskType.UNKNOWN:
            return self._fail({"raw_preview": raw[:120]}, TaskType.UNKNOWN,
                               campaign_tag,
                               "Cannot determine task type from file content. "
                               "Try forcing a type via the dropdown.",
                               source_file=Path(file_path).name)

        # ── Build payload ──────────────────────────────────────────────────
        print("  [3/5] Building payload ...")
        builder = _PAYLOAD_BUILDERS[resolved]
        payload = builder(raw, fmt, structured)

        # ── Build index envelope ───────────────────────────────────────────
        print("  [4/5] Building request index envelope ...")
        env = build_envelope(resolved, self.session_id,
                              raw[:120], campaign_tag,
                              source_file=Path(file_path).name)
        print(f"        Serial : {env['serial_number']}  |  ID: {env['request_id']}")

        # ── Validate ───────────────────────────────────────────────────────
        valid, msg = _VALIDATORS.get(resolved, lambda _: (False, "No validator"))(payload)
        if not valid:
            env["routing_status"] = "FAILED"
            INDEX_REGISTRY.register(env)
            return self._fail(payload, resolved, campaign_tag, msg, env,
                               source_file=Path(file_path).name)

        # ── Route ──────────────────────────────────────────────────────────
        print("  [5/5] Routing to domain agent ...")
        env["routing_status"] = "DISPATCHED"
        INDEX_REGISTRY.register(env)

        augmented      = {**payload, "_index": env}
        routing_result = self._route_with_rotation(_ROUTERS[resolved], augmented)
        routing_result["index_envelope"] = env

        env["routing_status"] = (
            "COMPLETED" if routing_result.get("status") == "COMPLETED"
            else "ERROR" if routing_result.get("status") == "ERROR"
            else "STUB"
        )
        INDEX_REGISTRY.register(env)

        # ── Store result for later correlation ────────────────────────────
        with _SESSION_LOCK:
            _SESSION_ROUTING_RESULTS.setdefault(self.session_id, []).append(routing_result)

        summary = (
            f"[{env['serial_number']}] {resolved} ({method}) → "
            f"{env['routing_status']}  |  file={Path(file_path).name}"
        )
        print(f"\n  [OK]  {summary}")
        print(SEP)

        return {
            "index_envelope":    env,
            "task_type":         resolved,
            "classify_method":   method,
            "classify_scores":   scores,
            "file_format":       fmt,
            "source_file":       Path(file_path).name,
            "parse_warning":     parse_err,
            "validation":        {"passed": True, "message": "OK"},
            "routing_result":    routing_result,
            "dispatch_summary":  summary,
        }

    # ── Classic dict-based dispatch (kept for CLI self-test / legacy) ─────────
    def dispatch(self, raw_input: dict,
                 task_type: str = None,
                 campaign_tag: str = None) -> dict:
        SEP = "-" * 64
        print(f"\n{SEP}")
        print("  TASK DISPATCHER — Manual Input")
        print(SEP)

        print("  [1/4] Classifying task ...")
        if task_type:
            resolved = task_type.strip().upper()
        else:
            resolved = classify_task(raw_input, self.groq_client)
        print(f"        Type: {resolved}")

        if resolved == TaskType.UNKNOWN:
            return self._fail(raw_input, resolved, campaign_tag,
                              "Cannot determine task type.")

        print("  [2/4] Building request index envelope ...")
        env = build_envelope(resolved, self.session_id,
                              json.dumps(raw_input), campaign_tag)

        print("  [3/4] Validating input ...")
        valid, msg = _VALIDATORS.get(resolved, lambda _: (False, "No validator"))(raw_input)
        if not valid:
            env["routing_status"] = "FAILED"
            INDEX_REGISTRY.register(env)
            return self._fail(raw_input, resolved, campaign_tag, msg, env)

        print("  [4/4] Routing to domain agent ...")
        env["routing_status"] = "DISPATCHED"
        INDEX_REGISTRY.register(env)

        augmented      = {**raw_input, "_index": env}
        routing_result = self._route_with_rotation(_ROUTERS[resolved], augmented)
        routing_result["index_envelope"] = env

        env["routing_status"] = (
            "COMPLETED" if routing_result.get("status") == "COMPLETED"
            else "ERROR" if routing_result.get("status") == "ERROR"
            else "STUB"
        )
        INDEX_REGISTRY.register(env)

        # ── Store result for later correlation ────────────────────────────
        with _SESSION_LOCK:
            _SESSION_ROUTING_RESULTS.setdefault(self.session_id, []).append(routing_result)

        summary = (
            f"[{env['serial_number']}] {resolved} → "
            f"{env['routing_status']} at {env['timestamp_utc']}"
        )
        print(f"\n  [OK]  {summary}")

        return {
            "index_envelope":   env,
            "task_type":        resolved,
            "validation":       {"passed": True, "message": "OK"},
            "routing_result":   routing_result,
            "dispatch_summary": summary,
        }

    # ------------------------------------------------------------------
    def _fail(self, raw_input, resolved, campaign_tag, reason,
              env=None, source_file="manual"):
        print(f"  [FAIL] {reason}")
        if env is None:
            env = build_envelope(
                resolved or TaskType.UNKNOWN,
                self.session_id,
                str(raw_input)[:120],
                campaign_tag,
                source_file=source_file,
            )
            env["routing_status"] = "FAILED"
            INDEX_REGISTRY.register(env)
        return {
            "index_envelope":   env,
            "task_type":        resolved,
            "source_file":      source_file,
            "validation":       {"passed": False, "message": reason},
            "routing_result":   None,
            "dispatch_summary": f"[FAILED] {reason}",
        }

    def index_report(self):
        SEP = "=" * 64
        print(f"\n{SEP}\n  DISPATCH INDEX REPORT\n  Session : {self.session_id}\n{SEP}")
        summary = INDEX_REGISTRY.summary()
        if not summary:
            print("  (empty)"); return
        for ttype, entries in summary.items():
            print(f"\n  [{ttype}]  {len(entries)} task(s)")
            for e in entries:
                print(f"    {e['serial']:<28}  {e['status']:<12}  {e['timestamp']}")
        total = sum(len(v) for v in summary.values())
        print(f"\n  Total : {total}  |  Types : {list(summary.keys())}")
        print(SEP)

    def run_correlation(self) -> dict:
        """
        Run the Correlation Agent (Section III-E) over all routing results
        collected in this session.  Called from GUI or CLI after ≥1 agent runs.
        """
        if not _CORRELATION_AVAILABLE:
            return {"error": "correlation_agent.py not found in the same folder"}

        with _SESSION_LOCK:
            routing_results = list(_SESSION_ROUTING_RESULTS.get(self.session_id, []))

        if not routing_results:
            return {"error": "No agent results yet — run at least one analysis first"}

        # Build AgentReport objects from routing results
        reports = []
        for rr in routing_results:
            report = agent_result_to_report(rr)
            if report:
                reports.append(report)

        if not reports:
            return {"error": "No completed agent results to correlate (all may have errored or STUBbed)"}

        # Run correlation
        corr_agent = CorrelationAgent(
            groq_api_key=self.api_key,
            memory_dir="memory",
            temporal_window_seconds=3600,
        )
        result = corr_agent.correlate(reports)
        return {"success": True, "result": result, "result_dict": result.to_dict()}

    def correlation_context(self) -> dict:
        return {
            "session_id": self.session_id,
            "envelopes":  INDEX_REGISTRY.all_envelopes(),
            "by_type": {
                TaskType.EMAIL: INDEX_REGISTRY.by_type(TaskType.EMAIL),
                TaskType.IP:    INDEX_REGISTRY.by_type(TaskType.IP),
                TaskType.LOG:   INDEX_REGISTRY.by_type(TaskType.LOG),
            },
            "by_session": INDEX_REGISTRY.by_session(self.session_id),
            "summary":    INDEX_REGISTRY.summary(),
        }


# ══════════════════════════════════════════════════════════════════════════════
# TKINTER GUI  — Unified File-Upload Design
# ══════════════════════════════════════════════════════════════════════════════

def launch_gui(initial_key: str = DEFAULT_GROQ_KEY):
    """Polished SOC dashboard GUI — full-width, properly scaled, rich output."""
    try:
        import tkinter as tk
        from tkinter import ttk, scrolledtext, messagebox, filedialog
    except ImportError:
        print("[ERR] tkinter not available.  Ubuntu: sudo apt install python3-tk")
        sys.exit(1)

    # ── DPI awareness (Windows) ───────────────────────────────────────────────
    try:
        import ctypes
        ctypes.windll.shcore.SetProcessDpiAwareness(2)
    except Exception:
        pass

    # ── Scale factor ─────────────────────────────────────────────────────────
    try:
        import ctypes
        _dpi   = ctypes.windll.user32.GetDpiForSystem()
        SCALE  = _dpi / 96
    except Exception:
        SCALE = 1.0
    def _s(n): return max(8, round(n * SCALE))

    # ── Colour palette ────────────────────────────────────────────────────────
    C = {
        "bg":       "#0d1117",
        "panel":    "#161b22",
        "panel2":   "#1c2128",
        "border":   "#21262d",
        "input":    "#0d1117",
        "accent":   "#1f6feb",
        "green":    "#3fb950",
        "yellow":   "#d29922",
        "orange":   "#e3562a",
        "red":      "#f85149",
        "cyan":     "#58a6ff",
        "purple":   "#bc8cff",
        "teal":     "#39d0d8",
        "text":     "#e6edf3",
        "muted":    "#8b949e",
        "dim":      "#484f58",
        "codebg":   "#010409",
    }

    # ── Fonts ─────────────────────────────────────────────────────────────────
    for fam in ("Cascadia Code", "Consolas", "Courier New"):
        MONO = fam; break
    FONT_MONO   = (MONO,        _s(10))
    FONT_MONO_S = (MONO,        _s(9))
    FONT_MONO_B = (MONO,        _s(10), "bold")
    FONT_SANS   = ("Segoe UI",  _s(10))
    FONT_SANS_B = ("Segoe UI",  _s(10), "bold")
    FONT_TITLE  = ("Segoe UI",  _s(16), "bold")
    FONT_SMALL  = ("Segoe UI",  _s(9))
    FONT_H2     = ("Segoe UI",  _s(11), "bold")
    FONT_BADGE  = ("Segoe UI",  _s(10), "bold")

    dispatcher = [None]
    _last_res   = [None]

    # ── Root window ───────────────────────────────────────────────────────────
    root = tk.Tk()
    root.title("Multi-Agent Cybersecurity System  ·  SOC Dispatcher")
    root.geometry("1400x920")
    root.configure(bg=C["bg"])
    root.resizable(True, True)
    root.minsize(1000, 650)

    # ── Widget factories ──────────────────────────────────────────────────────
    def _lbl(p, text, fg=None, bg=None, font=None, **kw):
        return tk.Label(p, text=text, bg=bg or C["panel"],
                        fg=fg or C["text"], font=font or FONT_SANS, **kw)

    def _entry(p, width=30, var=None, show=None, font=None, **kw):
        e = tk.Entry(p, width=width, bg=C["input"], fg=C["text"],
                     insertbackground=C["cyan"], relief="flat",
                     font=font or FONT_MONO, highlightthickness=1,
                     highlightcolor=C["accent"], highlightbackground=C["border"], **kw)
        if var:  e.config(textvariable=var)
        if show: e.config(show=show)
        return e

    def _btn(p, text, cmd, bg=None, fg="#ffffff", padx=14, pady=6, width=None, **kw):
        b = tk.Button(p, text=text, command=cmd or (lambda: None),
                      bg=bg or C["accent"], fg=fg,
                      font=FONT_SANS_B, relief="flat",
                      padx=padx, pady=pady, cursor="hand2",
                      activebackground=C["cyan"],
                      activeforeground="#0d1117",
                      bd=0, highlightthickness=0, **kw)
        if width: b.config(width=width)
        # Hover effect
        def _on(e):  b.config(bg=C["cyan"], fg="#0d1117")
        def _off(e): b.config(bg=bg or C["accent"], fg=fg)
        b.bind("<Enter>", _on)
        b.bind("<Leave>", _off)
        return b

    def _divider(p, color=None, vertical=False):
        return tk.Frame(p, bg=color or C["border"],
                        width=1 if vertical else None,
                        height=None if vertical else 1)

    def _card(p, **kw):
        return tk.Frame(p, bg=C["panel"],
                        highlightthickness=1,
                        highlightbackground=C["border"], **kw)

    # ── Output box with colour tags ───────────────────────────────────────────
    def _outbox(p, height=20, base_fg=None):
        st = scrolledtext.ScrolledText(
            p, height=height, bg=C["codebg"],
            fg=base_fg or C["green"],
            font=FONT_MONO_S, relief="flat",
            state="disabled", wrap="word",
            selectbackground=C["accent"],
            insertbackground=C["cyan"],
            padx=10, pady=8,
        )
        tags = {
            "hdr":    (C["cyan"],   FONT_MONO_B),
            "sep":    (C["border"], FONT_MONO_S),
            "key":    ("#79c0ff",   FONT_MONO_S),
            "good":   (C["green"],  FONT_MONO_S),
            "warn":   (C["yellow"], FONT_MONO_S),
            "bad":    (C["red"],    FONT_MONO_B),
            "info":   (C["cyan"],   FONT_MONO_S),
            "muted":  (C["muted"],  FONT_MONO_S),
            "normal": (C["text"],   FONT_MONO_S),
            "label":  (C["purple"], FONT_MONO_B),
            "crit":   (C["red"],    FONT_MONO_B),
            "high":   (C["orange"], FONT_MONO_B),
            "med":    (C["yellow"], FONT_MONO_B),
            "low":    (C["green"],  FONT_MONO_B),
            "ip":     (C["teal"],   FONT_MONO_S),
        }
        for tag, (fg, fnt) in tags.items():
            st.tag_configure(tag, foreground=fg, font=fnt)
        return st

    def _write(box, text):
        def _w():
            box.config(state="normal")
            box.delete("1.0", "end")
            box.insert("end", text)
            box.config(state="disabled")
            box.see("1.0")
        root.after(0, _w)

    def _rich(box, segs, clear=True):
        def _w():
            box.config(state="normal")
            if clear: box.delete("1.0", "end")
            for txt, tag in segs:
                box.insert("end", txt, tag) if tag else box.insert("end", txt)
            box.config(state="disabled")
            box.see("1.0")
        root.after(0, _w)

    def _console(text):
        ts = datetime.now().strftime("%H:%M:%S")
        def _a():
            con.config(state="normal")
            con.insert("end", f"[{ts}] {text}\n")
            con.see("end")
            con.config(state="disabled")
        root.after(0, _a)

    def _run_bg(fn, *a): threading.Thread(target=fn, args=a, daemon=True).start()

    def _need_disp():
        if not dispatcher[0]:
            messagebox.showwarning("Not Connected", "Enter your API key and click Connect first.")
            return False
        return True

    # ── Rich formatters ───────────────────────────────────────────────────────
    def _fmt_email(res):
        rr = (res.get("routing_result") or {})
        r  = rr.get("result") or {}
        ev = res.get("index_envelope") or {}
        v  = r.get("risk_verdict", "UNKNOWN")
        sc = r.get("risk_score", 0)
        ac = r.get("recommended_action", "—")
        vtag = {"PHISHING": "crit", "SUSPICIOUS": "med", "SAFE": "good"}.get(v, "normal")
        s = [
            ("═"*70+"\n","sep"), ("  EMAIL VERIFICATION AGENT  —  REPORT\n","hdr"), ("═"*70+"\n","sep"),
            ("  Serial   : ","key"),(f"{ev.get('serial_number','—')}\n","normal"),
            ("  Session  : ","key"),(f"{ev.get('session_id','—')}\n","normal"),
            ("  Campaign : ","key"),(f"{ev.get('campaign_tag','—')}\n","normal"),
            ("  Time     : ","key"),(f"{ev.get('timestamp_utc','—')}\n","normal"),
            ("\n",None),
            ("─"*70+"\n","sep"),("  VERDICT\n","hdr"),("─"*70+"\n","sep"),
            ("  Risk Verdict   : ","key"),(f"{v}\n",vtag),
            ("  Risk Score     : ","key"),(f"{sc:.4f}  ({sc*100:.1f}%)\n",vtag),
            ("  Recommended    : ","key"),(f"{ac}\n","warn" if ac!="ALLOW" else "good"),
            ("  LLM Used       : ","key"),(f"{r.get('llm_success',False)}\n","normal"),
        ]
        comp = r.get("component_scores", {})
        if comp:
            s += [("\n",None),("─"*70+"\n","sep"),("  COMPONENT SCORES\n","hdr"),("─"*70+"\n","sep")]
            for k, v2 in comp.items():
                bar = "█"*int(v2*32)+"░"*(32-int(v2*32))
                t2 = "bad" if v2>0.7 else "warn" if v2>0.4 else "good"
                s += [(f"  {k:<16}: ","key"),(f"[{bar}]  {v2:.3f}\n",t2)]
        llm = r.get("llm_analysis") or {}
        if isinstance(llm, dict) and llm:
            s += [("\n",None),("─"*70+"\n","sep"),("  LLM ANALYSIS\n","hdr"),("─"*70+"\n","sep")]
            j = llm.get("justification", llm.get("reasoning",""))
            if j: s += [("  Justification : ","key"),(f"{j[:350]}\n","normal")]
            for ind in llm.get("key_indicators",[])[:5]:
                s += [(f"    ▸ {ind}\n","warn")]
        meta = r.get("metadata",{})
        if meta:
            s += [("\n",None),("─"*70+"\n","sep"),("  METADATA\n","hdr"),("─"*70+"\n","sep")]
            for k2,v3 in list(meta.items())[:10]:
                if v3: s += [(f"  {str(k2):<18}: ","key"),(f"{str(v3)[:90]}\n","normal")]
        s += [("\n",None),("═"*70+"\n","sep")]
        return s

    def _fmt_log(res):
        rr = (res.get("routing_result") or {})
        r  = rr.get("result") or {}
        ev = res.get("index_envelope") or {}
        sv = r.get("final_severity","UNKNOWN")
        lb = r.get("final_label","UNKNOWN")
        ac = r.get("recommended_action","—")
        io = r.get("ioc","—")
        st = {"CRITICAL":"crit","HIGH":"high","MEDIUM":"med","LOW":"low"}.get(sv,"normal")
        s = [
            ("═"*70+"\n","sep"),("  LOG ANALYZER AGENT  —  REPORT\n","hdr"),("═"*70+"\n","sep"),
            ("  Serial   : ","key"),(f"{ev.get('serial_number','—')}\n","normal"),
            ("  Session  : ","key"),(f"{ev.get('session_id','—')}\n","normal"),
            ("  Campaign : ","key"),(f"{ev.get('campaign_tag','—')}\n","normal"),
            ("  Time     : ","key"),(f"{ev.get('timestamp_utc','—')}\n","normal"),
            ("\n",None),("─"*70+"\n","sep"),("  DETECTION RESULT\n","hdr"),("─"*70+"\n","sep"),
            ("  Final Label  : ","key"),(f"{lb}\n",st),
            ("  Severity     : ","key"),(f"{sv}\n",st),
            ("  Action       : ","key"),(f"{ac}\n","warn"),
            ("  IOC          : ","key"),(f"{io}\n","bad" if io!="—" else "muted"),
        ]
        nf = r.get("stage1_normalized_fields",{})
        if nf:
            s += [("\n",None),("─"*70+"\n","sep"),("  STAGE 1  —  NORMALISED FIELDS\n","hdr"),("─"*70+"\n","sep")]
            for k,v in list(nf.items())[:12]:
                if v and v!="N/A": s += [(f"  {str(k):<18}: ","key"),(f"{str(v)[:80]}\n","normal")]
        sg = r.get("stage2_signature",{})
        if sg:
            s += [("\n",None),("─"*70+"\n","sep"),("  STAGE 2  —  SIGNATURE DETECTION\n","hdr"),("─"*70+"\n","sep"),
                  ("  Label    : ","key"),(f"{sg.get('label','—')}\n",st),
                  ("  Severity : ","key"),(f"{sg.get('severity','—')}\n",st)]
        llm = r.get("stage3_llm",{})
        if llm:
            s += [("\n",None),("─"*70+"\n","sep"),("  STAGE 3  —  LLM ANALYSIS\n","hdr"),("─"*70+"\n","sep"),
                  ("  Attack Type : ","key"),(f"{llm.get('attack_type','—')}\n",st),
                  ("  Confidence  : ","key"),(f"{llm.get('confidence',0):.2f}\n","normal")]
        ex = r.get("explanation","")
        if ex:
            s += [("\n",None),("─"*70+"\n","sep"),("  EXPLANATION\n","hdr"),("─"*70+"\n","sep"),
                  (f"  {ex[:500]}\n","normal")]
        mi = r.get("mitigation","")
        if mi:
            s += [("\n",None),("─"*70+"\n","sep"),("  MITIGATION\n","hdr"),("─"*70+"\n","sep"),
                  (f"  {mi[:300]}\n","good")]
        s += [("\n",None),("═"*70+"\n","sep")]
        return s

    def _fmt_ip(res):
        rr = (res.get("routing_result") or {})
        r  = rr.get("result") or {}
        ev = res.get("index_envelope") or {}
        sm = r.get("summary",{})
        nc = sm.get("total_cves_found",0)
        nh = sm.get("total_hosts",0)
        cr = sm.get("critical_hosts",[])
        sv = sm.get("severity_counts",{})
        s = [
            ("═"*70+"\n","sep"),("  IP RANGE ANALYZER AGENT  —  REPORT\n","hdr"),("═"*70+"\n","sep"),
            ("  Serial   : ","key"),(f"{ev.get('serial_number','—')}\n","normal"),
            ("  Session  : ","key"),(f"{ev.get('session_id','—')}\n","normal"),
            ("  Campaign : ","key"),(f"{ev.get('campaign_tag','—')}\n","normal"),
            ("  Time     : ","key"),(f"{ev.get('timestamp_utc','—')}\n","normal"),
            ("\n",None),("─"*70+"\n","sep"),("  SCAN SUMMARY\n","hdr"),("─"*70+"\n","sep"),
            ("  Target Range   : ","key"),(f"{r.get('ip_range','—')}\n","ip"),
            ("  Hosts Found    : ","key"),(f"{nh}\n","normal"),
            ("  Total CVEs     : ","key"),(f"{nc}\n","crit" if nc>5 else "warn" if nc>0 else "good"),
            ("  Critical Hosts : ","key"),(f"{', '.join(cr) if cr else 'None'}\n","crit" if cr else "good"),
        ]
        if sv:
            s += [("\n  Severity breakdown:\n","key")]
            for k,v in sv.items():
                t = {"CRITICAL":"crit","HIGH":"high","MEDIUM":"med","LOW":"low"}.get(k,"normal")
                s += [(f"    {k:<12}: {v}\n",t)]
        hosts = r.get("host_details",{})
        if hosts:
            s += [("\n",None),("─"*70+"\n","sep"),("  HOST DETAILS\n","hdr"),("─"*70+"\n","sep")]
            for ip, info in list(hosts.items())[:6]:
                s += [(f"  {ip}\n","ip")]
                for svc in info.get("services",[])[:8]:
                    port = svc.get("port","?"); nm = svc.get("name","?")
                    cvs = svc.get("cves",[])
                    cv_s = ", ".join(c.get("id",c) if isinstance(c,dict) else str(c) for c in cvs[:3])
                    s += [(f"    {str(port):<7} {nm:<18}","key"),(f"CVEs: {cv_s or 'none'}\n","bad" if cvs else "muted")]
        llm = r.get("llm_analysis","")
        if llm and isinstance(llm,str) and len(llm)>10:
            s += [("\n",None),("─"*70+"\n","sep"),("  LLM RISK ANALYSIS\n","hdr"),("─"*70+"\n","sep"),
                  (f"{llm[:800]}\n","normal")]
        s += [("\n",None),("═"*70+"\n","sep")]
        return s

    def _fmt_corr(res):
        result = res.get("result")
        if not result: return [("No result\n","warn")]
        segs = []
        for line in result.pretty_print().split("\n"):
            if "═" in line or "─" in line: segs.append((line+"\n","sep"))
            elif "CRITICAL" in line: segs.append((line+"\n","crit"))
            elif "HIGH" in line and "Corr" not in line: segs.append((line+"\n","high"))
            elif "MEDIUM" in line: segs.append((line+"\n","med"))
            elif "YES" in line and "Corr" in line: segs.append((line+"\n","bad"))
            elif "NO " in line and "agent" in line: segs.append((line+"\n","good"))
            elif any(x in line for x in ["Confidence","Threat","Attack","Generated"]): segs.append((line+"\n","info"))
            elif any(x in line for x in ["NARRATIVE","RECOMMENDED","EVIDENCE","ENTITIES","FALSE"]): segs.append((line+"\n","hdr"))
            elif line.strip().startswith(("1.","2.","3.","4.","5.","6.","7.","8.","9.","•","▸")): segs.append((line+"\n","warn"))
            else: segs.append((line+"\n",None))
        return segs

    def _fmt_generic(res):
        segs = []
        for line in json.dumps(res, indent=2, default=str).split("\n"):
            if ":" in line:
                i = line.index(":")
                segs.append((line[:i+1],"key"))
                rest = line[i+1:]
                t = "bad" if any(w in rest.lower() for w in ["error","fail","critical"]) \
                    else "good" if any(w in rest.lower() for w in ["complete","safe","true"]) \
                    else "normal"
                segs.append((rest+"\n",t))
            else:
                segs.append((line+"\n","normal"))
        return segs

    def _show_result(res, box):
        tt = res.get("task_type","")
        fn = {TaskType.EMAIL:_fmt_email, TaskType.LOG:_fmt_log, TaskType.IP:_fmt_ip}.get(tt, _fmt_generic)
        _rich(box, fn(res))

    # ─────────────────────────────────────────────────────────────────────────
    # ██  WINDOW LAYOUT  ██
    # ─────────────────────────────────────────────────────────────────────────
    #
    #  ┌─────────────────────────────────────────────────────────────────────┐
    #  │  HEADER BAR                                                         │
    #  ├──────────────────────┬──────────────────────────────────────────────┤
    #  │  LEFT  (380px fixed) │  RIGHT  (expands)                            │
    #  │  ┌──────────────┐    │  ┌────────────────────────────────────────┐  │
    #  │  │ File Upload  │    │  │ Agent Result │ Correlation │ History   │  │
    #  │  │ Manual Input │    │  │                                        │  │
    #  │  └──────────────┘    │  └────────────────────────────────────────┘  │
    #  ├──────────────────────┴──────────────────────────────────────────────┤
    #  │  CONSOLE (4 lines)                                                  │
    #  └─────────────────────────────────────────────────────────────────────┘
    #
    # We use grid on root so proportions hold on resize.

    root.grid_rowconfigure(1, weight=1)
    root.grid_columnconfigure(0, weight=1)

    # ── HEADER FRAME — two rows so nothing clips on narrow windows ──────────
    hdr = tk.Frame(root, bg=C["panel"])
    hdr.grid(row=0, column=0, sticky="ew")
    _divider(hdr).pack(side="bottom", fill="x")

    # Row 1: title only
    hdr_row1 = tk.Frame(hdr, bg=C["panel"], pady=8, padx=16)
    hdr_row1.pack(fill="x")
    tk.Label(hdr_row1, text="Multi-Agent Cybersecurity System",
             bg=C["panel"], fg=C["cyan"], font=FONT_TITLE).pack(side="left")

    # Thin divider between row1 and row2 (child of hdr, not hdr_row2)
    _divider(hdr).pack(fill="x")

    # Row 2: full-width API key bar — pure grid, no pack children
    hdr_row2 = tk.Frame(hdr, bg=C["panel2"], pady=7, padx=12)
    hdr_row2.pack(fill="x")
    hdr_row2.columnconfigure(1, weight=1)   # key entry expands

    _lbl(hdr_row2, "Groq API Key(s):", fg=C["muted"], bg=C["panel2"],
         font=FONT_SMALL).grid(row=0, column=0, sticky="w", padx=(0, 6))

    # ── Primary key entry ────────────────────────────────────────────────────
    api_var = tk.StringVar(value=initial_key)
    api_e = _entry(hdr_row2, var=api_var, show="*")
    api_e.grid(row=0, column=1, sticky="ew", padx=(0, 6))

    def _toggle_vis():
        cur = api_e.cget("show")
        api_e.config(show="" if cur == "*" else "*")
        _show_key_btn.config(text="Hide" if cur == "*" else "Show")
    _show_key_btn = _btn(hdr_row2, "Show", _toggle_vis, C["border"], padx=10, pady=3)
    _show_key_btn.grid(row=0, column=2, padx=(0, 6))

    # ── "+ More Keys" toggle ────────────────────────────────────────────────
    _extra_keys_visible = [False]
    _extra_key_frame    = [None]

    def _toggle_extra_keys():
        if _extra_keys_visible[0]:
            _extra_key_frame[0].grid_remove()
            _extra_keys_visible[0] = False
            _more_keys_btn.config(text="+ More Keys")
        else:
            _extra_key_frame[0].grid()
            _extra_keys_visible[0] = True
            _more_keys_btn.config(text="− Hide Keys")

    _more_keys_btn = _btn(hdr_row2, "+ More Keys", _toggle_extra_keys,
                          C["border"], padx=8, pady=3)
    _more_keys_btn.grid(row=0, column=3, padx=(0, 6))

    def _connect():
        # Gather all non-empty keys (primary + extras)
        keys = [api_var.get().strip()]
        if _extra_key_frame[0]:
            for ev in _extra_key_vars:
                v = ev.get().strip()
                if v:
                    keys.append(v)
        keys = [k for k in keys if k]

        invalid = [k for k in keys if not k.startswith("gsk_")]
        if invalid:
            messagebox.showerror("Invalid Key",
                f"{len(invalid)} key(s) don't start with 'gsk_'.\n"
                "Please check your entries.")
            return

        def _init():
            try:
                if len(keys) >= 2:
                    disp = TaskDispatcherAgent(api_keys=keys)
                    _label = f"Multi-key ({len(keys)} keys, auto-rotation ON)"
                else:
                    disp = TaskDispatcherAgent(groq_api_key=keys[0])
                    _label = "Single key"
                dispatcher[0] = disp
                sid = dispatcher[0].session_id
                root.after(0, lambda: status_dot.config(
                    text=f"● Connected  ·  {_label}  ·  Session: {sid}",
                    fg=C["green"]))
                _console(f"Connected [{_label}] · Session: {sid}")
            except Exception as ex:
                root.after(0, lambda: messagebox.showerror("Error", str(ex)))
        _run_bg(_init)

    _btn(hdr_row2, "Connect", _connect, C["accent"], padx=14, pady=3).grid(
        row=0, column=4, padx=(0, 12))

    status_dot = tk.Label(hdr_row2, text="● Not connected",
                          bg=C["panel2"], fg=C["red"], font=FONT_SANS_B)
    status_dot.grid(row=0, column=5, sticky="e", padx=(0, 4))

    # ── Extra key entries (row 1–8, hidden by default) ───────────────────────
    _extra_key_vars  = []
    _extra_key_frame[0] = tk.Frame(hdr_row2, bg=C["panel2"])
    _extra_key_frame[0].grid(row=1, column=0, columnspan=6, sticky="ew",
                              pady=(4, 0))
    _extra_key_frame[0].grid_remove()   # hidden until toggled

    tk.Label(_extra_key_frame[0],
             text="Add up to 8 extra keys (auto-rotated on rate limit 429):",
             bg=C["panel2"], fg=C["muted"], font=FONT_SMALL
             ).grid(row=0, column=0, columnspan=4, sticky="w", pady=(0, 3))

    for _i in range(8):   # slots 2–9
        _ev = tk.StringVar()
        _extra_key_vars.append(_ev)
        tk.Label(_extra_key_frame[0], text=f"Key {_i+2}:",
                 bg=C["panel2"], fg=C["muted"], font=FONT_SMALL,
                 width=6, anchor="e"
                 ).grid(row=_i+1, column=0, sticky="e", padx=(0, 4))
        _entry(_extra_key_frame[0], var=_ev, show="*").grid(
            row=_i+1, column=1, sticky="ew", padx=(0, 6), pady=2)
    _extra_key_frame[0].columnconfigure(1, weight=1)

    # ── BODY FRAME (left + right) ─────────────────────────────────────────────
    body = tk.Frame(root, bg=C["bg"])
    body.grid(row=1, column=0, sticky="nsew", padx=8, pady=(6, 4))
    body.grid_rowconfigure(0, weight=1)
    body.grid_columnconfigure(1, weight=1)

    # ─────────────────────────────────────────────────────────────────────────
    # LEFT PANEL  (380 px, scrollable via canvas)
    # We use a Canvas + inner frame so content never gets clipped
    # ─────────────────────────────────────────────────────────────────────────
    left_outer = tk.Frame(body, bg=C["panel"], width=390,
                          highlightthickness=1, highlightbackground=C["border"])
    left_outer.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
    left_outer.grid_propagate(False)

    left_canvas = tk.Canvas(left_outer, bg=C["panel"], bd=0,
                             highlightthickness=0, width=370)
    left_scroll  = ttk.Scrollbar(left_outer, orient="vertical",
                                  command=left_canvas.yview)
    left_canvas.configure(yscrollcommand=left_scroll.set)
    left_scroll.pack(side="right", fill="y")
    left_canvas.pack(side="left", fill="both", expand=True)

    inner = tk.Frame(left_canvas, bg=C["panel"])
    _win = left_canvas.create_window((0, 0), window=inner, anchor="nw")

    def _on_inner_configure(e):
        left_canvas.configure(scrollregion=left_canvas.bbox("all"))
    def _on_canvas_configure(e):
        left_canvas.itemconfig(_win, width=e.width)
    inner.bind("<Configure>",       _on_inner_configure)
    left_canvas.bind("<Configure>", _on_canvas_configure)

    def _on_mousewheel(e):
        left_canvas.yview_scroll(int(-1*(e.delta/120)), "units")
    left_canvas.bind_all("<MouseWheel>", _on_mousewheel)

    # ── Left section header helper ─────────────────────────────────────────────
    def _sec(title):
        f = tk.Frame(inner, bg=C["panel2"], pady=0)
        f.pack(fill="x", padx=8, pady=(0, 6))
        hf = tk.Frame(f, bg=C["border"], height=1)
        hf.pack(fill="x")
        tk.Label(f, text=f"  {title}",
                 bg=C["panel2"], fg=C["cyan"],
                 font=FONT_SANS_B, pady=6, padx=4,
                 anchor="w").pack(fill="x")
        body_f = tk.Frame(f, bg=C["panel2"], padx=8, pady=6)
        body_f.pack(fill="x")
        return body_f

    # ── SECTION: API Status pill ──────────────────────────────────────────────
    pad_top = tk.Frame(inner, bg=C["panel"], height=8)
    pad_top.pack(fill="x")

    # ── SECTION: File Upload ──────────────────────────────────────────────────
    sf = _sec("1 · Select File")

    file_var = tk.StringVar()
    frow = tk.Frame(sf, bg=C["panel2"])
    frow.pack(fill="x", pady=(0, 4))
    file_e = _entry(frow, width=22, var=file_var, font=FONT_SMALL)
    file_e.pack(side="left", fill="x", expand=True, padx=(0, 4))

    _current_raw   = [""]
    _current_fmt   = ["text"]
    _current_struc = [None]

    def _on_file(path):
        raw, fmt, structured, err = parse_file_content(path)
        _current_raw[0]   = raw
        _current_fmt[0]   = fmt
        _current_struc[0] = structured
        sz     = Path(path).stat().st_size
        nlines = raw.count("\n")
        root.after(0, lambda: _file_info.config(
            text=f"Format: {fmt.upper()}  ·  {sz:,} B  ·  {nlines:,} lines",
            fg=C["cyan"]))
        root.after(0, lambda: _set_prev("\n".join(raw.split("\n")[:60])))
        if dispatcher[0]:
            scores = _score_content(raw, fmt, structured)
            best   = max(scores, key=scores.get)
            root.after(0, lambda: _cls_lbl.config(
                text=f"Auto-detected: {best}  (score={scores[best]})",
                fg=C["cyan"] if scores[best]>=15 else C["yellow"]))
        if err: _console(f"Parse warn: {err}")
        _console(f"Loaded: {Path(path).name}")

    def _browse():
        p = filedialog.askopenfilename(
            title="Select security data file",
            filetypes=[("All Supported","*.txt *.log *.eml *.json *.csv"),
                       ("Text","*.txt"),("Log","*.log"),("Email","*.eml"),
                       ("JSON","*.json"),("CSV","*.csv"),("All","*.*")])
        if p: file_var.set(p); _on_file(p)

    def _clear():
        file_var.set(""); _current_raw[0] = ""
        _file_info.config(text="No file loaded", fg=C["muted"])
        _cls_lbl.config(text="Classifier: waiting...", fg=C["muted"])
        _set_prev("")
        _write(res_box, "Waiting for analysis...\n\nUpload a file or paste text,\nthen click Dispatch & Analyze.")
        _verdict_var.set("—"); _verdict_lbl.config(fg=C["muted"])

    btn_row = tk.Frame(sf, bg=C["panel2"])
    btn_row.pack(fill="x", pady=(0, 4))
    _btn(btn_row, "Browse…", _browse, C["accent"], padx=10, pady=4).pack(side="left", padx=(0, 4))
    _btn(btn_row, "Clear",   _clear,  C["border"], padx=10, pady=4).pack(side="left")

    _file_info = _lbl(sf, "No file loaded", fg=C["muted"], bg=C["panel2"], font=FONT_SMALL)
    _file_info.pack(anchor="w")

    # ── SECTION: Classification ───────────────────────────────────────────────
    sc = _sec("2 · Classification")
    _cls_lbl = _lbl(sc, "Classifier: waiting...", fg=C["muted"], bg=C["panel2"], font=FONT_SMALL)
    _cls_lbl.pack(anchor="w", pady=(0, 4))

    override_var = tk.StringVar(value="Auto")
    cls_row = tk.Frame(sc, bg=C["panel2"])
    cls_row.pack(fill="x")
    _lbl(cls_row, "Override:", fg=C["muted"], bg=C["panel2"], font=FONT_SMALL).pack(side="left", padx=(0, 4))
    ovr_cb = ttk.Combobox(cls_row, textvariable=override_var, state="readonly",
                           values=["Auto", "EMAIL", "IP", "LOG"], width=10)
    ovr_cb.pack(side="left")

    # ── SECTION: Campaign Tag ─────────────────────────────────────────────────
    stag = _sec("3 · Campaign Tag  (optional)")
    camp_e = _entry(stag, width=30, font=FONT_SMALL)
    camp_e.insert(0, "SOC-INCIDENT-2025")
    camp_e.pack(fill="x")

    # ── SECTION: File Preview ─────────────────────────────────────────────────
    sprev = _sec("4 · File Preview")
    prev_box = scrolledtext.ScrolledText(
        sprev, height=8, bg=C["input"], fg=C["muted"],
        font=FONT_MONO_S, relief="flat", state="disabled", wrap="word", padx=6, pady=4)
    prev_box.pack(fill="x")

    def _set_prev(text):
        prev_box.config(state="normal")
        prev_box.delete("1.0","end")
        prev_box.insert("1.0", text)
        prev_box.config(state="disabled")

    # ── DISPATCH BUTTON ───────────────────────────────────────────────────────
    disp_f = tk.Frame(inner, bg=C["panel"], padx=8, pady=6)
    disp_f.pack(fill="x")

    disp_btn = _btn(disp_f, "▶   Dispatch & Analyze", None, C["green"], pady=10)
    disp_btn.pack(fill="x")

    def _do_dispatch():
        if not _need_disp(): return
        path = file_var.get().strip()
        if not path: messagebox.showwarning("No File","Select a file first."); return
        if not Path(path).exists(): messagebox.showerror("Not Found",f"Cannot find:\n{path}"); return
        tag = camp_e.get().strip() or None
        ov  = None if override_var.get()=="Auto" else override_var.get()
        _console(f"Dispatching: {Path(path).name} …")
        root.after(0, lambda: _verdict_var.set("Analyzing…"))
        root.after(0, lambda: _verdict_lbl.config(fg=C["yellow"]))
        _write(res_box, "Running analysis…\nPlease wait.\n")
        right_nb.select(0)

        def _worker():
            res = dispatcher[0].dispatch_file(path, campaign_tag=tag, override_type=ov)
            _last_res[0] = res
            _show_result(res, res_box)
            _update_verdict(res)
            _refresh_hist()
            env = res.get("index_envelope",{})
            _console(f"Done — {env.get('routing_status','?')}  serial={env.get('serial_number','')}")
        _run_bg(_worker)

    disp_btn.config(command=_do_dispatch)

    # ── SECTION: Manual Input ─────────────────────────────────────────────────
    sman = _sec("5 · Manual Input  (paste text)")

    man_box = scrolledtext.ScrolledText(
        sman, height=9, bg=C["input"], fg=C["text"],
        font=FONT_MONO_S, relief="flat", wrap="word",
        insertbackground=C["cyan"], padx=6, pady=4)
    man_box.pack(fill="x", pady=(0, 4))

    samp_row = tk.Frame(sman, bg=C["panel2"])
    samp_row.pack(anchor="w", pady=(0, 4))
    _lbl(samp_row, "Samples:", fg=C["muted"], bg=C["panel2"], font=FONT_SMALL).pack(side="left", padx=(0,4))
    _SEMAIL = "From: security-alert@paypa1.com\nSubject: Urgent: Verify your account immediately\n\nDear Customer, your account has been locked.\nVerify at: http://paypa1-secure.net/login?token=abc123"
    _SIP    = "target=192.168.56.0/24\nPort 22 open ssh\nPort 80 open http\nPort 3306 open mysql"
    _SLOG   = "Apr 06 14:22:01 srv01 sshd[1234]: Failed password for root from 192.168.56.103 port 54321 ssh2\nApr 06 14:22:04 srv01 sshd[1235]: Failed password for root from 192.168.56.103 port 54322 ssh2"
    def _load(t): man_box.delete("1.0","end"); man_box.insert("1.0",t)
    _btn(samp_row,"Email", lambda:_load(_SEMAIL), C["border"], padx=8, pady=3).pack(side="left",padx=2)
    _btn(samp_row,"IP",    lambda:_load(_SIP),    C["border"], padx=8, pady=3).pack(side="left",padx=2)
    _btn(samp_row,"Log",   lambda:_load(_SLOG),   C["border"], padx=8, pady=3).pack(side="left",padx=2)

    man_ctrl = tk.Frame(sman, bg=C["panel2"])
    man_ctrl.pack(fill="x", pady=(0, 4))
    _lbl(man_ctrl,"Force:", fg=C["muted"],bg=C["panel2"],font=FONT_SMALL).pack(side="left",padx=(0,4))
    man_ov = tk.StringVar(value="Auto")
    ttk.Combobox(man_ctrl, textvariable=man_ov, state="readonly",
                 values=["Auto","EMAIL","IP","LOG"], width=8).pack(side="left",padx=(0,8))
    _lbl(man_ctrl,"Campaign:",fg=C["muted"],bg=C["panel2"],font=FONT_SMALL).pack(side="left",padx=(0,4))
    man_camp = _entry(man_ctrl, width=14, font=FONT_SMALL)
    man_camp.insert(0,"MANUAL")
    man_camp.pack(side="left")

    def _do_manual():
        if not _need_disp(): return
        raw = man_box.get("1.0","end").strip()
        if not raw: messagebox.showwarning("Empty","Paste content first."); return
        _console("Manual dispatch …")
        _write(res_box,"Running analysis…\nPlease wait.\n")
        right_nb.select(0)

        def _worker():
            fmt, structured = "text", None
            try: structured = json.loads(raw); fmt = "json"
            except Exception: pass
            ov2 = man_ov.get()
            if ov2 in ("EMAIL","IP","LOG"): resolved,method,scores = ov2,"override",{}
            else: resolved,method,scores = classify_content(raw,fmt,structured,dispatcher[0].groq_client)
            if resolved == TaskType.UNKNOWN:
                _write(res_box,"Could not classify. Try forcing a type."); return
            res = dispatcher[0].dispatch(
                _PAYLOAD_BUILDERS[resolved](raw,fmt,structured),
                task_type=resolved, campaign_tag=man_camp.get().strip() or None)
            _last_res[0] = res
            _show_result(res, res_box)
            _update_verdict(res)
            _refresh_hist()
            env = res.get("index_envelope",{})
            _console(f"Manual done — {env.get('routing_status','?')}")
        _run_bg(_worker)

    _btn(sman, "▶   Dispatch Manual Input", _do_manual, C["accent"], pady=8).pack(fill="x")

    # bottom padding
    tk.Frame(inner, bg=C["panel"], height=12).pack(fill="x")

    # ─────────────────────────────────────────────────────────────────────────
    # RIGHT PANEL
    # ─────────────────────────────────────────────────────────────────────────
    right_panel = tk.Frame(body, bg=C["bg"])
    right_panel.grid(row=0, column=1, sticky="nsew")
    right_panel.grid_rowconfigure(1, weight=1)
    right_panel.grid_columnconfigure(0, weight=1)

    # ── Verdict bar (always visible at top of right panel) ────────────────────
    vbar = tk.Frame(right_panel, bg=C["panel"], pady=7, padx=12)
    vbar.grid(row=0, column=0, sticky="ew")
    _divider(vbar).pack(side="bottom", fill="x")

    _lbl(vbar, "Verdict:", fg=C["muted"], bg=C["panel"]).pack(side="left")
    _verdict_var = tk.StringVar(value="—")
    _verdict_lbl = tk.Label(vbar, textvariable=_verdict_var,
                            bg=C["panel"], fg=C["muted"], font=FONT_BADGE)
    _verdict_lbl.pack(side="left", padx=(8, 20))

    # Type badge
    _type_var = tk.StringVar(value="")
    _type_lbl = tk.Label(vbar, textvariable=_type_var,
                         bg=C["border"], fg=C["text"],
                         font=FONT_SMALL, padx=8, pady=2, relief="flat")
    _type_lbl.pack(side="left", padx=(0, 12))

    # Buttons right
    def _copy_json():
        if _last_res[0]:
            root.clipboard_clear()
            root.clipboard_append(json.dumps(_last_res[0], indent=2, default=str))
            _console("Result JSON copied.")
    def _save_txt():
        if not _last_res[0]: return
        p = filedialog.asksaveasfilename(defaultextension=".txt",
                                          filetypes=[("Text","*.txt"),("JSON","*.json"),("All","*.*")])
        if p:
            with open(p,"w",encoding="utf-8") as fh:
                fh.write(json.dumps(_last_res[0],indent=2,default=str))
            _console(f"Saved to {p}")

    _btn(vbar,"Copy JSON", _copy_json, C["border"], padx=10, pady=4).pack(side="right", padx=4)
    _btn(vbar,"Save .txt",  _save_txt,  C["border"], padx=10, pady=4).pack(side="right", padx=4)

    def _update_verdict(res):
        _last_res[0] = res
        ev = res.get("index_envelope",{})
        tt = res.get("task_type","")
        rr = (res.get("routing_result") or {})
        r  = rr.get("result") or {}
        st = ev.get("routing_status","?")

        if tt == TaskType.EMAIL:
            v  = r.get("risk_verdict",st)
            sc = r.get("risk_score",0)
            cl = {"PHISHING":C["red"],"SUSPICIOUS":C["yellow"],"SAFE":C["green"]}.get(v,C["text"])
            tx = f"{v}  ({sc*100:.0f}%)"
            root.after(0, lambda: _type_var.set(" EMAIL "))
        elif tt == TaskType.LOG:
            sv = r.get("final_severity",st)
            lb = r.get("final_label",st)
            cl = {"CRITICAL":C["red"],"HIGH":C["orange"],"MEDIUM":C["yellow"],"LOW":C["green"]}.get(sv,C["text"])
            tx = f"{lb}  [{sv}]"
            root.after(0, lambda: _type_var.set(" LOG "))
        elif tt == TaskType.IP:
            nc = (r.get("summary") or {}).get("total_cves_found",0)
            cl = C["red"] if nc>5 else C["yellow"] if nc>0 else C["green"]
            tx = f"{nc} CVEs found  ·  {st}"
            root.after(0, lambda: _type_var.set(" IP SCAN "))
        else:
            cl = C["red"] if st!="COMPLETED" else C["green"]
            tx = st
            root.after(0, lambda: _type_var.set(" UNKNOWN "))

        root.after(0, lambda: _verdict_var.set(tx))
        root.after(0, lambda: _verdict_lbl.config(fg=cl))

    # ── Right Notebook ─────────────────────────────────────────────────────────
    style = ttk.Style()
    style.theme_use("default")
    for nm in ("R.TNotebook","L.TNotebook"):
        style.configure(nm, background=C["bg"], borderwidth=0)
        style.configure(nm+".Tab", background=C["border"], foreground=C["muted"],
                        padding=[14, 6], font=FONT_SANS_B)
        style.map(nm+".Tab",
                  background=[("selected",C["accent"])],
                  foreground=[("selected","#ffffff")])

    right_nb = ttk.Notebook(right_panel, style="R.TNotebook")
    right_nb.grid(row=1, column=0, sticky="nsew")

    # ── Right Tab 1: Agent Result ──────────────────────────────────────────────
    tab_res = tk.Frame(right_nb, bg=C["bg"])
    right_nb.add(tab_res, text="  Agent Result  ")

    res_box = _outbox(tab_res, height=32)
    res_box.pack(fill="both", expand=True, padx=6, pady=6)
    _write(res_box, "Waiting for analysis...\n\nUpload a file or paste text on the left,\nthen click Dispatch & Analyze.")

    # ── Right Tab 2: Correlation ───────────────────────────────────────────────
    tab_corr = tk.Frame(right_nb, bg=C["bg"])
    right_nb.add(tab_corr, text="  Correlation Agent  ")

    corr_top = tk.Frame(tab_corr, bg=C["panel"], pady=7, padx=12)
    corr_top.pack(fill="x")
    _divider(corr_top).pack(side="bottom", fill="x")

    _corr_info = tk.Label(corr_top, text="Run at least one agent first, then click Correlate.",
                          bg=C["panel"], fg=C["yellow"], font=FONT_SANS_B)
    _corr_info.pack(side="left")

    def _upd_corr_info():
        if not dispatcher[0]: return
        with _SESSION_LOCK:
            all_r = _SESSION_ROUTING_RESULTS.get(dispatcher[0].session_id,[])
        n    = len(all_r)
        done = sum(1 for x in all_r if x.get("status")=="COMPLETED")
        root.after(0, lambda: _corr_info.config(
            text=f"Session: {n} results queued  ·  {done} completed",
            fg=C["green"] if done>=2 else C["yellow"]))

    corr_btn_row = tk.Frame(tab_corr, bg=C["bg"], pady=4, padx=6)
    corr_btn_row.pack(fill="x")

    corr_out = _outbox(tab_corr, height=30, base_fg=C["cyan"])
    corr_out.pack(fill="both", expand=True, padx=6, pady=(0,6))

    def _do_corr():
        if not _need_disp(): return
        _upd_corr_info()
        _console("Running Correlation Agent…")
        _write(corr_out, "Running correlation analysis…\nPlease wait.\n")
        def _worker():
            res = dispatcher[0].run_correlation()
            if "error" in res:
                _write(corr_out, f"ERROR: {res['error']}\n")
                _console(f"Corr error: {res['error']}"); return
            _rich(corr_out, _fmt_corr(res))
            r2 = res["result"]
            _console(f"Corr done: {r2.correlation_level}  conf={r2.confidence:.0%}  id={r2.report_id}")
        _run_bg(_worker)

    _btn(corr_btn_row,"Run Correlation Agent", _do_corr, C["accent"], pady=5).pack(side="left",padx=4)
    _btn(corr_btn_row,"Refresh Count", lambda:_run_bg(_upd_corr_info), C["border"], pady=5).pack(side="left",padx=4)
    _btn(corr_btn_row,"Clear Output",  lambda:_write(corr_out,""),      C["border"], pady=5).pack(side="left",padx=4)

    # ── Right Tab 3: History ───────────────────────────────────────────────────
    tab_hist = tk.Frame(right_nb, bg=C["bg"])
    right_nb.add(tab_hist, text="  Dispatch History  ")

    hist_btn_row = tk.Frame(tab_hist, bg=C["bg"], pady=4, padx=6)
    hist_btn_row.pack(fill="x")

    hist_out = _outbox(tab_hist, height=30)
    hist_out.pack(fill="both", expand=True, padx=6, pady=(0,6))

    def _refresh_hist():
        summary = INDEX_REGISTRY.summary()
        segs = [("═"*70+"\n","sep"),("  DISPATCH HISTORY\n","hdr"),("═"*70+"\n","sep")]
        if dispatcher[0]:
            segs += [(f"  Session: {dispatcher[0].session_id}\n","info"),("\n",None)]
        if not summary:
            segs += [("  (no tasks dispatched yet)\n","muted")]
        else:
            for tt2, entries in summary.items():
                segs += [(f"  [{tt2}]  {len(entries)} task(s)\n","hdr"),
                         (f"  {'Serial':<30} {'Status':<12} {'Campaign':<22} Source\n","key"),
                         ("  "+"─"*70+"\n","sep")]
                for e in entries:
                    stag2 = "good" if e["status"]=="COMPLETED" else "bad" if e["status"]=="ERROR" else "warn"
                    segs += [(f"  {e['serial']:<30}","key"),
                             (f"{e['status']:<12}",stag2),
                             (f"{e['campaign']:<22} {str(e.get('source','manual'))}\n","normal")]
                segs += [("\n",None)]
        _rich(hist_out, segs)

    def _copy_hist():
        root.clipboard_clear()
        root.clipboard_append(json.dumps(INDEX_REGISTRY.summary(), indent=2))
        _console("History copied.")

    def _clear_hist():
        INDEX_REGISTRY._store.clear(); INDEX_REGISTRY._counters.clear()
        _refresh_hist(); _console("History cleared.")

    _btn(hist_btn_row,"Refresh",  _refresh_hist, C["accent"], pady=5).pack(side="left",padx=4)
    _btn(hist_btn_row,"Copy JSON",_copy_hist,    C["border"], pady=5).pack(side="left",padx=4)
    _btn(hist_btn_row,"Clear All",_clear_hist,   C["red"],    pady=5).pack(side="left",padx=4)

    # ─────────────────────────────────────────────────────────────────────────
    # CONSOLE (bottom of root)
    # ─────────────────────────────────────────────────────────────────────────
    con_frame = tk.Frame(root, bg=C["bg"])
    con_frame.grid(row=2, column=0, sticky="ew", padx=8, pady=(0,6))
    _divider(con_frame, C["border"]).pack(fill="x", pady=(0,4))

    ch = tk.Frame(con_frame, bg=C["bg"])
    ch.pack(fill="x")
    _lbl(ch, "Console", fg=C["dim"], bg=C["bg"], font=FONT_SMALL).pack(side="left")
    _btn(ch,"Clear",lambda:_write(con,""),C["border"],padx=8,pady=2).pack(side="right")

    con = scrolledtext.ScrolledText(
        con_frame, height=4, bg=C["codebg"], fg=C["muted"],
        font=FONT_MONO_S, state="disabled", wrap="word", relief="flat",
        padx=8, pady=4, selectbackground=C["accent"])
    con.pack(fill="x")

    root.grid_rowconfigure(2, weight=0)
    _console("GUI ready · Enter your Groq API key and click Connect.")
    root.mainloop()



# ══════════════════════════════════════════════════════════════════════════════
# CLI SELF-TEST
# ══════════════════════════════════════════════════════════════════════════════

def cli_selftest(api_key: str):
    print("\n" + "=" * 64)
    print("  TASK DISPATCHER — CLI Self-Test")
    print("=" * 64)

    d = TaskDispatcherAgent(groq_api_key=api_key)

    print("\n[TEST 1] Phishing email (dict payload)")
    r1 = d.dispatch({
        "sender":        "security-alert@paypa1.com",
        "subject":       "Urgent: Verify your account immediately",
        "email_content": (
            "Dear Customer, your account has been locked. "
            "Please verify your details at http://paypa1-secure.net/login"
        ),
        "headers": {"X-Mailer": "PhishKit 3.2", "Reply-To": "harvest@evil.ru"},
    }, campaign_tag="CLI-TEST")
    print(f"  Serial : {r1['index_envelope']['serial_number']}")
    print(f"  Status : {r1['index_envelope']['routing_status']}")

    print("\n[TEST 2] IP scan")
    r2 = d.dispatch(
        {"target": "192.168.56.103"},
        task_type="IP", campaign_tag="CLI-TEST",
    )
    print(f"  Serial : {r2['index_envelope']['serial_number']}")
    print(f"  Status : {r2['index_envelope']['routing_status']}")

    print("\n[TEST 3] Log analysis")
    r3 = d.dispatch({
        "log_content": (
            "Apr 06 14:22:01 srv01 sshd[1234]: Failed password for root "
            "from 192.168.56.103 port 54321 ssh2\n"
            "Apr 06 14:22:15 srv01 sudo:  root ran /bin/bash"
        )
    }, campaign_tag="CLI-TEST")
    print(f"  Serial : {r3['index_envelope']['serial_number']}")
    print(f"  Status : {r3['index_envelope']['routing_status']}")

    print("\n[TEST 4] Content classifier (EVE JSON string)")
    eve_sample = json.dumps({
        "timestamp": "2024-01-01T00:00:00Z",
        "event_type": "alert",
        "src_ip": "192.168.1.100",
        "dest_ip": "10.0.0.1",
        "alert": {"signature": "ET SCAN Nmap", "severity": 2}
    })
    task, method, scores = classify_content(eve_sample, "json",
                                             json.loads(eve_sample))
    print(f"  Classified as : {task}  (method={method})")
    print(f"  Scores        : {scores}")

    d.index_report()


# ══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SOC Task Dispatcher Agent")
    parser.add_argument("--api-key", default=DEFAULT_GROQ_KEY)
    parser.add_argument("--cli", action="store_true",
                        help="Run CLI self-test instead of GUI")
    args = parser.parse_args()

    if args.cli:
        cli_selftest(args.api_key)
    else:
        launch_gui(initial_key=args.api_key)