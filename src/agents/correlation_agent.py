#!/usr/bin/env python3
"""
=============================================================================
 CORRELATION AGENT  —  Contextual Recommendation System
=============================================================================
 Paper: "A Multi-Agent System for Cybersecurity Threat Detection and
         Correlation using Large Language Models"
         IEEE Access, DOI: 10.1109/ACCESS.2025.3602681  —  Section III-E

 MEMORY: Simple JSON files on disk (no SQLite, no database)
   memory/results/   — one JSON file per correlation result
   memory/entities/  — one JSON file per tracked entity (IOC)
   memory/index.json — lightweight index for fast lookup

 PAPER PIPELINE (Section III-E verbatim):
   Step 1  Receive & normalize agent reports
   Step 2  Entity extraction via RegEx (IPs, domains, CVEs, URLs, users)
   Step 3  Cross-agent entity matching
   Step 4  Temporal correlation
   Step 5  Confidence scoring
   Step 6  LLM narrative (LLaMA 3.3-70B via Groq, Chain-of-Thought)
   Step 7  Build CorrelationResult
   Step 8  Persist to filesystem memory
=============================================================================
"""

import re
import os
import json
import time
import logging
import hashlib
import ipaddress
from datetime import datetime, timezone, timedelta
from typing import Optional
from pathlib import Path

try:
    from groq import Groq
    _GROQ_AVAILABLE = True
except ImportError:
    _GROQ_AVAILABLE = False

# ── Key rotation manager (optional — graceful if not found) ───────────────
try:
    from key_manager import KeyManager, build_key_manager
    _KEY_MANAGER_AVAILABLE = True
except ImportError:
    _KEY_MANAGER_AVAILABLE = False

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [CORR] %(levelname)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("CorrelationAgent")


# ═══════════════════════════════════════════════════════════════════════════
# DATA STRUCTURES
# ═══════════════════════════════════════════════════════════════════════════

class AgentReport:
    """Standard contract: every domain agent produces one of these."""

    def __init__(self, agent_name: str, risk_score: float, verdict: str,
                 indicators: dict, raw_summary: str, timestamp: Optional[str] = None):
        self.agent_name  = agent_name
        self.risk_score  = float(min(max(risk_score, 0.0), 10.0))
        self.verdict     = verdict
        self.indicators  = indicators if isinstance(indicators, dict) else {}
        self.raw_summary = str(raw_summary)
        self.timestamp   = timestamp or datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        return {
            "agent_name":  self.agent_name,
            "risk_score":  self.risk_score,
            "verdict":     self.verdict,
            "indicators":  self.indicators,
            "raw_summary": self.raw_summary,
            "timestamp":   self.timestamp,
        }


class CorrelationResult:
    """Final output from the Contextual Recommendation System."""

    def __init__(self, correlated, confidence, correlation_level,
                 matched_entities, temporal_overlap, temporal_window_secs,
                 narrative, recommendations, involved_agents, threat_type,
                 attack_vector, evidence_traces, entity_map,
                 false_positive_indicators):
        self.correlated               = correlated
        self.confidence               = round(float(confidence), 4)
        self.correlation_level        = correlation_level
        self.matched_entities         = matched_entities
        self.temporal_overlap         = temporal_overlap
        self.temporal_window_secs     = temporal_window_secs
        self.narrative                = narrative
        self.recommendations          = recommendations
        self.involved_agents          = involved_agents
        self.threat_type              = threat_type
        self.attack_vector            = attack_vector
        self.evidence_traces          = evidence_traces
        self.entity_map               = entity_map
        self.false_positive_indicators = false_positive_indicators
        self.generated_at             = datetime.now(timezone.utc).isoformat()
        self.report_id                = hashlib.sha1(
            (self.generated_at + threat_type).encode()
        ).hexdigest()[:12]

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items()}

    def pretty_print(self) -> str:
        sep  = "═" * 76
        sep2 = "─" * 76
        icons = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "NONE": "⚪"}
        icon  = icons.get(self.correlation_level, "❓")
        lines = [
            sep,
            f"  CONTEXTUAL RECOMMENDATION SYSTEM — REPORT [{self.report_id}]",
            sep,
            f"  Generated        : {self.generated_at}",
            f"  Correlated       : {'YES ⚠  MULTI-DOMAIN THREAT' if self.correlated else 'NO — agents isolated'}",
            f"  {icon} Level      : {self.correlation_level}",
            f"  Confidence       : {self.confidence:.1%}",
            f"  Threat Type      : {self.threat_type}",
            f"  Attack Vector    : {self.attack_vector}",
            f"  Agents           : {', '.join(self.involved_agents)}",
            f"  Temporal Overlap : {'YES (' + str(self.temporal_window_secs) + 's window)' if self.temporal_overlap else 'NO'}",
            "",
            sep2 + " NARRATIVE",
            self.narrative,
            "",
        ]
        if self.matched_entities:
            lines.append(sep2 + " CORRELATED ENTITIES")
            for e in self.matched_entities:
                lines.append(f"  [{e['type'].upper():10s}] {e['value']:40s} "
                             f"seen_in={e['seen_in']}  freq={e['frequency']}")
            lines.append("")
        if self.false_positive_indicators:
            lines.append(sep2 + " FALSE POSITIVE WARNINGS")
            for fp in self.false_positive_indicators:
                lines.append(f"  • {fp}")
            lines.append("")
        if self.recommendations:
            lines.append(sep2 + " RECOMMENDED ACTIONS")
            for i, r in enumerate(self.recommendations, 1):
                lines.append(f"  {i:2d}. {r}")
            lines.append("")
        lines.append(sep2 + " EVIDENCE TRACES")
        for t in self.evidence_traces:
            lines.append(f"  [{t['agent']:28s}] verdict={t['verdict']:30s} risk={t['risk_score']:.1f}/10")
        lines.append("")
        lines.append(sep)
        return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════
# ENTITY EXTRACTOR
# Paper: "search for matches using regular expressions to detect common
#  entities such as IP addresses, URLs, or domain names"
# ═══════════════════════════════════════════════════════════════════════════

class EntityExtractor:

    _PAT = {
        "ip": re.compile(
            r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
            r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'),
        "domain": re.compile(
            r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'
            r'+(?:com|net|org|io|gov|edu|co|info|biz|xyz|ru|cn|de|uk|fr|'
            r'br|jp|in|au|ca|mx|nl|pl|se|dk|ch|es|it|pt|tk|top|club|'
            r'online|site|tech|app|dev|cloud|live|click|link)\b',
            re.IGNORECASE),
        "url": re.compile(r'https?://[^\s\'"<>\]\[]+', re.IGNORECASE),
        "email_addr": re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'),
        "user": re.compile(r'\b(?:user(?:name)?|for|login)[:\s=]+([a-zA-Z0-9_\-\.@]{3,32})', re.IGNORECASE),
        "cve": re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.IGNORECASE),
        "hash": re.compile(r'\b[0-9a-fA-F]{32,64}\b'),
        "port": re.compile(r'\b(\d{2,5})/(?:tcp|udp)\b', re.IGNORECASE),
    }

    ENTITY_TYPES = list(_PAT.keys())

    @classmethod
    def extract(cls, text: str) -> dict:
        text   = str(text)
        result = {t: [] for t in cls.ENTITY_TYPES}
        for etype, pat in cls._PAT.items():
            found = pat.findall(text)
            seen  = set()
            clean = []
            for v in found:
                v = str(v).strip()
                v = v.upper() if etype == "cve" else v.lower()
                if len(v) >= 3 and v not in seen:
                    seen.add(v)
                    clean.append(v)
            result[etype] = clean
        return result

    @classmethod
    def extract_recursive(cls, obj, depth: int = 0) -> dict:
        result = {t: set() for t in cls.ENTITY_TYPES}
        if depth > 8:
            return {t: list(v) for t, v in result.items()}
        if isinstance(obj, str):
            for t, vals in cls.extract(obj).items():
                result[t].update(vals)
        elif isinstance(obj, dict):
            for v in obj.values():
                for t, vals in cls.extract_recursive(v, depth+1).items():
                    result[t].update(vals)
        elif isinstance(obj, (list, tuple)):
            for item in obj:
                for t, vals in cls.extract_recursive(item, depth+1).items():
                    result[t].update(vals)
        elif obj is not None:
            for t, vals in cls.extract(str(obj)).items():
                result[t].update(vals)
        return {t: sorted(v) for t, v in result.items()}

    @classmethod
    def merge(cls, *dicts) -> dict:
        merged = {t: set() for t in cls.ENTITY_TYPES}
        for d in dicts:
            for t, vals in d.items():
                merged[t].update(vals)
        return {t: sorted(v) for t, v in merged.items()}


# ═══════════════════════════════════════════════════════════════════════════
# TEMPORAL CORRELATOR
# Paper: "temporal correlation by examining the timing of events,
#  identifying coordinated activities such as phishing campaigns
#  followed by lateral movement"
# ═══════════════════════════════════════════════════════════════════════════

class TemporalCorrelator:

    _FMTS = [
        "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%SZ",  "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",   "%Y-%m-%d %H:%M:%S.%f",
    ]

    def __init__(self, window_seconds: int = 3600):
        self.window = window_seconds

    def _parse(self, ts: str) -> Optional[float]:
        for fmt in self._FMTS:
            try:
                dt = datetime.strptime(ts, fmt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.timestamp()
            except ValueError:
                continue
        return None

    def analyze(self, reports: list) -> dict:
        parsed = []
        for r in reports:
            ts = self._parse(r.timestamp)
            if ts is not None:
                parsed.append((r.agent_name, ts, r.timestamp))
        parsed.sort(key=lambda x: x[1])

        if len(parsed) < 2:
            return {"overlapping": False, "time_span_secs": 0,
                    "min_gap_secs": 0, "sequence": [(a, t) for a, _, t in parsed]}

        span    = parsed[-1][1] - parsed[0][1]
        gaps    = [parsed[i+1][1] - parsed[i][1] for i in range(len(parsed)-1)]
        min_gap = min(gaps) if gaps else 0

        # Partial temporal credit for events within 2× window
        if span <= self.window:
            temporal_sc = 1.0
        elif span <= self.window * 2:
            temporal_sc = max(0, 1.0 - (span - self.window) / self.window)
        else:
            temporal_sc = 0.0

        return {
            "overlapping":    span <= self.window,
            "time_span_secs": round(span, 1),
            "min_gap_secs":   round(min_gap, 1),
            "sequence":       [(a, t) for a, _, t in parsed],
            "temporal_score": round(temporal_sc, 4),
        }


# ═══════════════════════════════════════════════════════════════════════════
# CROSS-AGENT ENTITY MATCHER
# Paper: "if an email analysis flags a suspicious domain and that same
#  domain appears in a failed login event or an exposed service,
#  the system flags it as a correlated anomaly"
# ═══════════════════════════════════════════════════════════════════════════

class CrossAgentMatcher:

    MIN_AGENTS = 2

    # How significant each entity type is as a correlation signal
    TYPE_WEIGHTS = {
        "cve": 1.0, "ip": 0.9, "domain": 0.85, "url": 0.80,
        "email_addr": 0.75, "hash": 0.95, "user": 0.60, "port": 0.35,
    }

    def match(self, agent_entities: dict) -> list:
        """agent_entities: {agent_name: {etype: [values]}}"""
        index: dict = {}
        for agent_name, entities in agent_entities.items():
            for etype, values in entities.items():
                for val in values:
                    val = val.strip()
                    if len(val) < 3:
                        continue
                    key = (etype, val)
                    index.setdefault(key, {})[agent_name] = \
                        index.get(key, {}).get(agent_name, 0) + 1

        matches = []
        for (etype, val), agent_counts in index.items():
            if len(agent_counts) >= self.MIN_AGENTS:
                weight = self.TYPE_WEIGHTS.get(etype, 0.5)
                freq   = sum(agent_counts.values())
                sig    = weight * (len(agent_counts) / 3.0) * min(freq / 2.0, 1.0)
                matches.append({
                    "type": etype, "value": val,
                    "seen_in":     sorted(agent_counts.keys()),
                    "frequency":   freq,
                    "weight":      round(weight, 2),
                    "significance": round(sig, 4),
                })
        matches.sort(key=lambda x: x["significance"], reverse=True)
        return matches


# ═══════════════════════════════════════════════════════════════════════════
# CONFIDENCE SCORER
# Paper: "assigns a correlation confidence level, indicating the likelihood
#  that these events are part of a unified threat scenario"
# Targets 87% correlation accuracy from Table VI
# ═══════════════════════════════════════════════════════════════════════════

class ConfidenceScorer:

    _CRITICAL_VERDICTS = {
        "phishing", "ssh-patator", "bot-c2", "sqli", "heartbleed",
        "infiltration", "ddos", "critical_cve", "critical_vulnerability",
        "lateral_movement", "exfiltration", "ransomware", "apt",
    }

    def score(self, matched_entities: list, temporal_info: dict, reports: list) -> tuple:
        """Returns (confidence: float, level: str, breakdown: dict)"""

        # A) Entity match quality (35%)
        if matched_entities:
            entity_sc = min(sum(e["significance"] for e in matched_entities) / 2.0, 1.0)
        else:
            entity_sc = 0.0

        # B) Temporal overlap (20%)
        temporal_sc = temporal_info.get("temporal_score", 0.0)

        # C) Average agent risk score normalized 0-1 (25%)
        risk_sc = sum(r.risk_score for r in reports) / (len(reports) * 10.0) if reports else 0.0

        # D) Agent coverage breadth — reward 3 agents over 1 (12%)
        breadth_sc = min((len(reports) - 1) / 2.0, 1.0)

        # E) Severity boost from critical verdicts (8%)
        severity_sc = 0.0
        for r in reports:
            v_lower = r.verdict.lower().replace(" ", "_")
            if any(cv in v_lower for cv in self._CRITICAL_VERDICTS):
                severity_sc = min(severity_sc + 0.5, 1.0)

        # Weights: entity quality is primary, breadth alone must not push benign
        # multi-agent events over threshold
        confidence = (
            0.40 * entity_sc   +
            0.20 * temporal_sc +
            0.20 * risk_sc     +
            0.08 * breadth_sc  +
            0.12 * severity_sc
        )
        confidence = round(min(confidence, 1.0), 4)

        if   confidence >= 0.80: level = "CRITICAL"
        elif confidence >= 0.65: level = "HIGH"
        elif confidence >= 0.45: level = "MEDIUM"
        elif confidence >= 0.25: level = "LOW"
        else:                    level = "NONE"

        breakdown = {
            "entity_match_quality":   round(entity_sc,   4),
            "temporal_overlap":       round(temporal_sc,  4),
            "agent_risk_avg":         round(risk_sc,      4),
            "agent_coverage_breadth": round(breadth_sc,  4),
            "verdict_severity":       round(severity_sc,  4),
        }
        return confidence, level, breakdown

    def detect_false_positives(self, matched_entities: list, reports: list) -> list:
        fps = []
        # Only port numbers matched → low specificity
        if matched_entities and all(e["type"] == "port" for e in matched_entities):
            fps.append("Only port numbers matched — insufficient specificity")
        # All agents report low risk
        if reports and all(r.risk_score < 3.0 for r in reports):
            fps.append("All agents report low risk — correlation may be incidental")
        # Authorized/benign keywords in summaries
        benign_keywords = ["authorized", "whitelisted", "maintenance", "scheduled",
                           "change ticket", "pentest", "ci/cd", "backup", "routine"]
        all_summaries = " ".join(r.raw_summary.lower() for r in reports)
        if any(kw in all_summaries for kw in benign_keywords):
            fps.append("Authorized/benign activity keywords detected — verify before acting")
        # Single entity match with all agents having low-medium risk
        if len(matched_entities) == 1 and reports:
            avg_risk = sum(r.risk_score for r in reports) / len(reports)
            if avg_risk < 5.0:
                fps.append("Single shared entity with low average risk — weak correlation signal")
        return fps


# ═══════════════════════════════════════════════════════════════════════════
# THREAT CLASSIFIER
# ═══════════════════════════════════════════════════════════════════════════

class ThreatClassifier:

    _STAGES = {
        "Reconnaissance":       ["port_scan", "nmap", "masscan", "scan"],
        "Initial_Access":       ["phishing", "exploit", "credential_theft"],
        "Execution":            ["command_execution", "shell", "macro"],
        "Persistence":          ["backdoor", "rootkit", "registry", "cron"],
        "Privilege_Escalation": ["privilege_escalat", "sudo", "escalat"],
        "Lateral_Movement":     ["lateral", "psexec", "rdp", "smb"],
        "Credential_Access":    ["brute_force", "patator", "credential"],
        "Exfiltration":         ["exfil", "c2", "beacon", "data_transfer"],
        "Impact":               ["ddos", "ransomware", "encrypt", "destroy"],
    }

    def classify(self, reports: list, matched_entities: list) -> dict:
        all_text = " ".join(
            r.verdict.lower() + " " + r.raw_summary.lower() for r in reports
        )
        stages = [s for s, kws in self._STAGES.items() if any(kw in all_text for kw in kws)]
        max_risk = max((r.risk_score for r in reports), default=0)

        if   max_risk >= 8.0: severity = "CRITICAL"
        elif max_risk >= 6.0: severity = "HIGH"
        elif max_risk >= 4.0: severity = "MEDIUM"
        else:                 severity = "LOW"

        if len(stages) >= 3:   threat_type = "Multi-Stage APT"
        elif len(stages) == 2: threat_type = " + ".join(stages)
        elif stages:           threat_type = stages[0].replace("_", " ")
        else:                  threat_type = " | ".join(set(r.verdict for r in reports))

        return {"stages_detected": stages, "threat_type": threat_type, "severity": severity}


# ═══════════════════════════════════════════════════════════════════════════
# FILESYSTEM MEMORY MODULE
# Paper: "a memory module for storing results of recent analyses and
#  high-risk patterns … compare current logs with historical behaviors …
#  promoting temporal correlation and tracking evolution of threats"
#
# Implementation: plain JSON files, no database required
#   memory/
#     index.json          — index of all results (fast lookup)
#     results/<id>.json   — full result per correlation event
#     entities/<val>.json — history per tracked entity/IOC
# ═══════════════════════════════════════════════════════════════════════════

class CorrelationMemory:

    def __init__(self, memory_dir: str = "memory"):
        self.base      = Path(memory_dir)
        self.results_  = self.base / "results"
        self.entities_ = self.base / "entities"
        self.index_f   = self.base / "index.json"

        # Create dirs if needed
        self.results_.mkdir(parents=True, exist_ok=True)
        self.entities_.mkdir(parents=True, exist_ok=True)

        # Load or create index
        if self.index_f.exists():
            self._index: list = json.loads(self.index_f.read_text())
        else:
            self._index = []
            self._save_index()

        logger.info(f"CorrelationMemory ready: {self.base} | {len(self._index)} past results")

    # ── Internal helpers ──────────────────────────────────────────────────

    def _save_index(self):
        self.index_f.write_text(json.dumps(self._index, indent=2))

    def _entity_file(self, value: str) -> Path:
        # Sanitise entity value for use as a filename
        safe = re.sub(r'[^\w.\-]', '_', value.lower())[:80]
        return self.entities_ / f"{safe}.json"

    # ── Public API ────────────────────────────────────────────────────────

    def store(self, result: "CorrelationResult"):
        """Persist one CorrelationResult to disk."""

        # 1. Save full result JSON
        result_path = self.results_ / f"{result.report_id}.json"
        result_path.write_text(
            json.dumps(result.to_dict(), indent=2, default=str)
        )

        # 2. Append to index
        entry = {
            "report_id":    result.report_id,
            "generated_at": result.generated_at,
            "level":        result.correlation_level,
            "confidence":   result.confidence,
            "correlated":   result.correlated,
            "threat_type":  result.threat_type,
            "agents":       result.involved_agents,
            "n_entities":   len(result.matched_entities),
        }
        self._index.append(entry)
        # Keep last 1000 entries in index
        self._index = self._index[-1000:]
        self._save_index()

        # 3. Update per-entity files
        now = datetime.now(timezone.utc).isoformat()
        for entity in result.matched_entities:
            ef = self._entity_file(entity["value"])
            if ef.exists():
                data = json.loads(ef.read_text())
            else:
                data = {
                    "entity_type":   entity["type"],
                    "entity_value":  entity["value"],
                    "first_seen":    now,
                    "last_seen":     now,
                    "occurrences":   0,
                    "report_ids":    [],
                    "threat_types":  [],
                    "levels":        [],
                }
            data["last_seen"]     = now
            data["occurrences"]  += 1
            data["report_ids"]    = (data["report_ids"] + [result.report_id])[-50:]
            if result.threat_type not in data["threat_types"]:
                data["threat_types"].append(result.threat_type)
            if result.correlation_level not in data["levels"]:
                data["levels"].append(result.correlation_level)
            ef.write_text(json.dumps(data, indent=2))

        logger.info(f"Memory stored: {result.report_id} → {result_path.name}")

    def recall_recent(self, n: int = 20) -> list:
        """Return n most recent index entries."""
        return list(reversed(self._index[-n:]))

    def recall_by_level(self, level: str) -> list:
        """Return all index entries at a given level."""
        return [e for e in self._index if e.get("level") == level.upper()]

    def recall_by_entity(self, value: str) -> Optional[dict]:
        """Return entity history for a specific IOC value."""
        ef = self._entity_file(value)
        if ef.exists():
            return json.loads(ef.read_text())
        return None

    def recurring_iocs(self, min_occurrences: int = 2) -> list:
        """Return all tracked entities seen ≥ min_occurrences times."""
        found = []
        for ef in self.entities_.glob("*.json"):
            try:
                data = json.loads(ef.read_text())
                if data.get("occurrences", 0) >= min_occurrences:
                    found.append(data)
            except Exception:
                pass
        found.sort(key=lambda x: x.get("occurrences", 0), reverse=True)
        return found

    def get_full_result(self, report_id: str) -> Optional[dict]:
        """Load a full CorrelationResult dict by report_id."""
        p = self.results_ / f"{report_id}.json"
        return json.loads(p.read_text()) if p.exists() else None

    def stats(self) -> dict:
        n_results    = len(self._index)
        n_correlated = sum(1 for e in self._index if e.get("correlated"))
        n_entities   = len(list(self.entities_.glob("*.json")))
        n_recurring  = len(self.recurring_iocs(min_occurrences=2))
        by_level     = {}
        for e in self._index:
            lv = e.get("level", "NONE")
            by_level[lv] = by_level.get(lv, 0) + 1
        return {
            "total_results":    n_results,
            "correlated_count": n_correlated,
            "unique_entities":  n_entities,
            "recurring_iocs":   n_recurring,
            "by_level":         by_level,
            "memory_dir":       str(self.base),
        }


# ═══════════════════════════════════════════════════════════════════════════
# LLM NARRATIVE GENERATOR
# Paper: "LLaMA 3.3-70B … used to synthesize clear and contextualized
#  threat narratives … Chain-of-Thought prompting"
# ═══════════════════════════════════════════════════════════════════════════

class NarrativeGenerator:

    MODEL       = "llama-3.3-70b-versatile"
    TEMPERATURE = 0.15
    MAX_TOKENS  = 2000

    _SYSTEM = (
        "You are the Contextual Recommendation System of a multi-agent "
        "cybersecurity platform (IEEE Access DOI 10.1109/ACCESS.2025.3602681).\n"
        "Synthesize outputs from three specialized agents (Email Verification, "
        "Log Analyzer, IP Range Analyzer) into one threat intelligence report.\n\n"
        "RULES:\n"
        "1. Chain-of-Thought: Step A→evidence per agent; Step B→cross-domain links; "
        "Step C→unified kill-chain assessment; Step D→conclusion.\n"
        "2. Cite which agent found each indicator.\n"
        "3. Never fabricate IOCs not present in the provided data.\n"
        "4. Output ONLY valid JSON with keys: threat_type, attack_vector, "
        "narrative, recommendations (list), confidence_notes, iocs (list).\n"
    )

    def __init__(self, api_key: Optional[str] = None, key_manager=None):
        if not _GROQ_AVAILABLE:
            raise ImportError("groq package not installed: pip install groq")
        # Accept a KeyManager (preferred) or a plain key string
        if key_manager is not None and _KEY_MANAGER_AVAILABLE:
            self._key_manager = key_manager
            key = key_manager.current_key()
        else:
            self._key_manager = None
            key = api_key or os.environ.get("GROQ_API_KEY", "")
        if not key:
            raise EnvironmentError("GROQ_API_KEY not set")
        self.client = Groq(api_key=key)
        self._current_key = key

    def generate(self, reports, matched_entities, temporal_info,
                 confidence, level, breakdown) -> dict:

        agent_sec = "\n\n".join(
            f"### {r.agent_name}\nRisk: {r.risk_score}/10 | Verdict: {r.verdict}\n"
            f"Timestamp: {r.timestamp}\nIndicators: {json.dumps(r.indicators, indent=2)}\n"
            f"Summary: {r.raw_summary[:500]}"
            for r in reports
        )

        entity_sec = "\n".join(
            f"  [{e['type'].upper()}] {e['value']} — agents={e['seen_in']}"
            for e in matched_entities[:15]
        ) or "  None"

        user_msg = (
            f"=== AGENT REPORTS ===\n{agent_sec}\n\n"
            f"=== MATCHED ENTITIES (cross-agent) ===\n{entity_sec}\n\n"
            f"=== TEMPORAL ===\n"
            f"Overlap: {temporal_info.get('overlapping')} | "
            f"Span: {temporal_info.get('time_span_secs',0):.0f}s | "
            f"Sequence: {temporal_info.get('sequence', [])}\n\n"
            f"=== CONFIDENCE ===\n{confidence:.1%} ({level})\n"
            + "\n".join(f"  {k}: {v:.3f}" for k, v in breakdown.items())
            + "\n\nApply chain-of-thought (A→D) and return the JSON report."
        )

        for attempt in range(3):
            try:
                time.sleep(1.5 * (attempt + 1))
                resp = self.client.chat.completions.create(
                    model=self.MODEL,
                    messages=[
                        {"role": "system", "content": self._SYSTEM},
                        {"role": "user",   "content": user_msg},
                    ],
                    temperature=self.TEMPERATURE,
                    max_tokens=self.MAX_TOKENS,
                    response_format={"type": "json_object"},
                )
                raw    = resp.choices[0].message.content.strip()
                parsed = json.loads(raw)
                logger.info("LLM narrative generated successfully")
                return {
                    "threat_type":      parsed.get("threat_type",     "unknown"),
                    "attack_vector":    parsed.get("attack_vector",   "unknown"),
                    "narrative":        parsed.get("narrative",       raw),
                    "recommendations":  parsed.get("recommendations", []),
                    "confidence_notes": parsed.get("confidence_notes",""),
                    "iocs":             parsed.get("iocs",            []),
                }
            except Exception as exc:
                err = str(exc)
                if "429" in err or "rate_limit" in err.lower():
                    if self._key_manager is not None:
                        new_key = self._key_manager.rotate()
                        if new_key:
                            logger.warning(f"Rate limit — rotating to next key…")
                            self.client = Groq(api_key=new_key)
                            self._current_key = new_key
                            time.sleep(1.5)
                        else:
                            wait = 60 * (attempt + 1)
                            logger.warning(f"All keys exhausted — sleeping {wait}s…")
                            time.sleep(wait)
                    else:
                        wait = 60 * (attempt + 1)
                        logger.warning(f"Rate limit — sleeping {wait}s…")
                        time.sleep(wait)
                else:
                    logger.warning(f"LLM error attempt {attempt+1}: {err[:100]}")

        logger.warning("LLM failed — using rule-based fallback")
        return self._fallback(reports, matched_entities, confidence, level)

    def _fallback(self, reports, matched_entities, confidence, level) -> dict:
        entities_str = ", ".join(
            f"{e['type']}:{e['value']}" for e in matched_entities[:8]
        ) or "none"
        narrative = (
            "[FALLBACK — LLM unavailable]\n\n"
            "Agents: " + ", ".join(r.agent_name for r in reports) + "\n\n"
            "Verdicts:\n" + "\n".join(
                f"  • {r.agent_name}: {r.verdict} (risk={r.risk_score}/10)"
                for r in reports
            ) + f"\n\nShared indicators: {entities_str}\n"
            f"Confidence: {confidence:.1%} ({level})\n\n"
            "Manual SOC analyst review required for full narrative."
        )
        threat_type = " + ".join(sorted(set(r.verdict.lower() for r in reports)))
        return {
            "threat_type":      threat_type,
            "attack_vector":    " → ".join(r.agent_name.replace("Agent","") for r in reports),
            "narrative":        narrative,
            "recommendations":  [
                "Block all flagged IPs at the firewall immediately.",
                "Quarantine flagged emails and notify affected users.",
                "Patch all identified CVEs — CRITICAL severity first.",
                "Enable enhanced logging on flagged hosts.",
                "Escalate to Tier-2 analyst for manual correlation.",
                "Search SIEM for matched IOCs over last 72 hours.",
                "Update detection rules with confirmed indicators.",
            ],
            "confidence_notes": "LLM unavailable — rule-based only. Human review required.",
            "iocs":             [e["value"] for e in matched_entities[:10]],
        }


# ═══════════════════════════════════════════════════════════════════════════
# CORRELATION AGENT — Main Orchestrator (Section III-E)
# ═══════════════════════════════════════════════════════════════════════════

class CorrelationAgent:
    """
    Production Contextual Recommendation System.
    Called by task_dispatcher_gui.py after all domain agents complete.

    Usage:
        agent  = CorrelationAgent(groq_api_key="gsk_...", memory_dir="memory")
        result = agent.correlate([email_report, log_report, ip_report])
        print(result.pretty_print())
    """

    def __init__(
        self,
        groq_api_key: Optional[str]  = None,
        groq_api_keys: list          = None,
        key_manager                  = None,
        memory_dir:   str            = "memory",
        temporal_window_seconds: int = 3600,
        min_confidence_threshold: float = 0.35,
    ):
        self.extractor  = EntityExtractor()
        self.matcher    = CrossAgentMatcher()
        self.temporal   = TemporalCorrelator(window_seconds=temporal_window_seconds)
        self.scorer     = ConfidenceScorer()
        self.classifier = ThreatClassifier()
        self.memory     = CorrelationMemory(memory_dir=memory_dir)
        self.threshold  = min_confidence_threshold

        # ── Key resolution (priority: key_manager > groq_api_keys list > single key > env) ──
        self._key_manager = None
        if key_manager is not None and _KEY_MANAGER_AVAILABLE:
            self._key_manager = key_manager
            logger.info(f"Using provided KeyManager with {len(key_manager._keys)} key(s)")
        elif groq_api_keys and _KEY_MANAGER_AVAILABLE:
            try:
                self._key_manager = KeyManager(groq_api_keys)
                logger.info(f"KeyManager created from groq_api_keys list ({len(groq_api_keys)} key(s))")
            except Exception as e:
                logger.warning(f"KeyManager init failed: {e}")

        # ── LLM — optional, graceful fallback ──────────────────────────────────
        self._llm: Optional[NarrativeGenerator] = None
        if _GROQ_AVAILABLE:
            try:
                if self._key_manager is not None:
                    self._llm = NarrativeGenerator(key_manager=self._key_manager)
                else:
                    key = groq_api_key or os.environ.get("GROQ_API_KEY", "")
                    if key:
                        self._llm = NarrativeGenerator(api_key=key)
                    else:
                        logger.warning("No GROQ_API_KEY — using rule-based narrative")
            except Exception as e:
                logger.warning(f"LLM init failed: {e}")
        else:
            logger.warning("groq package not installed — using rule-based narrative")

        llm_status = "✓" if self._llm else "✗ (fallback)"
        km_status  = f"KeyManager({len(self._key_manager._keys)} keys)" if self._key_manager else "single-key"
        logger.info(
            f"CorrelationAgent ready | LLM={llm_status} | Keys={km_status} "
            f"| Memory={memory_dir} | Window={temporal_window_seconds}s"
        )

    def correlate(self, reports: list) -> CorrelationResult:
        """
        Main entry point. Accept list of AgentReport, return CorrelationResult.
        This is called by the task dispatcher after all agents have run.
        """
        if not reports:
            raise ValueError("correlate() needs at least one AgentReport")

        logger.info(f"correlate() | agents={[r.agent_name for r in reports]}")

        # Step 2: Extract entities from each agent's report
        agent_entities: dict = {}
        for r in reports:
            text_ent = self.extractor.extract(r.raw_summary)
            dict_ent = self.extractor.extract_recursive(r.indicators)
            agent_entities[r.agent_name] = self.extractor.merge(text_ent, dict_ent)

        # Step 3: Cross-agent entity matching
        matched_entities = self.matcher.match(agent_entities)
        logger.info(f"  Matched entities: {len(matched_entities)}")

        # Step 4: Temporal correlation
        temporal_info = self.temporal.analyze(reports)
        logger.info(f"  Temporal overlap: {temporal_info['overlapping']} | span={temporal_info['time_span_secs']}s")

        # Step 5: Confidence scoring
        confidence, level, breakdown = self.scorer.score(matched_entities, temporal_info, reports)
        fp_indicators = self.scorer.detect_false_positives(matched_entities, reports)

        # Correlated requires:
        #   (a) genuine cross-agent evidence: shared entities OR temporal overlap WITH entities
        #   (b) confidence above threshold
        #   (c) NOT suppressed by strong false-positive signals
        #
        # Three suppression rules target the known FP patterns:
        #   Rule 1 — temporal-only + benign keywords + low risk
        #   Rule 2 — only private/internal IPs matched + fp indicators present
        #   Rule 3 — zero shared entities + no temporal overlap (pure breadth bonus)
        has_entity_match   = len(matched_entities) > 0
        has_temporal_only  = temporal_info["overlapping"] and not has_entity_match
        has_cross_agent_evidence = has_entity_match or temporal_info["overlapping"]

        def _is_private_ip(val):
            try:
                return ipaddress.ip_address(val).is_private
            except Exception:
                return False

        # Rule 1: temporal overlap alone with benign signals and low risk
        _suppress_r1 = (
            has_temporal_only and
            len(fp_indicators) > 0 and
            all(r.risk_score < 5.0 for r in reports)
        )

        # Rule 2: only private/internal IPs matched AND fp indicators present
        # (catches authorized internal scanner, IT admin, pen test cases)
        _suppress_r2 = (
            has_entity_match and
            len(fp_indicators) > 0 and
            all(
                e["type"] == "ip" and _is_private_ip(e["value"])
                for e in matched_entities
            )
        )

        # Rule 3: zero shared entities + no temporal overlap
        # (pure multi-agent breadth bonus — not real evidence)
        _suppress_r3 = (
            not has_entity_match and
            not temporal_info["overlapping"]
        )

        # Rule 4: zero shared entities + temporal overlap ONLY
        # (agents fired at the same time but found NOTHING in common — not correlated)
        # Guard: only suppress when all verdicts are non-critical and avg risk < 7.0
        _avg_risk = sum(r.risk_score for r in reports) / len(reports) if reports else 0
        _any_critical_verdict = any(
            any(cv in r.verdict.lower() for cv in [
                "phishing","ssh-patator","bot-c2","sqli","heartbleed",
                "infiltration","ddos","ransomware","apt","critical"
            ])
            for r in reports
        )
        _suppress_r4 = (
            not has_entity_match and
            temporal_info["overlapping"] and
            not _any_critical_verdict and
            _avg_risk < 7.0
        )

        _benign_suppressed = _suppress_r1 or _suppress_r2 or _suppress_r3 or _suppress_r4

        correlated = (
            confidence >= self.threshold and
            has_cross_agent_evidence and
            not _benign_suppressed
        )
        if _suppress_r1:
            logger.info("  Suppressed [R1]: temporal-only overlap with FP indicators and low risk")
        if _suppress_r2:
            logger.info("  Suppressed [R2]: only private IPs matched with FP indicators")
        if _suppress_r3:
            logger.info("  Suppressed [R3]: zero shared entities and no temporal overlap")
        if _suppress_r4:
            logger.info("  Suppressed [R4]: zero shared entities, temporal only, non-critical low-risk")
        logger.info(f"  Confidence={confidence:.1%} | Level={level} | Correlated={correlated}")

        # Threat classification
        threat_info = self.classifier.classify(reports, matched_entities)

        # Step 6: LLM narrative
        if self._llm:
            llm_out = self._llm.generate(
                reports, matched_entities, temporal_info, confidence, level, breakdown
            )
        else:
            gen     = NarrativeGenerator.__new__(NarrativeGenerator)
            llm_out = gen._fallback(reports, matched_entities, confidence, level)

        threat_type    = llm_out.get("threat_type") or threat_info["threat_type"]
        attack_vector  = llm_out.get("attack_vector") or (
            " → ".join(threat_info.get("stages_detected") or [r.agent_name for r in reports])
        )
        recommendations = llm_out.get("recommendations") or [
            "Block flagged IPs at firewall.", "Quarantine flagged emails.",
            "Patch identified CVEs immediately.", "Enable enhanced logging.",
            "Escalate to Tier-2 analyst.", "Search SIEM for matched IOCs.",
        ]
        narrative = llm_out.get("narrative", "")
        iocs      = llm_out.get("iocs") or [e["value"] for e in matched_entities[:10]]

        # Step 7: Build CorrelationResult
        evidence_traces = [
            {
                "agent":       r.agent_name,
                "verdict":     r.verdict,
                "risk_score":  r.risk_score,
                "timestamp":   r.timestamp,
                "summary":     r.raw_summary[:250] + ("…" if len(r.raw_summary) > 250 else ""),
            }
            for r in reports
        ]
        entity_map = {
            a: {k: v for k, v in ents.items() if v}
            for a, ents in agent_entities.items()
        }

        result = CorrelationResult(
            correlated=correlated,
            confidence=confidence,
            correlation_level=level,
            matched_entities=matched_entities,
            temporal_overlap=temporal_info["overlapping"],
            temporal_window_secs=self.temporal.window,
            narrative=narrative,
            recommendations=recommendations,
            involved_agents=[r.agent_name for r in reports],
            threat_type=threat_type,
            attack_vector=attack_vector,
            evidence_traces=evidence_traces,
            entity_map=entity_map,
            false_positive_indicators=fp_indicators,
        )

        # Step 8: Persist to filesystem memory
        self.memory.store(result)

        logger.info(f"Done | report_id={result.report_id} | level={level}")
        return result

    # Convenience wrappers around memory
    def recall_entity(self, value: str) -> Optional[dict]:
        return self.memory.recall_by_entity(value)

    def recurring_iocs(self, min_count: int = 2) -> list:
        return self.memory.recurring_iocs(min_occurrences=min_count)

    def stats(self) -> dict:
        return self.memory.stats()


# ═══════════════════════════════════════════════════════════════════════════
# INTEGRATION HELPERS
# Used by task_dispatcher_gui.py to build AgentReport from raw agent dicts
# ═══════════════════════════════════════════════════════════════════════════

def build_email_report(risk_score, verdict, indicators, summary, timestamp=None) -> AgentReport:
    score = float(risk_score)
    if score <= 1.0:
        score *= 10
    return AgentReport("EmailVerificationAgent", score, verdict, indicators, summary, timestamp)


def build_log_report(risk_score, verdict, indicators, summary, timestamp=None) -> AgentReport:
    sev_map = {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.0, "NONE": 0.5}
    if isinstance(risk_score, str):
        risk_score = sev_map.get(risk_score.upper(), 5.0)
    return AgentReport("LogAnalyzerAgent", float(risk_score), verdict, indicators, summary, timestamp)


def build_ip_report(risk_score, verdict, indicators, summary, timestamp=None) -> AgentReport:
    return AgentReport("IPRangeAnalyzerAgent", float(risk_score), verdict, indicators, summary, timestamp)


def agent_result_to_report(routing_result: dict) -> Optional[AgentReport]:
    """
    Universal adapter: convert the raw dict returned by any domain agent
    (as routed through task_dispatcher_gui.py) into an AgentReport.
    """
    if not routing_result or not isinstance(routing_result, dict):
        return None
    agent  = routing_result.get("agent", "")
    status = routing_result.get("status", "")
    result = routing_result.get("result") or {}

    if status != "COMPLETED" or not result:
        return None

    # ── Email ──
    if "Email" in agent or "email" in agent.lower():
        raw_risk = float(result.get("risk_score", 0.5))
        risk     = raw_risk * 10 if raw_risk <= 1.0 else raw_risk
        verdict  = result.get("risk_verdict", result.get("risk_label", "UNKNOWN"))
        indicators = {
            "metadata":    result.get("metadata", {}),
            "regex":       result.get("regex_analysis", {}),
            "faiss":       result.get("faiss_analysis", {}),
            "dns":         result.get("dns_validation", []),
            "scores":      result.get("component_scores", {}),
        }
        summary = (
            f"Verdict={verdict} risk={risk:.1f}/10 "
            f"action={result.get('recommended_action','?')} "
            f"llm={result.get('llm_analysis',{}).get('justification','N/A')[:120]}"
        )
        return AgentReport("EmailVerificationAgent", risk, verdict, indicators, summary)

    # ── Log ──
    elif "Log" in agent or "log" in agent.lower():
        sev    = result.get("final_severity", "UNKNOWN")
        sev_map = {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.0, "NONE": 0.5}
        risk   = sev_map.get(sev.upper(), 3.0)
        verdict = result.get("final_label", result.get("risk_verdict", "Unknown"))
        indicators = {
            "stage1": result.get("stage1_normalized_fields", {}),
            "stage2": result.get("stage2_signature", {}),
            "stage3": result.get("stage3_llm", {}),
            "ioc":    result.get("ioc", ""),
        }
        summary = (
            f"Verdict={verdict} severity={sev} ioc={result.get('ioc','?')} "
            f"explanation={result.get('explanation','N/A')[:120]}"
        )
        return AgentReport("LogAnalyzerAgent", risk, verdict, indicators, summary)

    # ── IP ──
    elif "IP" in agent or "ip" in agent.lower():
        summ   = result.get("summary", {})
        n_cves = summ.get("total_cves_found", 0)
        crits  = len(summ.get("critical_hosts", []))
        risk   = min(9.5, 4.0 + n_cves * 0.25 + crits * 1.5)
        verdict = f"CVE_SCAN: {n_cves}_cves critical_hosts={crits}"
        indicators = {
            "ip_range": result.get("ip_range", ""),
            "summary":  summ,
            "hosts": {
                k: {"services": [
                    {"port": s.get("port"), "name": s.get("name"),
                     "cves": [c.get("id") for c in s.get("cves", [])][:5]}
                    for s in v.get("services", [])[:8]
                ]}
                for k, v in list(result.get("host_details", {}).items())[:5]
            },
        }
        summary = (
            f"Range={result.get('ip_range','?')} hosts={summ.get('total_hosts',0)} "
            f"cves={n_cves} critical={summ.get('critical_hosts',[])} "
            f"llm={str(result.get('llm_analysis','N/A'))[:120]}"
        )
        return AgentReport("IPRangeAnalyzerAgent", risk, verdict, indicators, summary)

    return None