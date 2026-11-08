#!/usr/bin/env python3
"""
=============================================================================
 AGENT MEMORY MODULE  —  Shared Persistent Storage for All Agents
=============================================================================
 Paper: "A Multi-Agent System for Cybersecurity Threat Detection and
         Correlation using Large Language Models"
         IEEE Access, DOI: 10.1109/ACCESS.2025.3602681

 Every agent (Email, Log, IP, Correlation) saves its reports here.
 Reports are organised into subfolders:

   memory/
     email/        ← EmailVerificationAgent reports
     log/          ← LogAnalyzerAgent reports
     ip/           ← IPRangeAnalyzerAgent reports
     correlation/  ← CorrelationAgent reports
       results/    ← full correlation result JSONs
       entities/   ← per-IOC history files
     index.json    ← lightweight cross-agent index (last 2000 entries)

 Usage (any agent):
     from agent_memory import AgentMemory
     mem = AgentMemory()                   # default dir: "memory"
     mem.save_email_report(report_dict)
     mem.save_log_report(report_dict)
     mem.save_ip_report(report_dict)
     # Correlation Agent uses its own CorrelationMemory class
     # which already writes into memory/correlation/
=============================================================================
"""

import os
import re
import json
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


class AgentMemory:
    """
    Centralised file-based memory for the multi-agent system.
    Thread-safe for single-process use (file writes are atomic enough
    for this application; add fcntl locks if needed for multi-process).
    """

    # Subfolder names
    SUBFOLDERS = {
        "email":       "email",
        "log":         "log",
        "ip":          "ip",
        "correlation": "correlation",
    }

    def __init__(self, memory_dir: str = "memory"):
        self.base = Path(memory_dir)

        # Create all subfolders
        for sub in self.SUBFOLDERS.values():
            (self.base / sub).mkdir(parents=True, exist_ok=True)

        # Correlation sub-subfolders (used by CorrelationMemory too)
        (self.base / "correlation" / "results").mkdir(parents=True, exist_ok=True)
        (self.base / "correlation" / "entities").mkdir(parents=True, exist_ok=True)

        # Cross-agent index
        self.index_path = self.base / "index.json"
        if self.index_path.exists():
            try:
                self._index: list = json.loads(self.index_path.read_text())
            except Exception:
                self._index = []
        else:
            self._index = []
            self._write_index()

    # ─────────────────────────────────────────────────────────────────
    # Internal helpers
    # ─────────────────────────────────────────────────────────────────

    def _now_iso(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def _make_id(self, prefix: str, data: dict) -> str:
        """Generate a short deterministic ID from timestamp + content hash."""
        ts_safe = self._now_iso().replace(":", "-").replace("+", "").replace(".", "-")
        h = hashlib.sha1(json.dumps(data, default=str, sort_keys=True).encode()).hexdigest()[:8]
        return f"{prefix}_{ts_safe}_{h}"

    def _write_index(self):
        self.index_path.write_text(json.dumps(self._index, indent=2, default=str))

    def _append_index(self, entry: dict):
        self._index.append(entry)
        self._index = self._index[-2000:]   # keep last 2000 entries
        self._write_index()

    def _safe_filename(self, name: str) -> str:
        """Sanitise a string for use as a filename."""
        return re.sub(r'[^\w.\-]', '_', str(name))[:80]

    # ─────────────────────────────────────────────────────────────────
    # PUBLIC API — one save_*_report method per agent
    # ─────────────────────────────────────────────────────────────────

    def save_email_report(self, report: dict, session_id: str = "standalone") -> str:
        """
        Save an EmailVerificationAgent report.
        Returns the file path written.
        """
        report_id   = self._make_id("email", report)
        folder      = self.base / "email"
        file_path   = folder / f"{report_id}.json"

        enriched = dict(report)
        enriched.setdefault("saved_at",    self._now_iso())
        enriched.setdefault("agent",       "EmailVerificationAgent")
        enriched.setdefault("session_id",  session_id)
        enriched.setdefault("report_id",   report_id)

        file_path.write_text(json.dumps(enriched, indent=2, default=str))

        self._append_index({
            "report_id":    report_id,
            "agent":        "EmailVerificationAgent",
            "saved_at":     enriched["saved_at"],
            "session_id":   session_id,
            "verdict":      report.get("risk_verdict", report.get("verdict", "UNKNOWN")),
            "risk_score":   report.get("risk_score", 0),
            "file":         str(file_path),
        })
        return str(file_path)

    def save_log_report(self, report: dict, session_id: str = "standalone") -> str:
        """
        Save a LogAnalyzerAgent report.
        Returns the file path written.
        """
        report_id   = self._make_id("log", report)
        folder      = self.base / "log"
        file_path   = folder / f"{report_id}.json"

        enriched = dict(report)
        enriched.setdefault("saved_at",    self._now_iso())
        enriched.setdefault("agent",       "LogAnalyzerAgent")
        enriched.setdefault("session_id",  session_id)
        enriched.setdefault("report_id",   report_id)

        file_path.write_text(json.dumps(enriched, indent=2, default=str))

        self._append_index({
            "report_id":    report_id,
            "agent":        "LogAnalyzerAgent",
            "saved_at":     enriched["saved_at"],
            "session_id":   session_id,
            "verdict":      report.get("final_label", report.get("verdict", "UNKNOWN")),
            "severity":     report.get("final_severity", "UNKNOWN"),
            "file":         str(file_path),
        })
        return str(file_path)

    def save_ip_report(self, report: dict, session_id: str = "standalone") -> str:
        """
        Save an IPRangeAnalyzerAgent report.
        Returns the file path written.
        """
        report_id   = self._make_id("ip", report)
        folder      = self.base / "ip"
        file_path   = folder / f"{report_id}.json"

        enriched = dict(report)
        enriched.setdefault("saved_at",    self._now_iso())
        enriched.setdefault("agent",       "IPRangeAnalyzerAgent")
        enriched.setdefault("session_id",  session_id)
        enriched.setdefault("report_id",   report_id)

        file_path.write_text(json.dumps(enriched, indent=2, default=str))

        summary = report.get("summary", {})
        self._append_index({
            "report_id":    report_id,
            "agent":        "IPRangeAnalyzerAgent",
            "saved_at":     enriched["saved_at"],
            "session_id":   session_id,
            "ip_range":     report.get("ip_range", "unknown"),
            "total_cves":   summary.get("total_cves_found", 0),
            "critical_hosts": summary.get("critical_hosts", []),
            "file":         str(file_path),
        })
        return str(file_path)

    # ─────────────────────────────────────────────────────────────────
    # Query helpers
    # ─────────────────────────────────────────────────────────────────

    def recent(self, n: int = 20, agent: str = None) -> list:
        """Return the n most recent index entries, optionally filtered by agent."""
        entries = list(reversed(self._index[-n * 5:]))
        if agent:
            entries = [e for e in entries if e.get("agent") == agent]
        return entries[:n]

    def by_session(self, session_id: str) -> list:
        return [e for e in self._index if e.get("session_id") == session_id]

    def stats(self) -> dict:
        total     = len(self._index)
        by_agent  = {}
        for e in self._index:
            a = e.get("agent", "unknown")
            by_agent[a] = by_agent.get(a, 0) + 1
        return {
            "total_reports": total,
            "by_agent":      by_agent,
            "memory_dir":    str(self.base),
            "subfolders":    {k: str(self.base / v) for k, v in self.SUBFOLDERS.items()},
        }


# Module-level singleton — agents import this
_DEFAULT_MEMORY: Optional[AgentMemory] = None


def get_memory(memory_dir: str = "memory") -> AgentMemory:
    """Return the global AgentMemory singleton (create once)."""
    global _DEFAULT_MEMORY
    if _DEFAULT_MEMORY is None or str(_DEFAULT_MEMORY.base) != memory_dir:
        _DEFAULT_MEMORY = AgentMemory(memory_dir=memory_dir)
    return _DEFAULT_MEMORY
