# 🛡️ Multi-Agent Cybersecurity Threat Detection & Correlation System

> **Based on:** "A Multi-Agent System for Cybersecurity Threat Detection and Correlation using Large Language Models"  
> **Published in:** IEEE Access — DOI: [10.1109/ACCESS.2025.3602681](https://doi.org/10.1109/ACCESS.2025.3602681)

A modular, LLM-powered multi-agent pipeline for automated cybersecurity threat analysis. The system scans IP ranges, analyses email headers, parses logs, and correlates findings into unified risk reports — all driven by large language models via the Groq API. 

---

## 📐 Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Task Dispatcher GUI                  │
│              (task_dispatcher_gui.py)                   │
└────────────┬────────────────────────────────────────────┘
             │
   ┌─────────▼──────────┐
   │    Agent Pool       │
   ├─────────────────────┤
   │  EmailVerification  │  ← Analyses email headers & sender reputation
   │  LogAnalyzer        │  ← Parses system/network logs for anomalies
   │  IPRangeAnalyzer    │  ← Scans hosts for open ports & CVEs
   │  CorrelationAgent   │  ← Cross-agent threat correlation
   └─────────┬───────────┘
             │
   ┌─────────▼───────────┐
   │    Agent Memory      │  ← Persistent shared storage (agent_memory.py)
   │  memory/             │
   │    email/            │
   │    log/              │
   │    ip/               │
   │    correlation/      │
   │    index.json        │
   └──────────────────────┘
```

---

## 🗂️ Project Structure

```
.
├── task_dispatcher_gui.py    # GUI front-end for dispatching agent tasks
├── agent_memory.py           # Shared persistent storage for all agents
├── key_manager.py            # Groq API key rotation (up to 10 keys)
├── evaluate_correlation.py   # Evaluation harness for correlation quality
├── email_vdb.index           # FAISS vector index for email intelligence
├── memory/                   # Created at runtime — agent report storage
│   ├── email/
│   ├── log/
│   ├── ip/
│   └── correlation/
│       ├── results/
│       └── entities/
└── README.md
```

---

## ✨ Features

- **IP Range Scanning** — Nmap-based host discovery with service fingerprinting and CVE lookup
- **Email Verification** — Header analysis, sender reputation scoring, and phishing detection
- **Log Analysis** — LLM-driven parsing of system and network logs for anomalous patterns
- **Threat Correlation** — Cross-source IOC correlation with chain-of-thought LLM reasoning
- **Shared Agent Memory** — All agents write to a unified file-based store with a cross-agent index
- **API Key Rotation** — Automatic Groq key rotation on rate limits (supports up to 10 keys)
- **GUI Dispatcher** — Desktop GUI for task submission and report review

---

## 🚀 Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/<your-username>/<repo-name>.git
cd <repo-name>
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

> Key dependencies: `groq`, `faiss-cpu`, `python-nmap`, `tkinter` (usually bundled with Python)

### 3. Configure API keys

```bash
export GROQ_API_KEYS="gsk_key1,gsk_key2,gsk_key3"
```

Or pass keys directly in code:

```python
from key_manager import build_key_manager
km = build_key_manager("gsk_key1,gsk_key2")
```

### 4. Launch the GUI

```bash
python task_dispatcher_gui.py
```

### 5. Run programmatically

```python
from agent_memory import AgentMemory

mem = AgentMemory()
mem.save_ip_report(report_dict, session_id="scan-001")
mem.save_email_report(report_dict, session_id="scan-001")

# Query recent reports
print(mem.recent(n=10))
print(mem.stats())
```

---

## 🔑 Key Manager

Handles automatic key rotation when a Groq API key hits its rate limit (HTTP 429).

```python
from key_manager import KeyManager

km = KeyManager(["gsk_key1", "gsk_key2", "gsk_key3"])

# Use in any agent
result = km.call_with_rotation(
    lambda key: groq.Groq(api_key=key).chat.completions.create(
        model="llama3-70b-8192",
        messages=[{"role": "user", "content": "Analyse this threat..."}]
    )
)

# Check pool status
print(km.status())
```

Supports up to **10 keys** with a configurable cooldown window (default: 60 seconds).

---

## 🧠 Agent Memory

All agents share a single `AgentMemory` instance backed by the local filesystem.

```python
from agent_memory import get_memory

mem = get_memory()                         # Global singleton
mem.save_email_report(report)
mem.save_log_report(report)
mem.save_ip_report(report)

# Cross-agent queries
mem.recent(n=20, agent="IPRangeAnalyzerAgent")
mem.by_session("session-abc123")
mem.stats()
```

The lightweight `index.json` keeps the last **2,000** entries across all agents for fast querying without loading individual report files.

---

## 📊 Sample Output

The IP agent produces structured JSON reports with per-port CVE details and an LLM chain-of-thought analysis. Example (abbreviated):

```json
{
  "ip_range": "192.168.1.10",
  "summary": {
    "total_hosts": 1,
    "total_cves_found": 6,
    "critical_hosts": ["192.168.1.10"]
  },
  "llm_analysis": "Host risk level is CRITICAL due to CVE-2011-2523 (CVSS 9.8)..."
}
```

---

## 📈 Evaluation

Run the correlation evaluation harness to benchmark agent output quality:

```bash
python evaluate_correlation.py --memory-dir memory/ --output results/
```

---

## 📄 Citation

If you use this system in your research, please cite:

```bibtex
@article{yourpaper2025,
  title   = {A Multi-Agent System for Cybersecurity Threat Detection and
             Correlation using Large Language Models},
  journal = {IEEE Access},
  year    = {2025},
  doi     = {10.1109/ACCESS.2025.3602681}
}
```

---

## 📜 License

This project is released for research purposes. See [LICENSE](LICENSE) for details.
