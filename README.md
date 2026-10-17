# CyberTriage Agent 🛡️

> **Graph Hacks Hackathon** — Autonomous Cybersecurity Triage powered by FalkorDB, Gemini, and Cytoscape.js

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Browser (index.html)                 │
│  ┌───────────────────────┐  ┌─────────────────────────┐ │
│  │   Cytoscape.js Graph  │  │  Agent Reasoning Sidebar│ │
│  │  (Multi-hop highlight)│  │  (SSE real-time stream) │ │
│  └───────────────────────┘  └─────────────────────────┘ │
└─────────────────────┬───────────────────────────────────┘
                      │ HTTP / SSE
┌─────────────────────▼───────────────────────────────────┐
│                   FastAPI (main.py)                      │
│  POST /trigger_investigation                             │
│  GET  /graph_state        GET /agent_trace               │
│  GET  /stream_trace/{id}  GET /health                    │
└────────────┬──────────────────────┬──────────────────────┘
             │                      │
┌────────────▼──────────┐  ┌────────▼──────────────────────┐
│   agent.py            │  │  database.py                  │
│   ReAct Loop          │  │  FalkorDB connector            │
│   Gemini function     │  └────────┬──────────────────────┘
│   calling             │           │ Cypher
│   Confidence scoring  │  ┌────────▼──────────────────────┐
│   Auto-remediation    │  │  FalkorDB (security_graph)    │
└────────────┬──────────┘  │  Nodes: IP, Device, User,    │
             │              │         Service, Alert         │
┌────────────▼──────────┐  │  Edges: ACCESSED, OWNS,      │
│   tools.py (MCP)      │  │         TRIGGERED,             │
│   5 Cypher tools      ├──►         COMMUNICATES_WITH      │
│   JSON Schema registry│  └───────────────────────────────┘
└───────────────────────┘
```

## Attack Path Seeded

```
192.168.1.200 (Malicious IP)
  ──[ACCESSED]──► Server-PROD-01 (Device)           ← Hop 1
  ──[ACCESSED]──► Server-PROD-02 (Device)
                      ↑
              [COMMUNICATES_WITH]
                      │
              jsmith (User, compromised)             ← Hop 2
                ──[OWNS]──► Server-PROD-01
                ──[ACCESSED]──► DB-CRITICAL          ← Hop 3 (blast radius)
                ──[ACCESSED]──► Auth-API
                ──[ACCESSED]──► HR-Portal
                ──[TRIGGERED]──► ALERT-001 (Alert)
```

## Quick Start

### 1. Prerequisites

- Python 3.11+
- [FalkorDB](https://docs.falkordb.com/getting-started.html) running on `localhost:6379`
  ```bash
  # Docker one-liner
  docker run -p 6379:6379 falkordb/falkordb:latest
  ```
- A Gemini API key from [Google AI Studio](https://aistudio.google.com/)

### 2. Install dependencies

```bash
cd cybersec-triage-agent
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 3. Configure

```bash
cp .env.example .env
# Edit .env and set GEMINI_API_KEY=...
```

Then load it:
```bash
export $(cat .env | xargs)
```

### 4. Seed the graph

```bash
python seed.py
```

Expected output:
```
Seed complete — 10 nodes, 11 edges in 'security_graph'.
```

### 5. Start the API

```bash
uvicorn main:app --reload --port 8000
```

### 6. Open the dashboard

Navigate to **http://localhost:8000** in your browser.

---

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/trigger_investigation` | Start autonomous triage. Body: `{"alert_id": "ALERT-001"}` |
| `GET`  | `/graph_state` | All nodes + edges in Cytoscape.js format |
| `GET`  | `/agent_trace` | Full reasoning trace of last investigation |
| `GET`  | `/stream_trace/{alert_id}` | SSE stream of reasoning steps (real-time) |
| `GET`  | `/health` | FalkorDB connectivity check |
| `GET`  | `/` | Dashboard UI |

---

## MCP Tools

| Tool | Cypher Op | When Called |
|------|-----------|-------------|
| `get_alert_context` | `MATCH (src)-[:TRIGGERED]->(a:Security_Alert)` | Hop 0 — always first |
| `trace_lateral_movement` | `MATCH (ip)-[*1..3]->(target)` | Hop 1 — after malicious IP identified |
| `identify_blast_radius` | `MATCH (u:User)-[:ACCESSED]->(s:Service)` | Hop 2 — after user identified |
| `isolate_device` | `SET d.status = 'Isolated'` | Remediation (confidence ≥ 0.80) |
| `revoke_user_tokens` | `SET u.auth_status = 'revoked'` | Remediation (confidence ≥ 0.80) |

---

## Confidence Scoring

| Evidence | Δ Confidence |
|----------|-------------|
| Malicious-reputation IP found | +0.20 |
| Lateral movement hop confirmed | +0.10 per hop (max +0.20) |
| PII-bearing service accessed | +0.10 |
| Compromised user has admin rights | +0.10 |

**Threshold:** `0.80` — autonomous remediation fires when reached.

---

## Project Structure

```
cybersec-triage-agent/
├── database.py          # FalkorDB connection utility
├── seed.py              # Graph population script
├── tools.py             # MCP tool definitions (5 tools + JSON Schema registry)
├── agent.py             # ReAct loop, Gemini function-calling, confidence engine
├── main.py              # FastAPI app + SSE streaming
├── requirements.txt
├── .env.example
└── templates/
    └── index.html       # Cytoscape.js dashboard
```
