"""
main.py — FastAPI application for the Cybersecurity Triage Agent.

Endpoints:
    POST /trigger_investigation  — Start the ReAct agent for an alert.
    GET  /graph_state            — Return all nodes + edges in Cytoscape.js format.
    GET  /agent_trace            — Return the reasoning trace from the last run.
    GET  /health                 — Database connectivity check.
    GET  /                       — Serve the dashboard UI (index.html).

Real-time updates are pushed via Server-Sent Events (SSE) at:
    GET  /stream_trace/{alert_id}
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncGenerator

import uvicorn
from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from agent import TriageResult, run_investigation
from database import get_graph, health_check

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
)
logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# In-memory state (single-process demo; swap for Redis in production)
# ─────────────────────────────────────────────────────────────────────────────

_latest_result: TriageResult | None = None
_active_investigations: dict[str, str] = {}   # alert_id → status
_sse_queues: dict[str, asyncio.Queue] = {}     # alert_id → event queue


# ─────────────────────────────────────────────────────────────────────────────
# Lifespan
# ─────────────────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting Cybersecurity Triage Agent API …")
    hc = health_check()
    if hc["status"] != "ok":
        logger.warning("FalkorDB health check returned: %s", hc)
    else:
        logger.info("FalkorDB connection OK → graph: %s", hc["graph"])
    yield
    logger.info("Shutting down.")


# ─────────────────────────────────────────────────────────────────────────────
# App
# ─────────────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="Cybersecurity Triage Agent",
    description="Autonomous graph-powered security triage with multi-hop reasoning.",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static files (if any assets are added later)
_STATIC_DIR = Path(__file__).parent / "static"
if _STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")


# ─────────────────────────────────────────────────────────────────────────────
# Pydantic models
# ─────────────────────────────────────────────────────────────────────────────

class InvestigationRequest(BaseModel):
    alert_id: str = "ALERT-001"


class InvestigationResponse(BaseModel):
    alert_id: str
    status: str
    message: str


# ─────────────────────────────────────────────────────────────────────────────
# Helper — run agent in background and push SSE events
# ─────────────────────────────────────────────────────────────────────────────

async def _run_agent_background(alert_id: str) -> None:
    global _latest_result
    _active_investigations[alert_id] = "running"

    # Create SSE queue for this alert
    queue: asyncio.Queue = asyncio.Queue()
    _sse_queues[alert_id] = queue

    try:
        loop = asyncio.get_running_loop()
        result: TriageResult = await loop.run_in_executor(
            None, run_investigation, alert_id
        )
        _latest_result = result
        _active_investigations[alert_id] = "completed"

        # Push each trace step as an SSE event
        for step in result.reasoning_trace:
            await queue.put(json.dumps(step))
        await queue.put("__DONE__")

    except Exception as exc:
        logger.error("Investigation failed: %s", exc)
        _active_investigations[alert_id] = "error"
        await queue.put(json.dumps({"type": "error", "content": str(exc)}))
        await queue.put("__DONE__")


# ─────────────────────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def serve_dashboard():
    """Serve the explainability dashboard."""
    index_path = Path(__file__).parent / "templates" / "index.html"
    if not index_path.exists():
        raise HTTPException(status_code=404, detail="Dashboard HTML not found.")
    return HTMLResponse(content=index_path.read_text(encoding="utf-8"))


@app.get("/health", tags=["System"])
async def api_health() -> dict:
    """Database + API health check."""
    return health_check()


@app.post("/trigger_investigation", response_model=InvestigationResponse, tags=["Agent"])
async def trigger_investigation(
    request: InvestigationRequest,
    background_tasks: BackgroundTasks,
) -> InvestigationResponse:
    """
    Start an autonomous triage investigation for the given alert_id.
    The agent runs in the background; poll /agent_trace or listen to
    /stream_trace/{alert_id} for real-time updates.
    """
    alert_id = request.alert_id
    if _active_investigations.get(alert_id) == "running":
        return InvestigationResponse(
            alert_id=alert_id,
            status="already_running",
            message=f"Investigation for '{alert_id}' is already in progress.",
        )

    background_tasks.add_task(_run_agent_background, alert_id)
    return InvestigationResponse(
        alert_id=alert_id,
        status="started",
        message=f"Investigation for '{alert_id}' started. Stream at /stream_trace/{alert_id}",
    )


@app.get("/graph_state", tags=["Graph"])
async def graph_state() -> dict:
    """
    Return all nodes and edges from FalkorDB in Cytoscape.js-compatible JSON.

    Cytoscape elements format:
        { "nodes": [...], "edges": [...] }

    Each node:  { "data": { "id", "label", "type", ...props } }
    Each edge:  { "data": { "id", "source", "target", "label", ...props } }
    """
    graph = get_graph()

    # ── Fetch nodes ──────────────────────────────────────────────────────────
    node_result = graph.query(
        "MATCH (n) RETURN n, labels(n) AS lbs, id(n) AS nid"
    )
    nodes = []
    id_map: dict[int, str] = {}   # internal DB id → user-facing id

    for row in node_result.result_set:
        node, labels, nid = row
        props = dict(node.properties)
        node_id = props.get("id") or f"node-{nid}"
        id_map[nid] = node_id
        label_str = list(labels)[0] if labels else "Unknown"
        nodes.append({
            "data": {
                "id": node_id,
                "label": props.get("label") or props.get("name") or node_id,
                "type": label_str,
                **props,
            }
        })

    # ── Fetch edges ──────────────────────────────────────────────────────────
    edge_result = graph.query(
        "MATCH (a)-[r]->(b) RETURN id(a) AS src, id(b) AS tgt, type(r) AS rtype, properties(r) AS rprops, id(r) AS rid"
    )
    edges = []
    for row in edge_result.result_set:
        src_nid, tgt_nid, rtype, rprops, rid = row
        src_id = id_map.get(src_nid, str(src_nid))
        tgt_id = id_map.get(tgt_nid, str(tgt_nid))
        edge_props = dict(rprops) if rprops else {}
        edges.append({
            "data": {
                "id": f"edge-{rid}",
                "source": src_id,
                "target": tgt_id,
                "label": rtype,
                **edge_props,
            }
        })

    # ── Highlight nodes touched by last investigation ────────────────────────
    touched: set[str] = set()
    if _latest_result:
        touched = set(_latest_result.graph_nodes_touched)

    for node in nodes:
        node["data"]["highlighted"] = node["data"]["id"] in touched

    return {
        "nodes": nodes,
        "edges": edges,
        "meta": {
            "node_count": len(nodes),
            "edge_count": len(edges),
            "highlighted_count": len(touched),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        },
    }


@app.get("/agent_trace", tags=["Agent"])
async def agent_trace() -> dict:
    """
    Return the full reasoning trace from the most recent investigation.
    """
    if _latest_result is None:
        return {
            "status": "no_investigation_run",
            "trace": [],
            "message": "POST /trigger_investigation first.",
        }
    return {
        "status": "ok",
        "alert_id": _latest_result.alert_id,
        "verdict": _latest_result.verdict,
        "confidence": _latest_result.confidence,
        "actions_taken": _latest_result.actions_taken,
        "summary": _latest_result.summary,
        "trace": _latest_result.reasoning_trace,
        "graph_nodes_touched": _latest_result.graph_nodes_touched,
        "started_at": _latest_result.started_at,
        "completed_at": _latest_result.completed_at,
    }


@app.get("/stream_trace/{alert_id}", tags=["Agent"])
async def stream_trace(alert_id: str) -> StreamingResponse:
    """
    Server-Sent Events endpoint. Streams reasoning trace steps in real-time
    as the agent executes.  Connect with EventSource in the browser.
    """
    async def event_generator() -> AsyncGenerator[str, None]:
        # Wait up to 2 s for the queue to be created (race with background task)
        for _ in range(20):
            if alert_id in _sse_queues:
                break
            await asyncio.sleep(0.1)

        queue = _sse_queues.get(alert_id)
        if queue is None:
            yield f"data: {json.dumps({'error': 'Investigation not found or not started'})}\n\n"
            return

        while True:
            try:
                item = await asyncio.wait_for(queue.get(), timeout=60.0)
            except asyncio.TimeoutError:
                yield "data: {\"type\": \"heartbeat\"}\n\n"
                continue

            if item == "__DONE__":
                yield f"data: {json.dumps({'type': 'done'})}\n\n"
                break
            yield f"data: {item}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/investigations", tags=["Agent"])
async def list_investigations() -> dict:
    """List all investigations and their statuses."""
    return {"investigations": _active_investigations}


# ─────────────────────────────────────────────────────────────────────────────
# Entry-point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info",
    )
