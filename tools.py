"""
tools.py — MCP-style tool definitions for the cybersecurity triage agent.

Each function is a discrete, typed tool that executes a specific Cypher query
against FalkorDB and returns a structured JSON-serialisable dict.

The tool registry at the bottom exposes every tool as a JSON Schema object
so the LLM can perform structured function-calling / MCP selection.
"""

from __future__ import annotations

import json
import logging
import textwrap
from datetime import datetime, timezone
from typing import Any

from database import get_graph

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Internal helper
# ─────────────────────────────────────────────────────────────────────────────

def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _run_query(cypher: str, params: dict | None = None) -> tuple[list, str]:
    """
    Execute a Cypher query, returning (result_set, cypher_used).
    Raises on DB error so callers can surface it in the trace.
    """
    graph = get_graph()
    logger.debug("Executing Cypher:\n%s\nParams: %s", cypher, params)
    result = graph.query(cypher, params or {})
    return result.result_set, cypher


def _row_to_dict(row: list, keys: list[str]) -> dict:
    """Zip a result-set row with its column keys."""
    return {k: (v.properties if hasattr(v, "properties") else v) for k, v in zip(keys, row)}


# ─────────────────────────────────────────────────────────────────────────────
# Tool 1 — get_alert_context
# ─────────────────────────────────────────────────────────────────────────────

def get_alert_context(alert_id: str) -> dict[str, Any]:
    """
    Fetch the Security_Alert node and its first-degree neighbours
    (the entities that triggered it).

    Args:
        alert_id: e.g. "ALERT-001"

    Returns:
        JSON-safe dict with alert details and triggering sources.
    """
    cypher = textwrap.dedent("""
        MATCH (src)-[r:TRIGGERED]->(a:Security_Alert {alert_id: $alert_id})
        RETURN a, src, type(r) AS rel_type, r
    """)
    try:
        rows, used_cypher = _run_query(cypher, {"alert_id": alert_id})
        sources = []
        alert_data: dict = {}
        for row in rows:
            alert_node, src_node, rel_type, rel = row
            if not alert_data:
                alert_data = dict(alert_node.properties)
            sources.append({
                "source_type": list(src_node.labels)[0] if src_node.labels else "Unknown",
                "source_properties": dict(src_node.properties),
                "relationship": rel_type,
                "relationship_properties": dict(rel.properties) if rel else {},
            })
        if not alert_data:
            # Alert exists but no incoming TRIGGERED edges — fetch it directly
            rows2, _ = _run_query(
                "MATCH (a:Security_Alert {alert_id: $id}) RETURN a",
                {"id": alert_id},
            )
            if rows2:
                alert_data = dict(rows2[0][0].properties)
        return {
            "tool": "get_alert_context",
            "cypher": used_cypher,
            "timestamp": _utcnow(),
            "alert_id": alert_id,
            "alert": alert_data,
            "triggering_sources": sources,
            "hop": 0,
        }
    except Exception as exc:
        logger.error("get_alert_context failed: %s", exc)
        return {"tool": "get_alert_context", "error": str(exc), "alert_id": alert_id}


# ─────────────────────────────────────────────────────────────────────────────
# Tool 2 — trace_lateral_movement
# ─────────────────────────────────────────────────────────────────────────────

def trace_lateral_movement(ip_address: str, max_hops: int = 3) -> dict[str, Any]:
    """
    Variable-length multi-hop traversal from a suspicious IP to find all
    reachable nodes within *max_hops* relationship hops.

    Args:
        ip_address: e.g. "192.168.1.200"
        max_hops:   maximum traversal depth (default 3)

    Returns:
        JSON-safe dict with all reachable nodes and the paths taken.
    """
    cypher = textwrap.dedent(f"""
        MATCH path = (ip:IP_Address {{address: $ip}})-[*1..{max_hops}]->(target)
        WHERE target <> ip
        RETURN ip, target, [r IN relationships(path) | type(r)] AS rel_types,
               length(path) AS hops,
               [n IN nodes(path) | n.id] AS node_ids,
               labels(target) AS target_labels
        ORDER BY hops
    """)
    try:
        rows, used_cypher = _run_query(cypher, {"ip": ip_address})
        traversal_paths: list[dict] = []
        seen_targets: set[str] = set()
        for row in rows:
            ip_node, target_node, rel_types, hops, node_ids, target_labels = row
            target_id = target_node.properties.get("id", str(target_node.id))
            seen_targets.add(target_id)
            traversal_paths.append({
                "hop_count": hops,
                "relationship_chain": rel_types,
                "path_node_ids": node_ids,
                "target": {
                    "id": target_id,
                    "labels": list(target_labels) if target_labels else [],
                    "properties": dict(target_node.properties),
                },
            })
        return {
            "tool": "trace_lateral_movement",
            "cypher": used_cypher,
            "timestamp": _utcnow(),
            "ip_address": ip_address,
            "max_hops": max_hops,
            "unique_targets_found": len(seen_targets),
            "traversal_paths": traversal_paths,
            "threat_confirmed": len(traversal_paths) > 0,
        }
    except Exception as exc:
        logger.error("trace_lateral_movement failed: %s", exc)
        return {"tool": "trace_lateral_movement", "error": str(exc), "ip_address": ip_address}


# ─────────────────────────────────────────────────────────────────────────────
# Tool 3 — identify_blast_radius
# ─────────────────────────────────────────────────────────────────────────────

def identify_blast_radius(user_id: str) -> dict[str, Any]:
    """
    Find all services the specified user has directly accessed and calculate
    the potential blast radius (sensitivity, PII exposure, etc.).

    Args:
        user_id: FalkorDB node id, e.g. "user-jsmith"

    Returns:
        JSON-safe dict with accessed services and blast-radius score.
    """
    cypher = textwrap.dedent("""
        MATCH (u:User {id: $uid})-[r:ACCESSED]->(s:Service)
        RETURN u, s, r
    """)
    try:
        rows, used_cypher = _run_query(cypher, {"uid": user_id})
        user_data: dict = {}
        services: list[dict] = []
        pii_exposed = False
        high_sensitivity_count = 0
        for row in rows:
            u_node, s_node, rel = row
            if not user_data:
                user_data = dict(u_node.properties)
            s_props = dict(s_node.properties)
            rel_props = dict(rel.properties) if rel else {}
            if s_props.get("contains_pii"):
                pii_exposed = True
            if s_props.get("data_sensitivity") in ("HIGH", "CRITICAL"):
                high_sensitivity_count += 1
            services.append({
                "service": s_props,
                "access_details": rel_props,
            })

        # Blast radius score (0–100)
        blast_score = min(100, len(services) * 15 + high_sensitivity_count * 20 + (30 if pii_exposed else 0))

        return {
            "tool": "identify_blast_radius",
            "cypher": used_cypher,
            "timestamp": _utcnow(),
            "user_id": user_id,
            "user": user_data,
            "services_accessed": services,
            "service_count": len(services),
            "pii_exposed": pii_exposed,
            "high_sensitivity_services": high_sensitivity_count,
            "blast_radius_score": blast_score,
            "critical": blast_score >= 60,
        }
    except Exception as exc:
        logger.error("identify_blast_radius failed: %s", exc)
        return {"tool": "identify_blast_radius", "error": str(exc), "user_id": user_id}


# ─────────────────────────────────────────────────────────────────────────────
# Tool 4 — isolate_device
# ─────────────────────────────────────────────────────────────────────────────

def isolate_device(device_id: str) -> dict[str, Any]:
    """
    Set the ``status`` property of a Device node to "Isolated" to reflect
    a containment action (e.g., network quarantine).

    Args:
        device_id: FalkorDB node id, e.g. "dev-prod-01"

    Returns:
        JSON-safe dict confirming the action taken.
    """
    cypher = textwrap.dedent("""
        MATCH (d:Device {id: $did})
        SET d.status = 'Isolated',
            d.isolated_at = $ts,
            d.isolation_reason = 'Autonomous agent containment action'
        RETURN d
    """)
    ts = _utcnow()
    try:
        rows, used_cypher = _run_query(cypher, {"did": device_id, "ts": ts})
        if not rows:
            return {
                "tool": "isolate_device",
                "cypher": used_cypher,
                "timestamp": ts,
                "device_id": device_id,
                "success": False,
                "detail": "Device not found",
            }
        device = dict(rows[0][0].properties)
        logger.warning("ACTION — Device %s has been ISOLATED at %s", device_id, ts)
        return {
            "tool": "isolate_device",
            "cypher": used_cypher,
            "timestamp": ts,
            "device_id": device_id,
            "success": True,
            "action": "ISOLATE",
            "device": device,
            "detail": f"Device '{device.get('hostname', device_id)}' status set to Isolated.",
        }
    except Exception as exc:
        logger.error("isolate_device failed: %s", exc)
        return {"tool": "isolate_device", "error": str(exc), "device_id": device_id, "success": False}


# ─────────────────────────────────────────────────────────────────────────────
# Tool 5 — revoke_user_tokens
# ─────────────────────────────────────────────────────────────────────────────

def revoke_user_tokens(user_id: str) -> dict[str, Any]:
    """
    Set ``auth_status`` to "revoked" on a User node to reflect forced
    session termination / token invalidation.

    Args:
        user_id: FalkorDB node id, e.g. "user-jsmith"

    Returns:
        JSON-safe dict confirming the action taken.
    """
    cypher = textwrap.dedent("""
        MATCH (u:User {id: $uid})
        SET u.auth_status = 'revoked',
            u.revoked_at = $ts,
            u.revocation_reason = 'Autonomous agent security action'
        RETURN u
    """)
    ts = _utcnow()
    try:
        rows, used_cypher = _run_query(cypher, {"uid": user_id, "ts": ts})
        if not rows:
            return {
                "tool": "revoke_user_tokens",
                "cypher": used_cypher,
                "timestamp": ts,
                "user_id": user_id,
                "success": False,
                "detail": "User not found",
            }
        user = dict(rows[0][0].properties)
        logger.warning("ACTION — Tokens for user %s REVOKED at %s", user_id, ts)
        return {
            "tool": "revoke_user_tokens",
            "cypher": used_cypher,
            "timestamp": ts,
            "user_id": user_id,
            "success": True,
            "action": "REVOKE_TOKENS",
            "user": user,
            "detail": f"User '{user.get('username', user_id)}' auth_status set to revoked.",
        }
    except Exception as exc:
        logger.error("revoke_user_tokens failed: %s", exc)
        return {"tool": "revoke_user_tokens", "error": str(exc), "user_id": user_id, "success": False}


# ─────────────────────────────────────────────────────────────────────────────
# Tool registry — JSON Schema for LLM function-calling / MCP tool selection
# ─────────────────────────────────────────────────────────────────────────────

TOOL_REGISTRY: list[dict] = [
    {
        "name": "get_alert_context",
        "description": (
            "Fetch a Security_Alert node and all entities that triggered it. "
            "Use this as the FIRST step of any investigation to understand the "
            "initial signal before tracing further."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "alert_id": {
                    "type": "string",
                    "description": "The alert_id field of the Security_Alert node, e.g. 'ALERT-001'.",
                }
            },
            "required": ["alert_id"],
        },
    },
    {
        "name": "trace_lateral_movement",
        "description": (
            "Execute a variable-length graph traversal (up to 3 hops) from a "
            "suspicious IP address to discover all reachable devices, users, and "
            "services. Use this AFTER get_alert_context when a malicious IP is "
            "identified."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "ip_address": {
                    "type": "string",
                    "description": "The IP address string, e.g. '192.168.1.200'.",
                },
                "max_hops": {
                    "type": "integer",
                    "description": "Maximum traversal depth (1–5). Default 3.",
                    "default": 3,
                },
            },
            "required": ["ip_address"],
        },
    },
    {
        "name": "identify_blast_radius",
        "description": (
            "Find all services a compromised user has accessed and calculate a "
            "blast-radius score. Call this when you have identified a compromised "
            "user ID from earlier hops."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "user_id": {
                    "type": "string",
                    "description": "The id field of the User node, e.g. 'user-jsmith'.",
                }
            },
            "required": ["user_id"],
        },
    },
    {
        "name": "isolate_device",
        "description": (
            "REMEDIATION ACTION: Set a Device node's status to 'Isolated' to "
            "reflect containment. Only call when threat is confirmed via multi-hop "
            "trace AND confidence ≥ 0.80."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "device_id": {
                    "type": "string",
                    "description": "The id field of the Device node, e.g. 'dev-prod-01'.",
                }
            },
            "required": ["device_id"],
        },
    },
    {
        "name": "revoke_user_tokens",
        "description": (
            "REMEDIATION ACTION: Revoke all sessions/tokens for a User by setting "
            "auth_status to 'revoked'. Only call when a user account is confirmed "
            "compromised AND confidence ≥ 0.80."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "user_id": {
                    "type": "string",
                    "description": "The id field of the User node, e.g. 'user-jsmith'.",
                }
            },
            "required": ["user_id"],
        },
    },
]

# Python dispatch map for the agent loop
TOOL_DISPATCH: dict[str, Any] = {
    "get_alert_context": get_alert_context,
    "trace_lateral_movement": trace_lateral_movement,
    "identify_blast_radius": identify_blast_radius,
    "isolate_device": isolate_device,
    "revoke_user_tokens": revoke_user_tokens,
}


def dispatch(tool_name: str, arguments: dict) -> dict:
    """
    Dispatch a tool call by name, returning its JSON-safe result dict.
    Raises KeyError if tool_name is unknown.
    """
    fn = TOOL_DISPATCH[tool_name]
    return fn(**arguments)
