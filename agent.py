"""
agent.py — ReAct (Reason + Act) cybersecurity triage agent.

The agent loop:
1. Receives a Security_Alert ID as input.
2. Iteratively reasons about what tool to call next using the Gemini API
   with structured function-calling.
3. Dispatches the chosen tool against FalkorDB.
4. Appends every step to a ``reasoning_trace`` for full explainability.
5. Evaluates a confidence threshold; when threat is confirmed (≥ 0.80)
   it autonomously calls isolate_device / revoke_user_tokens.
6. Returns a complete TriageResult containing the trace and final verdict.

Environment:
    GEMINI_API_KEY  — required for LLM calls.
    CONFIDENCE_THRESHOLD — float 0-1 (default 0.80).
"""

from __future__ import annotations

import json
import logging
import os
import textwrap
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from google import genai
from google.genai import types as genai_types

from tools import TOOL_REGISTRY, dispatch

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────────────────────────────────

_MODEL = "gemini-3.8-flash"
_MAX_ITERATIONS = 12          # safety cap on ReAct loop
_CONFIDENCE_THRESHOLD = float(os.getenv("CONFIDENCE_THRESHOLD", "0.80"))

# ─────────────────────────────────────────────────────────────────────────────
# Data classes
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class TraceStep:
    step_index: int
    timestamp: str
    hop: int
    type: str                  # "reasoning" | "tool_call" | "tool_result" | "action" | "verdict"
    content: str               # human-readable explanation
    tool_name: str | None = None
    tool_arguments: dict | None = None
    tool_result: dict | None = None
    cypher_query: str | None = None
    confidence: float | None = None
    nodes_involved: list[str] = field(default_factory=list)
    edges_involved: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if v is not None and v != []}


@dataclass
class TriageResult:
    alert_id: str
    started_at: str
    completed_at: str
    verdict: str               # "THREAT_CONFIRMED" | "THREAT_UNCONFIRMED" | "ERROR"
    confidence: float
    actions_taken: list[str]
    reasoning_trace: list[dict]
    graph_nodes_touched: list[str]
    graph_edges_touched: list[str]
    summary: str

    def to_dict(self) -> dict:
        return self.__dict__


# ─────────────────────────────────────────────────────────────────────────────
# System prompt
# ─────────────────────────────────────────────────────────────────────────────

_SYSTEM_PROMPT = textwrap.dedent("""
You are an autonomous cybersecurity triage agent backed by a live enterprise
knowledge graph (FalkorDB).  Your task is to investigate a security alert and
determine whether the threat is real.

ReAct Protocol
--------------
You will iterate through Thought → Action cycles:
- THOUGHT: Explain your reasoning about the current state of the investigation,
  what you know so far, and what question you must answer next.
- ACTION: Call exactly ONE tool from the tool registry to gather evidence or
  take a containment action.

Investigation Flow (follow this order)
--------------------------------------
Hop 0  — Call get_alert_context with the given alert_id.
Hop 1  — Identify suspicious IPs from the triggering sources, then call
          trace_lateral_movement to discover connected devices and users.
Hop 2  — For any compromised user found, call identify_blast_radius to
          enumerate the affected services.
Hop 3  — Evaluate confidence.  If ≥ 0.80 and threat is confirmed:
          a) Call isolate_device for each critical device found.
          b) Call revoke_user_tokens for each compromised user found.

Confidence Calculation
-----------------------
Start at 0.50.  Add:
  +0.20 if a malicious-reputation IP accessed a device.
  +0.10 per additional hop of confirmed lateral movement (max +0.20).
  +0.10 if PII-bearing services were accessed.
  +0.10 if the compromised user has admin/superadmin privileges.

Stopping Conditions
-------------------
Stop when: threat confirmed + remediation actions taken, OR max hops reached,
OR evidence conclusively shows a false-positive (confidence < 0.30).

Output Format
-------------
Before calling each tool, output a THOUGHT block:
  THOUGHT: <your reasoning>

After receiving each tool result, summarise what you learned in one sentence.
Do NOT hallucinate graph data — only reason from tool results.
""").strip()


# ─────────────────────────────────────────────────────────────────────────────
# Agent
# ─────────────────────────────────────────────────────────────────────────────

class CyberTriageAgent:
    """
    Stateful ReAct agent.  One instance per investigation.
    """

    def __init__(self, alert_id: str) -> None:
        self.alert_id = alert_id
        self.client = genai.Client(api_key=os.environ["GEMINI_API_KEY"])
        self.confidence: float = 0.50
        self.actions_taken: list[str] = []
        self.reasoning_trace: list[dict] = []
        self.graph_nodes_touched: list[str] = []
        self.graph_edges_touched: list[str] = []
        self._step_index: int = 0
        self._hop: int = 0
        self._tool_results_so_far: list[dict] = []   # accumulate context
        self._previous_interaction_id: str | None = None

    # ── trace helpers ────────────────────────────────────────────────────────

    def _log(self, step: TraceStep) -> None:
        self.reasoning_trace.append(step.to_dict())
        logger.info("[Step %02d | Hop %d | %s] %s", step.step_index, step.hop, step.type, step.content[:120])

    def _next_step(self, **kwargs) -> TraceStep:
        self._step_index += 1
        return TraceStep(
            step_index=self._step_index,
            timestamp=datetime.now(timezone.utc).isoformat(),
            hop=self._hop,
            **kwargs,
        )

    def _record_graph_contact(self, tool_result: dict) -> None:
        """Extract node/edge IDs from a tool result for graph highlighting."""
        # Nodes from traversal paths
        for path in tool_result.get("traversal_paths", []):
            for nid in path.get("path_node_ids", []):
                if nid and nid not in self.graph_nodes_touched:
                    self.graph_nodes_touched.append(nid)
            target = path.get("target", {})
            tid = target.get("id", "")
            if tid and tid not in self.graph_nodes_touched:
                self.graph_nodes_touched.append(tid)

        # Alert and triggering sources
        for src in tool_result.get("triggering_sources", []):
            sid = src.get("source_properties", {}).get("id", "")
            if sid and sid not in self.graph_nodes_touched:
                self.graph_nodes_touched.append(sid)

        # User
        user = tool_result.get("user", {})
        if isinstance(user, dict):
            uid = user.get("id", "")
            if uid and uid not in self.graph_nodes_touched:
                self.graph_nodes_touched.append(uid)

        # Services
        for svc_entry in tool_result.get("services_accessed", []):
            svc = svc_entry.get("service", {})
            svid = svc.get("id", "")
            if svid and svid not in self.graph_nodes_touched:
                self.graph_nodes_touched.append(svid)

        # Device after action
        device = tool_result.get("device", {})
        if isinstance(device, dict):
            did = device.get("id", "")
            if did and did not in self.graph_nodes_touched:
                self.graph_nodes_touched.append(did)

    # ── confidence update ────────────────────────────────────────────────────

    def _update_confidence(self, tool_name: str, result: dict) -> None:
        if tool_name == "trace_lateral_movement":
            if result.get("threat_confirmed"):
                self.confidence = min(1.0, self.confidence + 0.20)
                hops = len({p["hop_count"] for p in result.get("traversal_paths", [])})
                self.confidence = min(1.0, self.confidence + 0.10 * min(hops, 2))
        elif tool_name == "identify_blast_radius":
            if result.get("pii_exposed"):
                self.confidence = min(1.0, self.confidence + 0.10)
            user = result.get("user", {})
            if isinstance(user, dict) and user.get("privilege_level") in ("admin", "superadmin"):
                self.confidence = min(1.0, self.confidence + 0.10)
        elif tool_name == "get_alert_context":
            for src in result.get("triggering_sources", []):
                props = src.get("source_properties", {})
                if props.get("reputation") == "malicious":
                    self.confidence = min(1.0, self.confidence + 0.20)
                    break

    # ── tool dispatch ────────────────────────────────────────────────────────

    def _call_tool(self, tool_name: str, arguments: dict) -> dict:
        step = self._next_step(
            type="tool_call",
            content=f"Calling tool '{tool_name}' with args: {json.dumps(arguments)}",
            tool_name=tool_name,
            tool_arguments=arguments,
        )
        self._log(step)

        result = dispatch(tool_name, arguments)
        self._update_confidence(tool_name, result)
        self._record_graph_contact(result)
        self._tool_results_so_far.append(result)

        result_step = self._next_step(
            type="tool_result",
            content=f"Tool '{tool_name}' returned {len(json.dumps(result))} bytes. Confidence now {self.confidence:.2f}.",
            tool_name=tool_name,
            tool_result=result,
            cypher_query=result.get("cypher"),
            confidence=self.confidence,
            nodes_involved=self.graph_nodes_touched[:],
        )
        self._log(result_step)
        return result

    # ── LLM reason + act ────────────────────────────────────────────────────

    def _build_context_message(self) -> str:
        """Summarise the investigation so far into a compact LLM prompt."""
        lines = [
            f"CURRENT INVESTIGATION STATUS",
            f"Alert ID: {self.alert_id}",
            f"Current confidence: {self.confidence:.2f}",
            f"Confidence threshold for action: {_CONFIDENCE_THRESHOLD}",
            f"Actions already taken: {self.actions_taken or 'none'}",
            "",
            "TOOL RESULTS COLLECTED SO FAR:",
        ]
        for i, res in enumerate(self._tool_results_so_far):
            lines.append(f"\n[Result {i + 1}] Tool: {res.get('tool', '?')}")
            # Include a compact JSON summary (cap at ~600 chars)
            compact = json.dumps(res, indent=2)
            if len(compact) > 600:
                compact = compact[:600] + " …(truncated)"
            lines.append(compact)

        lines += [
            "",
            "NEXT STEP:",
            "Output a THOUGHT explaining your reasoning, then call the most appropriate tool.",
            "If the investigation is complete (threat confirmed + actions taken, or false positive), output STOP.",
        ]
        return "\n".join(lines)

    def _llm_next_action(self) -> tuple[str | None, dict | None, str]:
        """
        Ask the LLM for the next tool to call.
        Returns (tool_name, arguments, thought_text).
        Returns (None, None, thought_text) when agent decides to stop.
        """
        user_msg = self._build_context_message()

        # Build function declarations from our registry
        tool_declarations = [
            genai_types.FunctionDeclaration(
                name=t["name"],
                description=t["description"],
                parameters=t["parameters"],
            )
            for t in TOOL_REGISTRY
        ]

        kwargs: dict[str, Any] = dict(
            model=_MODEL,
            input=user_msg,
            system_instruction=_SYSTEM_PROMPT,
            tools=[genai_types.Tool(function_declarations=tool_declarations)],
            store=False,
        )
        if self._previous_interaction_id:
            kwargs["previous_interaction_id"] = self._previous_interaction_id

        interaction = self.client.interactions.create(**kwargs)
        self._previous_interaction_id = interaction.id

        # Extract thought and function call from steps
        thought_text = ""
        tool_name: str | None = None
        arguments: dict = {}

        for step in interaction.steps:
            if step.type == "thought" and hasattr(step, "summary") and step.summary:
                thought_text = step.summary
            elif step.type == "model_output":
                for part in getattr(step, "content", []):
                    if hasattr(part, "type") and part.type == "text":
                        text = part.text or ""
                        if "THOUGHT:" in text:
                            thought_text = text.split("THOUGHT:")[-1].strip().split("\n")[0]
                        if "STOP" in text and not tool_name:
                            return None, None, thought_text or text
            elif step.type == "function_call":
                tool_name = step.name
                arguments = step.arguments or {}

        return tool_name, arguments if tool_name else None, thought_text

    # ── remediation ──────────────────────────────────────────────────────────

    def _run_remediation(self) -> None:
        """After threat confirmed, autonomously isolate devices & revoke tokens."""
        self._hop = 3

        # Gather target IDs from accumulated results
        devices_to_isolate: list[str] = []
        users_to_revoke: list[str] = []

        for res in self._tool_results_so_far:
            # Devices from lateral movement
            for path in res.get("traversal_paths", []):
                target = path.get("target", {})
                if "Device" in target.get("labels", []):
                    did = target.get("id", "")
                    if did and did not in devices_to_isolate:
                        devices_to_isolate.append(did)
            # Users from blast radius
            if res.get("tool") == "identify_blast_radius" and res.get("critical"):
                uid = res.get("user_id", "")
                if uid and uid not in users_to_revoke:
                    users_to_revoke.append(uid)

        for did in devices_to_isolate:
            action_step = self._next_step(
                type="action",
                content=f"THREAT CONFIRMED (confidence={self.confidence:.2f}). Isolating device '{did}'.",
                confidence=self.confidence,
            )
            self._log(action_step)
            result = self._call_tool("isolate_device", {"device_id": did})
            if result.get("success"):
                self.actions_taken.append(f"ISOLATED:{did}")

        for uid in users_to_revoke:
            action_step = self._next_step(
                type="action",
                content=f"THREAT CONFIRMED (confidence={self.confidence:.2f}). Revoking tokens for user '{uid}'.",
                confidence=self.confidence,
            )
            self._log(action_step)
            result = self._call_tool("revoke_user_tokens", {"user_id": uid})
            if result.get("success"):
                self.actions_taken.append(f"REVOKED:{uid}")

    # ── main loop ────────────────────────────────────────────────────────────

    def run(self) -> TriageResult:
        started_at = datetime.now(timezone.utc).isoformat()
        logger.info("=== Starting triage for alert '%s' ===", self.alert_id)

        verdict = "THREAT_UNCONFIRMED"
        summary = ""
        remediation_done = False

        # Initial kickoff step
        init_step = self._next_step(
            type="reasoning",
            content=f"Investigation started for alert '{self.alert_id}'. Beginning ReAct loop.",
        )
        self._log(init_step)

        for iteration in range(_MAX_ITERATIONS):
            self._hop = min(iteration, 3)

            # ── LLM decides next action ──────────────────────────────────────
            try:
                tool_name, arguments, thought = self._llm_next_action()
            except Exception as exc:
                logger.error("LLM call failed at iteration %d: %s", iteration, exc)
                thought_step = self._next_step(
                    type="reasoning",
                    content=f"LLM call failed: {exc}. Attempting fallback rule-based step.",
                )
                self._log(thought_step)
                # Fallback: run tools in fixed order
                tool_name, arguments = self._fallback_step(iteration)
                thought = "Fallback mode (LLM unavailable)."

            if thought:
                thought_step = self._next_step(
                    type="reasoning",
                    content=f"THOUGHT: {thought}",
                    confidence=self.confidence,
                )
                self._log(thought_step)

            if tool_name is None:
                # LLM decided to stop
                logger.info("Agent decided to stop at iteration %d.", iteration)
                break

            # ── Execute the tool ──────────────────────────────────────────────
            if arguments is None:
                arguments = {}
            self._call_tool(tool_name, arguments)

            # ── Check if we should trigger remediation ────────────────────────
            if self.confidence >= _CONFIDENCE_THRESHOLD and not remediation_done:
                verdict = "THREAT_CONFIRMED"
                remediation_step = self._next_step(
                    type="reasoning",
                    content=(
                        f"Confidence {self.confidence:.2f} ≥ threshold {_CONFIDENCE_THRESHOLD}. "
                        "Threat CONFIRMED. Initiating containment actions."
                    ),
                    confidence=self.confidence,
                )
                self._log(remediation_step)
                self._run_remediation()
                remediation_done = True
                break  # Stop after remediation

        # ── Final verdict ────────────────────────────────────────────────────
        summary = self._generate_summary(verdict)
        verdict_step = self._next_step(
            type="verdict",
            content=summary,
            confidence=self.confidence,
        )
        self._log(verdict_step)

        completed_at = datetime.now(timezone.utc).isoformat()
        return TriageResult(
            alert_id=self.alert_id,
            started_at=started_at,
            completed_at=completed_at,
            verdict=verdict,
            confidence=self.confidence,
            actions_taken=self.actions_taken,
            reasoning_trace=self.reasoning_trace,
            graph_nodes_touched=list(set(self.graph_nodes_touched)),
            graph_edges_touched=list(set(self.graph_edges_touched)),
            summary=summary,
        )

    # ── fallback when LLM is unavailable ─────────────────────────────────────

    def _fallback_step(self, iteration: int) -> tuple[str | None, dict | None]:
        """Rule-based fallback when the LLM API is down."""
        completed_tools = {r.get("tool") for r in self._tool_results_so_far}

        if "get_alert_context" not in completed_tools:
            return "get_alert_context", {"alert_id": self.alert_id}

        if "trace_lateral_movement" not in completed_tools:
            # Find IP from alert context result
            alert_res = next((r for r in self._tool_results_so_far if r.get("tool") == "get_alert_context"), {})
            for src in alert_res.get("triggering_sources", []):
                ip = src.get("source_properties", {}).get("address")
                if ip:
                    return "trace_lateral_movement", {"ip_address": ip}
            return None, None

        if "identify_blast_radius" not in completed_tools:
            lm_res = next((r for r in self._tool_results_so_far if r.get("tool") == "trace_lateral_movement"), {})
            for path in lm_res.get("traversal_paths", []):
                target = path.get("target", {})
                if "User" in target.get("labels", []):
                    return "identify_blast_radius", {"user_id": target["id"]}
            return None, None

        return None, None  # Stop

    def _generate_summary(self, verdict: str) -> str:
        lines = [f"Investigation of {self.alert_id} complete."]
        lines.append(f"Verdict: {verdict} (confidence={self.confidence:.0%}).")
        if self.actions_taken:
            lines.append(f"Actions: {', '.join(self.actions_taken)}.")
        else:
            lines.append("No containment actions were taken.")
        tools_used = list({r.get("tool") for r in self._tool_results_so_far})
        lines.append(f"Tools invoked: {', '.join(tools_used)}.")
        lines.append(f"Graph nodes touched: {len(set(self.graph_nodes_touched))}.")
        return " ".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# Convenience function (used by FastAPI)
# ─────────────────────────────────────────────────────────────────────────────

def run_investigation(alert_id: str) -> TriageResult:
    agent = CyberTriageAgent(alert_id=alert_id)
    return agent.run()
