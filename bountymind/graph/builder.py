from __future__ import annotations

from datetime import datetime, timezone

from langgraph.graph import StateGraph, START, END
from langgraph.types import Send

from ..core.state import BountyMindState
from ..hitl.interrupt_types import HITLType
from ..hitl.interrupt_manager import create_hitl_node
from .commander import commander_node
from ..agents.recon.surface_agent import surface_agent_node
from ..agents.recon.behavior_agent import behavior_agent_node
from ..agents.intelligence.research_agent import research_agent_node
from ..agents.strategy.strategy_engine import strategy_engine_node
from ..agents.synthesis.chain_synthesizer import chain_synthesizer_node
from ..agents.validator.validator_agent import validator_node
from ..agents.reporter.report_agent import reporter_node
from ..agents.team.web_tester import WebTester
from ..agents.team.auth_prober import AuthProber
from ..agents.team.logic_analyst import LogicAnalyst
from ..agents.team.code_inspector import CodeInspector
from ..agents.team.integration_scout import IntegrationScout
from ..agents.team.infra_prober import InfraProber


TEAM = [WebTester(), AuthProber(), LogicAnalyst(), CodeInspector(), IntegrationScout(), InfraProber()]


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


async def _recon_join_node(state: BountyMindState) -> dict:
    now = _utcnow()
    return {
        "phase":         "INTELLIGENCE",
        "phase_history": [{"phase": "INTELLIGENCE_START", "timestamp": now}],
        "audit_log":     [{"event": "recon_join_complete", "timestamp": now}],
    }


async def _attack_fan_out_node(state: BountyMindState) -> dict:
    now = _utcnow()
    return {
        "phase":         "ATTACK",
        "phase_history": [{"phase": "ATTACK_START", "timestamp": now}],
        "audit_log":     [{"event": "attack_swarm_launched", "timestamp": now}],
    }


async def _attack_join_node(state: BountyMindState) -> dict:
    now    = _utcnow()
    raw    = list(state.get("raw_findings") or [])
    status = dict(state.get("agent_status") or {})
    for agent in TEAM:
        if agent.agent_id not in status:
            status[agent.agent_id] = {
                "phase":        "complete",
                "iteration":    0,
                "last_finding": None,
                "active":       False,
            }
    return {
        "raw_findings":  raw,
        "agent_status":  status,
        "phase":         "SYNTHESIS",
        "phase_history": [{"phase": "ATTACK_COMPLETE", "timestamp": now}],
        "audit_log": [{
            "event":        "attack_join_complete",
            "timestamp":    now,
            "raw_findings": len(raw),
        }],
    }


def _route_to_attack_swarm(state: BountyMindState):
    loadouts   = state.get("agent_loadouts") or {}
    first_wave = [
        agent_id for agent_id, lo in loadouts.items()
        if lo.get("active", False) and lo.get("priority", 0) == 0
    ]
    if not first_wave:
        first_wave = [agent.agent_id for agent in TEAM[:2]]

    scope_rules = state.get("scope_rules") or {}
    thread_id   = state.get("thread_id", "")

    return [
        Send(f"agent_{agent_id}", {
            "loadout":             loadouts.get(agent_id, _minimal_loadout(agent_id, state)),
            "iteration":           0,
            "test_idx":            0,
            "local_findings":      [],
            "messages":            [],
            "memory_writes":       [],
            "thread_id":           thread_id,
            "scope_rules":         scope_rules,
            "_should_collaborate": False,
            "raw_findings":        [],
        })
        for agent_id in first_wave
    ]


def _minimal_loadout(agent_id: str, state: BountyMindState) -> dict:
    endpoints = (state.get("surface_inventory") or {}).get("endpoints", [])
    first_url = endpoints[0]["url"] if endpoints else "/"
    return {
        "agent_id":              agent_id,
        "active":                True,
        "priority":              0,
        "mission":               f"Minimal fallback for {agent_id}",
        "rationale":             "no loadout generated",
        "hypotheses":            [],
        "test_cases":            [{"surface": first_url, "technique": "manual_review", "expected": "", "priority": 0}],
        "system_prompt":         f"You are {agent_id}.",
        "methodology":           ["review", "report"],
        "tools":                 [],
        "tool_configs":          {},
        "write_channels":        ["observations"],
        "read_channels":         ["observations"],
        "handoff_targets":       [],
        "max_iterations":        5,
        "interrupt_conditions":  [],
        "success_criteria":      [],
    }


_compiled_graph = None


async def build_graph(checkpointer=None):
    global _compiled_graph

    builder = StateGraph(BountyMindState)

    # Core nodes
    builder.add_node("commander",       commander_node)
    builder.add_node("surface_recon",   surface_agent_node)
    builder.add_node("behavior_recon",  behavior_agent_node)
    builder.add_node("recon_join",      _recon_join_node)
    builder.add_node("research",        research_agent_node)
    builder.add_node("strategy",        strategy_engine_node)
    builder.add_node("attack_fan_out",  _attack_fan_out_node)
    builder.add_node("attack_join",     _attack_join_node)
    builder.add_node("synthesizer",     chain_synthesizer_node)
    builder.add_node("validator",       validator_node)
    builder.add_node("reporter",        reporter_node)

    # HITL nodes (one per HITLType)
    for hitl_type in HITLType:
        builder.add_node(f"hitl_{hitl_type.value}", create_hitl_node(hitl_type))

    # Team agent subgraphs — compiled once at startup
    for agent in TEAM:
        builder.add_node(f"agent_{agent.agent_id}", agent.build_subgraph())

    # Edges
    builder.add_edge(START,           "commander")
    builder.add_edge("commander",     f"hitl_{HITLType.SCOPE_REVIEW.value}")
    builder.add_edge(f"hitl_{HITLType.SCOPE_REVIEW.value}",   "surface_recon")
    builder.add_edge("surface_recon", "behavior_recon")
    builder.add_edge("behavior_recon","recon_join")
    builder.add_edge("recon_join",    "research")
    builder.add_edge("research",      f"hitl_{HITLType.STRATEGY_REVIEW.value}")
    builder.add_edge(f"hitl_{HITLType.STRATEGY_REVIEW.value}", "strategy")
    builder.add_edge("strategy",      f"hitl_{HITLType.LOADOUT_REVIEW.value}")

    # Fan-out: HITL_LOADOUT_REVIEW → attack swarm (Send API)
    builder.add_conditional_edges(
        f"hitl_{HITLType.LOADOUT_REVIEW.value}",
        _route_to_attack_swarm,
    )

    # Each team agent feeds back into attack_join
    for agent in TEAM:
        builder.add_edge(f"agent_{agent.agent_id}", "attack_join")

    builder.add_edge("attack_join",  "synthesizer")
    builder.add_edge("synthesizer",  "validator")
    builder.add_edge("validator",    f"hitl_{HITLType.PRE_REPORT.value}")
    builder.add_edge(f"hitl_{HITLType.PRE_REPORT.value}", "reporter")
    builder.add_edge("reporter",     END)

    _compiled_graph = builder.compile(checkpointer=checkpointer)
    return _compiled_graph


def get_graph():
    if _compiled_graph is None:
        raise RuntimeError("Graph not initialized. Call build_graph() first.")
    return _compiled_graph
