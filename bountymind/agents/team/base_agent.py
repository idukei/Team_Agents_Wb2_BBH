import asyncio
import operator
from datetime import datetime, timezone
from typing import Annotated, TypedDict

from langchain_core.messages import HumanMessage
from langgraph.graph import StateGraph, START, END
from langgraph.graph.state import CompiledStateGraph
from langgraph.types import Command

from ...core.fireworks import get_model
from ...core.models import AgentLoadOut, RawFinding
from ...tools.registry import ToolRegistry
from ...tools.scope_checker import validate_scope, ScopeViolationError


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _build_raw_finding(
    test_case: dict,
    result: dict,
    agent_id: str,
) -> dict:
    cvss = _estimate_cvss(test_case.get("technique", ""), result)
    return {
        "id":                f"{agent_id}:{test_case.get('surface','')}:{test_case.get('technique','')}:{_utcnow()}",
        "agent_id":          agent_id,
        "url":               test_case.get("surface", ""),
        "vuln_type":         test_case.get("technique", ""),
        "title":             f"{test_case.get('technique','unknown')} at {test_case.get('surface','')}",
        "description":       result.get("description", result.get("output", "")),
        "request":           result.get("request", {}),
        "response_diff":     result.get("response_diff", {}),
        "payload":           result.get("payload", ""),
        "reproduction_steps": result.get("reproduction_steps", []),
        "evidence":          result.get("evidence", {}),
        "cvss_estimate":     cvss,
        "severity":          _cvss_to_severity(cvss),
        "timestamp":         _utcnow(),
        "raw_output":        str(result.get("output", ""))[:2000],
    }


def _estimate_cvss(technique: str, result: dict) -> float:
    base_scores = {
        "sql_injection":         9.8,
        "rce":                   10.0,
        "xss":                   6.1,
        "stored_xss":            8.8,
        "csrf":                  6.5,
        "idor":                  7.5,
        "ssrf":                  8.6,
        "xxe":                   7.5,
        "open_redirect":         6.1,
        "timing_attack":         5.3,
        "reset_token_analysis":  7.5,
        "oauth_redirect_uri":    8.1,
        "path_traversal":        7.5,
        "information_disclosure": 5.3,
        "jwt_weakness":          8.1,
        "mass_assignment":       8.1,
        "privilege_escalation":  8.8,
        "cors_misconfiguration": 6.5,
        "user_enumeration":      5.3,
        "rate_limiting":         5.3,
        "security_headers":      3.1,
        "js_secret":             7.2,
        "subdomain_takeover":    8.6,
        "default":               5.0,
    }
    score = base_scores.get(technique.lower(), base_scores["default"])
    if result.get("confirmed"):
        score = min(score + 0.5, 10.0)
    if result.get("requires_auth"):
        score = max(score - 1.5, 1.0)
    return round(score, 1)


def _cvss_to_severity(cvss: float) -> str:
    if cvss >= 9.0:  return "CRITICAL"
    if cvss >= 7.0:  return "HIGH"
    if cvss >= 4.0:  return "MEDIUM"
    if cvss >= 0.1:  return "LOW"
    return "INFORMATIONAL"


class AgentState(TypedDict):
    loadout:             dict
    iteration:           int
    test_idx:            int
    local_findings:      list
    messages:            Annotated[list, operator.add]
    memory_writes:       list
    thread_id:           str
    scope_rules:         dict
    _should_collaborate: bool                           # persisted so _route_execute can read it
    raw_findings:        Annotated[list, operator.add]  # propagates to BountyMindState


class BaseTeamAgent:
    agent_id:    str = "BaseAgent"
    model_alias: str = "MODEL_AGENT_STD"

    def build_subgraph(self) -> CompiledStateGraph:
        builder = StateGraph(AgentState)

        builder.add_node("check_active", self._check_active_node)
        builder.add_node("orient",       self._orient_node)
        builder.add_node("execute",      self._execute_node)
        builder.add_node("collaborate",  self._collaborate_node)
        builder.add_node("report",       self._report_node)

        builder.add_edge(START, "check_active")

        builder.add_conditional_edges("check_active", self._route_active, {
            "active":   "orient",
            "inactive": END,
        })

        builder.add_edge("orient", "execute")

        builder.add_conditional_edges("execute", self._route_execute, {
            "next_test":   "orient",
            "collaborate": "collaborate",
            "done":        "report",
        })

        builder.add_edge("collaborate", "execute")
        builder.add_edge("report",      END)

        return builder.compile()

    async def _check_active_node(self, state: AgentState) -> dict:
        loadout = state.get("loadout", {})
        if not loadout.get("active", True):
            return {
                "messages": [{
                    "role":    "system",
                    "content": f"[{self.agent_id}] inactive — rationale: {loadout.get('rationale', 'not relevant for this target')}",
                    "agent":   self.agent_id,
                    "ts":      _utcnow(),
                }]
            }
        return {}

    def _route_active(self, state: AgentState) -> str:
        return "active" if state.get("loadout", {}).get("active", True) else "inactive"

    async def _orient_node(self, state: AgentState) -> dict:
        loadout     = AgentLoadOut(**state["loadout"])
        methodology = loadout.methodology
        step_idx    = min(state.get("iteration", 0), len(methodology) - 1)
        current_step = methodology[step_idx] if methodology else "Execute next test case"

        return {
            "messages": [{
                "role":    "system",
                "content": f"[{self.agent_id}] orient → step: {current_step} | test_idx: {state.get('test_idx', 0)}",
                "agent":   self.agent_id,
                "ts":      _utcnow(),
            }]
        }

    async def _execute_node(self, state: AgentState) -> dict:
        loadout    = AgentLoadOut(**state["loadout"])
        test_idx   = state.get("test_idx", 0)
        iteration  = state.get("iteration", 0)
        scope_rules = state.get("scope_rules", {})

        if test_idx >= len(loadout.test_cases):
            return {
                "messages": [{
                    "role":    "system",
                    "content": f"[{self.agent_id}] all test cases exhausted",
                    "agent":   self.agent_id,
                    "ts":      _utcnow(),
                }]
            }

        if iteration >= loadout.max_iterations:
            return {
                "messages": [{
                    "role":    "system",
                    "content": f"[{self.agent_id}] max_iterations reached ({loadout.max_iterations})",
                    "agent":   self.agent_id,
                    "ts":      _utcnow(),
                }]
            }

        tc = loadout.test_cases[test_idx]
        surface = tc.get("surface", "")

        try:
            validate_scope(surface, scope_rules)
        except ScopeViolationError as e:
            return {
                "test_idx":  test_idx + 1,
                "iteration": iteration + 1,
                "messages": [{
                    "role":    "system",
                    "content": f"[{self.agent_id}] scope violation skipped: {surface}",
                    "agent":   self.agent_id,
                    "ts":      _utcnow(),
                }]
            }

        technique   = tc.get("technique", "")
        tool_config = loadout.tool_configs.get(technique, {})

        try:
            tool_fn = ToolRegistry.get(technique)
            result  = await tool_fn(target=surface, **tool_config)
        except KeyError:
            result = await self._llm_execute(tc, loadout, state)
        except Exception as e:
            result = {"output": f"tool error: {str(e)}", "confirmed": False}

        findings = list(state.get("local_findings", []))
        if result.get("output") or result.get("confirmed"):
            finding = _build_raw_finding(tc, result, self.agent_id)
            findings.append(finding)

        should_collab = (
            len(findings) > 0
            and iteration > 0
            and iteration % 3 == 0
        )

        return {
            "local_findings": findings,
            "test_idx":       test_idx + 1,
            "iteration":      iteration + 1,
            "messages": [{
                "role":    "system",
                "content": f"[{self.agent_id}] executed {technique} on {surface} → {'finding' if result.get('confirmed') else 'no finding'}",
                "agent":   self.agent_id,
                "ts":      _utcnow(),
            }],
            "_should_collaborate": should_collab,
        }

    def _route_execute(self, state: AgentState) -> str:
        loadout  = AgentLoadOut(**state["loadout"])
        test_idx = state.get("test_idx", 0)
        iteration = state.get("iteration", 0)

        if test_idx >= len(loadout.test_cases) or iteration >= loadout.max_iterations:
            return "done"

        if state.get("_should_collaborate"):
            return "collaborate"

        return "next_test"

    async def _collaborate_node(self, state: AgentState) -> dict:
        thread_id = state.get("thread_id", "default")

        try:
            from langgraph.store.memory import InMemoryStore
            from ...memory.shared import SharedMemory

            store  = InMemoryStore()
            memory = SharedMemory(store, thread_id)

            local_findings = state.get("local_findings", [])
            if local_findings:
                await memory.write_findings(self.agent_id, local_findings)

            for channel in AgentLoadOut(**state["loadout"]).read_channels:
                cross_data = await memory.read(channel, exclude=self.agent_id)
                if cross_data:
                    chain_candidates = await memory.find_chain_candidates(local_findings)
                    if chain_candidates:
                        return {
                            "memory_writes": chain_candidates,
                            "messages": [{
                                "role":    "system",
                                "content": f"[{self.agent_id}] found {len(chain_candidates)} chain candidates via {channel}",
                                "agent":   self.agent_id,
                                "ts":      _utcnow(),
                            }]
                        }
        except Exception:
            pass

        return {
            "messages": [{
                "role":    "system",
                "content": f"[{self.agent_id}] collaborate — no cross-agent chains detected yet",
                "agent":   self.agent_id,
                "ts":      _utcnow(),
            }]
        }

    async def _report_node(self, state: AgentState) -> dict:
        local_findings = state.get("local_findings", [])
        return {
            "raw_findings": local_findings,   # propagates to BountyMindState.raw_findings via operator.add
            "messages": [{
                "role":    "system",
                "content": f"[{self.agent_id}] completed — {len(local_findings)} findings",
                "agent":   self.agent_id,
                "ts":      _utcnow(),
            }],
        }

    async def _llm_execute(self, tc: dict, loadout: AgentLoadOut, state: AgentState) -> dict:
        try:
            llm = get_model(self.model_alias, temperature=0.1)

            prompt = f"""You are {self.agent_id} performing a bug bounty test.

Mission: {loadout.mission}

Current test case:
- Surface: {tc.get('surface')}
- Technique: {tc.get('technique')}
- Expected vulnerability: {tc.get('expected')}

System prompt context:
{loadout.system_prompt[:500]}

Based on the technique and surface, describe:
1. What exact HTTP request you would send
2. What response would indicate a vulnerability
3. Whether this is a confirmed finding based on your analysis

Respond in JSON: {{"confirmed": bool, "output": str, "request": dict, "response_diff": dict, "payload": str, "reproduction_steps": [str], "description": str}}"""

            response = await llm.ainvoke([HumanMessage(content=prompt)])
            import json, re
            m = re.search(r'\{.*\}', response.content, re.DOTALL)
            if m:
                return json.loads(m.group(0))
        except Exception:
            pass
        return {"output": "", "confirmed": False}
