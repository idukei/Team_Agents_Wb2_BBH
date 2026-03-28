import json
from datetime import datetime, timezone

from langgraph.types import interrupt
from langgraph.config import get_stream_writer

from ..core.state import BountyMindState
from .interrupt_types import HITLType, HITL_METADATA


def create_hitl_node(interrupt_type: HITLType):
    async def hitl_node(state: BountyMindState) -> dict:
        now = datetime.now(timezone.utc).isoformat()
        metadata = HITL_METADATA.get(interrupt_type, {})

        payload = _build_payload(state, interrupt_type)

        try:
            writer = get_stream_writer()
            writer({
                "type":           "hitl_pending",
                "interrupt_type": interrupt_type.value,
                "hitl_id":        metadata.get("id", ""),
                "label":          metadata.get("label", ""),
                "description":    metadata.get("description", ""),
                "operator_can":   metadata.get("operator_can", []),
                "payload":        payload,
                "thread_id":      state.get("thread_id", ""),
                "timestamp":      now,
            })
        except Exception:
            pass

        response = interrupt(payload)

        state_updates = _apply_response(state, response, interrupt_type)
        state_updates["interrupt_log"] = [{
            "interrupt_type": interrupt_type.value,
            "hitl_id":        metadata.get("id", ""),
            "timestamp":      now,
            "response":       _sanitize_response(response),
        }]
        state_updates["pending_interrupts"] = [
            p for p in (state.get("pending_interrupts") or [])
            if p.get("interrupt_type") != interrupt_type.value
        ]

        return state_updates

    hitl_node.__name__ = f"hitl_{interrupt_type.value}"
    return hitl_node


def _build_payload(state: BountyMindState, interrupt_type: HITLType) -> dict:
    base = {
        "interrupt_type": interrupt_type.value,
        "thread_id":      state.get("thread_id", ""),
        "phase":          state.get("phase", ""),
    }

    if interrupt_type == HITLType.SCOPE_REVIEW:
        return {**base,
            "target_brief": state.get("target_brief", ""),
            "scope_rules":  state.get("scope_rules", {}),
            "run_config":   state.get("run_config", {}),
        }

    if interrupt_type == HITLType.STRATEGY_REVIEW:
        return {**base,
            "attack_strategy":  state.get("attack_strategy", {}),
            "surface_summary": {
                "endpoints_count":    len((state.get("surface_inventory") or {}).get("endpoints", [])),
                "forms_count":        len((state.get("surface_inventory") or {}).get("forms", [])),
                "technologies_count": len((state.get("surface_inventory") or {}).get("technologies", [])),
                "behaviors_count":    len((state.get("surface_inventory") or {}).get("behaviors", [])),
            },
        }

    if interrupt_type == HITLType.LOADOUT_REVIEW:
        return {**base,
            "agent_loadouts":     state.get("agent_loadouts", {}),
            "surface_inventory":  state.get("surface_inventory", {}),
            "attack_strategy":    state.get("attack_strategy", {}),
        }

    if interrupt_type == HITLType.CREDENTIALS:
        return {**base,
            "requesting_agent":  state.get("phase", "unknown_agent"),
            "required_fields":   ["username", "password"],
            "context":           "Agent requires credentials to test authenticated endpoints.",
        }

    if interrupt_type == HITLType.HIGH_SEVERITY:
        raw_findings = state.get("raw_findings") or []
        high_sev = [f for f in raw_findings if f.get("cvss_estimate", 0) >= 9.0]
        return {**base,
            "finding":      high_sev[-1] if high_sev else {},
            "all_findings": high_sev,
        }

    if interrupt_type == HITLType.DESTRUCTIVE:
        return {**base,
            "action":      "Destructive action pending operator approval",
            "context":     state.get("phase", ""),
        }

    if interrupt_type == HITLType.AGENT_STALLED:
        return {**base,
            "agent_status": state.get("agent_status", {}),
            "agent_loadouts": state.get("agent_loadouts", {}),
        }

    if interrupt_type == HITLType.NEW_SURFACE:
        return {**base,
            "new_surfaces": [],
            "context":      "New attack surface discovered during execution.",
        }

    if interrupt_type == HITLType.CHAIN_CRITICAL:
        return {**base,
            "attack_chains": state.get("attack_chains", []),
        }

    if interrupt_type == HITLType.PRE_REPORT:
        return {**base,
            "validated_findings": state.get("validated_findings", []),
            "attack_chains":      state.get("attack_chains", []),
            "false_positives":    state.get("false_positives", []),
        }

    return base


def _apply_response(state: BountyMindState, response: dict, interrupt_type: HITLType) -> dict:
    if not isinstance(response, dict):
        response = {"action": "approve"}

    action = response.get("action", "approve")

    if interrupt_type == HITLType.SCOPE_REVIEW:
        updates = {}
        if "scope_rules" in response:
            updates["scope_rules"] = response["scope_rules"]
        if "operator_context" in response:
            updates["operator_context"] = {
                **(state.get("operator_context") or {}),
                **response["operator_context"],
            }
        return updates

    if interrupt_type == HITLType.STRATEGY_REVIEW:
        if action == "edit" and "attack_strategy" in response:
            return {"attack_strategy": response["attack_strategy"]}
        return {}

    if interrupt_type == HITLType.LOADOUT_REVIEW:
        updates = {}
        if action == "edit" and "agent_loadouts" in response:
            current = dict(state.get("agent_loadouts") or {})
            current.update(response["agent_loadouts"])
            updates["agent_loadouts"] = current
        if "operator_context" in response:
            updates["operator_context"] = {
                **(state.get("operator_context") or {}),
                **response["operator_context"],
            }
        return updates

    if interrupt_type == HITLType.CREDENTIALS:
        if "credentials" in response:
            return {
                "operator_context": {
                    **(state.get("operator_context") or {}),
                    "credentials": response["credentials"],
                }
            }
        return {}

    if interrupt_type == HITLType.HIGH_SEVERITY:
        if action == "reject":
            raw = list(state.get("raw_findings") or [])
            fps = list(state.get("false_positives") or [])
            high_sev = [f for f in raw if f.get("cvss_estimate", 0) >= 9.0]
            for f in high_sev:
                f["rejected_by_operator"] = True
                fps.append(f)
            return {"false_positives": fps}
        return {}

    if interrupt_type == HITLType.PRE_REPORT:
        updates = {}
        if "validated_findings" in response:
            updates["validated_findings"] = response["validated_findings"]
        if "operator_context" in response:
            updates["operator_context"] = {
                **(state.get("operator_context") or {}),
                **response["operator_context"],
            }
        return updates

    return {}


def _sanitize_response(response) -> dict:
    if not isinstance(response, dict):
        return {"raw": str(response)[:500]}
    sanitized = {}
    for k, v in response.items():
        if k == "credentials":
            sanitized[k] = "***REDACTED***"
        else:
            sanitized[k] = str(v)[:200] if isinstance(v, str) else v
    return sanitized
