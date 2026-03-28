from ..core.state import BountyMindState
from .interrupt_types import HITLType


def should_trigger_high_severity(state: BountyMindState) -> bool:
    raw_findings = state.get("raw_findings") or []
    approved_urls = {
        log.get("response", {}).get("finding_url", "")
        for log in (state.get("interrupt_log") or [])
        if log.get("interrupt_type") == HITLType.HIGH_SEVERITY.value
    }
    return any(
        f.get("cvss_estimate", 0) >= 9.0
        and f.get("url", "") not in approved_urls
        for f in raw_findings
    )


def should_trigger_agent_stalled(state: BountyMindState, agent_id: str) -> bool:
    agent_status = (state.get("agent_status") or {}).get(agent_id, {})
    loadout = (state.get("agent_loadouts") or {}).get(agent_id, {})
    max_iter = loadout.get("max_iterations", 25)
    current  = agent_status.get("iteration", 0)
    findings = agent_status.get("findings_count", 0)
    return current >= max_iter and findings == 0


def should_trigger_chain_critical(state: BountyMindState) -> bool:
    chains = state.get("attack_chains") or []
    approved = {
        log.get("chain_id", "")
        for log in (state.get("interrupt_log") or [])
        if log.get("interrupt_type") == HITLType.CHAIN_CRITICAL.value
    }
    return any(
        c.get("cvss_composed", 0) >= 9.5 and c.get("id", "") not in approved
        for c in chains
    )
