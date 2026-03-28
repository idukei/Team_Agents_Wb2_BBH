from ..core.state import BountyMindState

PHASE_ORDER = [
    "BRIEF", "RECON", "INTELLIGENCE", "STRATEGY",
    "ATTACK", "SYNTHESIS", "VALIDATION", "REVIEW", "REPORT",
]


def route_from_phase(state: BountyMindState) -> str:
    phase = state.get("phase", "BRIEF")
    idx   = PHASE_ORDER.index(phase) if phase in PHASE_ORDER else 0
    if idx + 1 < len(PHASE_ORDER):
        return PHASE_ORDER[idx + 1].lower()
    return "end"
