import uuid
from datetime import datetime, timezone
from ..core.state import BountyMindState


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


async def commander_node(state: BountyMindState) -> dict:
    now = _utcnow()

    thread_id = state.get("thread_id") or str(uuid.uuid4())

    target_brief = state.get("target_brief", "")
    scope_rules  = state.get("scope_rules")  or _derive_scope(target_brief)
    run_config   = state.get("run_config")   or {}

    confidence_threshold = run_config.get("confidence_threshold", 0.85)

    return {
        "thread_id":           thread_id,
        "scope_rules":         scope_rules,
        "confidence_threshold": confidence_threshold,
        "phase":               "RECON",
        "phase_history": [{
            "phase":     "BRIEF",
            "timestamp": now,
            "agent":     "commander",
        }],
        "audit_log": [{
            "event":     "run_initialized",
            "timestamp": now,
            "thread_id": thread_id,
            "target":    target_brief[:100],
        }],
    }


def _derive_scope(target_brief: str) -> dict:
    import re
    urls = re.findall(r'https?://[^\s\'"]+', target_brief)
    if urls:
        from urllib.parse import urlparse
        hosts = list({f"https://{urlparse(u).netloc}" for u in urls if urlparse(u).netloc})
        return {
            "in_scope":        hosts + [h.replace("https://", "https://*.") for h in hosts],
            "out_of_scope":    [],
            "allowed_methods": ["GET", "POST", "PUT", "PATCH", "DELETE"],
            "max_depth":       3,
        }
    return {
        "in_scope":        [],
        "out_of_scope":    [],
        "allowed_methods": ["GET", "POST", "PUT", "PATCH", "DELETE"],
        "max_depth":       3,
    }
