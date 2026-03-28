import uuid
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel
from ...api.main import get_graph_instance

router = APIRouter(prefix="/api/runs", tags=["runs"])


class StartRunRequest(BaseModel):
    target_brief: str
    scope_rules:  dict  = {}
    run_config:   dict  = {}


@router.post("")
async def start_run(body: StartRunRequest, bg: BackgroundTasks):
    thread_id = str(uuid.uuid4())
    graph     = get_graph_instance()
    config    = {"configurable": {"thread_id": thread_id}}

    initial_state = {
        "target_brief":       body.target_brief,
        "scope_rules":        body.scope_rules,
        "run_config":         body.run_config,
        "operator_context":   {},
        "surface_inventory":  {},
        "target_context":     {},
        "attack_strategy":    {},
        "agent_loadouts":     {},
        "agent_status":       {},
        "shared_memory":      {},
        "raw_findings":       [],
        "validated_findings": [],
        "attack_chains":      [],
        "false_positives":    [],
        "phase":              "BRIEF",
        "phase_history":      [],
        "messages":           [],
        "pending_interrupts": [],
        "interrupt_log":      [],
        "audit_log":          [],
        "thread_id":          thread_id,
        "confidence_threshold": body.run_config.get("confidence_threshold", 0.85),
    }

    bg.add_task(_run_graph, graph, initial_state, config)

    return {
        "thread_id":  thread_id,
        "status":     "started",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }


async def _run_graph(graph, initial_state: dict, config: dict):
    try:
        await graph.ainvoke(initial_state, config=config)
    except Exception as e:
        print(f"[run_graph] error: {e}")


@router.get("/{thread_id}")
async def get_run(thread_id: str):
    graph  = get_graph_instance()
    config = {"configurable": {"thread_id": thread_id}}
    try:
        state = await graph.aget_state(config)
        if not state:
            raise HTTPException(status_code=404, detail="Run not found")
        return {
            "thread_id": thread_id,
            "phase":     state.values.get("phase", "BRIEF"),
            "state":     _safe_serialize(state.values),
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("")
async def list_runs():
    return {"runs": [], "message": "List runs requires persistent checkpointer"}


def _safe_serialize(values: dict) -> dict:
    import json
    safe = {}
    for k, v in values.items():
        try:
            json.dumps(v)
            safe[k] = v
        except (TypeError, ValueError):
            safe[k] = str(v)[:500]
    return safe
