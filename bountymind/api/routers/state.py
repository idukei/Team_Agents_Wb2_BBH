from fastapi import APIRouter, HTTPException
from ...api.main import get_graph_instance

router = APIRouter(prefix="/api/runs", tags=["state"])


@router.patch("/{thread_id}/state")
async def inject_state(thread_id: str, updates: dict):
    graph = get_graph_instance()
    config = {"configurable": {"thread_id": thread_id}}
    try:
        await graph.aupdate_state(config, updates, as_node="commander")
        return {"updated": True, "fields": list(updates.keys())}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{thread_id}/checkpoints")
async def list_checkpoints(thread_id: str):
    graph = get_graph_instance()
    config = {"configurable": {"thread_id": thread_id}}
    try:
        checkpoints = []
        async for checkpoint in graph.aget_state_history(config):
            checkpoints.append({
                "checkpoint_id": checkpoint.config["configurable"].get("checkpoint_id", ""),
                "phase":         checkpoint.values.get("phase", ""),
                "timestamp":     checkpoint.metadata.get("created_at", ""),
                "step":          checkpoint.metadata.get("step", 0),
            })
        return {"checkpoints": checkpoints}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{thread_id}/rollback/{checkpoint_id}")
async def rollback_to_checkpoint(thread_id: str, checkpoint_id: str):
    graph = get_graph_instance()
    config = {
        "configurable": {
            "thread_id":     thread_id,
            "checkpoint_id": checkpoint_id,
        }
    }
    try:
        await graph.ainvoke(None, config=config)
        return {"status": "rolled_back", "checkpoint_id": checkpoint_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
