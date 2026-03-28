from fastapi import APIRouter, HTTPException
from langgraph.types import Command
from ...api.main import get_graph_instance

router = APIRouter(prefix="/api/runs", tags=["hitl"])


@router.post("/{thread_id}/interrupt/{hitl_type}/respond")
async def respond_to_interrupt(thread_id: str, hitl_type: str, body: dict):
    graph = get_graph_instance()
    config = {"configurable": {"thread_id": thread_id}}

    try:
        state_updates = body.get("state_updates", {})
        if state_updates:
            await graph.aupdate_state(config, state_updates)

        resume_value = body.get("response", {"action": "approve"})
        await graph.ainvoke(Command(resume=resume_value), config=config)

        return {"status": "resumed", "thread_id": thread_id, "hitl_type": hitl_type}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{thread_id}/interrupt/pending")
async def get_pending_interrupts(thread_id: str):
    graph = get_graph_instance()
    config = {"configurable": {"thread_id": thread_id}}
    try:
        state = await graph.aget_state(config)
        tasks = state.tasks if hasattr(state, "tasks") else []
        interrupts = []
        for task in tasks:
            if hasattr(task, "interrupts") and task.interrupts:
                for i in task.interrupts:
                    interrupts.append({
                        "task_id":  task.id,
                        "payload":  i.value if hasattr(i, "value") else {},
                    })
        return {"pending": interrupts}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
