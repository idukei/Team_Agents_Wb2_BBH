import asyncio
import json
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from .main import get_graph_instance

router = APIRouter()


@router.websocket("/ws/{thread_id}")
async def websocket_endpoint(ws: WebSocket, thread_id: str):
    await ws.accept()
    graph  = get_graph_instance()
    config = {"configurable": {"thread_id": thread_id}}

    try:
        while True:
            try:
                state = await graph.aget_state(config)
                if state and hasattr(state, "values"):
                    import json as _json
                    safe = {}
                    for k, v in state.values.items():
                        try:
                            _json.dumps(v)
                            safe[k] = v
                        except Exception:
                            safe[k] = str(v)[:200]
                    await ws.send_json({"type": "state_update", "state": safe})
            except Exception:
                pass
            await asyncio.sleep(2)
    except WebSocketDisconnect:
        pass
