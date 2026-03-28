from __future__ import annotations

import json
from datetime import datetime, timezone

from fastapi import APIRouter
from fastapi.responses import StreamingResponse

router = APIRouter(prefix="/api/runs", tags=["stream"])


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _format_sse_part(part: tuple) -> dict | None:
    """Convert a LangGraph astream part to a serialisable SSE event dict.

    astream with stream_mode=['messages','updates','values'] and subgraphs=True
    yields tuples: (namespace_tuple, (mode, data))
    """
    try:
        namespace, (mode, data) = part
        ns_str = ":".join(namespace) if namespace else "root"

        if mode == "messages":
            # data is (AIMessageChunk, metadata_dict)
            chunk, meta = data
            return {
                "type":      "token",
                "namespace": ns_str,
                "content":   chunk.content if hasattr(chunk, "content") else str(chunk),
                "node":      meta.get("langgraph_node", "") if isinstance(meta, dict) else "",
                "timestamp": _utcnow(),
            }

        if mode == "updates":
            # data is {node_name: state_delta_dict}
            return {
                "type":      "node_update",
                "namespace": ns_str,
                "updates":   _serialize(data),
                "timestamp": _utcnow(),
            }

        if mode == "values":
            # data is the full state snapshot dict
            serialized = _serialize(data) if isinstance(data, dict) else {}
            return {
                "type":      "state_snapshot",
                "namespace": ns_str,
                "phase":     serialized.get("phase", ""),
                "state":     serialized,
                "timestamp": _utcnow(),
            }

    except Exception:
        pass
    return None


def _serialize(obj) -> dict:
    """Best-effort JSON-safe serialisation of a state dict."""
    if not isinstance(obj, dict):
        return {"raw": str(obj)[:500]}
    safe = {}
    for k, v in obj.items():
        try:
            json.dumps(v)
            safe[k] = v
        except (TypeError, ValueError):
            safe[k] = str(v)[:500]
    return safe


async def _event_generator(thread_id: str):
    from ...api.main import get_graph_instance  # lazy import avoids circular dependency
    graph  = get_graph_instance()
    config = {"configurable": {"thread_id": thread_id}}

    try:
        async for part in graph.astream(
            None,
            config=config,
            stream_mode=["messages", "updates", "values"],
            subgraphs=True,
        ):
            event = _format_sse_part(part)
            if event:
                yield f"data: {json.dumps(event)}\n\n"
    except Exception as e:
        yield f"data: {json.dumps({'type': 'stream_error', 'error': str(e), 'timestamp': _utcnow()})}\n\n"

    yield f"data: {json.dumps({'type': 'run_complete', 'timestamp': _utcnow()})}\n\n"


@router.get("/{thread_id}/stream")
async def stream_run(thread_id: str):
    return StreamingResponse(
        _event_generator(thread_id),
        media_type="text/event-stream",
        headers={
            "Cache-Control":               "no-cache",
            "X-Accel-Buffering":           "no",
            "Access-Control-Allow-Origin": "*",
        },
    )
