import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from ..graph.checkpointer import get_checkpointer
from ..graph.builder import build_graph

_graph_instance = None


def get_graph_instance():
    if _graph_instance is None:
        raise RuntimeError("Graph not initialized")
    return _graph_instance


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _graph_instance
    checkpointer = await get_checkpointer()
    _graph_instance = await build_graph(checkpointer=checkpointer)
    yield
    _graph_instance = None


app = FastAPI(title="BountyMind API", version="4.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from .routers import runs, stream, hitl, state as state_router
from .websocket import router as ws_router

app.include_router(runs.router)
app.include_router(stream.router)
app.include_router(hitl.router)
app.include_router(state_router.router)
app.include_router(ws_router)


@app.get("/health")
async def health():
    return {"status": "ok", "graph": _graph_instance is not None}
