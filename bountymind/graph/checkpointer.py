from __future__ import annotations

import aiosqlite

from ..core.config import app_config


async def get_checkpointer():
    """Return the appropriate LangGraph checkpointer based on environment.

    - production + POSTGRES_URL set → AsyncPostgresSaver
    - dev (default)                 → AsyncSqliteSaver (persistent, file-based)
    - last resort                   → MemorySaver (in-memory, no persistence)

    NOTE: AsyncSqliteSaver requires an open aiosqlite connection for its lifetime.
    The connection is opened here and kept open for the application's lifetime.
    """
    # Production: Postgres
    if app_config.APP_ENV == "production" and app_config.POSTGRES_URL:
        try:
            from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
            cp = AsyncPostgresSaver.from_conn_string(app_config.POSTGRES_URL)
            await cp.setup()
            print(f"[checkpointer] Using AsyncPostgresSaver ({app_config.POSTGRES_URL[:30]}...)")
            return cp
        except Exception as e:
            print(f"[checkpointer] Postgres unavailable ({e}), falling back to SQLite")

    # Development default: SQLite (persistent, no Docker dependency)
    try:
        from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver
        conn = await aiosqlite.connect("bountymind_dev.db")
        cp = AsyncSqliteSaver(conn)
        await cp.setup()
        print("[checkpointer] Using AsyncSqliteSaver (bountymind_dev.db)")
        return cp
    except Exception as e:
        print(f"[checkpointer] SQLite unavailable ({e}), falling back to MemorySaver")
        from langgraph.checkpoint.memory import MemorySaver
        return MemorySaver()
