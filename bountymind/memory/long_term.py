from datetime import datetime, timezone
from langgraph.store.base import BaseStore


_NS_TECHNIQUES = ("long_term", "successful_techniques")
_NS_LOADOUTS   = ("long_term", "productive_loadouts")
_NS_REPORTS    = ("long_term", "accepted_reports")


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


class LongTermMemory:
    def __init__(self, store: BaseStore):
        self.store = store

    async def save_technique(self, technique: str, context: dict) -> None:
        key = f"{technique}:{_utcnow()}"
        await self.store.aput(_NS_TECHNIQUES, key, {
            "technique": technique,
            "context":   context,
            "timestamp": _utcnow(),
        })

    async def get_techniques(self, query: str = "", limit: int = 10) -> list[dict]:
        try:
            items = await self.store.asearch(_NS_TECHNIQUES, query=query, limit=limit)
            return [i.value for i in items]
        except Exception:
            return []

    async def save_productive_loadout(self, agent_id: str, loadout: dict, findings_count: int) -> None:
        key = f"{agent_id}:{_utcnow()}"
        await self.store.aput(_NS_LOADOUTS, key, {
            "agent_id":      agent_id,
            "loadout":       loadout,
            "findings_count": findings_count,
            "timestamp":     _utcnow(),
        })

    async def get_productive_loadouts(self, agent_id: str) -> list[dict]:
        try:
            items = await self.store.asearch(_NS_LOADOUTS, query=agent_id, limit=5)
            return [i.value for i in items if i.value.get("agent_id") == agent_id]
        except Exception:
            return []

    async def save_report(self, finding: dict, platform: str) -> None:
        key = f"{platform}:{_utcnow()}"
        await self.store.aput(_NS_REPORTS, key, {
            "finding":   finding,
            "platform":  platform,
            "timestamp": _utcnow(),
        })

    async def get_reports(self, platform: str = "", limit: int = 10) -> list[dict]:
        try:
            items = await self.store.asearch(_NS_REPORTS, query=platform, limit=limit)
            return [i.value for i in items]
        except Exception:
            return []
