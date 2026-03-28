import asyncio
from datetime import datetime, timezone
from typing import Any

from langgraph.store.base import BaseStore


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _identify_connections(my_findings: list[dict], all_observations: list[dict]) -> list[dict]:
    candidates = []
    for finding in my_findings:
        f_url  = finding.get("url", "")
        f_type = finding.get("vuln_type", "")
        for obs in all_observations:
            o_url   = obs.get("url", "")
            o_type  = obs.get("vuln_type", "")
            o_agent = obs.get("agent_id", "")
            if not o_url:
                continue
            url_related = (
                f_url == o_url
                or (f_url and o_url and f_url.split("/")[2] == o_url.split("/")[2])
            )
            chain_pairs = [
                ("open_redirect",      "xss"),
                ("user_enumeration",   "reset_token_predictable"),
                ("idor",               "information_disclosure"),
                ("mass_assignment",    "privilege_escalation"),
                ("ssrf",               "internal_exposure"),
                ("xss",                "csrf"),
                ("path_traversal",     "information_disclosure"),
                ("jwt_weakness",       "account_takeover"),
            ]
            type_related = any(
                (f_type in pair and o_type in pair)
                for pair in chain_pairs
            )
            if url_related or type_related:
                candidates.append({
                    "my_finding":    finding,
                    "related":       obs,
                    "related_agent": o_agent,
                    "chain_hint":    f"{f_type} + {o_type}" if type_related else f"same surface: {f_url}",
                })
    return candidates


class SharedMemory:
    def __init__(self, store: BaseStore, thread_id: str):
        self.store     = store
        self.ns        = ("working_memory", thread_id)
        self.thread_id = thread_id

    async def write(self, channel: str, agent_id: str, data: dict) -> None:
        key = f"{channel}:{agent_id}"
        await self.store.aput(self.ns, key, {
            **data,
            "agent_id":  agent_id,
            "channel":   channel,
            "timestamp": _utcnow(),
        })

    async def read(self, channel: str, exclude: str | None = None) -> list[dict]:
        try:
            items = await self.store.asearch(self.ns, query=channel, limit=50)
            return [
                i.value for i in items
                if i.key.startswith(channel)
                and (exclude is None or i.value.get("agent_id") != exclude)
            ]
        except Exception:
            return []

    async def read_all(self, exclude: str | None = None) -> list[dict]:
        try:
            items = await self.store.asearch(self.ns, query="", limit=200)
            return [
                i.value for i in items
                if exclude is None or i.value.get("agent_id") != exclude
            ]
        except Exception:
            return []

    async def find_chain_candidates(self, my_findings: list[dict]) -> list[dict]:
        all_obs = await self.read("observations")
        return _identify_connections(my_findings, all_obs)

    async def write_findings(self, agent_id: str, findings: list[dict]) -> None:
        await self.write("observations", agent_id, {"findings": findings})

    async def read_findings(self, exclude: str | None = None) -> list[dict]:
        observations = await self.read("observations", exclude=exclude)
        all_findings = []
        for obs in observations:
            all_findings.extend(obs.get("findings", []))
        return all_findings
