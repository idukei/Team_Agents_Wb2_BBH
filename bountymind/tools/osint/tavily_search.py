import asyncio
import httpx
import json
from ...core.config import app_config


async def tavily_search(query: str, max_results: int = 5) -> list[dict]:
    if not app_config.TAVILY_API_KEY:
        return await _duckduckgo_fallback(query, max_results)

    try:
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.post(
                "https://api.tavily.com/search",
                json={
                    "api_key":       app_config.TAVILY_API_KEY,
                    "query":         query,
                    "search_depth":  "basic",
                    "max_results":   max_results,
                    "include_answer": False,
                },
            )
            if resp.status_code == 200:
                data = resp.json()
                return [
                    {
                        "title":   r.get("title", ""),
                        "url":     r.get("url", ""),
                        "content": r.get("content", "")[:500],
                        "score":   r.get("score", 0.0),
                    }
                    for r in data.get("results", [])
                ]
    except Exception:
        pass

    return await _duckduckgo_fallback(query, max_results)


async def _duckduckgo_fallback(query: str, max_results: int) -> list[dict]:
    try:
        async with httpx.AsyncClient(
            timeout=15,
            headers={"User-Agent": "Mozilla/5.0 BountyMind-OSINT/4.0"},
            follow_redirects=True,
        ) as client:
            resp = await client.get(
                "https://html.duckduckgo.com/html/",
                params={"q": query},
            )
            import re
            results = []
            for m in re.finditer(r'<a[^>]+class="result__a"[^>]+href="([^"]+)"[^>]*>([^<]+)</a>', resp.text):
                results.append({
                    "title":   m.group(2).strip(),
                    "url":     m.group(1),
                    "content": "",
                    "score":   0.5,
                })
                if len(results) >= max_results:
                    break
            return results
    except Exception:
        return []
