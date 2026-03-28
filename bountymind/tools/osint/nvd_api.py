import asyncio
import httpx
from urllib.parse import quote


NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


async def nvd_search_cve(technology: str, version: str = "") -> list[dict]:
    query = technology
    if version:
        query += f" {version}"

    try:
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.get(
                NVD_BASE,
                params={
                    "keywordSearch": query,
                    "resultsPerPage": 10,
                    "startIndex":    0,
                },
                headers={"User-Agent": "BountyMind-Intel/4.0"},
            )

            if resp.status_code == 200:
                data = resp.json()
                results = []
                for vuln in data.get("vulnerabilities", []):
                    cve_data = vuln.get("cve", {})
                    cve_id = cve_data.get("id", "")

                    descriptions = cve_data.get("descriptions", [])
                    desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

                    metrics = cve_data.get("metrics", {})
                    cvss_score = 0.0
                    for metric_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                        if metric_key in metrics and metrics[metric_key]:
                            cvss_score = metrics[metric_key][0].get("cvssData", {}).get("baseScore", 0.0)
                            break

                    refs = cve_data.get("references", [])
                    poc_url = next((r["url"] for r in refs if any(p in r.get("url", "").lower()
                                   for p in ["exploit", "poc", "github.com/exploit"])), "")

                    results.append({
                        "cve":         cve_id,
                        "technology":  technology,
                        "version":     version,
                        "cvss":        cvss_score,
                        "description": desc[:300],
                        "poc":         poc_url,
                    })

                return results
    except Exception:
        pass

    return []


async def nvd_batch_search(tech_list: list[dict]) -> list[dict]:
    all_cves = []
    for tech in tech_list[:10]:
        name = tech.get("name", "")
        version = tech.get("version", "")
        if name:
            cves = await nvd_search_cve(name, version)
            all_cves.extend(cves)
            await asyncio.sleep(0.6)
    return all_cves
