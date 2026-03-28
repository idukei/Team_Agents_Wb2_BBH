import os
import httpx

HACKERONE_TOKEN = os.getenv("HACKERONE_TOKEN", "")
NVD_API_KEY     = os.getenv("NVD_API_KEY",     "")


async def search_hacktivity(tech_fingerprint: str, sector: str, auth_type: str) -> list[dict]:
    if HACKERONE_TOKEN:
        return await _hackerone_hacktivity(tech_fingerprint, sector)
    return _static_hacktivity(tech_fingerprint, sector, auth_type)


async def _hackerone_hacktivity(tech_fingerprint: str, sector: str) -> list[dict]:
    query = """
    query($q: String!) {
      hacktivity(order_by: {field: popular}, filter: {query: $q}, first: 10) {
        edges {
          node {
            ... on HacktivityItemInterface {
              disclosed_at
              report { title url severity_rating }
            }
          }
        }
      }
    }
    """
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(
                "https://hackerone.com/graphql",
                json={"query": query, "variables": {"q": f"{tech_fingerprint} {sector}"}},
                headers={"Authorization": f"Bearer {HACKERONE_TOKEN}"},
            )
            if resp.status_code == 200:
                edges = (resp.json().get("data") or {}).get("hacktivity", {}).get("edges", [])
                results = []
                for e in edges:
                    node   = e.get("node", {})
                    report = node.get("report", {})
                    if report.get("title"):
                        results.append({
                            "title":    report["title"],
                            "url":      report.get("url", ""),
                            "severity": report.get("severity_rating", ""),
                            "date":     node.get("disclosed_at", ""),
                        })
                return results
    except Exception:
        pass
    return _static_hacktivity(tech_fingerprint, sector, "")


def _static_hacktivity(tech_fingerprint: str, sector: str, auth_type: str) -> list[dict]:
    base = [
        {"title": "IDOR via sequential IDs on REST API",                  "severity": "high",     "technique": "idor"},
        {"title": "Stored XSS in user-controlled input field",            "severity": "medium",   "technique": "stored_xss"},
        {"title": "Open redirect allows token theft post-authentication", "severity": "medium",   "technique": "open_redirect"},
        {"title": "Mass assignment on user object allows role escalation","severity": "critical", "technique": "mass_assignment"},
        {"title": "Password reset token entropy too low",                 "severity": "high",     "technique": "reset_token_analysis"},
        {"title": "CORS wildcard on API allows cross-origin reads",       "severity": "high",     "technique": "cors_misconfiguration"},
        {"title": "SSRF via webhook URL parameter",                       "severity": "critical", "technique": "ssrf"},
        {"title": "JWT algorithm confusion (RS256→HS256)",                "severity": "critical", "technique": "jwt_weakness"},
    ]

    sector_extras = {
        "fintech":    [{"title": "Race condition in payment endpoint", "severity": "critical", "technique": "race_condition"}],
        "saas_b2b":   [{"title": "Tenant isolation bypass via subdomain", "severity": "critical", "technique": "idor"}],
        "ecommerce":  [{"title": "Price manipulation via cart parameter tampering", "severity": "high", "technique": "parameter_tampering"}],
        "devtools":   [{"title": "Webhook SSRF reaches internal metadata", "severity": "critical", "technique": "ssrf"}],
    }

    extras = sector_extras.get(sector, [])
    return (base + extras)[:10]


async def search_cves(technologies: list[dict]) -> list[dict]:
    cves = []
    for tech in technologies[:5]:
        name    = tech.get("name", "")
        version = tech.get("version", "")
        if name:
            found = await _nvd_search(name, version)
            cves.extend(found)
    return cves[:10]


async def _nvd_search(product: str, version: str) -> list[dict]:
    params: dict = {"keywordSearch": product, "resultsPerPage": "5"}
    if version:
        params["keywordSearch"] = f"{product} {version}"
    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params=params,
                headers=headers,
            )
            if resp.status_code != 200:
                return []

            items = resp.json().get("vulnerabilities", [])
            results = []
            for item in items:
                cve   = item.get("cve", {})
                cvss  = _extract_cvss(cve)
                descs = cve.get("descriptions", [])
                desc  = next((d["value"] for d in descs if d.get("lang") == "en"), "")
                results.append({
                    "id":          cve.get("id", ""),
                    "description": desc[:200],
                    "cvss_score":  cvss,
                    "product":     product,
                    "version":     version,
                })
            return results
    except Exception:
        return []


def _extract_cvss(cve: dict) -> float:
    try:
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key, [])
            if entries:
                return entries[0].get("cvssData", {}).get("baseScore", 0.0)
    except Exception:
        pass
    return 0.0


async def search_proven_techniques(tech_fingerprint: str, auth_mechanisms: list[dict]) -> list[dict]:
    base = [
        {"technique": "idor",              "description": "Test sequential/predictable IDs on all endpoints", "priority": 1},
        {"technique": "mass_assignment",   "description": "Send extra fields like role/admin in POST/PUT",    "priority": 1},
        {"technique": "open_redirect",     "description": "Test redirect/next/url params on auth flows",      "priority": 2},
        {"technique": "cors_check",        "description": "Test CORS with evil origin on all API endpoints",  "priority": 1},
        {"technique": "csrf_check",        "description": "Check forms for CSRF token presence",              "priority": 2},
        {"technique": "user_enumeration",  "description": "Compare responses for valid/invalid usernames",    "priority": 2},
        {"technique": "js_secret_scan",    "description": "Analyze all .js bundles for hardcoded secrets",    "priority": 1},
        {"technique": "timing_attack",     "description": "Time-diff login requests for user enumeration",    "priority": 3},
    ]

    fp = tech_fingerprint.lower()
    if "react" in fp or "vue" in fp or "angular" in fp:
        base.append({"technique": "source_map_leak", "description": "Check for exposed .js.map files", "priority": 2})
    if "graphql" in fp:
        base.append({"technique": "graphql_introspection", "description": "Test GraphQL introspection in prod", "priority": 1})
    if "jwt" in str(auth_mechanisms).lower():
        base.append({"technique": "jwt_weakness", "description": "Test JWT alg:none and key confusion", "priority": 1})

    return base


async def search_github_osint(domain: str) -> list[str]:
    if not domain or not os.getenv("GITHUB_TOKEN"):
        return [
            f"Search GitHub for: '{domain} api_key OR secret OR password'",
            f"Search Shodan for exposed services on {domain}",
            f"Check certificate transparency logs for {domain} subdomains",
        ]

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                "https://api.github.com/search/code",
                params={"q": f"{domain} api_key OR secret", "per_page": "5"},
                headers={
                    "Authorization": f"Bearer {os.getenv('GITHUB_TOKEN')}",
                    "Accept":        "application/vnd.github.v3+json",
                },
            )
            if resp.status_code == 200:
                items = resp.json().get("items", [])
                return [
                    f"GitHub leak: {item['repository']['full_name']}/{item['name']}"
                    for item in items
                ]
    except Exception:
        pass

    return [f"OSINT search pending for {domain}"]
