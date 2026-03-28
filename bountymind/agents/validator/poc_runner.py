import asyncio
import httpx
from datetime import datetime, timezone


async def run_poc(finding: dict, replications: int = 3) -> dict:
    technique = finding.get("vuln_type", "")
    request   = finding.get("request", {})
    url       = request.get("url", finding.get("url", ""))
    payload   = finding.get("payload", "")

    if not url:
        return {"reproduced": False, "reproducibility": 0.0, "attempts": 0}

    successes = 0
    attempts  = 0

    try:
        async with httpx.AsyncClient(timeout=10, verify=False, follow_redirects=True) as client:
            for _ in range(replications):
                attempts += 1
                try:
                    result = await _replay_request(client, finding)
                    if result:
                        successes += 1
                except Exception:
                    pass
                await asyncio.sleep(0.3)
    except Exception:
        pass

    reproducibility = successes / max(attempts, 1)
    return {
        "reproduced":      successes > 0,
        "reproducibility": round(reproducibility, 2),
        "attempts":        attempts,
        "successes":       successes,
        "timestamp":       datetime.now(timezone.utc).isoformat(),
    }


async def _replay_request(client: httpx.AsyncClient, finding: dict) -> bool:
    technique = finding.get("vuln_type", "")
    request   = finding.get("request", {})
    url       = request.get("url", finding.get("url", ""))
    payload   = finding.get("payload", "")
    params    = request.get("params", {})
    method    = request.get("method", "GET").upper()

    if not url:
        return False

    try:
        if method == "POST":
            if isinstance(params, dict):
                resp = await client.post(url, data=params,
                                         headers={"User-Agent": "Mozilla/5.0 BountyMind-PoC/4.0"})
            else:
                resp = await client.post(url,
                                         headers={"User-Agent": "Mozilla/5.0 BountyMind-PoC/4.0"})
        else:
            kwargs = {}
            if isinstance(params, dict) and params:
                kwargs["params"] = params
            resp = await client.get(url,
                                    headers={"User-Agent": "Mozilla/5.0 BountyMind-PoC/4.0"},
                                    **kwargs)

        if technique in ("xss", "xss_reflected") and payload:
            return payload in resp.text
        if technique in ("open_redirect", "oauth_redirect_uri"):
            return resp.status_code in (301, 302, 303, 307, 308)
        if technique in ("user_enumeration", "timing_attack"):
            return resp.status_code in (200, 400, 422)
        if technique in ("idor",):
            return resp.status_code == 200
        if technique in ("cors_check", "cors_misconfiguration"):
            acao = resp.headers.get("access-control-allow-origin", "")
            return acao == "*" or "evil" in acao
        if technique in ("csrf", "csrf_check"):
            return resp.status_code == 200

        return resp.status_code < 500
    except Exception:
        return False
