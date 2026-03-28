from .base_agent import BaseTeamAgent, AgentState, _build_raw_finding, _utcnow
from ...core.models import AgentLoadOut
from ...tools.scope_checker import validate_scope, ScopeViolationError
from ...tools.web.js_bundle_tool import analyze_js_bundle


class CodeInspector(BaseTeamAgent):
    agent_id    = "CodeInspector"
    model_alias = "MODEL_AGENT_CODE"

    async def _execute_node(self, state: AgentState) -> dict:
        loadout   = AgentLoadOut(**state["loadout"])
        test_idx  = state.get("test_idx", 0)
        iteration = state.get("iteration", 0)
        scope_rules = state.get("scope_rules", {})

        if test_idx >= len(loadout.test_cases) or iteration >= loadout.max_iterations:
            return {"messages":[{"role":"system","content":"[CodeInspector] done","agent":self.agent_id,"ts":_utcnow()}]}

        tc      = loadout.test_cases[test_idx]
        surface = tc.get("surface","")

        try:
            validate_scope(surface, scope_rules)
        except ScopeViolationError:
            return {"test_idx": test_idx+1, "iteration": iteration+1,
                    "messages":[{"role":"system","content":"[CodeInspector] scope skip","agent":self.agent_id,"ts":_utcnow()}]}

        technique = tc.get("technique","")

        result = await self._run_code_technique(technique, surface, scope_rules, tc, loadout)

        findings = list(state.get("local_findings", []))
        if result.get("confirmed") or result.get("output"):
            findings.append(_build_raw_finding(tc, result, self.agent_id))

        should_collab = len(findings) > 0 and iteration > 0 and iteration % 3 == 0

        return {
            "local_findings": findings,
            "test_idx":       test_idx + 1,
            "iteration":      iteration + 1,
            "_should_collaborate": should_collab,
            "messages": [{"role":"system","content":f"[CodeInspector] {technique} → {'✓' if result.get('confirmed') else '·'}","agent":self.agent_id,"ts":_utcnow()}],
        }

    async def _run_code_technique(self, technique: str, surface: str, scope_rules: dict, tc: dict, loadout: AgentLoadOut) -> dict:
        if technique in ("js_secret_scan", "js_bundle_analyzer"):
            return await self._js_secret_scan([surface], scope_rules)
        if technique in ("source_map_leak",):
            return await self._source_map_leak(surface, scope_rules)
        if technique in ("api_key_exposure",):
            return await self._js_secret_scan([surface], scope_rules)
        return await self._llm_execute(tc, loadout, {})  # type: ignore

    async def _js_secret_scan(self, js_urls: list[str], scope_rules: dict) -> dict:
        findings = await analyze_js_bundle(js_urls, scope_rules)
        sensitive_types = ["api_key", "secret", "token", "aws_key", "password", "stripe_key", "sendgrid"]
        critical = [f for f in findings if f.get("type") in sensitive_types]
        if critical:
            return {
                "confirmed":   True,
                "output":      f"Found {len(critical)} sensitive values in JS: {[f['type'] for f in critical]}",
                "description": f"Sensitive data exposure in JavaScript bundle: {critical[0].get('type')} found",
                "request":     {"urls": js_urls},
                "response_diff": {"secrets_found": len(critical)},
                "payload":     "",
                "evidence":    {"secrets": critical[:5]},
                "reproduction_steps": [
                    f"1. Fetch JavaScript file: {js_urls[0] if js_urls else 'unknown'}",
                    f"2. Search for {critical[0].get('type')} pattern",
                    f"3. Found: {critical[0].get('value','')[:50]}...",
                ],
            }
        if findings:
            return {
                "confirmed":   False,
                "output":      f"Found {len(findings)} non-critical JS findings (endpoints, config)",
                "evidence":    {"findings": findings[:5]},
            }
        return {"confirmed": False, "output": ""}

    async def _source_map_leak(self, url: str, scope_rules: dict) -> dict:
        import httpx
        map_url = url + ".map" if not url.endswith(".map") else url
        try:
            async with httpx.AsyncClient(timeout=8, verify=False) as client:
                resp = await client.get(map_url,
                                        headers={"User-Agent": "Mozilla/5.0 BountyMind/4.0"})
                if resp.status_code == 200 and "sources" in resp.text:
                    return {
                        "confirmed":   True,
                        "output":      f"Source map exposed at {map_url}",
                        "description": f"Source map leak: original source code accessible at {map_url}",
                        "request":     {"url": map_url},
                        "response_diff": {"source_map_exposed": True},
                        "payload":     "",
                        "reproduction_steps": [
                            f"1. Fetch {map_url}",
                            "2. Observe sourceMappingURL or .map file with original source",
                            "3. Reconstruct original source code from map",
                        ],
                    }
        except Exception:
            pass
        return {"confirmed": False, "output": ""}
