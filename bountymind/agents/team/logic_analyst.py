import httpx
from .base_agent import BaseTeamAgent, AgentState, _build_raw_finding, _utcnow
from ...core.models import AgentLoadOut
from ...tools.scope_checker import validate_scope, ScopeViolationError


class LogicAnalyst(BaseTeamAgent):
    agent_id    = "LogicAnalyst"
    model_alias = "MODEL_SYNTHESIZER"

    async def _execute_node(self, state: AgentState) -> dict:
        loadout   = AgentLoadOut(**state["loadout"])
        test_idx  = state.get("test_idx", 0)
        iteration = state.get("iteration", 0)
        scope_rules = state.get("scope_rules", {})

        if test_idx >= len(loadout.test_cases) or iteration >= loadout.max_iterations:
            return {"messages": [{"role":"system","content":"[LogicAnalyst] done","agent":self.agent_id,"ts":_utcnow()}]}

        tc = loadout.test_cases[test_idx]
        surface = tc.get("surface", "")

        try:
            validate_scope(surface, scope_rules)
        except ScopeViolationError:
            return {"test_idx": test_idx+1, "iteration": iteration+1,
                    "messages":[{"role":"system","content":"[LogicAnalyst] scope skip","agent":self.agent_id,"ts":_utcnow()}]}

        technique   = tc.get("technique","")
        tool_config = loadout.tool_configs.get(technique, {})

        result = await self._run_logic_technique(technique, surface, tool_config, tc, loadout)

        findings = list(state.get("local_findings", []))
        if result.get("confirmed") or result.get("output"):
            findings.append(_build_raw_finding(tc, result, self.agent_id))

        should_collab = len(findings) > 0 and iteration > 0 and iteration % 3 == 0

        return {
            "local_findings": findings,
            "test_idx":       test_idx + 1,
            "iteration":      iteration + 1,
            "_should_collaborate": should_collab,
            "messages": [{"role":"system","content":f"[LogicAnalyst] {technique} → {'✓' if result.get('confirmed') else '·'}","agent":self.agent_id,"ts":_utcnow()}],
        }

    async def _run_logic_technique(self, technique: str, surface: str, config: dict, tc: dict, loadout: AgentLoadOut) -> dict:
        if technique in ("idor", "insecure_direct_object_reference"):
            return await self._test_idor(surface, config)
        if technique in ("mass_assignment",):
            return await self._test_mass_assignment(surface, config)
        if technique in ("privilege_escalation", "privilege_escalation_check"):
            return await self._test_privilege_escalation(surface, config)
        if technique in ("business_logic", "workflow_bypass"):
            return await self._test_workflow_bypass(surface, config)
        return await self._llm_execute(tc, loadout, {})  # type: ignore

    async def _test_idor(self, url: str, config: dict) -> dict:
        id_param = config.get("id_param", "id")
        try:
            async with httpx.AsyncClient(timeout=8, verify=False, follow_redirects=True) as client:
                resp1 = await client.get(f"{url}?{id_param}=1",
                                         headers={"User-Agent": "Mozilla/5.0 BountyMind/4.0"})
                resp2 = await client.get(f"{url}?{id_param}=2",
                                         headers={"User-Agent": "Mozilla/5.0 BountyMind/4.0"})

                if resp1.status_code == 200 and resp2.status_code == 200:
                    if resp1.text[:200] != resp2.text[:200]:
                        return {
                            "confirmed":   True,
                            "output":      f"IDOR: different objects accessible at {url}?{id_param}=1 and ?{id_param}=2",
                            "description": f"Potential IDOR at {url} via parameter {id_param}",
                            "request":     {"url": url, "param": id_param},
                            "response_diff": {"id1_accessible": True, "id2_accessible": True},
                            "payload":     f"{id_param}=1 / {id_param}=2",
                            "reproduction_steps": [
                                f"1. GET {url}?{id_param}=1 — returns data",
                                f"2. GET {url}?{id_param}=2 — returns different data",
                                "3. Verify if authenticated user should have access to object #2",
                            ],
                        }
        except Exception:
            pass
        return {"confirmed": False, "output": ""}

    async def _test_mass_assignment(self, url: str, config: dict) -> dict:
        privileged_fields = config.get("fields", ["role", "admin", "is_admin", "privilege", "permissions"])
        try:
            async with httpx.AsyncClient(timeout=8, verify=False, follow_redirects=True) as client:
                for field in privileged_fields:
                    payload = {field: "admin"}
                    resp = await client.post(url, json=payload,
                                             headers={"User-Agent": "Mozilla/5.0 BountyMind/4.0",
                                                      "Content-Type": "application/json"})
                    if resp.status_code in (200, 201) and field in resp.text:
                        return {
                            "confirmed":   True,
                            "output":      f"Mass assignment: field '{field}' accepted at {url}",
                            "description": f"Mass assignment vulnerability at {url}: privileged field '{field}' accepted",
                            "request":     {"url": url, "payload": payload},
                            "response_diff": {"field_accepted": field},
                            "payload":     str(payload),
                            "reproduction_steps": [
                                f"1. POST {url} with {{'{field}': 'admin'}}",
                                f"2. Observe '{field}' reflected in response",
                                "3. Confirm privilege escalation via mass assignment",
                            ],
                        }
        except Exception:
            pass
        return {"confirmed": False, "output": ""}

    async def _test_privilege_escalation(self, url: str, config: dict) -> dict:
        admin_paths = ["/admin", "/api/admin", "/dashboard/admin", "/management", "/superuser"]
        try:
            async with httpx.AsyncClient(timeout=8, verify=False, follow_redirects=False) as client:
                import re
                from urllib.parse import urlparse
                base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
                for path in admin_paths:
                    resp = await client.get(base + path,
                                            headers={"User-Agent": "Mozilla/5.0 BountyMind/4.0"})
                    if resp.status_code == 200:
                        return {
                            "confirmed":   True,
                            "output":      f"Admin endpoint accessible without elevated privileges: {base+path}",
                            "description": f"Privilege escalation: {base+path} accessible without admin role",
                            "request":     {"url": base+path},
                            "response_diff": {"status": 200, "path": path},
                            "payload":     "",
                            "reproduction_steps": [
                                f"1. Navigate to {base+path} without admin privileges",
                                "2. Observe 200 response",
                                "3. Confirm unauthorized access to admin functionality",
                            ],
                        }
        except Exception:
            pass
        return {"confirmed": False, "output": ""}

    async def _test_workflow_bypass(self, url: str, config: dict) -> dict:
        step_params = config.get("steps", ["step=2", "step=3", "checkout"])
        try:
            async with httpx.AsyncClient(timeout=8, verify=False, follow_redirects=True) as client:
                for step in step_params:
                    test_url = f"{url}?{step}" if "=" in step else f"{url}/{step}"
                    resp = await client.get(test_url,
                                            headers={"User-Agent": "Mozilla/5.0 BountyMind/4.0"})
                    if resp.status_code == 200 and any(k in resp.text.lower()
                        for k in ["checkout", "payment", "confirm", "order"]):
                        return {
                            "confirmed":   True,
                            "output":      f"Workflow step bypassed: {test_url}",
                            "description": f"Business logic bypass: step skipped at {test_url}",
                            "request":     {"url": test_url},
                            "response_diff": {"bypassed_step": step},
                            "payload":     test_url,
                            "reproduction_steps": [
                                f"1. Navigate directly to {test_url}",
                                "2. Observe access to later workflow step without completing earlier steps",
                                "3. Confirm business logic bypass",
                            ],
                        }
        except Exception:
            pass
        return {"confirmed": False, "output": ""}
