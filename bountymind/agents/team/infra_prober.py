import asyncio
import httpx
from urllib.parse import urlparse
from .base_agent import BaseTeamAgent, AgentState, _build_raw_finding, _utcnow
from ...core.models import AgentLoadOut
from ...tools.scope_checker import validate_scope, ScopeViolationError
from ...tools.recon.naabu_tool import naabu_scan


class InfraProber(BaseTeamAgent):
    agent_id    = "InfraProber"
    model_alias = "MODEL_AGENT_STD"

    async def _execute_node(self, state: AgentState) -> dict:
        loadout   = AgentLoadOut(**state["loadout"])
        test_idx  = state.get("test_idx", 0)
        iteration = state.get("iteration", 0)
        scope_rules = state.get("scope_rules", {})

        if test_idx >= len(loadout.test_cases) or iteration >= loadout.max_iterations:
            return {"messages":[{"role":"system","content":"[InfraProber] done","agent":self.agent_id,"ts":_utcnow()}]}

        tc      = loadout.test_cases[test_idx]
        surface = tc.get("surface","")

        try:
            validate_scope(surface, scope_rules)
        except ScopeViolationError:
            return {"test_idx": test_idx+1, "iteration": iteration+1,
                    "messages":[{"role":"system","content":"[InfraProber] scope skip","agent":self.agent_id,"ts":_utcnow()}]}

        technique   = tc.get("technique","")
        tool_config = loadout.tool_configs.get(technique, {})

        result = await self._run_infra_technique(technique, surface, scope_rules, tool_config, tc, loadout)

        findings = list(state.get("local_findings", []))
        if result.get("confirmed") or result.get("output"):
            findings.append(_build_raw_finding(tc, result, self.agent_id))

        should_collab = len(findings) > 0 and iteration > 0 and iteration % 3 == 0

        return {
            "local_findings": findings,
            "test_idx":       test_idx + 1,
            "iteration":      iteration + 1,
            "_should_collaborate": should_collab,
            "messages":[{"role":"system","content":f"[InfraProber] {technique} → {'✓' if result.get('confirmed') else '·'}","agent":self.agent_id,"ts":_utcnow()}],
        }

    async def _run_infra_technique(self, technique: str, surface: str, scope_rules: dict, config: dict, tc: dict, loadout: AgentLoadOut) -> dict:
        if technique in ("port_scan", "naabu"):
            return await self._port_scan(surface, scope_rules)
        if technique in ("exposed_services",):
            return await self._exposed_services(surface)
        if technique in ("cloud_metadata",):
            return await self._cloud_metadata(surface)
        if technique in ("env_files", "sensitive_files"):
            return await self._sensitive_files(surface)
        return await self._llm_execute(tc, loadout, {})  # type: ignore

    async def _port_scan(self, target: str, scope_rules: dict) -> dict:
        services = await naabu_scan(target, scope_rules, top_ports=50)
        dangerous_ports = {
            6379: "Redis (unauthenticated)",
            27017: "MongoDB (unauthenticated)",
            5432: "PostgreSQL",
            3306: "MySQL",
            9200: "Elasticsearch",
            2375: "Docker daemon (unauthenticated)",
            8500: "Consul",
            5601: "Kibana",
            4567: "Sinatra/development server",
        }
        exposed = [s for s in services if s.get("port") in dangerous_ports]
        if exposed:
            return {
                "confirmed":   True,
                "output":      f"Dangerous services exposed: {[str(s['service']) + ':' + str(s['port']) for s in exposed]}",
                "description": f"Dangerous ports exposed on {target}: {[s['port'] for s in exposed]}",
                "request":     {"target": target},
                "response_diff": {"exposed_services": exposed},
                "payload":     "",
                "reproduction_steps": [
                    f"1. Run port scan on {target}",
                    f"2. Found exposed services: {[str(s['port']) for s in exposed]}",
                    "3. Verify unauthenticated access to each service",
                ],
            }
        if services:
            return {"confirmed": False, "output": f"Port scan: {len(services)} ports open, none critically dangerous"}
        return {"confirmed": False, "output": ""}

    async def _exposed_services(self, target: str) -> dict:
        parsed = urlparse(target)
        base   = f"{parsed.scheme}://{parsed.netloc}"
        paths  = ["/.env", "/.git/HEAD", "/config.php", "/wp-config.php",
                  "/database.yml", "/config/database.yml", "/.htaccess",
                  "/server-status", "/phpinfo.php", "/info.php"]
        try:
            async with httpx.AsyncClient(timeout=6, verify=False) as client:
                for path in paths:
                    resp = await client.get(base + path,
                                            headers={"User-Agent": "Mozilla/5.0 BountyMind/4.0"})
                    if resp.status_code == 200 and any(
                        kw in resp.text for kw in
                        ["DB_PASSWORD", "APP_SECRET", "database:", "ref: refs/heads", "<?php", "phpinfo"]
                    ):
                        return {
                            "confirmed":   True,
                            "output":      f"Sensitive file exposed: {base+path}",
                            "description": f"Sensitive file exposure at {base+path}",
                            "request":     {"url": base+path},
                            "response_diff": {"file_exposed": path, "status": 200},
                            "payload":     "",
                            "reproduction_steps": [
                                f"1. GET {base+path}",
                                "2. Observe sensitive configuration data in response",
                            ],
                        }
        except Exception:
            pass
        return {"confirmed": False, "output": ""}

    async def _cloud_metadata(self, target: str) -> dict:
        metadata_urls = [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.170.2/v2/metadata",
            "http://metadata.google.internal/computeMetadata/v1/",
        ]
        try:
            async with httpx.AsyncClient(timeout=3, verify=False) as client:
                for url in metadata_urls:
                    try:
                        resp = await client.get(url, headers={"Metadata-Flavor": "Google"})
                        if resp.status_code == 200 and len(resp.text) > 10:
                            return {
                                "confirmed":   True,
                                "output":      f"Cloud metadata accessible: {url}",
                                "description": f"Cloud metadata service accessible from target host context",
                                "request":     {"url": url},
                                "response_diff": {"accessible": True},
                                "payload":     "",
                                "reproduction_steps": [
                                    f"1. Fetch {url} from target context (via SSRF or direct)",
                                    "2. Observe IAM credentials, instance metadata",
                                ],
                            }
                    except Exception:
                        pass
        except Exception:
            pass
        return {"confirmed": False, "output": ""}

    async def _sensitive_files(self, target: str) -> dict:
        return await self._exposed_services(target)
