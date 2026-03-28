import json
import re
from datetime import datetime, timezone

from langchain_core.messages import HumanMessage, SystemMessage

from ...core.fireworks import get_model
from ...core.models import AgentLoadOut
from ...core.state import BountyMindState
from ...tools.registry import ToolRegistry
from .loadout_validator import validate_loadout


STRATEGY_SYSTEM = """Eres el Strategy Engine de BountyMind. Generas estrategias de bug bounty
completamente específicas para el objetivo analizado.

REGLAS CRÍTICAS:
- Los test_cases DEBEN usar datos reales del surface_inventory (URLs exactas, field names reales)
- Las tool_configs DEBEN usar URLs, field names y versiones exactas detectadas
- Los system_prompts DEBEN incluir técnicas de hacktivity relevantes
- Asigna active:false con rationale a agentes no relevantes para este target
- Los 6 agentes son SIEMPRE los mismos: WebTester, AuthProber, LogicAnalyst, CodeInspector, IntegrationScout, InfraProber
- NUNCA inventes URLs o field names — úsalos exclusivamente del surface_inventory proporcionado

FORMATO DE SALIDA: JSON puro con claves "attack_strategy" y "agent_loadouts". Sin markdown, sin explicaciones."""


def build_strategy_prompt(
    surface_inventory: dict,
    target_context: dict,
    tool_descriptions: str,
) -> str:
    endpoints   = surface_inventory.get("endpoints", [])[:20]
    forms       = surface_inventory.get("forms", [])[:10]
    auth_mechs  = surface_inventory.get("auth_mechanisms", [])
    technologies = surface_inventory.get("technologies", [])
    ext_links   = surface_inventory.get("external_links", [])[:10]
    behaviors   = surface_inventory.get("behaviors", [])
    js_findings = surface_inventory.get("js_findings", [])[:10]
    infra       = surface_inventory.get("infrastructure", [])

    return f"""=== SUPERFICIE TÉCNICA COMPLETA ===
ENDPOINTS ({len(endpoints)} de {len(surface_inventory.get('endpoints', []))} totales):
{json.dumps(endpoints, indent=2)}

FORMS ({len(forms)}):
{json.dumps(forms, indent=2)}

AUTH MECHANISMS:
{json.dumps(auth_mechs, indent=2)}

TECHNOLOGIES:
{json.dumps(technologies, indent=2)}

EXTERNAL LINKS:
{json.dumps(ext_links, indent=2)}

BEHAVIORS OBSERVADOS:
{json.dumps(behaviors, indent=2)}

JS FINDINGS:
{json.dumps(js_findings, indent=2)}

INFRASTRUCTURE:
{json.dumps(infra, indent=2)}

=== INTELIGENCIA INVESTIGADA ===
Stack: {target_context.get('tech_fingerprint', 'Unknown')}
Sector: {target_context.get('sector', 'Unknown')}
CVEs conocidos: {json.dumps(target_context.get('cve_list', [])[:5], indent=2)}
Técnicas probadas: {json.dumps(target_context.get('proven_techniques', [])[:5], indent=2)}
Hacktivity: {json.dumps(target_context.get('hacktivity_items', [])[:5], indent=2)}
Patrones del sector: {json.dumps(target_context.get('sector_patterns', []), indent=2)}
Observaciones OSINT: {json.dumps(target_context.get('interesting_observations', []), indent=2)}

=== EQUIPO DISPONIBLE ===
- WebTester:        formularios, endpoints HTTP, flows, parámetros, redirect flows, cookies
- AuthProber:       auth mechanisms, password reset, tokens, JWT, OAuth, MFA, session mgmt
- LogicAnalyst:     lógica de negocio, workflows, invariantes, privilegios, pagos
- CodeInspector:    JS bundles, API keys, endpoints hardcoded, source maps, configs
- IntegrationScout: external links, webhooks, third-party, redirects, SSRF, CORS
- InfraProber:      servicios de red, ports, misconfigs de infraestructura, cloud exposure

=== TOOLS DISPONIBLES ===
{tool_descriptions}

=== INSTRUCCIÓN ===
Genera un JSON con exactamente estas dos claves: "attack_strategy" y "agent_loadouts".

"attack_strategy" debe seguir este schema:
{{
  "narrative": "descripción de la estrategia global",
  "threat_areas": [{{"area": str, "rationale": str, "priority": int, "surfaces_involved": [str]}}],
  "testing_sequence": [{{"step": int, "agents": [str], "rationale": str, "depends_on": [int]}}],
  "global_hypotheses": [{{"hypothesis": str, "rationale": str, "assigned_agent": str, "priority": int}}],
  "collaboration_plan": {{"channels": [str], "handoffs": [{{"from": str, "to": str, "trigger": str}}]}}
}}

"agent_loadouts" debe ser un dict con los 6 agent_ids como claves, cada uno con:
{{
  "agent_id": str,
  "active": bool,
  "priority": int (0=primera oleada, 1=segunda),
  "mission": str,
  "rationale": str,
  "hypotheses": [str],
  "test_cases": [{{"surface": str (URL REAL), "technique": str, "expected": str, "priority": int}}],
  "system_prompt": str,
  "methodology": [str],
  "tools": [str],
  "tool_configs": {{}},
  "write_channels": [str],
  "read_channels": [str],
  "handoff_targets": [str],
  "max_iterations": int,
  "interrupt_conditions": [str],
  "success_criteria": [str]
}}

IMPORTANTE: Los test_cases.surface DEBEN ser URLs que aparezcan en el surface_inventory.
Si un agente no es relevante, pon active:false con rationale explicando por qué."""


async def strategy_engine_node(state: BountyMindState) -> dict:
    now = datetime.now(timezone.utc).isoformat()
    surface_inventory = state.get("surface_inventory") or {}
    target_context    = state.get("target_context") or {}

    tool_descriptions = ToolRegistry.list_all_with_descriptions()

    llm = get_model("MODEL_THINKER", temperature=0.2)

    response = await llm.ainvoke([
        SystemMessage(content=STRATEGY_SYSTEM),
        HumanMessage(content=build_strategy_prompt(
            surface_inventory, target_context, tool_descriptions
        )),
    ])

    raw_json = _extract_json(response.content)

    attack_strategy = raw_json.get("attack_strategy", _empty_attack_strategy())
    raw_loadouts    = raw_json.get("agent_loadouts", {})

    loadouts = {}
    validation_errors = []
    for agent_id, loadout_dict in raw_loadouts.items():
        loadout_dict["agent_id"] = agent_id
        try:
            loadout = AgentLoadOut(**_fill_loadout_defaults(loadout_dict))
            loadout = _enrich_loadout_with_surface_data(loadout, surface_inventory)
            result  = validate_loadout(loadout, surface_inventory)
            if not result["valid"] and loadout.active:
                validation_errors.extend(result["errors"])
            loadouts[agent_id] = loadout.model_dump()
        except Exception as e:
            validation_errors.append(f"{agent_id}: {str(e)}")
            loadouts[agent_id] = _fallback_loadout(agent_id, surface_inventory)

    for agent_id in ["WebTester", "AuthProber", "LogicAnalyst",
                     "CodeInspector", "IntegrationScout", "InfraProber"]:
        if agent_id not in loadouts:
            loadouts[agent_id] = _fallback_loadout(agent_id, surface_inventory)

    return {
        "attack_strategy": attack_strategy,
        "agent_loadouts":  loadouts,
        "phase":           "STRATEGY",
        "phase_history":   [{"phase": "STRATEGY", "timestamp": now}],
        "audit_log": [{
            "event":             "strategy_generated",
            "timestamp":         now,
            "active_agents":     sum(1 for lo in loadouts.values() if lo.get("active")),
            "total_test_cases":  sum(len(lo.get("test_cases", [])) for lo in loadouts.values()),
            "validation_errors": validation_errors,
        }],
    }


def _extract_json(content: str) -> dict:
    json_match = re.search(r'\{.*\}', content, re.DOTALL)
    if json_match:
        try:
            return json.loads(json_match.group(0))
        except json.JSONDecodeError:
            pass
    try:
        start = content.index('{')
        depth = 0
        for i, ch in enumerate(content[start:], start):
            if ch == '{':
                depth += 1
            elif ch == '}':
                depth -= 1
                if depth == 0:
                    return json.loads(content[start:i+1])
    except (ValueError, json.JSONDecodeError):
        pass
    return {}


def _fill_loadout_defaults(d: dict) -> dict:
    defaults = {
        "active":             True,
        "priority":           0,
        "mission":            d.get("mission", f"Execute {d.get('agent_id','agent')} tasks"),
        "rationale":          d.get("rationale", ""),
        "hypotheses":         d.get("hypotheses", []),
        "test_cases":         d.get("test_cases", []),
        "system_prompt":      d.get("system_prompt", f"You are {d.get('agent_id','an agent')} for BountyMind."),
        "methodology":        d.get("methodology", ["Analyze", "Execute", "Report"]),
        "tools":              d.get("tools", []),
        "tool_configs":       d.get("tool_configs", {}),
        "write_channels":     d.get("write_channels", ["observations"]),
        "read_channels":      d.get("read_channels", ["observations"]),
        "handoff_targets":    d.get("handoff_targets", []),
        "max_iterations":     d.get("max_iterations", 25),
        "interrupt_conditions": d.get("interrupt_conditions", ["CVSS >= 9.0"]),
        "success_criteria":   d.get("success_criteria", ["finding_validated"]),
    }
    return {**defaults, **d}


def _enrich_loadout_with_surface_data(loadout: AgentLoadOut, surface_inventory: dict) -> AgentLoadOut:
    if not loadout.active:
        return loadout

    known_urls = {ep["url"] for ep in surface_inventory.get("endpoints", [])}
    known_urls.update(f["action"] for f in surface_inventory.get("forms", []))
    known_urls.update(f["url"]    for f in surface_inventory.get("forms", []))

    valid_test_cases = []
    for tc in loadout.test_cases:
        surface = tc.get("surface", "")
        if surface in known_urls:
            valid_test_cases.append(tc)
        else:
            closest = _find_closest_url(surface, known_urls)
            if closest:
                tc["surface"] = closest
                valid_test_cases.append(tc)

    data = loadout.model_dump()
    data["test_cases"] = valid_test_cases
    return AgentLoadOut(**data)


def _find_closest_url(target: str, known_urls: set) -> str:
    if not known_urls:
        return ""
    for url in known_urls:
        if any(part in url for part in target.split("/") if len(part) > 3):
            return url
    return next(iter(known_urls), "")


def _empty_attack_strategy() -> dict:
    return {
        "narrative":            "Strategy generation failed — using minimal fallback.",
        "threat_areas":         [],
        "testing_sequence":     [],
        "global_hypotheses":    [],
        "collaboration_plan":   {"channels": ["observations"], "handoffs": []},
    }


def _fallback_loadout(agent_id: str, surface_inventory: dict) -> dict:
    endpoints = surface_inventory.get("endpoints", [])
    first_url = endpoints[0]["url"] if endpoints else "/"
    return {
        "agent_id":            agent_id,
        "active":              False,
        "priority":            1,
        "mission":             f"Fallback loadout for {agent_id}",
        "rationale":           "Strategy engine failed to generate loadout for this agent",
        "hypotheses":          [],
        "test_cases":          [{"surface": first_url, "technique": "manual_review", "expected": "N/A", "priority": 0}],
        "system_prompt":       f"You are {agent_id}.",
        "methodology":         ["Review surface", "Report"],
        "tools":               [],
        "tool_configs":        {},
        "write_channels":      ["observations"],
        "read_channels":       ["observations"],
        "handoff_targets":     [],
        "max_iterations":      5,
        "interrupt_conditions": [],
        "success_criteria":    [],
    }
