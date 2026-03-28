import json
import re
from datetime import datetime, timezone

from langchain_core.messages import HumanMessage

from ...core.fireworks import get_model
from ...core.state import BountyMindState


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


SYNTHESIZER_SYSTEM = """Eres el Chain Synthesizer de BountyMind.
Tu trabajo es identificar conexiones entre findings individuales que forman cadenas de ataque más graves.

REGLAS:
- No busques patrones predefinidos — razona libremente sobre los findings concretos
- Una chain válida conecta 2+ findings donde el impacto combinado es mayor que la suma de partes
- El CVSS de la chain debe ser calculado considerando el impacto compuesto
- Solo reporta chains con alta confianza (confidence >= 0.7)

FORMATO: JSON con clave "attack_chains", lista de objetos."""


async def chain_synthesizer_node(state: BountyMindState) -> dict:
    now          = _utcnow()
    raw_findings = state.get("raw_findings") or []

    if len(raw_findings) < 2:
        return {
            "attack_chains": [],
            "phase":         "SYNTHESIS",
            "phase_history": [{"phase": "SYNTHESIS", "timestamp": now}],
            "audit_log":     [{"event": "synthesizer_no_findings", "timestamp": now}],
        }

    try:
        chains = await _llm_synthesize_chains(raw_findings)
    except Exception:
        chains = _rule_based_chains(raw_findings)

    return {
        "attack_chains": chains,
        "phase":         "SYNTHESIS",
        "phase_history": [{"phase": "SYNTHESIS", "timestamp": now}],
        "audit_log": [{
            "event":        "chains_synthesized",
            "timestamp":    now,
            "chains_found": len(chains),
            "findings_analyzed": len(raw_findings),
        }],
    }


async def _llm_synthesize_chains(raw_findings: list[dict]) -> list[dict]:
    llm = get_model("MODEL_SYNTHESIZER", temperature=0.1)

    findings_summary = []
    for f in raw_findings[:20]:
        findings_summary.append({
            "id":         f.get("id", "")[:50],
            "agent_id":   f.get("agent_id", ""),
            "url":        f.get("url", ""),
            "vuln_type":  f.get("vuln_type", ""),
            "severity":   f.get("severity", ""),
            "cvss":       f.get("cvss_estimate", 0),
            "title":      f.get("title", ""),
        })

    prompt = f"""{SYNTHESIZER_SYSTEM}

FINDINGS TO ANALYZE ({len(findings_summary)} total):
{json.dumps(findings_summary, indent=2)}

Identify attack chains. For each chain:
- Which findings are connected (use their ids)
- Why they form a chain (narrative)
- What the combined CVSS impact is
- What the attack scenario is

Return JSON:
{{
  "attack_chains": [
    {{
      "id": "chain_1",
      "title": "descriptive title",
      "finding_ids": ["id1", "id2"],
      "agents_involved": ["AgentA", "AgentB"],
      "narrative": "how the chain works",
      "attack_scenario": "step by step attack",
      "cvss_composed": 0.0,
      "confidence": 0.0,
      "impact": "business impact description"
    }}
  ]
}}

Only include chains with confidence >= 0.7. Empty list if no valid chains found."""

    response = await llm.ainvoke([HumanMessage(content=prompt)])
    content  = response.content

    json_match = re.search(r'\{.*\}', content, re.DOTALL)
    if json_match:
        try:
            data = json.loads(json_match.group(0))
            return data.get("attack_chains", [])
        except json.JSONDecodeError:
            pass

    return _rule_based_chains(raw_findings)


def _rule_based_chains(raw_findings: list[dict]) -> list[dict]:
    chains    = []
    chain_idx = 1

    CHAIN_COMBOS = [
        ("open_redirect",      "xss",                    "Open Redirect + XSS → Token Theft",      9.3),
        ("user_enumeration",   "reset_token_analysis",   "User Enum + Weak Reset Token → ATO",      9.1),
        ("idor",               "information_disclosure",  "IDOR + Info Disclosure → Data Exfil",     8.5),
        ("mass_assignment",    "privilege_escalation",   "Mass Assignment → Privilege Escalation",  9.0),
        ("ssrf",               "cloud_metadata",         "SSRF → Cloud Metadata Access → RCE",      9.8),
        ("cors_misconfiguration", "xss",                 "CORS + XSS → Cross-Origin Account Takeover", 9.2),
        ("js_secret",          "information_disclosure",  "JS Secret + Info Disclosure → Backend Access", 8.8),
        ("oauth_redirect_uri", "user_enumeration",       "OAuth Redirect + User Enum → Account Takeover", 9.0),
    ]

    by_type: dict[str, list[dict]] = {}
    for f in raw_findings:
        vt = f.get("vuln_type", "").lower()
        by_type.setdefault(vt, []).append(f)

    for type_a, type_b, title, composed_cvss in CHAIN_COMBOS:
        findings_a = by_type.get(type_a, [])
        findings_b = by_type.get(type_b, [])
        if findings_a and findings_b:
            fa = findings_a[0]
            fb = findings_b[0]
            chains.append({
                "id":               f"chain_{chain_idx}",
                "title":            title,
                "finding_ids":      [fa.get("id", ""), fb.get("id", "")],
                "agents_involved":  list({fa.get("agent_id", ""), fb.get("agent_id", "")}),
                "narrative":        f"Combining {type_a} at {fa.get('url','')} with {type_b} at {fb.get('url','')} creates a multi-step attack chain.",
                "attack_scenario":  f"1. Exploit {type_a} at {fa.get('url','')}\n2. Chain with {type_b} at {fb.get('url','')}\n3. Combined impact: {title}",
                "cvss_composed":    composed_cvss,
                "confidence":       0.75,
                "impact":           f"Chained exploitation enables: {title}",
            })
            chain_idx += 1

    return chains
