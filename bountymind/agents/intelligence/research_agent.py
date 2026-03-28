import json
import re
from datetime import datetime, timezone

from langchain_core.messages import HumanMessage

from ...core.fireworks import get_model
from ...core.state import BountyMindState
from .sources import (
    search_hacktivity,
    search_cves,
    search_proven_techniques,
    search_github_osint,
)


async def research_agent_node(state: BountyMindState) -> dict:
    now = datetime.now(timezone.utc).isoformat()
    surface_inventory = state.get("surface_inventory") or {}
    target_brief      = state.get("target_brief", "")

    technologies    = surface_inventory.get("technologies", [])
    auth_mechanisms = surface_inventory.get("auth_mechanisms", [])
    js_findings     = surface_inventory.get("js_findings", [])

    tech_fingerprint = _build_tech_fingerprint(technologies)
    sector           = _infer_sector(target_brief, technologies)
    auth_type        = auth_mechanisms[0].get("type", "form_login") if auth_mechanisms else "form_login"

    hacktivity_items = await search_hacktivity(tech_fingerprint, sector, auth_type)

    cve_list = await search_cves(technologies)

    npm_packages = [
        jf["value"] for jf in js_findings
        if jf.get("type") == "js_file" and "/" in jf.get("value", "")
    ]
    for pkg in _extract_npm_packages(js_findings)[:5]:
        from ...tools.osint.github_search import github_advisory_search
        pkg_cves = await github_advisory_search(pkg)
        cve_list.extend(pkg_cves)

    proven_techniques = await search_proven_techniques(tech_fingerprint, auth_mechanisms)

    domain = _extract_domain(target_brief)
    interesting_observations = await search_github_osint(domain)

    target_context_raw = {
        "tech_fingerprint":          tech_fingerprint,
        "sector":                    sector,
        "hacktivity_items":          hacktivity_items,
        "cve_list":                  cve_list,
        "proven_techniques":         proven_techniques,
        "sector_patterns":           _get_sector_patterns(sector, auth_type),
        "interesting_observations":  interesting_observations,
    }

    target_context = await _llm_synthesize(target_context_raw, surface_inventory, target_brief)

    return {
        "target_context": target_context,
        "phase":          "INTELLIGENCE",
        "phase_history":  [{"phase": "INTELLIGENCE", "timestamp": now, "agent": "research_agent"}],
        "audit_log": [
            {
                "event":     "research_completed",
                "timestamp": now,
                "cves_found":      len(target_context.get("cve_list", [])),
                "techniques_found": len(target_context.get("proven_techniques", [])),
                "hacktivity_items": len(target_context.get("hacktivity_items", [])),
            }
        ],
    }


async def _llm_synthesize(raw_context: dict, surface_inventory: dict, target_brief: str) -> dict:
    try:
        llm = get_model("MODEL_RESEARCH", temperature=0.1)

        prompt = f"""You are a security intelligence analyst for BountyMind.
Synthesize this raw intelligence data into a clean target_context for a bug bounty engagement.

TARGET: {target_brief}

RAW INTELLIGENCE:
Tech fingerprint: {raw_context['tech_fingerprint']}
Sector: {raw_context['sector']}
CVEs found: {json.dumps(raw_context['cve_list'][:5], indent=2)}
Hacktivity items: {json.dumps(raw_context['hacktivity_items'][:5], indent=2)}
Proven techniques: {json.dumps(raw_context['proven_techniques'][:5], indent=2)}
Interesting observations: {json.dumps(raw_context['interesting_observations'], indent=2)}

SURFACE SUMMARY:
- Endpoints: {len(surface_inventory.get('endpoints', []))}
- Forms: {json.dumps([{{'action': f['action'], 'fields': [fi['name'] for fi in f['fields']]}} for f in surface_inventory.get('forms', [])[:3]], indent=2)}
- Auth mechanisms: {json.dumps([m['type'] for m in surface_inventory.get('auth_mechanisms', [])], indent=2)}

Return a JSON object with these exact keys:
{{
  "tech_fingerprint": "concise stack description",
  "sector": "sector classification",
  "hacktivity_items": [...top 5 most relevant...],
  "cve_list": [...top 5 highest CVSS...],
  "proven_techniques": [...top 5 most applicable...],
  "sector_patterns": [...list of strings...],
  "interesting_observations": [...list of strings...]
}}

Focus on what's ACTUALLY applicable to this specific target. Remove generic noise."""

        response = await llm.ainvoke([HumanMessage(content=prompt)])
        content = response.content

        json_match = re.search(r'\{.*\}', content, re.DOTALL)
        if json_match:
            synthesized = json.loads(json_match.group(0))
            for key in raw_context:
                if key not in synthesized or not synthesized[key]:
                    synthesized[key] = raw_context[key]
            return synthesized
    except Exception:
        pass

    return raw_context


def _build_tech_fingerprint(technologies: list[dict]) -> str:
    if not technologies:
        return "Unknown stack"
    names = [t["name"] for t in sorted(technologies, key=lambda x: x.get("confidence", 0), reverse=True)[:5]]
    return " + ".join(names)


def _infer_sector(target_brief: str, technologies: list[dict]) -> str:
    brief_lower = target_brief.lower()
    tech_names  = [t["name"].lower() for t in technologies]

    sector_keywords = {
        "fintech":    ["payment", "bank", "finance", "crypto", "stripe", "wallet", "invoice"],
        "saas_b2b":   ["dashboard", "workspace", "team", "enterprise", "subscription"],
        "ecommerce":  ["shop", "store", "cart", "checkout", "product", "order"],
        "healthcare": ["health", "medical", "patient", "hospital", "clinic"],
        "social":     ["social", "feed", "follow", "post", "message", "chat"],
        "devtools":   ["developer", "api", "sdk", "docs", "github", "gitlab"],
        "gaming":     ["game", "player", "score", "level", "guild"],
        "media":      ["video", "stream", "music", "podcast", "content"],
    }

    for sector, keywords in sector_keywords.items():
        if any(k in brief_lower for k in keywords):
            return sector

    return "saas_generic"


def _get_sector_patterns(sector: str, auth_type: str) -> list[str]:
    patterns = {
        "fintech":    ["IDOR on transaction IDs", "Race conditions in payment flows",
                       "Mass assignment on account objects", "Insecure direct references to account numbers"],
        "saas_b2b":   ["Tenant isolation bypass", "IDOR on resource IDs", "Privilege escalation via role manipulation",
                       "Mass assignment on user objects"],
        "ecommerce":  ["Price manipulation via parameter tampering", "Coupon code bypass",
                       "Order status manipulation", "IDOR on order IDs"],
        "healthcare": ["HIPAA-relevant data exposure", "Patient record IDOR",
                       "Insecure file upload of medical records"],
        "social":     ["Account takeover via OAuth", "IDOR on user profiles",
                       "Stored XSS in user-generated content"],
        "devtools":   ["API key exposure in repos", "Webhook SSRF", "OAuth token leakage"],
        "saas_generic": ["IDOR on resource endpoints", "Privilege escalation",
                         "OAuth misconfiguration", "Insecure direct references"],
    }

    auth_patterns = {
        "form_login":    ["Credential stuffing no rate limit", "Username enumeration",
                          "Password reset token predictability"],
        "oauth_google":  ["OAuth redirect_uri manipulation", "State parameter CSRF",
                          "Token leakage via Referer header"],
        "jwt":           ["JWT algorithm confusion", "JWT none algorithm", "JWT key confusion"],
    }

    result = patterns.get(sector, patterns["saas_generic"])
    result += auth_patterns.get(auth_type, auth_patterns["form_login"])
    return result


def _extract_domain(target_brief: str) -> str:
    import re
    m = re.search(r'(?:https?://)?([a-zA-Z0-9\-]+\.[a-zA-Z]{2,})', target_brief)
    if m:
        parts = m.group(1).split(".")
        return parts[-2] if len(parts) >= 2 else m.group(1)
    return ""


def _extract_npm_packages(js_findings: list[dict]) -> list[str]:
    packages = []
    import re
    for jf in js_findings:
        value = jf.get("value", "")
        for pkg in re.findall(r'(?:node_modules|cdn\.jsdelivr\.net/npm)/([a-zA-Z0-9\-_@/]+)', value):
            name = pkg.split("/")[0].replace("@", "")
            if name and name not in packages:
                packages.append(name)
    return packages
