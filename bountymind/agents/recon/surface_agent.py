import asyncio
import json
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin

from langchain_core.messages import HumanMessage

from ...core.fireworks import get_model
from ...core.state import BountyMindState
from ...tools.scope_checker import validate_scope, ScopeViolationError
from ...tools.recon.httpx_tool import httpx_probe, probe_common_endpoints
from ...tools.recon.naabu_tool import naabu_scan
from ...tools.recon.subfinder_tool import subfinder_scan
from ...tools.recon.katana_tool import katana_crawl
from ...tools.recon.gau_tool import gau_fetch
from ...tools.recon.wappalyzer_tool import wappalyzer_fingerprint
from ...tools.web.js_bundle_tool import analyze_js_bundle
from ...tools.web.vercel_browser import browser_scrape


async def surface_agent_node(state: BountyMindState) -> dict:
    now = datetime.now(timezone.utc).isoformat()
    target_brief = state.get("target_brief", "")
    scope_rules  = state.get("scope_rules", {})

    target_url = _extract_url(target_brief)
    if not target_url:
        return {
            "surface_inventory": _empty_inventory(),
            "phase": "RECON",
            "phase_history": [{"phase": "RECON", "timestamp": now, "agent": "surface_agent"}],
            "audit_log": [{"event": "surface_agent_error", "reason": "no_url", "timestamp": now}],
        }

    try:
        validate_scope(target_url, scope_rules)
    except ScopeViolationError as e:
        return {
            "surface_inventory": _empty_inventory(),
            "audit_log": [{"event": "scope_violation", "url": target_url, "timestamp": now}],
        }

    inventory = _empty_inventory()
    audit_events = []

    common_endpoints = await probe_common_endpoints(target_url, scope_rules)
    audit_events.append({"event": "httpx_probe_done", "count": len(common_endpoints), "timestamp": now})

    for ep in common_endpoints:
        if ep and ep.get("url"):
            inventory["endpoints"].append({
                "url":             ep["url"],
                "method":          ep.get("method", "GET"),
                "status":          ep.get("status", 0),
                "auth_required":   ep.get("auth_required", False),
                "params":          ep.get("params", []),
                "response_time_ms": ep.get("response_time_ms", 0),
                "tech_hints":      ep.get("tech_hints", []),
            })

    subdomains = await subfinder_scan(target_url, scope_rules)
    audit_events.append({"event": "subfinder_done", "count": len(subdomains), "timestamp": now})

    sub_urls = [f"https://{s}" for s in subdomains[:10]]
    if sub_urls:
        sub_probes = await httpx_probe(sub_urls, scope_rules, timeout=6)
        for ep in sub_probes:
            if ep and ep.get("url") and ep.get("status", 0) > 0:
                inventory["endpoints"].append({
                    "url":             ep["url"],
                    "method":          "GET",
                    "status":          ep["status"],
                    "auth_required":   ep.get("auth_required", False),
                    "params":          [],
                    "response_time_ms": ep.get("response_time_ms", 0),
                    "tech_hints":      ep.get("tech_hints", []) + ["subdomain"],
                })

    infra = await naabu_scan(target_url, scope_rules, top_ports=50)
    inventory["infrastructure"].extend(infra)
    audit_events.append({"event": "naabu_done", "count": len(infra), "timestamp": now})

    crawl_result = await katana_crawl(target_url, scope_rules, depth=2)
    for ep in crawl_result.get("endpoints", []):
        if ep.get("url"):
            existing_urls = {e["url"] for e in inventory["endpoints"]}
            if ep["url"] not in existing_urls:
                inventory["endpoints"].append(ep)
    for form in crawl_result.get("forms", []):
        inventory["forms"].append(form)
    for jsf in crawl_result.get("js_findings", []):
        inventory["js_findings"].append(jsf)
    audit_events.append({"event": "katana_done", "forms": len(crawl_result.get("forms", [])), "timestamp": now})

    historical = await gau_fetch(target_url, scope_rules)
    for ep in historical[:50]:
        existing_urls = {e["url"] for e in inventory["endpoints"]}
        if ep.get("url") and ep["url"] not in existing_urls:
            inventory["endpoints"].append(ep)
    audit_events.append({"event": "gau_done", "count": len(historical), "timestamp": now})

    technologies = await wappalyzer_fingerprint(target_url, scope_rules)
    inventory["technologies"].extend(technologies)
    audit_events.append({"event": "wappalyzer_done", "count": len(technologies), "timestamp": now})

    js_urls = [jsf["value"] for jsf in inventory["js_findings"]
               if jsf.get("type") == "js_file" and jsf.get("value", "").endswith(".js")]
    if js_urls:
        js_secrets = await analyze_js_bundle(js_urls, scope_rules)
        for secret in js_secrets:
            existing = {j["value"] for j in inventory["js_findings"]}
            if secret.get("value") not in existing:
                inventory["js_findings"].append(secret)
        audit_events.append({"event": "js_analysis_done", "secrets_found": len(js_secrets), "timestamp": now})

    browser_result = await browser_scrape(target_url, scope_rules)
    for form in browser_result.get("forms", []):
        existing_actions = {f["action"] for f in inventory["forms"]}
        if form.get("action") not in existing_actions:
            inventory["forms"].append(form)
    for ext_link in browser_result.get("external_links", []):
        existing_links = {l["url"] for l in inventory["external_links"]}
        if ext_link.get("url") not in existing_links:
            inventory["external_links"].append(ext_link)
    for auth_mech in browser_result.get("auth_mechanisms", []):
        existing_types = {m["type"] for m in inventory["auth_mechanisms"]}
        if auth_mech.get("type") not in existing_types:
            inventory["auth_mechanisms"].append(auth_mech)
    audit_events.append({"event": "browser_done", "forms": len(browser_result.get("forms", [])), "timestamp": now})

    if inventory["technologies"]:
        inventory = await _llm_enrich_inventory(inventory, target_url)

    return {
        "surface_inventory": inventory,
        "phase":             "RECON",
        "phase_history":     [{"phase": "RECON", "timestamp": now, "agent": "surface_agent"}],
        "audit_log":         audit_events,
    }


async def _llm_enrich_inventory(inventory: dict, target_url: str) -> dict:
    try:
        llm = get_model("MODEL_RECON", temperature=0.1)
        prompt = f"""Analyze this surface inventory for {target_url} and:
1. Identify missing auth mechanisms based on the forms and endpoints
2. Classify endpoint auth_required status based on URL patterns
3. Identify the most significant tech_hints

Surface inventory summary:
- Endpoints: {len(inventory['endpoints'])}
- Forms: {json.dumps(inventory['forms'][:3], indent=2)}
- Technologies: {json.dumps(inventory['technologies'], indent=2)}
- Auth mechanisms: {json.dumps(inventory['auth_mechanisms'], indent=2)}

Return JSON with keys: "auth_mechanisms_additions" (list), "endpoint_corrections" (dict url->auth_required bool).
Keep it concise. Only add what's clearly missing."""

        response = await llm.ainvoke([HumanMessage(content=prompt)])
        content = response.content

        import re
        json_match = re.search(r'\{.*\}', content, re.DOTALL)
        if json_match:
            data = json.loads(json_match.group(0))

            for addition in data.get("auth_mechanisms_additions", []):
                existing_types = {m["type"] for m in inventory["auth_mechanisms"]}
                if isinstance(addition, dict) and addition.get("type") not in existing_types:
                    inventory["auth_mechanisms"].append(addition)

            corrections = data.get("endpoint_corrections", {})
            for ep in inventory["endpoints"]:
                if ep["url"] in corrections:
                    ep["auth_required"] = corrections[ep["url"]]
    except Exception:
        pass

    return inventory


def _extract_url(target_brief: str) -> str:
    import re
    url_match = re.search(r'https?://[^\s,;]+', target_brief)
    if url_match:
        return url_match.group(0).rstrip(".,;")
    words = target_brief.split()
    for word in words:
        if "." in word and not word.startswith("http"):
            return f"https://{word}"
    return ""


def _empty_inventory() -> dict:
    return {
        "endpoints":       [],
        "forms":           [],
        "auth_mechanisms": [],
        "technologies":    [],
        "external_links":  [],
        "behaviors":       [],
        "js_findings":     [],
        "infrastructure":  [],
    }
