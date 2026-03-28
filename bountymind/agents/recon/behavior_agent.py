import asyncio
import time
from datetime import datetime, timezone

import httpx

from ...core.state import BountyMindState
from ...tools.scope_checker import validate_scope, ScopeViolationError


MALFORMED_PAYLOADS = [
    "' OR '1'='1",
    "<script>alert(1)</script>",
    "../../../etc/passwd",
    "{{7*7}}",
    "${7*7}",
    "A" * 5000,
    "\x00",
    "%00",
    "'; DROP TABLE users; --",
]

SECURITY_HEADERS = [
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "x-xss-protection",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
]


async def behavior_agent_node(state: BountyMindState) -> dict:
    now = datetime.now(timezone.utc).isoformat()
    scope_rules       = state.get("scope_rules", {})
    surface_inventory = state.get("surface_inventory") or {}

    behaviors = list(surface_inventory.get("behaviors", []))
    audit_events = []

    updated_forms = list(surface_inventory.get("forms", []))
    for i, form in enumerate(updated_forms[:5]):
        form_url = form.get("action") or form.get("url", "")
        if not form_url:
            continue
        try:
            validate_scope(form_url, scope_rules)
        except ScopeViolationError:
            continue

        error_messages = await _probe_form_errors(form, scope_rules)
        if error_messages:
            updated_forms[i]["error_messages"] = error_messages
            behaviors.append({
                "pattern":     "form_error_disclosure",
                "url":         form_url,
                "significance": f"Form reveals error messages: {error_messages[:2]}",
            })

    audit_events.append({"event": "form_behavior_done", "timestamp": now})

    endpoints = surface_inventory.get("endpoints", [])
    auth_endpoints = [ep for ep in endpoints if ep.get("auth_required")]
    for ep in auth_endpoints[:5]:
        url = ep.get("url", "")
        try:
            validate_scope(url, scope_rules)
        except ScopeViolationError:
            continue

        rejection_behavior = await _probe_auth_rejection(url, scope_rules)
        if rejection_behavior:
            behaviors.append(rejection_behavior)

    audit_events.append({"event": "auth_rejection_done", "timestamp": now})

    target_urls = list({ep.get("url", "") for ep in endpoints[:5] if ep.get("url")})
    for url in target_urls[:3]:
        try:
            validate_scope(url, scope_rules)
        except ScopeViolationError:
            continue

        header_behaviors = await _probe_security_headers(url)
        behaviors.extend(header_behaviors)

    audit_events.append({"event": "security_headers_done", "timestamp": now})

    auth_form_endpoints = [
        ep for ep in endpoints
        if any(p in ep.get("url", "").lower() for p in ["/login", "/signin", "/auth", "/forgot"])
    ]
    if auth_form_endpoints:
        timing_results = await _probe_timing_auth(auth_form_endpoints[:2], scope_rules)
        behaviors.extend(timing_results)

    audit_events.append({"event": "timing_analysis_done", "timestamp": now})

    rate_limit_behavior = await _probe_rate_limiting(target_urls[:1], scope_rules)
    behaviors.extend(rate_limit_behavior)

    audit_events.append({"event": "rate_limiting_done", "timestamp": now})

    updated_inventory = dict(surface_inventory)
    updated_inventory["behaviors"] = behaviors
    updated_inventory["forms"]     = updated_forms

    return {
        "surface_inventory": updated_inventory,
        "audit_log": audit_events,
    }


async def _probe_form_errors(form: dict, scope_rules: dict) -> list[str]:
    action = form.get("action", "")
    method = form.get("method", "POST")
    fields = form.get("fields", [])

    if not action or not fields:
        return []

    test_data = {}
    for field in fields:
        if field.get("type") == "password":
            test_data[field["name"]] = "wrongpassword123"
        elif field.get("type") == "email":
            test_data[field["name"]] = "nonexistent@example.com"
        elif field.get("type") not in ("hidden", "submit", "button"):
            test_data[field["name"]] = "test"

    error_messages = []
    try:
        async with httpx.AsyncClient(timeout=10, verify=False, follow_redirects=True) as client:
            if method.upper() == "POST":
                resp = await client.post(action, data=test_data,
                                         headers={"User-Agent": "Mozilla/5.0 BountyMind/4.0"})
            else:
                resp = await client.get(action, params=test_data,
                                        headers={"User-Agent": "Mozilla/5.0 BountyMind/4.0"})

            import re
            html = resp.text
            for pattern in [
                r'(?:error|invalid|incorrect|wrong|failed)[^<]{0,100}',
                r'<[^>]*(?:error|alert|warning)[^>]*>([^<]{5,100})<',
                r'(?:user|email|password)[^<]{0,50}(?:not found|invalid|incorrect)[^<]{0,50}',
            ]:
                for m in re.finditer(pattern, html, re.IGNORECASE):
                    msg = m.group(0).strip()[:120]
                    if msg and msg not in error_messages:
                        error_messages.append(msg)
    except Exception:
        pass

    return error_messages[:5]


async def _probe_auth_rejection(url: str, scope_rules: dict) -> dict | None:
    try:
        async with httpx.AsyncClient(timeout=8, verify=False, follow_redirects=False) as client:
            resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0 BountyMind/4.0"})
            status = resp.status_code
            location = resp.headers.get("location", "")

            pattern = "direct_403"
            significance = f"Unauthenticated access returns {status}"

            if status in (301, 302):
                pattern = "redirect_to_login"
                significance = f"Redirects to: {location}"
            elif status == 401:
                pattern = "www_authenticate_401"
                www_auth = resp.headers.get("www-authenticate", "")
                significance = f"401 with WWW-Authenticate: {www_auth}"
            elif status == 200:
                pattern = "no_auth_check"
                significance = "Auth endpoint returns 200 without credentials — potential access control issue"

            return {
                "pattern":     pattern,
                "url":         url,
                "significance": significance,
            }
    except Exception:
        return None


async def _probe_security_headers(url: str) -> list[dict]:
    behaviors = []
    try:
        async with httpx.AsyncClient(timeout=8, verify=False) as client:
            resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0 BountyMind/4.0"})
            headers_lower = {k.lower(): v for k, v in resp.headers.items()}

            missing = []
            for header in SECURITY_HEADERS:
                if header not in headers_lower:
                    missing.append(header)

            if missing:
                behaviors.append({
                    "pattern":     "missing_security_headers",
                    "url":         url,
                    "significance": f"Missing: {', '.join(missing)}",
                })

            csp = headers_lower.get("content-security-policy", "")
            if csp and ("unsafe-inline" in csp or "unsafe-eval" in csp or "*" in csp):
                behaviors.append({
                    "pattern":     "weak_csp",
                    "url":         url,
                    "significance": f"Weak CSP policy: {csp[:200]}",
                })

            cors = headers_lower.get("access-control-allow-origin", "")
            if cors == "*":
                behaviors.append({
                    "pattern":     "cors_wildcard",
                    "url":         url,
                    "significance": "CORS Access-Control-Allow-Origin: * — any origin allowed",
                })
            elif cors and cors not in ("null",):
                behaviors.append({
                    "pattern":     "cors_configured",
                    "url":         url,
                    "significance": f"CORS origin: {cors}",
                })

            hsts = headers_lower.get("strict-transport-security", "")
            if hsts and "max-age=0" in hsts:
                behaviors.append({
                    "pattern":     "hsts_disabled",
                    "url":         url,
                    "significance": "HSTS explicitly set to max-age=0",
                })

    except Exception:
        pass
    return behaviors


async def _probe_timing_auth(auth_endpoints: list[dict], scope_rules: dict) -> list[dict]:
    behaviors = []

    for ep in auth_endpoints:
        url = ep.get("url", "")
        if not url:
            continue
        try:
            validate_scope(url, scope_rules)
        except ScopeViolationError:
            continue

        try:
            timings_existing = []
            timings_fake = []

            async with httpx.AsyncClient(timeout=15, verify=False, follow_redirects=True) as client:
                for _ in range(3):
                    t0 = time.monotonic()
                    await client.post(url, data={"email": "admin@example.com", "password": "wrongpass123"},
                                      headers={"User-Agent": "Mozilla/5.0 BountyMind/4.0"})
                    timings_existing.append((time.monotonic() - t0) * 1000)
                    await asyncio.sleep(0.2)

                for _ in range(3):
                    t0 = time.monotonic()
                    await client.post(url, data={"email": "nonexistent_user_xyz@fakefake.xyz", "password": "wrongpass123"},
                                      headers={"User-Agent": "Mozilla/5.0 BountyMind/4.0"})
                    timings_fake.append((time.monotonic() - t0) * 1000)
                    await asyncio.sleep(0.2)

            avg_existing = sum(timings_existing) / len(timings_existing)
            avg_fake = sum(timings_fake) / len(timings_fake)
            diff = abs(avg_existing - avg_fake)

            significance = f"Timing diff: {diff:.0f}ms (existing: {avg_existing:.0f}ms, fake: {avg_fake:.0f}ms)"

            if diff > 100:
                behaviors.append({
                    "pattern":     "timing_attack_user_enumeration",
                    "url":         url,
                    "significance": f"HIGH: {significance} — likely user enumeration via timing",
                })
            elif diff > 50:
                behaviors.append({
                    "pattern":     "timing_difference_medium",
                    "url":         url,
                    "significance": f"MEDIUM: {significance}",
                })
            else:
                behaviors.append({
                    "pattern":     "timing_consistent",
                    "url":         url,
                    "significance": f"Timing consistent: {significance}",
                })
        except Exception:
            pass

    return behaviors


async def _probe_rate_limiting(urls: list[str], scope_rules: dict) -> list[dict]:
    behaviors = []
    for url in urls:
        try:
            validate_scope(url, scope_rules)
        except ScopeViolationError:
            continue

        try:
            statuses = []
            async with httpx.AsyncClient(timeout=5, verify=False) as client:
                for i in range(12):
                    resp = await client.get(url, headers={"User-Agent": f"BountyMind-RateTest/{i}"})
                    statuses.append(resp.status_code)
                    if resp.status_code in (429, 503):
                        break
                    await asyncio.sleep(0.1)

            if 429 in statuses:
                idx = statuses.index(429)
                behaviors.append({
                    "pattern":     "rate_limiting_active",
                    "url":         url,
                    "significance": f"Rate limiting triggered at request #{idx + 1} (HTTP 429)",
                })
            elif 503 in statuses:
                behaviors.append({
                    "pattern":     "rate_limiting_503",
                    "url":         url,
                    "significance": "Rate limiting via 503 response",
                })
            else:
                behaviors.append({
                    "pattern":     "no_rate_limiting",
                    "url":         url,
                    "significance": f"No rate limiting detected after {len(statuses)} requests",
                })
        except Exception:
            pass

    return behaviors
