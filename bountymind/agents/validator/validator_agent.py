import json
import re
from datetime import datetime, timezone

from langchain_core.messages import HumanMessage

from ...core.fireworks import get_model
from ...core.state import BountyMindState
from .poc_runner import run_poc


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


VALIDATOR_SYSTEM = """Eres el Validator Agent de BountyMind.
Tu trabajo es analizar la evidencia de cada raw_finding y determinar si es un finding válido.

CRITERIOS:
- plausibility: ¿la descripción técnica tiene sentido para la técnica usada?
- evidence_quality: ¿hay request/response/payload concretos?
- impact_clarity: ¿está claro el impacto de seguridad?

Sé estricto. Los false positives dañan la credibilidad del reporte."""


async def validator_node(state: BountyMindState) -> dict:
    now          = _utcnow()
    raw_findings = state.get("raw_findings") or []
    threshold    = state.get("confidence_threshold") or 0.85

    if not raw_findings:
        return {
            "validated_findings": [],
            "false_positives":    [],
            "phase":              "VALIDATION",
            "phase_history":      [{"phase": "VALIDATION", "timestamp": now}],
            "audit_log":          [{"event": "validator_no_findings", "timestamp": now}],
        }

    validated = []
    false_pos  = []

    for finding in raw_findings:
        result = await _validate_finding(finding, threshold)
        if result["promote"]:
            promoted = {**finding, **result, "validated_at": now}
            validated.append(promoted)
        else:
            rejected = {**finding, "rejection_reason": result.get("rejection_reason", ""), "validated_at": now}
            false_pos.append(rejected)

    return {
        "validated_findings": validated,
        "false_positives":    false_pos,
        "phase":              "VALIDATION",
        "phase_history":      [{"phase": "VALIDATION", "timestamp": now}],
        "audit_log": [{
            "event":           "validation_complete",
            "timestamp":       now,
            "validated":       len(validated),
            "false_positives": len(false_pos),
            "threshold":       threshold,
        }],
    }


async def _validate_finding(finding: dict, threshold: float) -> dict:
    plausibility    = _check_plausibility(finding)
    evidence_quality = _check_evidence_quality(finding)
    impact_clarity   = _check_impact_clarity(finding)

    poc_result = await run_poc(finding, replications=3)
    reproducibility  = poc_result.get("reproducibility", 0.0)

    confidence = (
        plausibility     * 0.25 +
        evidence_quality * 0.25 +
        impact_clarity   * 0.20 +
        reproducibility  * 0.30
    )

    cvss = finding.get("cvss_estimate", 0)
    if cvss >= 9.0:
        try:
            formal = await _formal_verify(finding)
            if formal.get("verified"):
                confidence = min(confidence + 0.1, 1.0)
        except Exception:
            pass

    promote = confidence >= threshold
    rejection_reason = ""
    if not promote:
        if plausibility < 0.5:
            rejection_reason = "Low plausibility — technique/surface mismatch"
        elif evidence_quality < 0.3:
            rejection_reason = "Insufficient evidence — no request/response data"
        elif reproducibility == 0.0:
            rejection_reason = "Not reproducible — PoC failed all attempts"
        else:
            rejection_reason = f"Confidence {confidence:.2f} below threshold {threshold}"

    return {
        "promote":           promote,
        "confidence_score":  round(confidence, 3),
        "plausibility":      plausibility,
        "evidence_quality":  evidence_quality,
        "impact_clarity":    impact_clarity,
        "reproducibility":   reproducibility,
        "poc_result":        poc_result,
        "rejection_reason":  rejection_reason,
    }


def _check_plausibility(finding: dict) -> float:
    vuln_type = finding.get("vuln_type", "")
    url       = finding.get("url", "")
    desc      = finding.get("description", "")

    if not vuln_type or not url:
        return 0.2
    if not desc or len(desc) < 20:
        return 0.4

    PLAUSIBLE_PAIRS = {
        "xss":                    ["/search", "/comment", "/post", "/input", "?q=", "?s="],
        "xss_reflected":          ["/search", "/comment", "?q=", "?s="],
        "sql_injection":          ["/login", "/search", "/api/", "?id=", "?user="],
        "idor":                   ["/api/", "/user/", "/account/", "/order/", "?id="],
        "csrf":                   ["/settings", "/account", "/profile", "/password"],
        "open_redirect":          ["/login", "/auth", "/redirect", "/out", "?url=", "?next="],
        "ssrf":                   ["/api/", "/webhook", "/fetch", "/proxy"],
        "cors_misconfiguration":  ["/api/", "/graphql", "/v1/", "/v2/"],
        "user_enumeration":       ["/login", "/forgot", "/reset", "/signin"],
        "timing_attack":          ["/login", "/forgot", "/reset", "/auth"],
    }

    hints = PLAUSIBLE_PAIRS.get(vuln_type, [])
    if hints:
        if any(h in url.lower() for h in hints):
            return 0.9
        return 0.6

    return 0.7 if len(desc) > 50 else 0.5


def _check_evidence_quality(finding: dict) -> float:
    score = 0.0
    if finding.get("request") and finding["request"]:
        score += 0.3
    if finding.get("response_diff") and finding["response_diff"]:
        score += 0.3
    if finding.get("payload"):
        score += 0.2
    if finding.get("reproduction_steps") and len(finding["reproduction_steps"]) >= 2:
        score += 0.2
    return min(score, 1.0)


def _check_impact_clarity(finding: dict) -> float:
    desc     = finding.get("description", "")
    severity = finding.get("severity", "")
    cvss     = finding.get("cvss_estimate", 0)

    score = 0.0
    if desc and len(desc) > 30:
        score += 0.4
    if severity in ("CRITICAL", "HIGH", "MEDIUM"):
        score += 0.3
    if cvss > 0:
        score += 0.3

    return min(score, 1.0)


async def _formal_verify(finding: dict) -> dict:
    try:
        llm = get_model("MODEL_SYNTHESIZER", temperature=0.0)

        prompt = f"""Formally verify this security finding for a bug bounty report.

Finding:
{json.dumps({k: v for k, v in finding.items() if k not in ('raw_output', 'evidence')}, indent=2)}

Is this a genuine security vulnerability? Answer with JSON:
{{"verified": bool, "reasoning": str, "confidence": float 0-1}}"""

        response = await llm.ainvoke([HumanMessage(content=prompt)])
        m = re.search(r'\{.*\}', response.content, re.DOTALL)
        if m:
            return json.loads(m.group(0))
    except Exception:
        pass
    return {"verified": False, "reasoning": "formal verification failed", "confidence": 0.0}
