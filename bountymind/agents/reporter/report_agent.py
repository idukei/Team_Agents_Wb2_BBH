"""Report Agent — generates professional bug bounty reports from validated findings."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone

from langchain_core.messages import HumanMessage, SystemMessage

from ...core.fireworks import get_model
from ...core.state import BountyMindState
from .templates import REPORT_HEADER_TEMPLATE


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


REPORTER_SYSTEM = """You are the Report Agent for BountyMind, a professional bug bounty reporting system.

Your task is to generate a comprehensive, professional bug bounty report from validated security findings.

RULES:
- Write in professional English suitable for submission to bug bounty platforms (HackerOne, Bugcrowd, Intigriti)
- Each finding must have: clear description, concrete reproduction steps, business impact, and actionable remediation
- CVSS scores are already calculated — use them as-is
- For attack chains: explain the combined impact clearly and why the chain is more severe than individual findings
- Executive summary: 3-5 sentences covering total severity distribution, key risks, and overall security posture
- Be specific and technical — avoid vague language like "could lead to" — say "allows an attacker to"
- Remediation must be specific: name the exact fix (e.g. "Add SameSite=Strict to session cookies" not "improve security")

OUTPUT FORMAT: Valid JSON only. No markdown fences, no explanations outside JSON.
JSON structure:
{
  "executive_summary": "...",
  "findings_reports": [
    {
      "id": "finding_id",
      "remediation": "specific technical remediation",
      "impact": "concrete business impact description",
      "writeup": "full professional paragraph describing the vulnerability"
    }
  ],
  "chains_reports": [
    {
      "id": "chain_id",
      "combined_impact": "why chain severity > individual findings",
      "writeup": "professional narrative of the attack chain"
    }
  ]
}"""


async def reporter_node(state: BountyMindState) -> dict:
    now              = _utcnow()
    validated        = state.get("validated_findings") or []
    chains           = state.get("attack_chains")      or []
    target_brief     = state.get("target_brief", "Unknown Target")
    operator_context = state.get("operator_context")   or {}

    if not validated and not chains:
        return {
            "phase":         "REPORT",
            "phase_history": [{"phase": "REPORT", "timestamp": now}],
            "audit_log":     [{"event": "reporter_no_findings", "timestamp": now}],
            "messages": [{
                "role":    "system",
                "content": "[Reporter] No validated findings — report skipped",
                "agent":   "Reporter",
                "ts":      now,
            }],
        }

    try:
        report_data = await _generate_report(validated, chains, target_brief, operator_context)
    except Exception as e:
        report_data = _fallback_report(validated, chains, str(e))

    critical_high = sum(
        1 for f in validated
        if f.get("severity") in ("CRITICAL", "HIGH")
    )

    # Build the report markdown using the header template + per-finding/chain sections
    report_markdown = _build_report_markdown(
        validated, chains, target_brief, now,
        critical_high, report_data,
    )

    return {
        "phase":         "REPORT",
        "phase_history": [{"phase": "REPORT", "timestamp": now}],
        "audit_log": [{
            "event":          "report_generated",
            "timestamp":      now,
            "findings_count": len(validated),
            "chains_count":   len(chains),
            "critical_high":  critical_high,
        }],
        "messages": [{
            "role":    "system",
            "content": f"[Reporter] Report generated — {len(validated)} findings, {len(chains)} chains, {critical_high} critical/high",
            "agent":   "Reporter",
            "ts":      now,
        }],
        "operator_context": {
            **(state.get("operator_context") or {}),
            "final_report_markdown": report_markdown,
            "report_data":           report_data,
        },
    }


async def _generate_report(
    validated: list,
    chains: list,
    target_brief: str,
    operator_context: dict,
) -> dict:
    llm = get_model("MODEL_RESEARCH", temperature=0.1)

    # Prepare concise summaries (cap at 15 findings to stay within context)
    finding_summaries = []
    for f in validated[:15]:
        finding_summaries.append({
            "id":                f.get("id", "")[:50],
            "title":             f.get("title", ""),
            "vuln_type":         f.get("vuln_type", ""),
            "severity":          f.get("severity", ""),
            "cvss":              f.get("cvss_estimate", 0),
            "url":               f.get("url", ""),
            "description":       f.get("description", "")[:300],
            "payload":           f.get("payload", ""),
            "reproduction_steps": f.get("reproduction_steps", []),
            "agent_id":          f.get("agent_id", ""),
        })

    chain_summaries = []
    for c in chains[:5]:
        chain_summaries.append({
            "id":             c.get("id", ""),
            "title":          c.get("title", ""),
            "cvss_composed":  c.get("cvss_composed", 0),
            "narrative":      c.get("narrative", ""),
            "attack_scenario": c.get("attack_scenario", ""),
            "impact":         c.get("impact", ""),
            "agents_involved": c.get("agents_involved", []),
        })

    # Exclude credentials from operator context passed to LLM
    safe_operator_ctx = {
        k: v for k, v in operator_context.items()
        if k != "credentials"
    }

    user_content = f"""Target: {target_brief[:200]}

VALIDATED FINDINGS ({len(finding_summaries)}):
{json.dumps(finding_summaries, indent=2)}

ATTACK CHAINS ({len(chain_summaries)}):
{json.dumps(chain_summaries, indent=2)}

OPERATOR CONTEXT:
{json.dumps(safe_operator_ctx, indent=2)}

Generate the complete bug bounty report as JSON."""

    response = await llm.ainvoke([
        SystemMessage(content=REPORTER_SYSTEM),
        HumanMessage(content=user_content),
    ])

    m = re.search(r'\{.*\}', response.content, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(0))
        except json.JSONDecodeError:
            pass

    return _fallback_report(validated, chains, "JSON parse failed")


def _fallback_report(validated: list, chains: list, reason: str = "") -> dict:
    """Minimal structured report when LLM call fails."""
    severity_counts: dict[str, int] = {}
    for f in validated:
        sev = f.get("severity", "UNKNOWN")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    summary_parts = [f"{count} {sev.lower()}" for sev, count in severity_counts.items()]
    summary = (
        f"Security assessment identified {len(validated)} validated findings"
        + (f" ({', '.join(summary_parts)})" if summary_parts else "")
        + f". {len(chains)} attack chains were detected."
        + (f" (LLM report generation failed: {reason})" if reason else "")
    )

    return {
        "executive_summary": summary,
        "findings_reports": [
            {
                "id":          f.get("id", ""),
                "remediation": "Review and remediate the identified vulnerability following OWASP guidance.",
                "impact":      f.get("description", "Security vulnerability with potential for unauthorized access."),
                "writeup":     f.get("description", ""),
            }
            for f in validated
        ],
        "chains_reports": [
            {
                "id":             c.get("id", ""),
                "combined_impact": c.get("impact", "Chained exploitation increases overall severity."),
                "writeup":        c.get("narrative", ""),
            }
            for c in chains
        ],
    }


def _build_report_markdown(
    validated: list,
    chains: list,
    target_brief: str,
    timestamp: str,
    critical_high: int,
    report_data: dict,
) -> str:
    header = REPORT_HEADER_TEMPLATE.format(
        target=target_brief[:100],
        timestamp=timestamp,
        total_findings=len(validated),
        critical_high=critical_high,
        chains_count=len(chains),
        executive_summary=report_data.get("executive_summary", "No summary available."),
    )

    sections = [header]

    if validated:
        sections.append("## Findings\n")
        findings_by_id = {f.get("id", ""): f for f in validated}

        for fr in report_data.get("findings_reports", []):
            fid  = fr.get("id", "")
            raw  = findings_by_id.get(fid, {})
            sev  = raw.get("severity", "UNKNOWN")
            cvss = raw.get("cvss_estimate", 0)

            repro_steps = raw.get("reproduction_steps", [])
            repro_text  = "\n".join(f"{i+1}. {s}" for i, s in enumerate(repro_steps)) or "See description."

            sections.append(
                f"### {sev} — {raw.get('title', fid)}\n\n"
                f"**CVSS:** {cvss} | **URL:** {raw.get('url', 'N/A')} | "
                f"**Type:** {raw.get('vuln_type', 'N/A')}\n\n"
                f"**Description:** {fr.get('writeup', raw.get('description', ''))}\n\n"
                f"**Reproduction Steps:**\n{repro_text}\n\n"
                f"**Impact:** {fr.get('impact', '')}\n\n"
                f"**Remediation:** {fr.get('remediation', '')}\n\n---\n"
            )

    if chains:
        sections.append("## Attack Chains\n")
        chains_by_id = {c.get("id", ""): c for c in chains}

        for cr in report_data.get("chains_reports", []):
            cid = cr.get("id", "")
            raw = chains_by_id.get(cid, {})
            sections.append(
                f"### {raw.get('title', cid)}\n\n"
                f"**Composed CVSS:** {raw.get('cvss_composed', 'N/A')} | "
                f"**Confidence:** {raw.get('confidence', 0):.0%}\n\n"
                f"{cr.get('writeup', raw.get('narrative', ''))}\n\n"
                f"**Combined Impact:** {cr.get('combined_impact', raw.get('impact', ''))}\n\n---\n"
            )

    return "\n".join(sections)
