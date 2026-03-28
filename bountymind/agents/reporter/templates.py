"""Report generation templates for BountyMind."""

from __future__ import annotations

FINDING_TEMPLATE = """## {severity} — {title}

**CVSS:** {cvss} | **Severity:** {severity}
**URL:** {url}
**Vulnerability Type:** {vuln_type}
**Confidence Score:** {confidence:.0%}
**Agent:** {agent_id}

### Description
{description}

### Reproduction Steps
{reproduction_steps}

### Request Evidence
```
{request}
```

### Response Diff / Evidence
{response_diff}

### Payload
```
{payload}
```

### Business Impact
{impact}

### Remediation
{remediation}
"""

CHAIN_TEMPLATE = """## Attack Chain: {title}

**Composed CVSS:** {cvss_composed} | **Confidence:** {confidence:.0%}
**Agents Involved:** {agents}
**Finding IDs:** {finding_ids}

### Narrative
{narrative}

### Attack Scenario
{attack_scenario}

### Combined Business Impact
{impact}
"""

REPORT_HEADER_TEMPLATE = """# Bug Bounty Security Report

**Target:** {target}
**Generated:** {timestamp}
**Total Validated Findings:** {total_findings}
**Critical / High:** {critical_high}
**Attack Chains Identified:** {chains_count}

---

## Executive Summary

{executive_summary}

---
"""
