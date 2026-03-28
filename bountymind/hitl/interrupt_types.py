from enum import Enum


class HITLType(str, Enum):
    SCOPE_REVIEW    = "SCOPE_REVIEW"
    STRATEGY_REVIEW = "STRATEGY_REVIEW"
    LOADOUT_REVIEW  = "LOADOUT_REVIEW"
    CREDENTIALS     = "CREDENTIALS"
    HIGH_SEVERITY   = "HIGH_SEVERITY"
    DESTRUCTIVE     = "DESTRUCTIVE"
    AGENT_STALLED   = "AGENT_STALLED"
    NEW_SURFACE     = "NEW_SURFACE"
    CHAIN_CRITICAL  = "CHAIN_CRITICAL"
    PRE_REPORT      = "PRE_REPORT"


HITL_METADATA = {
    HITLType.SCOPE_REVIEW: {
        "id":          "HITL-0",
        "label":       "Scope Review",
        "description": "Review and confirm the target scope before recon begins.",
        "blocking":    True,
        "mandatory":   True,
        "operator_can": ["Approve scope", "Edit scope_rules", "Add context"],
    },
    HITLType.STRATEGY_REVIEW: {
        "id":          "HITL-1a",
        "label":       "Strategy Review",
        "description": "Review the attack strategy narrative and threat areas.",
        "blocking":    True,
        "mandatory":   True,
        "operator_can": ["Approve strategy", "Edit attack_strategy", "Add hypotheses"],
    },
    HITLType.LOADOUT_REVIEW: {
        "id":          "HITL-1b",
        "label":       "LoadOut Review",
        "description": "Review and edit agent LoadOuts before attack swarm launches.",
        "blocking":    True,
        "mandatory":   True,
        "operator_can": ["Approve all loadouts", "Edit test_cases", "Deactivate agents", "Modify tool_configs"],
    },
    HITLType.CREDENTIALS: {
        "id":          "HITL-2",
        "label":       "Credentials Required",
        "description": "Agent needs credentials to continue.",
        "blocking":    True,
        "mandatory":   False,
        "operator_can": ["Inject credentials via state", "Skip authentication tests"],
    },
    HITLType.HIGH_SEVERITY: {
        "id":          "HITL-3",
        "label":       "High Severity Finding",
        "description": "A finding with CVSS >= 9.0 was detected.",
        "blocking":    True,
        "mandatory":   False,
        "operator_can": ["Approve finding", "Reject finding", "Request re-verification"],
    },
    HITLType.DESTRUCTIVE: {
        "id":          "HITL-4",
        "label":       "Destructive Action",
        "description": "Agent is about to execute a potentially destructive action.",
        "blocking":    True,
        "mandatory":   False,
        "operator_can": ["Approve action", "Reject action", "Modify parameters"],
    },
    HITLType.AGENT_STALLED: {
        "id":          "HITL-5",
        "label":       "Agent Stalled",
        "description": "Agent reached max_iterations without findings.",
        "blocking":    True,
        "mandatory":   False,
        "operator_can": ["Re-forge LoadOut", "Terminate agent", "Add test_cases"],
    },
    HITLType.NEW_SURFACE: {
        "id":          "HITL-6",
        "label":       "New Surface Discovered",
        "description": "Agent discovered new attack surface not in original inventory.",
        "blocking":    True,
        "mandatory":   False,
        "operator_can": ["Approve additional test_cases", "Ignore surface", "Add to scope"],
    },
    HITLType.CHAIN_CRITICAL: {
        "id":          "HITL-7",
        "label":       "Critical Attack Chain",
        "description": "Chain Synthesizer detected a chain with CVSS >= 9.5.",
        "blocking":    True,
        "mandatory":   False,
        "operator_can": ["Confirm chain escalation", "Reject chain", "Add business context"],
    },
    HITLType.PRE_REPORT: {
        "id":          "HITL-8",
        "label":       "Pre-Report Review",
        "description": "Review validated findings before report generation.",
        "blocking":    True,
        "mandatory":   True,
        "operator_can": ["Approve findings", "Discard false positives", "Add business context"],
    },
}
