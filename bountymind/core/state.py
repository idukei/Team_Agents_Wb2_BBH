import operator
from typing import Annotated, TypedDict


PHASE_SEQUENCE = [
    "BRIEF", "RECON", "INTELLIGENCE", "STRATEGY",
    "ATTACK", "SYNTHESIS", "VALIDATION", "REVIEW", "REPORT",
]


class BountyMindState(TypedDict):
    target_brief:        str
    operator_context:    dict
    scope_rules:         dict
    run_config:          dict
    surface_inventory:   dict
    target_context:      dict
    attack_strategy:     dict
    agent_loadouts:      dict
    agent_status:        dict
    shared_memory:       dict
    raw_findings:        Annotated[list, operator.add]
    validated_findings:  list
    attack_chains:       list
    false_positives:     list
    phase:               str
    phase_history:       Annotated[list, operator.add]
    messages:            Annotated[list, operator.add]
    pending_interrupts:  list
    interrupt_log:       Annotated[list, operator.add]
    audit_log:           Annotated[list, operator.add]
    thread_id:           str
    confidence_threshold: float
