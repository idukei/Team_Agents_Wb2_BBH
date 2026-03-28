from typing import Any
from pydantic import BaseModel, Field


class TestCase(BaseModel):
    surface:   str
    technique: str
    expected:  str = ""
    priority:  int = 0


class AgentLoadOut(BaseModel):
    agent_id:             str
    active:               bool             = True
    priority:             int              = 0
    mission:              str              = ""
    rationale:            str              = ""
    hypotheses:           list[str]        = Field(default_factory=list)
    test_cases:           list[dict]       = Field(default_factory=list)
    system_prompt:        str              = ""
    methodology:          list[str]        = Field(default_factory=list)
    tools:                list[str]        = Field(default_factory=list)
    tool_configs:         dict[str, Any]   = Field(default_factory=dict)
    write_channels:       list[str]        = Field(default_factory=lambda: ["observations"])
    read_channels:        list[str]        = Field(default_factory=lambda: ["observations"])
    handoff_targets:      list[str]        = Field(default_factory=list)
    max_iterations:       int              = 25
    interrupt_conditions: list[str]        = Field(default_factory=list)
    success_criteria:     list[str]        = Field(default_factory=list)


class RawFinding(BaseModel):
    id:                   str
    agent_id:             str
    url:                  str
    vuln_type:            str
    title:                str
    description:          str
    request:              dict             = Field(default_factory=dict)
    response_diff:        dict             = Field(default_factory=dict)
    payload:              str              = ""
    reproduction_steps:   list[str]        = Field(default_factory=list)
    evidence:             dict             = Field(default_factory=dict)
    cvss_estimate:        float            = 0.0
    severity:             str              = "INFORMATIONAL"
    timestamp:            str              = ""
    raw_output:           str              = ""


class ScopeRules(BaseModel):
    in_scope:     list[str] = Field(default_factory=list)
    out_of_scope: list[str] = Field(default_factory=list)
    allowed_methods: list[str] = Field(default_factory=lambda: ["GET", "POST", "PUT", "PATCH", "DELETE"])
    max_depth:    int = 3


class ValidatedFinding(BaseModel):
    """A RawFinding that passed the Validator Agent's confidence threshold."""
    id:                   str
    agent_id:             str
    url:                  str
    vuln_type:            str
    title:                str
    description:          str
    request:              dict             = Field(default_factory=dict)
    response_diff:        dict             = Field(default_factory=dict)
    payload:              str              = ""
    reproduction_steps:   list[str]        = Field(default_factory=list)
    evidence:             dict             = Field(default_factory=dict)
    cvss_estimate:        float            = 0.0
    severity:             str              = "INFORMATIONAL"
    timestamp:            str              = ""
    raw_output:           str              = ""
    # Validation metadata
    confidence_score:     float            = 0.0
    plausibility:         float            = 0.0
    evidence_quality:     float            = 0.0
    impact_clarity:       float            = 0.0
    reproducibility:      float            = 0.0
    poc_result:           dict             = Field(default_factory=dict)
    validated_at:         str              = ""
    rejection_reason:     str              = ""


class AttackChain(BaseModel):
    """A composed multi-finding attack chain from the Chain Synthesizer."""
    id:                str
    title:             str
    finding_ids:       list[str]          = Field(default_factory=list)
    agents_involved:   list[str]          = Field(default_factory=list)
    narrative:         str                = ""
    attack_scenario:   str                = ""
    cvss_composed:     float              = 0.0
    confidence:        float              = 0.0
    impact:            str                = ""


class RunRequest(BaseModel):
    """Request body for POST /api/runs."""
    target_brief:        str
    scope_rules:         dict             = Field(default_factory=dict)
    run_config:          dict             = Field(default_factory=dict)
    operator_context:    dict             = Field(default_factory=dict)


class RunResponse(BaseModel):
    """Response body for POST /api/runs and GET /api/runs/{id}."""
    thread_id:           str
    phase:               str              = "BRIEF"
    status:              str              = "running"
