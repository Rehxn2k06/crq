"""
CRQ contract models. SINGLE SOURCE OF TRUTH.

Rules for everyone:
  1. Nothing outside this file defines an artifact shape.
  2. Every artifact is immutable and carries the id of the artifact it was built from.
  3. Every money field is named *_inr and is a float in rupees (not lakhs, not crores).
  4. Every probability field is 0.0-1.0.
  5. If you need a new field, add it here first, regenerate schemas, tell the team.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field

SCHEMA_VERSION = "0.1.0"


# ---------------------------------------------------------------- enums

class AssetType(str, Enum):
    SERVER = "server"
    WORKSTATION = "workstation"
    DATABASE = "database"
    NETWORK_DEVICE = "network_device"
    SAAS = "saas"
    CLOUD_RESOURCE = "cloud_resource"


class Privilege(str, Enum):
    NONE = "none"
    USER = "user"
    ADMIN = "admin"
    DATA_READ = "data_read"
    DATA_ADMIN = "data_admin"


class DataClass(str, Enum):
    PII = "pii"
    FINANCIAL = "financial"
    CREDENTIALS = "credentials"
    IP = "intellectual_property"
    PUBLIC = "public"


class Provenance(str, Enum):
    """Shown in the UI. Never lie about this."""
    SYNTHETIC = "synthetic"
    SCANNER = "scanner"
    MIXED = "mixed"


class LossComponent(str, Enum):
    DOWNTIME = "downtime"
    BREACH_RESPONSE = "breach_response"
    REGULATORY = "regulatory"
    REPUTATIONAL = "reputational"


# ---------------------------------------------------------------- snapshot (P1 owns)

class OrgProfile(BaseModel):
    name: str
    sector: str = Field(description="VCDB/NAICS-ish label, e.g. 'finance', 'healthcare'")
    is_sebi_regulated: bool = False
    sebi_entity_class: str | None = Field(
        default=None, description="MII | QRE | MID | SMALL | SELF_CERT"
    )
    annual_revenue_inr: float
    employee_count: int
    pii_records_count: int = Field(description="Drives the DPDP + breach-response model")


class Asset(BaseModel):
    asset_id: str
    hostname: str
    asset_type: AssetType
    business_unit: str
    internet_facing: bool = False
    revenue_dependency_inr_per_hour: float = 0.0
    data_classes: list[DataClass] = []
    pii_records_held: int = 0
    criticality_weight: float = Field(ge=0.0, le=1.0, default=0.0)
    tags: list[str] = []


class Dependency(BaseModel):
    from_asset_id: str
    to_asset_id: str
    kind: Literal["network", "data", "service", "trust"]
    note: str | None = None


class Identity(BaseModel):
    identity_id: str
    home_asset_id: str
    privilege: Privilege
    mfa_enabled: bool = False
    credential_reused_on: list[str] = Field(
        default=[], description="asset_ids where this credential also works. Lateral movement fuel."
    )


class Finding(BaseModel):
    finding_id: str
    asset_id: str
    cve_id: str | None = None
    cvss_base: float | None = Field(default=None, ge=0.0, le=10.0)
    cvss_vector: str | None = None
    epss: float | None = Field(default=None, ge=0.0, le=1.0)
    kev: bool = False
    grants_privilege: Privilege = Privilege.USER
    requires_privilege: Privilege = Privilege.NONE
    source: str = Field(description="trivy | openvas | prowler | wazuh | synthetic")
    first_seen: datetime | None = None
    status: Literal["open", "mitigated", "accepted"] = "open"


class AppliedControl(BaseModel):
    control_id: str
    applied_to_asset_ids: list[str]
    evidence_ref: str | None = None


class TelemetryMetrics(BaseModel):
    """Raw counters. Feeds the SEBI CCI parameters, which are literally ratios of these."""
    vulns_identified: int = 0
    vulns_mitigated: int = 0
    remote_users_total: int = 0
    remote_users_with_mfa: int = 0
    infosec_budget_inr: float = 0.0
    it_budget_inr: float = 0.0
    critical_systems_identified: int = 0
    systems_integrated_with_soc: int = 0
    total_it_systems: int = 0
    staff_total: int = 0
    staff_security_trained: int = 0
    incidents_total: int = 0
    incidents_closed_in_sla: int = 0
    assets_with_current_patch: int = 0
    backups_tested_count: int = 0
    backups_total_count: int = 0


class Snapshot(BaseModel):
    """The whole enterprise at one point in time. The only input to everything downstream."""
    schema_version: str = SCHEMA_VERSION
    snapshot_id: str
    created_at: datetime
    provenance: Provenance
    org: OrgProfile
    assets: list[Asset]
    dependencies: list[Dependency] = []
    identities: list[Identity] = []
    findings: list[Finding] = []
    existing_controls: list[AppliedControl] = []
    telemetry: TelemetryMetrics = TelemetryMetrics()


# ---------------------------------------------------------------- attack graph (P2 owns)

class GraphNode(BaseModel):
    node_id: str = Field(description="Convention: '{asset_id}:{privilege}'")
    asset_id: str
    privilege: Privilege
    is_entry: bool = False
    is_crown_jewel: bool = False


class GraphEdge(BaseModel):
    edge_id: str
    source_node_id: str
    target_node_id: str
    technique_id: str | None = Field(default=None, description="MITRE ATT&CK id, e.g. T1190")
    enabler_finding_id: str | None = None
    probability: float = Field(ge=0.0, le=1.0)
    rationale: str = Field(description="Human-readable. Shown in the trace panel. Mandatory.")
    blocked_by_control_ids: list[str] = []


class AttackGraph(BaseModel):
    schema_version: str = SCHEMA_VERSION
    graph_id: str
    snapshot_id: str
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    entry_node_ids: list[str]
    crown_jewel_node_ids: list[str]
    rules_version: str


# ---------------------------------------------------------------- path analysis (P2 owns)

class ChokePoint(BaseModel):
    node_id: str
    asset_id: str
    paths_through_fraction: float = Field(ge=0.0, le=1.0)
    crown_jewels_cut_if_removed: list[str]
    reachable_cj_value_inr: float


class CrownJewelReach(BaseModel):
    node_id: str
    asset_id: str
    compromise_probability: float = Field(ge=0.0, le=1.0)
    shortest_path_hops: int | None
    top_path_node_ids: list[str] = Field(description="Highest-probability path, for the demo")


class PathAnalysis(BaseModel):
    schema_version: str = SCHEMA_VERSION
    path_analysis_id: str
    graph_id: str
    choke_points: list[ChokePoint]
    crown_jewel_reach: list[CrownJewelReach]
    dead_end_node_fraction: float = Field(
        ge=0.0, le=1.0, description="Nodes on no path to any crown jewel. The '74%' stat, for your org."
    )


# ---------------------------------------------------------------- loss (P3 owns)

class SimConfig(BaseModel):
    trials: int = 25_000
    seed: int = Field(default=42, description="MUST be honoured. Common random numbers depend on it.")
    horizon_days: int = 365


class Assumption(BaseModel):
    """Glass-box requirement. Every soft input is declared here and shown in the UI."""
    key: str
    value: float | str
    unit: str | None = None
    source: str
    confidence: Literal["measured", "public_data", "estimated", "guess"]
    sensitivity_rank: int | None = Field(default=None, description="1 = moves the answer most")


class ScenarioContribution(BaseModel):
    scenario_id: str
    name: str
    triggering_node_ids: list[str]
    annual_frequency: float
    eal_inr: float
    share_of_total: float = Field(ge=0.0, le=1.0)


class ExceedancePoint(BaseModel):
    loss_inr: float
    probability_of_exceeding: float = Field(ge=0.0, le=1.0)


class LossDriver(BaseModel):
    ref_type: Literal["node", "finding", "asset"]
    ref_id: str
    label: str
    attributed_eal_inr: float


class LossResult(BaseModel):
    schema_version: str = SCHEMA_VERSION
    loss_result_id: str
    graph_id: str
    path_analysis_id: str
    config: SimConfig
    eal_inr: float = Field(description="Mean. Report it, but never lead with it.")
    median_inr: float
    p95_inr: float
    p99_inr: float
    exceedance_curve: list[ExceedancePoint]
    component_split_inr: dict[LossComponent, float]
    scenario_contributions: list[ScenarioContribution]
    top_drivers: list[LossDriver]
    assumptions: list[Assumption]


# ---------------------------------------------------------------- controls + optimizer (P3 owns)

class ControlCatalogEntry(BaseModel):
    control_id: str
    name: str
    description: str
    nist_800_53_ref: str | None = None
    cis_control_ref: str | None = None
    cost_inr_per_year: float
    cost_model: Literal["flat", "per_asset", "per_user"]
    blocks_technique_ids: list[str] = []
    blocks_finding_predicate: str | None = Field(
        default=None, description="Tiny DSL, e.g. 'kev==true' or 'cvss_base>=9.0'"
    )
    effectiveness: float = Field(ge=0.0, le=1.0, description="Edge probability multiplier is (1-effectiveness)")
    effectiveness_source: str
    cost_source: str = Field(description="URL or vendor quote. Mandatory. No unsourced prices.")


class SelectedControl(BaseModel):
    control_id: str
    name: str
    applied_to_asset_ids: list[str]
    cost_inr: float
    delta_eal_inr: float = Field(description="Marginal, computed in selection order. Not standalone.")
    roi_ratio: float = Field(description="delta_eal_inr / cost_inr")
    selection_rank: int
    reason: str


class ParetoPoint(BaseModel):
    budget_inr: float
    residual_eal_inr: float
    control_count: int


class Portfolio(BaseModel):
    schema_version: str = SCHEMA_VERSION
    portfolio_id: str
    loss_result_id: str
    budget_inr: float
    method: Literal["lazy_greedy", "milp"]
    selected: list[SelectedControl]
    total_cost_inr: float
    baseline_eal_inr: float
    residual_eal_inr: float
    risk_reduction_inr: float
    rosi: float = Field(description="(risk_reduction - cost) / cost")
    pareto_curve: list[ParetoPoint]
    optimality_gap: float | None = Field(default=None, description="Set when greedy is compared to MILP")
    solve_ms: float


# ---------------------------------------------------------------- compliance (P1 owns, phase 2)

class CCIParameter(BaseModel):
    param_id: str = Field(description="CCI-01 .. CCI-23")
    name: str
    weight_pct: float
    target_pct: float
    numerator: float
    denominator: float
    ratio_pct: float
    capped_score_pct: float = Field(description="min(ratio/target, 1.0) * 100")
    weighted_contribution: float
    evidence_refs: list[str] = []
    clause_ref: str | None = Field(default=None, description="CSCRF Annexure-K row")


class CCIResult(BaseModel):
    schema_version: str = SCHEMA_VERSION
    cci_result_id: str
    snapshot_id: str
    score: float = Field(ge=0.0, le=100.0, description="Two decimal places, per SEBI June 2025 FAQ")
    band: Literal["Exceptional", "Optimal", "Manageable", "Developing", "Bare Minimum", "Fail"]
    meets_minimum_for_entity_class: bool | None = None
    parameters: list[CCIParameter]


class RegulatoryExposure(BaseModel):
    schema_version: str = SCHEMA_VERSION
    snapshot_id: str
    dpdp_max_exposure_inr: float
    dpdp_breakdown: dict[str, float] = Field(description="clause -> ceiling in INR")
    modelled_expected_penalty_inr: float
    notes: list[str]


# ---------------------------------------------------------------- validation (P3 owns, phase 3)

class CalibrationBin(BaseModel):
    predicted_probability: float
    observed_frequency: float
    n: int


class CalibrationReport(BaseModel):
    schema_version: str = SCHEMA_VERSION
    report_id: str
    reference_dataset: str = "VCDB"
    brier_score: float
    log_score: float
    bins: list[CalibrationBin]
    notes: list[str]


# ---------------------------------------------------------------- run + trace (P4 owns)

class RunStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETE = "complete"
    FAILED = "failed"


class Run(BaseModel):
    schema_version: str = SCHEMA_VERSION
    run_id: str
    snapshot_id: str
    status: RunStatus
    created_at: datetime
    graph_id: str | None = None
    path_analysis_id: str | None = None
    loss_result_id: str | None = None
    portfolio_ids: list[str] = []
    cci_result_id: str | None = None
    error: str | None = None


class TraceStep(BaseModel):
    stage: str
    artifact_id: str
    element_id: str
    label: str
    detail: str
    inputs: list[str] = []


class TraceChain(BaseModel):
    """Powers the 'why is this number what it is' panel. The whole pitch depends on this working."""
    schema_version: str = SCHEMA_VERSION
    target_ref: str
    steps: list[TraceStep]


# ---------------------------------------------------------------- NL query (P4 owns, phase 3)

class NLQueryRequest(BaseModel):
    run_id: str
    question: str


class NLQueryPlan(BaseModel):
    """What the LLM is allowed to emit. Nothing else. It never returns numbers."""
    intent: Literal[
        "top_loss_drivers", "eal_summary", "choke_points", "portfolio_summary",
        "control_lookup", "cci_summary", "scenario_detail", "asset_detail",
        "compare_budgets", "exceedance_at_loss", "unsupported",
    ]
    filters: dict[str, str | float | int | bool] = {}
    limit: int = 10


class NLQueryResponse(BaseModel):
    plan: NLQueryPlan
    data: dict
    narrative: str = Field(description="Generated from data. The LLM never invents a figure.")
