# Function contracts

Every signature below is frozen. Implement the body, do not change the shape.
If you need a change, raise it with the team and edit `schemas.py` first.

Two hard rules that make the whole thing work:

1. **Everything is a pure function of its inputs.** No hidden global state, no reading
   from the DB inside the engine. The API layer loads artifacts and passes them in.
2. **`simulate()` must be deterministic given the same `seed`.** The optimizer compares
   dozens of candidate control sets. If the simulation wobbles between calls, the
   differences it measures are noise, not signal. This is called *common random numbers*
   and it is not optional.

---

## packages/ingest  — P1

```python
def generate_enterprise(
    profile: OrgProfile,
    asset_count: int,
    seed: int,
) -> Snapshot:
    """Synthetic org. Must set provenance=SYNTHETIC. Realistic topology:
    a DMZ, an internal tier, a data tier, a handful of crown jewels, credential
    reuse between tiers, ~15% of assets internet-facing at most."""

def parse_trivy(raw: dict, asset_id: str) -> list[Finding]:
    """Trivy JSON report -> Findings. source='trivy'."""

def parse_prowler(raw: dict) -> tuple[list[Asset], list[Finding]]:
    """Prowler cloud findings -> cloud assets + misconfiguration findings."""

def parse_wazuh(raw: dict) -> tuple[list[Asset], TelemetryMetrics]:
    """Wazuh agent inventory -> assets + SOC coverage counters."""

def enrich_findings(findings: list[Finding]) -> list[Finding]:
    """Fill epss, kev, cvss from the local NVD/EPSS/KEV mirrors.
    Offline. Never call an external API at request time."""

def merge_snapshot(parts: list[Snapshot]) -> Snapshot:
    """Combine connector outputs + synthetic filler. provenance=MIXED if sources differ."""
```

## packages/core — P2 (graph, paths)

```python
def build_graph(snapshot: Snapshot, rules_version: str = "v1") -> AttackGraph:
    """Snapshot -> attack graph.
    Nodes are (asset, privilege) states. Edges are actions an attacker can take.

    Minimum rule set for v1:
      R1 remote exploit    internet_facing asset + open finding      -> (asset, granted_priv)
      R2 local privesc     (asset, user) + local privesc finding     -> (asset, admin)
      R3 credential reuse  (asset_a, admin) + identity reused on b   -> (asset_b, user)
      R4 network pivot     (asset_a, user) + network dependency a->b -> (asset_b, none->user) if b has a finding
      R5 data access       (db_asset, admin)                         -> (db_asset, data_admin)

    Edge probability:
      base = epss if present, else cvss_base/10 * 0.1
      if kev: base = max(base, 0.6)
      if a blocking existing_control applies: base *= (1 - effectiveness)
    Every edge MUST carry a human-readable `rationale`. The trace panel renders it."""

def analyze_paths(graph: AttackGraph, snapshot: Snapshot) -> PathAnalysis:
    """Reachability from entry nodes to crown jewels.
    choke_points: for each node, fraction of crown-jewel-reaching paths that pass through it.
    dead_end_node_fraction: nodes on zero such paths.
    Use probability-weighted path enumeration with a depth cap (6 hops) to stay fast."""

def apply_controls(
    graph: AttackGraph,
    catalog: list[ControlCatalogEntry],
    applications: list[AppliedControl],
) -> AttackGraph:
    """Return a NEW graph with edge probabilities reduced. Pure. Must not mutate input.
    Called thousands of times by the optimizer, so keep it cheap (numpy-friendly)."""
```

## packages/core — P3 (loss, optimizer, validation)

```python
def build_scenarios(graph: AttackGraph, paths: PathAnalysis, snapshot: Snapshot) -> list[Scenario]:
    """Crown-jewel compromises -> named loss scenarios.
    e.g. reaching customer-db:data_admin -> 'mass_pii_exfiltration'."""

def simulate(
    graph: AttackGraph,
    paths: PathAnalysis,
    snapshot: Snapshot,
    config: SimConfig,
) -> LossResult:
    """Monte Carlo. Vectorised numpy, 25k trials, must run in under 2 seconds.

    Per scenario, per trial:
      frequency ~ Poisson(lambda) where lambda derives from path compromise probability
      severity  ~ LogNormal(mu, sigma) calibrated to Cyentia IRIS, scaled by asset value
      + downtime      = revenue_dependency_inr_per_hour * Duration ~ LogNormal
      + breach_resp   = per-record cost * pii_records_held
      + regulatory    = DPDP ceiling-bounded draw, only when PII data class is touched
      + reputational  = churn_rate * annual_revenue, churn_rate is an ASSUMPTION (declare it)

    Every soft input goes into `assumptions` with a confidence label.
    Sensitivity ranking: one-at-a-time +/-20% perturbation, rank by swing in EAL."""

def optimize(
    graph: AttackGraph,
    paths: PathAnalysis,
    snapshot: Snapshot,
    catalog: list[ControlCatalogEntry],
    budget_inr: float,
    config: SimConfig,
    method: Literal["lazy_greedy", "milp"] = "lazy_greedy",
) -> Portfolio:
    """Marginal control selection under budget.

    lazy_greedy (build this first, it always works):
      loop: for each unselected control, delta = baseline_eal - simulate(apply_controls(...)).eal
            pick argmax(delta / cost) that fits remaining budget
            recompute deltas for the rest (they change — that is the whole point)
      CELF lazy evaluation: keep a max-heap of stale deltas, only recompute the top one.
      Cuts the number of simulate() calls by roughly 10x.

    milp: OR-Tools, linearised over precomputed pairwise marginals. Runs as a CHECK
      against greedy, reports optimality_gap. Do not build this before greedy works.

    pareto_curve: rerun greedy at 0.25x/0.5x/0.75x/1x/1.5x/2x budget."""

def backtest(historical_snapshots: list[Snapshot], vcdb_events: list[dict]) -> CalibrationReport:
    """Bin predicted annual compromise probabilities, compare to observed VCDB
    frequencies for matching sector+size. Brier score + calibration curve."""
```

## packages/compliance — P1, phase 2

```python
def compute_cci(snapshot: Snapshot) -> CCIResult:
    """23 weighted SEBI CSCRF Annexure-K parameters from TelemetryMetrics.
    Each param: ratio = numerator/denominator*100, capped at its target, weighted, summed.
    Two decimal places. Bands: 91+ Exceptional, 81-90 Optimal, 71-80 Manageable,
    61-70 Developing, 51-60 Bare Minimum, <=50 Fail.
    Undefined (denominator 0) defaults to the parameter max/min per the SEBI FAQ.
    Every parameter carries evidence_refs pointing back at snapshot fields."""

def dpdp_exposure(snapshot: Snapshot) -> RegulatoryExposure:
    """Ceilings: 250cr security safeguards, 200cr notification + children's data,
    150cr Significant Data Fiduciary, 50cr residual. Per instance, no turnover linkage."""
```

## packages/api — P4

```python
def build_trace(run: Run, target_ref: str) -> TraceChain:
    """Walk artifact pointers backwards from any number on screen to its raw inputs.
    target_ref format: '{artifact_type}:{artifact_id}:{element_id}'
    e.g. 'loss_driver:LR-001:node-jenkins-prod-01:admin'"""

def plan_query(question: str, run: Run) -> NLQueryPlan:
    """LLM call. System prompt says: emit ONLY this JSON schema, no prose, no numbers.
    Validate against NLQueryPlan. On validation failure, return intent='unsupported'.
    NEVER pass the raw LLM text through to the user."""

def narrate(plan: NLQueryPlan, data: dict) -> str:
    """Second LLM call. Given the computed data, write 2-3 sentences of plain English.
    System prompt: 'Use only the figures provided. Do not calculate. Do not estimate.'"""
```
