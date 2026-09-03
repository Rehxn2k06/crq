"""P3 loss tests. Developed against a real generated snapshot, not the fixtures.

``contracts/fixtures/loss_result.json`` is a hand-written illustration of the
shape; it was never produced by this code and its numbers are not targets. So the
end-to-end tests here run the actual pipeline -- generate_enterprise(200 assets,
seed 20260331) -> build_graph -> analyze_paths -> simulate -- and assert the
properties the result has to have whatever the numbers come out as.

Alongside those, micro-tests on hand-built graphs pin the individual mechanisms
(the DPDP ceiling, the PII gate, the frequency model) so a failure points at one
mechanism rather than at the whole simulation.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone

import numpy as np
import pytest

from crq_core.graph import analyze_paths, build_graph
from crq_core.loss import (
    DPDP_SECURITY_CEILING_INR,
    PERTURBABLE,
    SECTOR_INCIDENT_MULTIPLIER,
    _base_incident_rate,
    _build_scenarios,
    _draw,
    _evaluate,
    _intrusion_index,
    _Params,
    _saturate,
    simulate,
)
from crq_core.schemas import (
    Asset,
    AssetType,
    AttackGraph,
    CrownJewelReach,
    DataClass,
    GraphEdge,
    GraphNode,
    LossComponent,
    LossResult,
    OrgProfile,
    PathAnalysis,
    Privilege,
    Provenance,
    SimConfig,
    Snapshot,
)

ASSET_COUNT = 200
SEED = 20260331


# --------------------------------------------------------------------------- #
# the real pipeline
# --------------------------------------------------------------------------- #

@pytest.fixture(scope="module")
def profile() -> OrgProfile:
    """The same mid-size SEBI-regulated broking house P1 generates against."""
    return OrgProfile(
        name="Meridian Broking Pvt Ltd",
        sector="finance",
        is_sebi_regulated=True,
        sebi_entity_class="QRE",
        annual_revenue_inr=8_40_00_00_000,
        employee_count=420,
        pii_records_count=2_400_000,
    )


@pytest.fixture(scope="module")
def snapshot(profile: OrgProfile) -> Snapshot:
    from crq_ingest.synthetic import generate_enterprise

    return generate_enterprise(profile, ASSET_COUNT, SEED)


@pytest.fixture(scope="module")
def graph(snapshot: Snapshot) -> AttackGraph:
    return build_graph(snapshot)


@pytest.fixture(scope="module")
def paths(graph: AttackGraph, snapshot: Snapshot) -> PathAnalysis:
    return analyze_paths(graph, snapshot)


@pytest.fixture(scope="module")
def config() -> SimConfig:
    return SimConfig(trials=25_000, seed=SEED)


@pytest.fixture(scope="module")
def result(graph: AttackGraph, paths: PathAnalysis, snapshot: Snapshot,
           config: SimConfig) -> LossResult:
    return simulate(graph, paths, snapshot, config)


# --------------------------------------------------------------------------- #
# the five properties the contract turns on
# --------------------------------------------------------------------------- #

def test_same_seed_produces_an_identical_result(graph, paths, snapshot, config, result):
    """The optimizer subtracts two of these to measure a control's effect. If the
    simulation wobbles between calls, it measures noise. Common random numbers."""
    again = simulate(graph, paths, snapshot, config)
    assert again.eal_inr == result.eal_inr
    assert again.model_dump_json() == result.model_dump_json()


def test_a_different_seed_moves_the_answer(graph, paths, snapshot, config, result):
    """Guards the test above from passing because nothing is random at all."""
    other = simulate(graph, paths, snapshot, config.model_copy(update={"seed": SEED + 1}))
    assert other.eal_inr != result.eal_inr
    # Two draws from the same model, so they should still be the same size.
    assert 0.5 < other.eal_inr / result.eal_inr < 2.0


def test_exceedance_curve_is_monotonically_decreasing(result: LossResult):
    curve = result.exceedance_curve
    assert len(curve) >= 5, "a curve with no points on it is not a curve"
    losses = [p.loss_inr for p in curve]
    probabilities = [p.probability_of_exceeding for p in curve]
    assert losses == sorted(losses), "loss levels must increase"
    assert len(set(losses)) == len(losses), "duplicate loss levels"
    assert all(a > b for a, b in zip(probabilities, probabilities[1:])), (
        "probability of exceeding must fall strictly as the loss level rises"
    )
    assert all(0.0 <= p <= 1.0 for p in probabilities)


def test_median_below_mean_below_p95(result: LossResult):
    """Cyber loss is heavy-tailed: the mean sits well above the median because a
    handful of trials carry it. If this ever inverts, the severity fit is wrong.

    With the base rate anchored at roughly one significant incident every eight
    years the median year costs nothing at all, so the gap is asserted against
    the p95 rather than as a ratio to a median that is legitimately zero.
    """
    assert result.median_inr < result.eal_inr < result.p95_inr < result.p99_inr
    assert result.p95_inr > 3.0 * result.eal_inr, "tail is too thin to be credible"


def test_component_split_sums_to_eal(result: LossResult):
    """The four components are a partition of every event, so their means must
    reconcile to the headline number exactly. Rounded to paise."""
    assert set(result.component_split_inr) == set(LossComponent)
    assert sum(result.component_split_inr.values()) == pytest.approx(result.eal_inr, abs=0.01)
    assert all(v >= 0.0 for v in result.component_split_inr.values())


def test_scenario_shares_sum_to_one(result: LossResult):
    shares = [s.share_of_total for s in result.scenario_contributions]
    assert shares, "a run with no scenarios has nothing to say"
    assert sum(shares) == pytest.approx(1.0, abs=1e-9)
    assert all(0.0 <= s <= 1.0 for s in shares)
    # And the rupee figures reconcile too, not just the shares.
    total = sum(s.eal_inr for s in result.scenario_contributions)
    assert total == pytest.approx(result.eal_inr, rel=1e-6)


# --------------------------------------------------------------------------- #
# performance + shape
# --------------------------------------------------------------------------- #

def test_twenty_five_thousand_trials_run_in_under_two_seconds(graph, paths, snapshot):
    """FUNCTIONS.md budget. Includes the full sensitivity sweep, which is 22
    further evaluations of the model on the same random numbers."""
    started = time.perf_counter()
    simulate(graph, paths, snapshot, SimConfig(trials=25_000, seed=SEED))
    elapsed = time.perf_counter() - started
    assert elapsed < 2.0, f"simulate took {elapsed:.2f}s"


def test_result_round_trips_through_json(result: LossResult):
    assert LossResult.model_validate_json(result.model_dump_json()) == result


def test_ids_point_back_at_the_artifacts_it_was_built_from(result, graph, paths):
    assert result.graph_id == graph.graph_id
    assert result.path_analysis_id == paths.path_analysis_id
    assert result.loss_result_id.startswith("LOSS-")


def test_every_reachable_crown_jewel_becomes_a_scenario(result, paths):
    reachable = {r.node_id for r in paths.crown_jewel_reach if r.compromise_probability > 0}
    triggered = {n for s in result.scenario_contributions for n in s.triggering_node_ids}
    assert triggered == reachable


def test_scenario_frequency_is_the_base_rate_times_conditional_reach(result, paths, snapshot):
    """The path probability is conditional on an intrusion, not an annual rate.
    A jewel's own frequency is therefore base_rate x P(reached | intrusion), and
    it must come out well below the org-wide incident rate."""
    rate = _base_incident_rate(snapshot)
    by_node = {r.node_id: r.compromise_probability for r in paths.crown_jewel_reach}
    for contribution in result.scenario_contributions:
        p = by_node[contribution.triggering_node_ids[0]]
        assert contribution.annual_frequency == pytest.approx(rate * p, abs=1e-6)
        assert contribution.annual_frequency < rate


def test_eal_is_a_credible_share_of_annual_revenue(result, snapshot):
    """The calibration gate. A firm does not lose a sixth of its revenue to cyber
    risk every year on average; if this model says it does, the frequency model
    is counting the probability of getting in once per crown jewel."""
    share = result.eal_inr / snapshot.org.annual_revenue_inr
    assert 0.001 < share < 0.05, f"EAL is {share:.2%} of annual revenue"


def test_the_base_rate_is_anchored_to_headcount_and_sector(snapshot):
    rate = _base_incident_rate(snapshot)
    assert 0.08 <= rate <= 0.15, f"base rate {rate} outside the plausible band"
    # 420 employees, finance: the 250-1,000 size band lifted by the sector.
    assert rate == pytest.approx(0.08 * SECTOR_INCIDENT_MULTIPLIER["finance"])

    smaller = snapshot.org.model_copy(update={"employee_count": 30})
    assert _base_incident_rate(snapshot.model_copy(update={"org": smaller})) < rate
    bigger = snapshot.org.model_copy(update={"employee_count": 50_000})
    assert _base_incident_rate(snapshot.model_copy(update={"org": bigger})) > rate
    # An unrecognised sector carries no multiplier rather than a guessed one.
    plain = snapshot.org.model_copy(update={"sector": "widgets"})
    assert _base_incident_rate(snapshot.model_copy(update={"org": plain})) == 0.08


def test_most_years_cost_nothing(graph, paths, snapshot, config, result):
    """One intrusion process at ~0.12/yr means the overwhelming majority of years
    have no crown-jewel compromise at all. That is the shape of the answer, and
    it is why the schema says never to lead with the mean."""
    params = _Params(org_annual_incident_rate=_base_incident_rate(snapshot))
    scenarios = _build_scenarios(graph, paths, snapshot)
    intrusions, draws = _draw(scenarios, params, config)
    sample = _evaluate(scenarios, intrusions, draws, snapshot, params, config)
    zero_share = float((sample.total == 0.0).mean())
    assert 0.80 < zero_share < 0.97
    assert result.median_inr == 0.0


def test_one_intrusion_can_reach_several_crown_jewels(graph, paths, snapshot, config):
    """The whole reason there is a single intrusion process. Two jewels being
    compromised in the same year must be commoner than it would be if the two
    scenarios ran as independent Poisson processes."""
    params = _Params(org_annual_incident_rate=_base_incident_rate(snapshot))
    scenarios = _build_scenarios(graph, paths, snapshot)
    intrusions, draws = _draw(scenarios, params, config)
    sample = _evaluate(scenarios, intrusions, draws, snapshot, params, config)

    hit = [s > 0.0 for s in sample.per_scenario]
    assert len(hit) >= 2
    pairs_seen = 0
    for i in range(len(hit)):
        for j in range(i + 1, len(hit)):
            joint = float((hit[i] & hit[j]).mean())
            independent = float(hit[i].mean()) * float(hit[j].mean())
            assert joint > independent * 2.0, "jewels are not correlated by the intrusion"
            pairs_seen += 1
    assert pairs_seen


def test_horizon_scales_the_loss(graph, paths, snapshot, result):
    """Half a year is roughly half the expected loss. Poisson frequency is linear
    in the horizon; the severity per event does not change."""
    half = simulate(graph, paths, snapshot,
                    SimConfig(trials=25_000, seed=SEED, horizon_days=182))
    assert 0.4 < half.eal_inr / result.eal_inr < 0.6


@pytest.mark.parametrize("trials", [1_000, 5_000])
def test_trial_count_is_honoured(graph, paths, snapshot, trials):
    result = simulate(graph, paths, snapshot, SimConfig(trials=trials, seed=SEED))
    assert result.config.trials == trials


def test_rejects_a_nonsense_config(graph, paths, snapshot):
    with pytest.raises(ValueError):
        simulate(graph, paths, snapshot, SimConfig(trials=0, seed=SEED))
    with pytest.raises(ValueError):
        simulate(graph, paths, snapshot, SimConfig(seed=SEED, horizon_days=0))


# --------------------------------------------------------------------------- #
# assumptions + sensitivity (the glass-box requirement)
# --------------------------------------------------------------------------- #

def test_every_assumption_is_declared_with_a_source_and_a_confidence(result: LossResult):
    assert result.assumptions
    keys = [a.key for a in result.assumptions]
    assert len(keys) == len(set(keys)), "duplicate assumption keys"
    for assumption in result.assumptions:
        assert assumption.source.strip(), f"{assumption.key} has no source"
        assert assumption.confidence in {"measured", "public_data", "estimated", "guess"}


def test_the_churn_rate_admits_it_is_a_guess(result: LossResult):
    """It is a guess. Saying otherwise on a glass-box tool is the one thing that
    would actually discredit the whole number."""
    churn = next(a for a in result.assumptions if a.key == "reputational_churn_rate")
    assert churn.confidence == "guess"
    assert "no defensible public source" in churn.source.lower()


def test_the_soft_inputs_that_matter_are_all_declared(result: LossResult):
    declared = {a.key for a in result.assumptions}
    for _, key in PERTURBABLE:
        assert key in declared, f"{key} is perturbed but never declared"
    for key in (
        "usd_inr_rate",
        "iris_severity_median_usd",
        "iris_severity_p95_usd",
        "breach_response_cost_per_record_inr",
        "dpdp_security_ceiling_inr",
        "reputational_churn_rate",
    ):
        assert key in declared


def test_sensitivity_ranks_are_a_dense_ordering_over_the_perturbed_inputs(result: LossResult):
    ranked = [a for a in result.assumptions if a.sensitivity_rank is not None]
    assert len(ranked) == len(PERTURBABLE)
    assert sorted(a.sensitivity_rank for a in ranked) == list(range(1, len(PERTURBABLE) + 1))
    # Statute is not an uncertainty, so it carries no rank.
    ceiling = next(a for a in result.assumptions if a.key == "dpdp_security_ceiling_inr")
    assert ceiling.sensitivity_rank is None


def test_sensitivity_rank_one_really_does_move_the_answer_most(
    graph, paths, snapshot, config, result
):
    """Re-derives the ranking the slow, obvious way and checks the top-ranked
    input against the bottom-ranked one."""
    from dataclasses import replace as dc_replace

    from crq_core.loss import PERTURBATION

    field_of = {key: field for field, key in PERTURBABLE}
    ranked = sorted(
        (a for a in result.assumptions if a.sensitivity_rank is not None),
        key=lambda a: a.sensitivity_rank,
    )
    base = _Params(org_annual_incident_rate=_base_incident_rate(snapshot))
    scenarios = _build_scenarios(graph, paths, snapshot)
    intrusions, draws = _draw(scenarios, base, config)
    cache: dict = {}

    def swing(key: str) -> float:
        field = field_of[key]
        current = getattr(base, field)
        high = _evaluate(scenarios, intrusions, draws, snapshot,
                         dc_replace(base, **{field: current * (1 + PERTURBATION)}), config, cache)
        low = _evaluate(scenarios, intrusions, draws, snapshot,
                        dc_replace(base, **{field: current * (1 - PERTURBATION)}), config, cache)
        return abs(float(high.total.mean()) - float(low.total.mean()))

    assert swing(ranked[0].key) > swing(ranked[-1].key)


# --------------------------------------------------------------------------- #
# top_drivers -- what the trace panel walks
# --------------------------------------------------------------------------- #

def test_drivers_point_at_things_that_exist(result, graph, snapshot):
    assert result.top_drivers, "a loss with no drivers cannot be traced"
    node_ids = {n.node_id for n in graph.nodes}
    finding_ids = {f.finding_id for f in snapshot.findings}
    asset_ids = {a.asset_id for a in snapshot.assets}
    for driver in result.top_drivers:
        assert driver.attributed_eal_inr > 0.0
        assert driver.label.strip()
        if driver.ref_type == "node":
            assert driver.ref_id in node_ids
        elif driver.ref_type == "finding":
            assert driver.ref_id in finding_ids
        else:
            assert driver.ref_id in asset_ids


def test_drivers_name_both_nodes_and_findings(result: LossResult):
    """The trace panel walks a number down to a state and then to the finding
    that enabled it. Both ends have to be present."""
    kinds = {d.ref_type for d in result.top_drivers}
    assert "node" in kinds and "finding" in kinds


def test_node_attribution_does_not_invent_money(result: LossResult):
    """Node rows are a partition of the EAL pushed back down the attack paths, so
    they can sum to less than the EAL when the list is truncated, never more."""
    attributed = sum(d.attributed_eal_inr for d in result.top_drivers if d.ref_type == "node")
    assert 0.0 < attributed <= result.eal_inr * 1.000001


def test_drivers_are_sorted_by_the_money(result: LossResult):
    amounts = [d.attributed_eal_inr for d in result.top_drivers]
    assert amounts == sorted(amounts, reverse=True)


def test_a_crown_jewel_state_is_among_the_drivers(result, paths):
    """The state where the loss actually lands must be traceable, not just the
    hops on the way to it."""
    crown_jewels = {r.node_id for r in paths.crown_jewel_reach}
    assert crown_jewels & {d.ref_id for d in result.top_drivers if d.ref_type == "node"}


# --------------------------------------------------------------------------- #
# mechanisms, on hand-built graphs
# --------------------------------------------------------------------------- #

def _micro(
    *,
    data_classes: list[DataClass],
    pii_records: int,
    revenue_per_hour: float = 100_000.0,
    probability: float = 0.5,
) -> tuple[AttackGraph, PathAnalysis, Snapshot]:
    """One entry, one hop, one crown jewel. Small enough that a failure names the
    mechanism it broke."""
    asset = Asset(
        asset_id="a-db",
        hostname="db-01",
        asset_type=AssetType.DATABASE,
        business_unit="ops",
        revenue_dependency_inr_per_hour=revenue_per_hour,
        data_classes=data_classes,
        pii_records_held=pii_records,
        criticality_weight=1.0,
        tags=["crown_jewel"],
    )
    snapshot = Snapshot(
        snapshot_id="SNAP-MICRO",
        created_at=datetime(2026, 3, 31, tzinfo=timezone.utc),
        provenance=Provenance.SYNTHETIC,
        org=OrgProfile(
            name="Micro Ltd",
            sector="finance",
            annual_revenue_inr=1_000_00_00_000,
            # Big enough that the base rate produces a workable event sample in
            # a few thousand trials; the mechanisms under test do not care.
            employee_count=50_000,
            pii_records_count=max(pii_records, 1),
        ),
        assets=[asset],
    )
    nodes = [
        GraphNode(node_id="internet:none", asset_id="internet", privilege=Privilege.NONE,
                  is_entry=True),
        GraphNode(node_id="a-db:data_admin", asset_id="a-db", privilege=Privilege.DATA_ADMIN,
                  is_crown_jewel=True),
    ]
    graph = AttackGraph(
        graph_id="GRAPH-MICRO",
        snapshot_id="SNAP-MICRO",
        nodes=nodes,
        edges=[
            GraphEdge(
                edge_id="e1",
                source_node_id="internet:none",
                target_node_id="a-db:data_admin",
                probability=probability,
                rationale="micro test edge",
            )
        ],
        entry_node_ids=["internet:none"],
        crown_jewel_node_ids=["a-db:data_admin"],
        rules_version="v1",
    )
    paths = PathAnalysis(
        path_analysis_id="PATH-MICRO",
        graph_id="GRAPH-MICRO",
        choke_points=[],
        crown_jewel_reach=[
            CrownJewelReach(
                node_id="a-db:data_admin",
                asset_id="a-db",
                compromise_probability=probability,
                shortest_path_hops=1,
                top_path_node_ids=["internet:none", "a-db:data_admin"],
            )
        ],
        dead_end_node_fraction=0.0,
    )
    return graph, paths, snapshot


def test_no_pii_data_class_means_no_regulatory_penalty():
    """DPDP is a personal-data statute. An asset holding no personal data cannot
    attract a penalty under it, however badly it is compromised."""
    graph, paths, snapshot = _micro(data_classes=[DataClass.FINANCIAL], pii_records=0)
    result = simulate(graph, paths, snapshot, SimConfig(trials=25_000, seed=SEED))
    assert result.component_split_inr[LossComponent.REGULATORY] == 0.0
    assert result.component_split_inr[LossComponent.BREACH_RESPONSE] == 0.0
    assert result.eal_inr > 0.0


def test_pii_holdings_do_attract_a_regulatory_penalty():
    graph, paths, snapshot = _micro(data_classes=[DataClass.PII], pii_records=500_000)
    result = simulate(graph, paths, snapshot, SimConfig(trials=25_000, seed=SEED))
    assert result.component_split_inr[LossComponent.REGULATORY] > 0.0
    assert result.component_split_inr[LossComponent.BREACH_RESPONSE] > 0.0


def test_regulatory_penalty_never_exceeds_the_dpdp_ceiling_per_event():
    """250 crore, per instance. A trial that suffers two breaches can be fined
    twice, so the bound is per event, not per year."""
    config = SimConfig(trials=25_000, seed=SEED)
    graph, paths, snapshot = _micro(data_classes=[DataClass.PII], pii_records=2_000_000)
    params = _Params(org_annual_incident_rate=_base_incident_rate(snapshot))
    scenarios = _build_scenarios(graph, paths, snapshot)
    intrusions, draws = _draw(scenarios, params, config)
    cache: dict = {}
    sample = _evaluate(scenarios, intrusions, draws, snapshot, params, config, cache)

    # A jewel can be compromised at most once per intrusion, so the number of
    # intrusions in a trial bounds the number of fineable instances in it.
    trial_of_intrusion, _ = _intrusion_index(
        intrusions, params.org_annual_incident_rate, config.trials, cache
    )
    intrusions_per_trial = np.bincount(trial_of_intrusion, minlength=config.trials)

    regulatory = sample.components[LossComponent.REGULATORY]
    assert np.all(regulatory <= intrusions_per_trial * DPDP_SECURITY_CEILING_INR + 1e-6)
    assert regulatory.max() > 0.0


def test_an_asset_with_no_revenue_dependency_takes_no_downtime_loss():
    graph, paths, snapshot = _micro(
        data_classes=[DataClass.PII], pii_records=100_000, revenue_per_hour=0.0
    )
    result = simulate(graph, paths, snapshot, SimConfig(trials=25_000, seed=SEED))
    assert result.component_split_inr[LossComponent.DOWNTIME] == 0.0


def test_an_unreachable_crown_jewel_contributes_nothing():
    graph, paths, snapshot = _micro(
        data_classes=[DataClass.PII], pii_records=100_000, probability=0.0
    )
    result = simulate(graph, paths, snapshot, SimConfig(trials=1_000, seed=SEED))
    assert result.scenario_contributions == []
    assert result.eal_inr == 0.0
    assert result.top_drivers == []


def test_a_higher_compromise_probability_costs_more():
    """Monotonicity. The optimizer's whole premise is that cutting path
    probability cuts loss; if this fails, nothing downstream means anything."""
    config = SimConfig(trials=25_000, seed=SEED)
    losses = []
    for probability in (0.1, 0.3, 0.6):
        graph, paths, snapshot = _micro(
            data_classes=[DataClass.PII], pii_records=500_000, probability=probability
        )
        losses.append(simulate(graph, paths, snapshot, config).eal_inr)
    assert losses == sorted(losses)


# --------------------------------------------------------------------------- #
# the severity saturation
# --------------------------------------------------------------------------- #

def test_saturation_leaves_ordinary_losses_alone_and_bends_the_tail():
    cap = 1_000.0
    values = np.array([1.0, 100.0, 499.0, 500.0, 900.0, 5_000.0, 15_000.0])
    bent = _saturate(values, cap)
    # Below the knee, untouched.
    assert np.allclose(bent[:4], values[:4])
    # Above it, reduced, still increasing, and strictly under the cap -- so the
    # cap does not surface as a point mass at a reported quantile.
    assert np.all(bent[4:] < values[4:])
    assert np.all(np.diff(bent) > 0)
    assert np.all(bent < cap)
    # ~37 spans past the knee the correction drops below one ulp of the cap and
    # the sum rounds onto it. Bounded above by the cap either way; the docstring
    # says so rather than claiming a clean asymptote.
    assert _saturate(np.array([1e6]), cap)[0] == cap
    assert np.all(_saturate(np.array([1e3, 1e6, 1e12]), cap) <= cap)


def test_no_reported_quantile_lands_exactly_on_the_event_cap(result, snapshot):
    cap = snapshot.org.annual_revenue_inr
    for value in (result.median_inr, result.p95_inr, result.p99_inr):
        assert value != cap
