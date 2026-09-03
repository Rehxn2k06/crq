"""P1 tests for the synthetic enterprise generator.

Three kinds of test in here:

* contract tests -- the things FUNCTIONS.md and the schema demand, per asset,
  per finding, per tier;
* the reproducibility test, which is the whole reason this generator exists in
  the shape it does: P3's optimizer compares dozens of candidate control sets
  against a common set of random numbers, and that argument collapses if the
  Snapshot underneath it wobbles;
* the validation gate, which runs the generated Snapshot through P2's
  ``build_graph`` and ``analyze_paths`` and asserts the crown jewels come out
  compromisable but not certain. An org whose crown jewels sit at 0.0 or 1.0
  tells the loss model nothing, so this is a test of the *topology*, not of the
  graph code.
"""

from __future__ import annotations

import time

import pytest

from crq_core.graph import analyze_paths, build_graph
from crq_core.schemas import (
    AssetType,
    DataClass,
    OrgProfile,
    Privilege,
    Provenance,
    Snapshot,
)
from crq_ingest.synthetic import (
    CJ_PROBABILITY_BAND,
    CROWN_JEWEL_COUNT,
    MAX_INTERNET_FACING_FRACTION,
    generate_enterprise,
    indicative_cci_score,
)

ASSET_COUNT = 200
SEED = 20260331
#: The gate has to hold for the topology, not for one lucky draw.
GATE_SEEDS = (1, 7, 42, 1234, 20260331)


@pytest.fixture(scope="module")
def profile() -> OrgProfile:
    """A mid-size SEBI-regulated broking house. QRE, so the CCI minimum bites."""
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
    return generate_enterprise(profile, ASSET_COUNT, SEED)


# --------------------------------------------------------------------------- #
# the contract
# --------------------------------------------------------------------------- #

def test_provenance_is_synthetic_and_nothing_claims_a_scanner(snapshot: Snapshot) -> None:
    assert snapshot.provenance is Provenance.SYNTHETIC
    assert {f.source for f in snapshot.findings} == {"synthetic"}


def test_snapshot_validates_against_the_schema(snapshot: Snapshot) -> None:
    """Round-trips through JSON, so anything the API serialises is legal too."""
    assert Snapshot.model_validate_json(snapshot.model_dump_json()) == snapshot


def test_asset_count_is_exact(profile: OrgProfile, snapshot: Snapshot) -> None:
    assert len(snapshot.assets) == ASSET_COUNT
    assert len({a.asset_id for a in snapshot.assets}) == ASSET_COUNT
    assert len({a.hostname for a in snapshot.assets}) == ASSET_COUNT


def test_at_most_fifteen_percent_is_internet_facing(snapshot: Snapshot) -> None:
    internet_facing = [a for a in snapshot.assets if a.internet_facing]
    assert internet_facing, "an org with no internet-facing asset has no entry point"
    assert len(internet_facing) <= ASSET_COUNT * MAX_INTERNET_FACING_FRACTION
    # Everything exposed is in the DMZ, and nothing in the DMZ is hidden.
    assert all("dmz" in a.tags for a in internet_facing)
    assert all(a.internet_facing for a in snapshot.assets if "dmz" in a.tags)


def test_the_four_tiers_are_all_present(snapshot: Snapshot) -> None:
    by_tag = {
        tag: [a for a in snapshot.assets if tag in a.tags]
        for tag in ("dmz", "internal", "identity_tier", "data")
    }
    for tag, assets in by_tag.items():
        assert assets, f"no assets in the {tag} tier"

    # The identity tier has a domain controller, and exactly one asset carries
    # the 'identity' tag crq_core.graph fans R3b/R3c out over.
    identity = [a for a in snapshot.assets if "identity" in a.tags]
    assert len(identity) == 1
    domain_controller = identity[0]
    assert domain_controller.hostname.startswith("dc-")
    assert DataClass.CREDENTIALS in domain_controller.data_classes


def test_crown_jewels_hold_pii(snapshot: Snapshot) -> None:
    jewels = [a for a in snapshot.assets if "crown_jewel" in a.tags]
    assert len(jewels) == CROWN_JEWEL_COUNT
    assert 3 <= len(jewels) <= 5
    for jewel in jewels:
        assert DataClass.PII in jewel.data_classes
        assert jewel.pii_records_held > 0
        assert jewel.asset_type in (AssetType.DATABASE, AssetType.CLOUD_RESOURCE)
        assert "data" in jewel.tags
        assert not jewel.internet_facing, "a crown jewel on the internet is not a topology"


def test_every_reference_points_at_a_real_asset(snapshot: Snapshot) -> None:
    """Referential integrity, the same check contracts/validate_fixtures.py runs."""
    asset_ids = {a.asset_id for a in snapshot.assets}
    for dependency in snapshot.dependencies:
        assert dependency.from_asset_id in asset_ids
        assert dependency.to_asset_id in asset_ids
        assert dependency.from_asset_id != dependency.to_asset_id
    for identity in snapshot.identities:
        assert identity.home_asset_id in asset_ids
        assert set(identity.credential_reused_on) <= asset_ids
        assert identity.home_asset_id not in identity.credential_reused_on
    for finding in snapshot.findings:
        assert finding.asset_id in asset_ids
    for control in snapshot.existing_controls:
        assert set(control.applied_to_asset_ids) <= asset_ids


def test_credential_reuse_links_the_tiers(snapshot: Snapshot) -> None:
    """Without this the data tier is only reachable down a service dependency and
    the whole point of the graph disappears."""
    tier_of: dict[str, str] = {}
    for asset in snapshot.assets:
        for tag in ("dmz", "data", "identity_tier", "internal"):
            if tag in asset.tags:
                tier_of[asset.asset_id] = tag
                break

    bridges = {
        (tier_of[identity.home_asset_id], tier_of[target])
        for identity in snapshot.identities
        for target in identity.credential_reused_on
    }
    crossings = {pair for pair in bridges if pair[0] != pair[1]}
    assert crossings, "no credential crosses a tier boundary"
    assert ("dmz", "internal") in crossings, "nothing bridges the DMZ to the internal tier"
    assert ("internal", "data") in crossings, "no credential reaches the data tier"
    assert ("internal", "identity_tier") in crossings, "nothing reaches the identity tier"

    # And at least one of those bridges has no MFA on it, which is what makes it
    # cheap for an attacker and worth the optimizer's money to fix.
    assert any(
        not identity.mfa_enabled and identity.credential_reused_on
        for identity in snapshot.identities
    )


# --------------------------------------------------------------------------- #
# findings
# --------------------------------------------------------------------------- #

def test_finding_count_is_in_range(snapshot: Snapshot) -> None:
    assert 250 <= len(snapshot.findings) <= 400
    assert len({f.finding_id for f in snapshot.findings}) == len(snapshot.findings)


def test_finding_distribution_is_realistic(snapshot: Snapshot) -> None:
    findings = snapshot.findings
    kev = [f for f in findings if f.kev]
    scored = [f.epss for f in findings if f.epss is not None]

    # ~5% in KEV.
    assert 0.03 <= len(kev) / len(findings) <= 0.07

    # Most EPSS under 0.1.
    assert sum(1 for e in scored if e < 0.1) / len(scored) >= 0.70

    # A handful above 0.8 -- enough to have a headline, not so many that the
    # whole estate looks like it is on fire.
    high = [e for e in scored if e > 0.8]
    assert 4 <= len(high) <= 30

    # Some findings genuinely have no EPSS. build_graph has a CVSS fallback for
    # exactly this case and it needs to be exercised by the demo data.
    assert any(f.epss is None for f in findings)
    assert all(f.cvss_base is not None for f in findings)


def test_kev_findings_carry_real_cve_ids_and_filler_does_not(snapshot: Snapshot) -> None:
    """The demo says 'this one is in CISA KEV' out loud, so those have to be real
    advisories. Everything else is fabricated and its id says so, rather than
    squatting on a CVE number that means something different in the real NVD."""
    for finding in snapshot.findings:
        if finding.kev:
            assert finding.cve_id is not None and finding.cve_id.startswith("CVE-")
        elif finding.cve_id is not None:
            assert finding.cve_id.startswith("SYN-")


def test_findings_are_open_or_mitigated_in_a_believable_mix(snapshot: Snapshot) -> None:
    statuses = [f.status for f in snapshot.findings]
    open_findings = [f for f in snapshot.findings if f.status == "open"]
    assert set(statuses) == {"open", "mitigated"}
    assert 0.25 <= len(open_findings) / len(snapshot.findings) <= 0.55
    # The vulnerability counters are the same numbers, not a parallel invention.
    assert snapshot.telemetry.vulns_identified == len(snapshot.findings)
    assert snapshot.telemetry.vulns_mitigated == len(snapshot.findings) - len(open_findings)


# --------------------------------------------------------------------------- #
# reproducibility
# --------------------------------------------------------------------------- #

def test_the_same_seed_produces_an_identical_snapshot(profile: OrgProfile) -> None:
    """The load-bearing test. P3 compares control portfolios against a common set
    of random numbers; if the Snapshot moves between calls, every difference the
    optimizer measures is noise."""
    first = generate_enterprise(profile, ASSET_COUNT, SEED)
    second = generate_enterprise(profile, ASSET_COUNT, SEED)
    assert first == second
    assert first.model_dump_json() == second.model_dump_json()


def test_a_different_seed_produces_a_different_snapshot(profile: OrgProfile) -> None:
    a = generate_enterprise(profile, ASSET_COUNT, SEED)
    b = generate_enterprise(profile, ASSET_COUNT, SEED + 1)
    assert a.snapshot_id != b.snapshot_id
    assert a.model_dump_json() != b.model_dump_json()
    # The cast is a function of the size, only the numbers on it move.
    assert [x.asset_id for x in a.assets] == [x.asset_id for x in b.assets]


def test_generation_does_not_read_the_clock(profile: OrgProfile) -> None:
    first = generate_enterprise(profile, ASSET_COUNT, SEED)
    time.sleep(0.01)
    second = generate_enterprise(profile, ASSET_COUNT, SEED)
    assert first.created_at == second.created_at
    assert [f.first_seen for f in first.findings] == [f.first_seen for f in second.findings]


def test_it_scales_to_other_sizes(profile: OrgProfile) -> None:
    """Structure and the finding budget hold at any size. The probability band
    does not, and is not asserted here -- the tunables are calibrated for a
    200-asset estate and the crown-jewel probabilities climb as the estate grows
    (see the note above the tunables in synthetic.py)."""
    for asset_count in (80, 120, 500):
        snapshot = generate_enterprise(profile, asset_count, SEED)
        assert len(snapshot.assets) == asset_count
        internet_facing = sum(1 for a in snapshot.assets if a.internet_facing)
        assert internet_facing <= asset_count * MAX_INTERNET_FACING_FRACTION
        assert len([a for a in snapshot.assets if "crown_jewel" in a.tags]) == CROWN_JEWEL_COUNT
        assert 250 <= len(snapshot.findings) <= 400


def test_an_org_too_small_for_four_tiers_is_refused(profile: OrgProfile) -> None:
    with pytest.raises(ValueError):
        generate_enterprise(profile, 20, SEED)


# --------------------------------------------------------------------------- #
# telemetry / CCI
# --------------------------------------------------------------------------- #

def test_telemetry_lands_the_cci_in_the_developing_band(snapshot: Snapshot) -> None:
    """compute_cci is not written yet, so this scores the proxy in synthetic.py:
    the unweighted mean of the Annexure-K ratios TelemetryMetrics can form. It is
    close enough to say which band the real weighted score lands in. Point this at
    crq_compliance.compute_cci the day it exists."""
    assert 55.0 <= indicative_cci_score(snapshot.telemetry) <= 70.0


def test_telemetry_counters_are_internally_consistent(snapshot: Snapshot) -> None:
    t = snapshot.telemetry
    assert t.total_it_systems == len(snapshot.assets)
    assert t.staff_total == snapshot.org.employee_count
    assert t.vulns_mitigated <= t.vulns_identified
    assert t.remote_users_with_mfa <= t.remote_users_total
    assert t.systems_integrated_with_soc <= t.critical_systems_identified
    assert t.incidents_closed_in_sla <= t.incidents_total
    assert t.backups_tested_count <= t.backups_total_count
    assert t.assets_with_current_patch <= t.total_it_systems
    assert 0 < t.infosec_budget_inr < t.it_budget_inr


# --------------------------------------------------------------------------- #
# the validation gate
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("seed", GATE_SEEDS)
def test_crown_jewel_probabilities_are_in_band(profile: OrgProfile, seed: int) -> None:
    """THE gate. Run the generated org through P2 and check the crown jewels come
    out compromisable but not certain.

    Near 0 means nothing links the tiers and the loss model has no scenario to
    price. Near 1 means every control looks worthless because the attacker wins
    regardless, and the optimizer's marginal deltas all collapse to zero. Either
    way the topology is wrong, not the graph -- so this test lives here.
    """
    snapshot = generate_enterprise(profile, ASSET_COUNT, seed)
    graph = build_graph(snapshot)
    paths = analyze_paths(graph, snapshot)

    low, high = CJ_PROBABILITY_BAND
    assert len(paths.crown_jewel_reach) == CROWN_JEWEL_COUNT
    for reach in paths.crown_jewel_reach:
        assert low <= reach.compromise_probability <= high, (
            f"seed={seed} {reach.node_id} compromise_probability="
            f"{reach.compromise_probability} outside {CJ_PROBABILITY_BAND}"
        )
        assert reach.shortest_path_hops is not None
        assert reach.top_path_node_ids[0] in graph.entry_node_ids
        assert reach.top_path_node_ids[-1] == reach.node_id


def test_the_graph_over_the_generated_org_is_worth_analysing(
    profile: OrgProfile, snapshot: Snapshot
) -> None:
    """Shape checks on the graph, so a topology change that guts it fails loudly
    even if the probabilities happen to stay in band."""
    graph = build_graph(snapshot)
    paths = analyze_paths(graph, snapshot)

    assert graph.entry_node_ids, "no way in"
    assert len(graph.crown_jewel_node_ids) == CROWN_JEWEL_COUNT
    assert all(n.privilege is Privilege.DATA_ADMIN
               for n in graph.nodes if n.is_crown_jewel), \
        "the objective on a data store is the data, not the host"
    assert len(graph.edges) > len(graph.nodes), "a graph with no branching is a list"
    assert all(edge.rationale for edge in graph.edges)

    # Something has to be a choke point, or there is nothing to recommend buying.
    assert paths.choke_points
    assert paths.choke_points[0].paths_through_fraction > 0.25
    # And some of the estate has to be irrelevant, or the '74% dead end' claim
    # in the README is not something this data can support.
    assert 0.1 < paths.dead_end_node_fraction < 0.95


def test_the_whole_pipeline_stays_fast(profile: OrgProfile) -> None:
    """The API generates, builds and analyses inside one request. Two seconds is
    the budget P3 works to for simulate(); ingest plus graph has to be far under."""
    start = time.perf_counter()
    snapshot = generate_enterprise(profile, ASSET_COUNT, SEED)
    analyze_paths(build_graph(snapshot), snapshot)
    assert time.perf_counter() - start < 2.0
