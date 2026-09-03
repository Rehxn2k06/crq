"""P2 tests. Developed against contracts/fixtures/snapshot.json.

Two kinds of test in here:

* fixture tests, which pin the demo story -- Jenkins is the choke point, all
  three crown jewels are reachable, every edge can be explained to a human;
* rule tests on hand-built micro-snapshots, one rule at a time, so a failure
  points at the rule that broke rather than at the whole graph.

Nothing here writes to contracts/. The fixtures are read-only inputs.
"""

from __future__ import annotations

import json
import random
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

from crq_core.graph import (
    KEV_PROBABILITY_FLOOR,
    MAX_PATH_HOPS,
    analyze_paths,
    apply_controls,
    build_graph,
)
from crq_core.schemas import (
    AppliedControl,
    Asset,
    AssetType,
    AttackGraph,
    ControlCatalogEntry,
    DataClass,
    Dependency,
    Finding,
    Identity,
    OrgProfile,
    Privilege,
    Provenance,
    Snapshot,
)

FIXTURES = Path(__file__).resolve().parents[3] / "contracts" / "fixtures"


# --------------------------------------------------------------------------- #
# fixtures
# --------------------------------------------------------------------------- #

@pytest.fixture(scope="module")
def snapshot() -> Snapshot:
    return Snapshot.model_validate_json((FIXTURES / "snapshot.json").read_text())


@pytest.fixture(scope="module")
def reference_graph() -> dict:
    """The hand-drawn contract fixture. We compare shape against it, not equality:
    it was drawn by hand to show the team what a graph looks like."""
    return json.loads((FIXTURES / "graph.json").read_text())


@pytest.fixture(scope="module")
def graph(snapshot: Snapshot):
    return build_graph(snapshot)


@pytest.fixture(scope="module")
def paths(graph, snapshot: Snapshot):
    return analyze_paths(graph, snapshot)


def _org() -> OrgProfile:
    return OrgProfile(
        name="Test Co",
        sector="finance",
        annual_revenue_inr=1_000_000_000.0,
        employee_count=100,
        pii_records_count=1000,
    )


def _asset(asset_id: str, **kwargs) -> Asset:
    defaults = dict(
        hostname=asset_id,
        asset_type=AssetType.SERVER,
        business_unit="it",
        internet_facing=False,
        criticality_weight=0.5,
    )
    defaults.update(kwargs)
    return Asset(asset_id=asset_id, **defaults)


def _finding(finding_id: str, asset_id: str, **kwargs) -> Finding:
    defaults = dict(source="synthetic", grants_privilege=Privilege.USER)
    defaults.update(kwargs)
    return Finding(finding_id=finding_id, asset_id=asset_id, **defaults)


def _snapshot(assets, **kwargs) -> Snapshot:
    return Snapshot(
        snapshot_id="SNAP-TEST-001",
        created_at=datetime(2026, 9, 1, tzinfo=timezone.utc),
        provenance=Provenance.SYNTHETIC,
        org=_org(),
        assets=assets,
        **kwargs,
    )


def _edge(graph, source: str, target: str):
    for edge in graph.edges:
        if edge.source_node_id == source and edge.target_node_id == target:
            return edge
    return None


# --------------------------------------------------------------------------- #
# build_graph: structure
# --------------------------------------------------------------------------- #

def test_graph_ids_trace_back_to_the_snapshot(graph, snapshot):
    assert graph.snapshot_id == snapshot.snapshot_id
    assert graph.graph_id == "GRAPH-DEMO-001"
    assert graph.rules_version == "v1"


def test_entry_node_is_the_internet(graph):
    assert graph.entry_node_ids == ["internet:none"]
    entries = [n for n in graph.nodes if n.is_entry]
    assert [n.node_id for n in entries] == ["internet:none"]


def test_node_ids_follow_the_asset_privilege_convention(graph, snapshot):
    known = {a.asset_id for a in snapshot.assets} | {"internet"}
    for node in graph.nodes:
        assert node.node_id == f"{node.asset_id}:{node.privilege.value}"
        assert node.asset_id in known


def test_covers_every_node_in_the_contract_fixture(graph, reference_graph):
    """Same node set as contracts/fixtures/graph.json. The derived graph may add
    states the hand-drawn fixture left out, but it must not miss any."""
    expected = {n["node_id"] for n in reference_graph["nodes"]}
    actual = {n.node_id for n in graph.nodes}
    assert expected <= actual, f"missing states: {sorted(expected - actual)}"


def test_extra_states_are_justified(graph, reference_graph):
    """Guards against the graph quietly exploding. The fixture has 10 states;
    anything we add on top of that should be a handful, not a tier."""
    expected = {n["node_id"] for n in reference_graph["nodes"]}
    actual = {n.node_id for n in graph.nodes}
    assert len(actual - expected) <= 3, f"unexpected states: {sorted(actual - expected)}"


def test_crown_jewels_are_the_tagged_assets(graph, snapshot):
    tagged = {a.asset_id for a in snapshot.assets if "crown_jewel" in a.tags}
    assert {n.rsplit(":", 1)[0] for n in graph.crown_jewel_node_ids} == tagged
    assert len(graph.crown_jewel_node_ids) == 3
    for node_id in graph.crown_jewel_node_ids:
        node = next(n for n in graph.nodes if n.node_id == node_id)
        assert node.is_crown_jewel


def test_crown_jewel_states_match_the_contract_fixture(graph, reference_graph):
    assert set(graph.crown_jewel_node_ids) == set(reference_graph["crown_jewel_node_ids"])


def test_edges_are_referentially_sound(graph, snapshot):
    node_ids = {n.node_id for n in graph.nodes}
    finding_ids = {f.finding_id for f in snapshot.findings}
    edge_ids = [e.edge_id for e in graph.edges]
    assert len(edge_ids) == len(set(edge_ids)), "duplicate edge ids"
    for edge in graph.edges:
        assert edge.source_node_id in node_ids
        assert edge.target_node_id in node_ids
        assert edge.source_node_id != edge.target_node_id
        assert 0.0 <= edge.probability <= 1.0
        assert edge.enabler_finding_id is None or edge.enabler_finding_id in finding_ids


def test_every_edge_carries_a_plain_english_rationale(graph, snapshot):
    """Non-negotiable #2 in the README: the trace panel renders this."""
    hostnames = {a.hostname for a in snapshot.assets}
    for edge in graph.edges:
        rationale = edge.rationale.strip()
        assert rationale, f"{edge.edge_id} has no rationale"
        assert len(rationale.split()) >= 8, f"{edge.edge_id} rationale is too thin: {rationale}"
        # Hostnames are lowercase and often open the sentence, so only the
        # full stop is enforced; the trace panel renders these verbatim.
        assert rationale.endswith("."), f"{edge.edge_id} rationale is not a sentence"
        assert any(h in rationale for h in hostnames), (
            f"{edge.edge_id} rationale names no host: {rationale}"
        )


def test_rationale_names_the_enabling_cve_when_there_is_one(graph, snapshot):
    findings = {f.finding_id: f for f in snapshot.findings}
    for edge in graph.edges:
        if edge.enabler_finding_id is None:
            continue
        cve = findings[edge.enabler_finding_id].cve_id
        if cve:
            assert cve in edge.rationale, f"{edge.edge_id} does not name {cve}"


def test_no_state_for_an_asset_nothing_can_touch(graph):
    """file-01 has no findings, no credentials and no dependencies. It should not
    appear in the graph at all."""
    assert not [n for n in graph.nodes if n.asset_id == "a-file-01"]


# --------------------------------------------------------------------------- #
# build_graph: the rules
# --------------------------------------------------------------------------- #

def test_r1_remote_exploit_from_the_internet(graph):
    edge = _edge(graph, "internet:none", "a-web-01:user")
    assert edge is not None
    assert edge.technique_id == "T1190"
    assert edge.enabler_finding_id == "f-001"
    assert edge.probability == pytest.approx(0.94)


def test_r1_does_not_fire_on_an_internal_asset():
    """app-01 has an unauthenticated finding but is not internet-facing."""
    snapshot = _snapshot(
        [_asset("a-internal", internet_facing=False)],
        findings=[_finding("f-1", "a-internal", epss=0.5)],
    )
    graph = build_graph(snapshot)
    assert graph.edges == []
    assert [n.node_id for n in graph.nodes] == ["internet:none"]


def test_r1_needs_an_open_finding():
    snapshot = _snapshot(
        [_asset("a-dmz", internet_facing=True)],
        findings=[_finding("f-1", "a-dmz", epss=0.5, status="mitigated")],
    )
    assert build_graph(snapshot).edges == []


def test_r2_privesc_is_folded_into_the_arriving_edge(graph):
    """f-004 needs user on dc-01 and grants admin. The attacker arrives from
    jenkins with a domain account and escalates in the same move, so the edge
    lands on admin and names the privesc CVE."""
    edge = _edge(graph, "a-jenkins-01:admin", "a-ad-01:admin")
    assert edge is not None
    assert edge.enabler_finding_id == "f-004"
    assert "CVE-2021-42287" in edge.rationale
    assert "escalates" in edge.rationale
    # arrival (0.7) * privesc (KEV floor 0.6)
    assert edge.probability == pytest.approx(0.42)
    assert not [n for n in graph.nodes if n.node_id == "a-ad-01:user"]


def test_r2_does_not_escalate_past_what_the_finding_grants():
    snapshot = _snapshot(
        [_asset("a-dmz", internet_facing=True)],
        findings=[
            _finding("f-1", "a-dmz", epss=0.5, grants_privilege=Privilege.USER),
            _finding(
                "f-2",
                "a-dmz",
                epss=0.4,
                requires_privilege=Privilege.ADMIN,
                grants_privilege=Privilege.ADMIN,
            ),
        ],
    )
    graph = build_graph(snapshot)
    assert {n.node_id for n in graph.nodes} == {"internet:none", "a-dmz:user"}


def test_r3_credential_reuse(graph):
    """i-svc-deploy is admin on jenkins and reused on app-01, without MFA."""
    edge = _edge(graph, "a-jenkins-01:admin", "a-app-01:user")
    assert edge is not None
    assert edge.technique_id == "T1078"
    assert edge.enabler_finding_id is None
    assert edge.probability == pytest.approx(0.75)
    assert "i-svc-deploy" in edge.rationale


def test_r3_mfa_reduces_the_reuse_probability():
    identity = Identity(
        identity_id="i-1",
        home_asset_id="a-dmz",
        privilege=Privilege.USER,
        mfa_enabled=True,
        credential_reused_on=["a-inner"],
    )
    plain = identity.model_copy(update={"mfa_enabled": False})
    assets = [_asset("a-dmz", internet_facing=True), _asset("a-inner")]
    findings = [_finding("f-1", "a-dmz", epss=0.5)]

    with_mfa = build_graph(_snapshot(assets, identities=[identity], findings=findings))
    without = build_graph(_snapshot(assets, identities=[plain], findings=findings))

    mfa_edge = _edge(with_mfa, "a-dmz:user", "a-inner:user")
    plain_edge = _edge(without, "a-dmz:user", "a-inner:user")
    assert mfa_edge.probability < plain_edge.probability
    assert "MFA" in mfa_edge.rationale


def test_r3_domain_admin_reaches_the_finance_database(graph):
    """db-finance has no findings of its own. The only way in is the DBA
    credential, replayed by whoever owns the domain controller."""
    edge = _edge(graph, "a-ad-01:admin", "a-db-fin:data_admin")
    assert edge is not None
    assert edge.technique_id == "T1078"
    assert "i-dba" in edge.rationale


def test_r4_pivot_uses_a_declared_dependency(graph):
    """vpn-01 -> ws-02 is a network dependency and ws-02 has an unauthenticated
    finding, so VPN admin becomes a workstation foothold."""
    edge = _edge(graph, "a-vpn-01:admin", "a-ws-02:user")
    assert edge is not None
    assert edge.technique_id == "T1021"
    assert edge.enabler_finding_id == "f-007"


def test_r4_does_not_pivot_without_a_dependency():
    """Two internal assets with findings and no relationship stay unconnected."""
    snapshot = _snapshot(
        [_asset("a-dmz", internet_facing=True), _asset("a-lonely")],
        findings=[_finding("f-1", "a-dmz", epss=0.5), _finding("f-2", "a-lonely", epss=0.5)],
    )
    graph = build_graph(snapshot)
    assert _edge(graph, "a-dmz:user", "a-lonely:user") is None


def test_r4_replays_the_service_credential_a_dependency_implies():
    """app -> db over a data dependency: the app holds a DB credential, so a
    foothold on the app reaches the data even though the DB has no CVE."""
    snapshot = _snapshot(
        [
            _asset("a-app", internet_facing=True),
            _asset("a-db", asset_type=AssetType.DATABASE, data_classes=[DataClass.PII]),
        ],
        dependencies=[Dependency(from_asset_id="a-app", to_asset_id="a-db", kind="data")],
        findings=[_finding("f-1", "a-app", epss=0.5)],
    )
    graph = build_graph(snapshot)
    edge = _edge(graph, "a-app:user", "a-db:data_read")
    assert edge is not None
    assert edge.enabler_finding_id is None
    assert "credential" in edge.rationale


def test_r5_data_access_from_host_admin():
    """Admin on the database host is admin over the data it stores."""
    snapshot = _snapshot(
        [
            _asset("a-dmz", internet_facing=True),
            _asset("a-db", asset_type=AssetType.DATABASE, data_classes=[DataClass.PII]),
        ],
        dependencies=[Dependency(from_asset_id="a-dmz", to_asset_id="a-db", kind="network")],
        findings=[
            _finding("f-1", "a-dmz", epss=0.5),
            _finding("f-2", "a-db", epss=0.5, grants_privilege=Privilege.ADMIN),
        ],
    )
    graph = build_graph(snapshot)
    edge = _edge(graph, "a-db:admin", "a-db:data_admin")
    assert edge is not None
    assert edge.technique_id == "T1530"


# --------------------------------------------------------------------------- #
# build_graph: the probability formula
# --------------------------------------------------------------------------- #

def test_probability_uses_epss_when_present(graph):
    assert _edge(graph, "internet:none", "a-vpn-01:admin").probability == pytest.approx(0.87)


def test_kev_floors_the_probability(graph):
    """f-003 has EPSS 0.42 but is in KEV, so it is floored at 0.6."""
    edge = _edge(graph, "a-app-01:user", "a-jenkins-01:admin")
    assert edge.enabler_finding_id == "f-003"
    assert edge.probability == pytest.approx(KEV_PROBABILITY_FLOOR)


def test_cvss_fallback_when_there_is_no_epss():
    """base = cvss_base/10 * 0.1."""
    snapshot = _snapshot(
        [_asset("a-dmz", internet_facing=True)],
        findings=[_finding("f-1", "a-dmz", cvss_base=7.5, epss=None)],
    )
    graph = build_graph(snapshot)
    assert _edge(graph, "internet:none", "a-dmz:user").probability == pytest.approx(0.075)


def test_an_existing_control_reduces_the_probability_and_is_named(graph):
    """ctl-edr covers ws-fin-01 and ws-eng-01. f-007 has EPSS 0.12, EDR is 40%
    effective, so the edge into ws-eng-01 is 0.12 * 0.6."""
    edge = _edge(graph, "a-vpn-01:admin", "a-ws-02:user")
    assert edge.blocked_by_control_ids == ["ctl-edr"]
    assert edge.probability == pytest.approx(0.072)
    assert "ctl-edr" in edge.rationale


def test_unprotected_assets_carry_no_blocking_controls(graph):
    for edge in graph.edges:
        if edge.blocked_by_control_ids:
            assert {edge.source_node_id.rsplit(":", 1)[0], edge.target_node_id.rsplit(":", 1)[0]} & {
                "a-ws-01",
                "a-ws-02",
            }


def test_a_finding_predicate_control_matches_on_kev():
    snapshot = _snapshot(
        [_asset("a-dmz", internet_facing=True)],
        findings=[_finding("f-1", "a-dmz", epss=0.9, kev=True)],
        existing_controls=[
            AppliedControl(control_id="ctl-patch-kev", applied_to_asset_ids=["a-dmz"])
        ],
    )
    graph = build_graph(snapshot)
    edge = _edge(graph, "internet:none", "a-dmz:user")
    assert edge.blocked_by_control_ids == ["ctl-patch-kev"]
    assert edge.probability == pytest.approx(0.9 * 0.15)


def test_an_unknown_control_id_is_ignored_not_guessed_at():
    snapshot = _snapshot(
        [_asset("a-dmz", internet_facing=True)],
        findings=[_finding("f-1", "a-dmz", epss=0.5)],
        existing_controls=[
            AppliedControl(control_id="ctl-who-knows", applied_to_asset_ids=["a-dmz"])
        ],
    )
    edge = _edge(build_graph(snapshot), "internet:none", "a-dmz:user")
    assert edge.probability == pytest.approx(0.5)
    assert edge.blocked_by_control_ids == []


# --------------------------------------------------------------------------- #
# build_graph: purity and determinism
# --------------------------------------------------------------------------- #

def test_build_graph_is_deterministic(snapshot):
    assert build_graph(snapshot).model_dump() == build_graph(snapshot).model_dump()


def test_build_graph_does_not_mutate_the_snapshot(snapshot):
    before = snapshot.model_dump_json()
    build_graph(snapshot)
    assert snapshot.model_dump_json() == before


def test_build_graph_rejects_an_unknown_rules_version(snapshot):
    with pytest.raises(ValueError):
        build_graph(snapshot, rules_version="v99")


def test_empty_snapshot_yields_just_the_entry_node():
    graph = build_graph(_snapshot([]))
    assert [n.node_id for n in graph.nodes] == ["internet:none"]
    assert graph.edges == []
    assert graph.crown_jewel_node_ids == []


# --------------------------------------------------------------------------- #
# analyze_paths
# --------------------------------------------------------------------------- #

def test_path_analysis_links_back_to_the_graph(paths, graph):
    assert paths.graph_id == graph.graph_id
    assert paths.path_analysis_id == "PATH-DEMO-001"


def test_jenkins_is_the_top_choke_point(paths):
    """The demo's whole point: the CI/CD box is what to spend money on."""
    top = paths.choke_points[0]
    assert top.node_id == "a-jenkins-01:admin"
    assert top.asset_id == "a-jenkins-01"
    assert 0.55 <= top.paths_through_fraction <= 0.95


def test_choke_points_are_ranked_and_exclude_the_obvious(paths, graph):
    fractions = [c.paths_through_fraction for c in paths.choke_points]
    assert fractions == sorted(fractions, reverse=True)
    ids = {c.node_id for c in paths.choke_points}
    assert not ids & set(graph.entry_node_ids), "an entry node is on every path by construction"
    assert not ids & set(graph.crown_jewel_node_ids), "a crown jewel is not its own choke point"
    for choke in paths.choke_points:
        assert 0.0 < choke.paths_through_fraction <= 1.0
        assert choke.reachable_cj_value_inr > 0.0


def test_cutting_jenkins_cuts_the_finance_database(paths):
    """db-finance is only reachable through the domain controller, and the domain
    controller is only reachable through Jenkins."""
    jenkins = next(c for c in paths.choke_points if c.node_id == "a-jenkins-01:admin")
    assert "a-db-fin:data_admin" in jenkins.crown_jewels_cut_if_removed


def test_every_crown_jewel_gets_a_reach_entry(paths, graph):
    assert [r.node_id for r in paths.crown_jewel_reach] == graph.crown_jewel_node_ids
    assert len(paths.crown_jewel_reach) == 3
    for reach in paths.crown_jewel_reach:
        assert reach.node_id.startswith(reach.asset_id + ":")
        assert 0.0 < reach.compromise_probability <= 1.0
        assert reach.shortest_path_hops is not None


def test_top_paths_start_at_an_entry_and_end_at_the_jewel(paths, graph):
    edges = {(e.source_node_id, e.target_node_id) for e in graph.edges}
    for reach in paths.crown_jewel_reach:
        path = reach.top_path_node_ids
        assert path[0] in graph.entry_node_ids
        assert path[-1] == reach.node_id
        assert len(path) - 1 <= MAX_PATH_HOPS
        assert len(set(path)) == len(path), "a top path must not revisit a state"
        for hop in zip(path, path[1:]):
            assert hop in edges


def test_shortest_hops_never_exceeds_the_depth_cap(paths):
    for reach in paths.crown_jewel_reach:
        assert 1 <= reach.shortest_path_hops <= MAX_PATH_HOPS


def test_the_customer_database_is_the_most_likely_jewel_to_fall(paths):
    reach = {r.node_id: r.compromise_probability for r in paths.crown_jewel_reach}
    assert reach["a-db-cust:data_admin"] == max(reach.values())


def test_dead_end_fraction_is_a_fraction(paths):
    assert 0.0 <= paths.dead_end_node_fraction <= 1.0


def test_analyze_paths_is_deterministic(graph, snapshot):
    assert analyze_paths(graph, snapshot).model_dump() == analyze_paths(graph, snapshot).model_dump()


def test_analyze_paths_does_not_mutate_its_inputs(graph, snapshot):
    graph_before, snapshot_before = graph.model_dump_json(), snapshot.model_dump_json()
    analyze_paths(graph, snapshot)
    assert graph.model_dump_json() == graph_before
    assert snapshot.model_dump_json() == snapshot_before


def test_paths_beyond_the_depth_cap_are_not_counted():
    """A chain of nine hops to the jewel. Nothing reaches it inside six, so the
    jewel is reported as unreachable rather than quietly included."""
    assets = [_asset("a-0", internet_facing=True)]
    findings = [_finding("f-0", "a-0", epss=0.9)]
    dependencies = []
    for i in range(1, 10):
        assets.append(_asset(f"a-{i}", tags=["crown_jewel"] if i == 9 else []))
        findings.append(_finding(f"f-{i}", f"a-{i}", epss=0.9))
        dependencies.append(
            Dependency(from_asset_id=f"a-{i - 1}", to_asset_id=f"a-{i}", kind="network")
        )
    graph = build_graph(_snapshot(assets, dependencies=dependencies, findings=findings))
    result = analyze_paths(graph, _snapshot(assets, dependencies=dependencies, findings=findings))

    reach = result.crown_jewel_reach[0]
    assert reach.node_id == "a-9:user"
    assert reach.compromise_probability == 0.0
    assert reach.shortest_path_hops is None
    assert reach.top_path_node_ids == []
    assert result.choke_points == []
    assert result.dead_end_node_fraction == 1.0


def test_an_unreachable_crown_jewel_still_gets_a_state_and_an_entry():
    snapshot = _snapshot(
        [
            _asset("a-dmz", internet_facing=True),
            _asset("a-vault", asset_type=AssetType.DATABASE, tags=["crown_jewel"]),
        ],
        findings=[_finding("f-1", "a-dmz", epss=0.5)],
    )
    graph = build_graph(snapshot)
    assert "a-vault:data_admin" in {n.node_id for n in graph.nodes}

    result = analyze_paths(graph, snapshot)
    reach = result.crown_jewel_reach[0]
    assert reach.node_id == "a-vault:data_admin"
    assert reach.compromise_probability == 0.0
    assert reach.shortest_path_hops is None


def test_hitting_the_enumeration_cap_is_announced(graph, snapshot, monkeypatch):
    """A graph too dense to enumerate is analysed on a partial path set. That
    biases every share in the result, so it must not pass silently -- PathAnalysis
    is frozen and has nowhere to record it, which leaves a warning."""
    import crq_core.graph as graph_module

    monkeypatch.setattr(graph_module, "MAX_PATHS_ENUMERATED", 2)
    with pytest.warns(RuntimeWarning, match="path cap"):
        result = analyze_paths(graph, snapshot)
    assert result.choke_points, "a truncated analysis still returns what it found"


def test_analyze_paths_handles_a_graph_with_no_crown_jewels():
    snapshot = _snapshot(
        [_asset("a-dmz", internet_facing=True)],
        findings=[_finding("f-1", "a-dmz", epss=0.5)],
    )
    result = analyze_paths(build_graph(snapshot), snapshot)
    assert result.choke_points == []
    assert result.crown_jewel_reach == []
    assert result.dead_end_node_fraction == 1.0


# --------------------------------------------------------------------------- #
# apply_controls
# --------------------------------------------------------------------------- #

@pytest.fixture(scope="module")
def catalog() -> list[ControlCatalogEntry]:
    raw = json.loads((FIXTURES / "control_catalog.json").read_text())
    return [ControlCatalogEntry.model_validate(entry) for entry in raw]


@pytest.fixture(scope="module")
def large_graph():
    """A 200-asset org, big enough that a slow apply_controls would show. Built
    from a fixed seed so the benchmark measures the code, not the dice."""
    rng = random.Random(7)
    types = list(AssetType)
    assets = [
        Asset(
            asset_id=f"a{i}",
            hostname=f"h{i}",
            asset_type=types[i % len(types)],
            business_unit="it",
            internet_facing=i < 25,
            revenue_dependency_inr_per_hour=1000.0 * i,
            data_classes=[DataClass.PII] if i % 17 == 0 else [],
            pii_records_held=1000 if i % 17 == 0 else 0,
            criticality_weight=0.5,
            tags=["crown_jewel"] if i % 40 == 0 else [],
        )
        for i in range(200)
    ]
    dependencies = [
        Dependency(
            from_asset_id=f"a{rng.randrange(200)}",
            to_asset_id=f"a{rng.randrange(200)}",
            kind=["network", "data", "service", "trust"][rng.randrange(4)],
        )
        for _ in range(400)
    ]
    findings = [
        Finding(
            finding_id=f"f{i}",
            asset_id=f"a{rng.randrange(200)}",
            cvss_base=8.0,
            epss=rng.random(),
            kev=i % 9 == 0,
            grants_privilege=Privilege.ADMIN if i % 2 else Privilege.USER,
            source="synthetic",
        )
        for i in range(300)
    ]
    identities = [
        Identity(
            identity_id=f"i{i}",
            home_asset_id=f"a{rng.randrange(200)}",
            privilege=Privilege.ADMIN if i % 2 else Privilege.USER,
            credential_reused_on=[f"a{rng.randrange(200)}" for _ in range(3)],
        )
        for i in range(40)
    ]
    snapshot = Snapshot(
        snapshot_id="SNAP-BENCH-001",
        created_at=datetime(2026, 9, 1, tzinfo=timezone.utc),
        provenance=Provenance.SYNTHETIC,
        org=_org(),
        assets=assets,
        dependencies=dependencies,
        identities=identities,
        findings=findings,
    )
    return build_graph(snapshot)


def _catalog_entry(catalog: list[ControlCatalogEntry], control_id: str) -> ControlCatalogEntry:
    return next(c for c in catalog if c.control_id == control_id)


def test_apply_controls_does_not_mutate_the_input_graph(graph, catalog):
    """Pure, and the optimizer bets everything on it: it re-applies candidate
    control sets to this same baseline thousands of times."""
    before = graph.model_dump_json()
    result = apply_controls(
        graph,
        catalog,
        [
            AppliedControl(control_id="ctl-waf", applied_to_asset_ids=["a-web-01", "a-web-02"]),
            AppliedControl(control_id="ctl-pam", applied_to_asset_ids=["a-jenkins-01"]),
            AppliedControl(control_id="ctl-segment-ci", applied_to_asset_ids=["a-jenkins-01"]),
        ],
    )
    assert graph.model_dump_json() == before, "apply_controls mutated the graph it was given"
    assert result is not graph
    assert result.model_dump_json() != before, "nothing was actually applied"


def test_apply_controls_returns_the_same_shape(graph, catalog):
    result = apply_controls(
        graph, catalog, [AppliedControl(control_id="ctl-waf", applied_to_asset_ids=["a-web-01"])]
    )
    assert isinstance(result, AttackGraph)
    assert [n.node_id for n in result.nodes] == [n.node_id for n in graph.nodes]
    assert [e.edge_id for e in result.edges] == [e.edge_id for e in graph.edges]
    assert result.graph_id == graph.graph_id
    assert result.snapshot_id == graph.snapshot_id
    assert result.crown_jewel_node_ids == graph.crown_jewel_node_ids
    assert result.entry_node_ids == graph.entry_node_ids
    # New spine: mutating a list on the copy must not reach the original.
    assert result.nodes is not graph.nodes
    assert result.edges is not graph.edges
    assert result.crown_jewel_node_ids is not graph.crown_jewel_node_ids


def test_a_control_reduces_the_probability_of_what_it_blocks(graph, catalog):
    """ctl-waf blocks T1190 at 55%. The internet -> web-01 exploit is 0.94."""
    result = apply_controls(
        graph, catalog, [AppliedControl(control_id="ctl-waf", applied_to_asset_ids=["a-web-01"])]
    )
    edge = _edge(result, "internet:none", "a-web-01:user")
    assert edge.probability == pytest.approx(0.94 * 0.45)
    assert "ctl-waf" in edge.blocked_by_control_ids


def test_a_control_leaves_other_techniques_alone(graph, catalog):
    """ctl-waf is a web firewall. It does nothing about credential reuse."""
    result = apply_controls(
        graph,
        catalog,
        [AppliedControl(control_id="ctl-waf", applied_to_asset_ids=["a-web-01", "a-jenkins-01"])],
    )
    for source, target in (
        ("a-jenkins-01:admin", "a-app-01:user"),
        ("a-ad-01:admin", "a-db-fin:data_admin"),
    ):
        assert _edge(result, source, target).probability == pytest.approx(
            _edge(graph, source, target).probability
        )


def test_a_control_applies_at_either_end_of_the_action(graph, catalog):
    """ctl-pam blocks T1078. Applied to jenkins it covers the credential reuse
    that leaves jenkins, not only what arrives there."""
    result = apply_controls(
        graph,
        catalog,
        [AppliedControl(control_id="ctl-pam", applied_to_asset_ids=["a-jenkins-01"])],
    )
    edge = _edge(result, "a-jenkins-01:admin", "a-app-01:user")
    assert edge.probability == pytest.approx(0.75 * 0.25)
    assert "ctl-pam" in edge.blocked_by_control_ids


def test_a_control_that_touches_neither_end_does_nothing(graph, catalog):
    result = apply_controls(
        graph, catalog, [AppliedControl(control_id="ctl-pam", applied_to_asset_ids=["a-file-01"])]
    )
    assert result.model_dump() == graph.model_dump()


def test_controls_stack_multiplicatively(graph, catalog):
    """ctl-segment-ci (70% on T1210) plus a second blocker on the same edge:
    0.6 * 0.3 * 0.5."""
    extra = _catalog_entry(catalog, "ctl-segment-ci").model_copy(
        update={"control_id": "ctl-second", "effectiveness": 0.5}
    )
    result = apply_controls(
        graph,
        [*catalog, extra],
        [
            AppliedControl(control_id="ctl-segment-ci", applied_to_asset_ids=["a-jenkins-01"]),
            AppliedControl(control_id="ctl-second", applied_to_asset_ids=["a-jenkins-01"]),
        ],
    )
    edge = _edge(result, "a-app-01:user", "a-jenkins-01:admin")
    assert edge.probability == pytest.approx(0.6 * 0.3 * 0.5)
    assert edge.blocked_by_control_ids == ["ctl-segment-ci", "ctl-second"]


def test_a_control_already_priced_into_the_baseline_is_not_charged_twice(graph, catalog):
    """ctl-edr is already on ws-eng-01 in the snapshot, so build_graph has
    already discounted that edge. Buying it again must change nothing."""
    edge_before = _edge(graph, "a-vpn-01:admin", "a-ws-02:user")
    assert edge_before.blocked_by_control_ids == ["ctl-edr"]

    result = apply_controls(
        graph, catalog, [AppliedControl(control_id="ctl-edr", applied_to_asset_ids=["a-ws-02"])]
    )
    edge_after = _edge(result, "a-vpn-01:admin", "a-ws-02:user")
    assert edge_after.probability == pytest.approx(edge_before.probability)
    assert edge_after.blocked_by_control_ids == ["ctl-edr"]


def test_a_snapshot_only_control_falls_back_to_the_module_table(graph):
    """ctl-edr is in no catalog. EXISTING_CONTROL_EFFECTS knows it blocks T1078
    at 40%, and that is what an empty catalog should still get you."""
    result = apply_controls(
        graph, [], [AppliedControl(control_id="ctl-edr", applied_to_asset_ids=["a-jenkins-01"])]
    )
    edge = _edge(result, "a-jenkins-01:admin", "a-app-01:user")
    assert edge.probability == pytest.approx(0.75 * 0.6)


def test_the_catalog_wins_over_the_module_table(graph, catalog):
    """The catalog is the priced thing being chosen between, so its numbers win."""
    override = _catalog_entry(catalog, "ctl-pam").model_copy(
        update={"control_id": "ctl-edr", "blocks_technique_ids": ["T1078"], "effectiveness": 0.9}
    )
    result = apply_controls(
        graph,
        [override],
        [AppliedControl(control_id="ctl-edr", applied_to_asset_ids=["a-jenkins-01"])],
    )
    edge = _edge(result, "a-jenkins-01:admin", "a-app-01:user")
    assert edge.probability == pytest.approx(0.75 * 0.1)


def test_an_unknown_control_is_ignored_and_announced(graph, catalog):
    with pytest.warns(RuntimeWarning, match="no effect data"):
        result = apply_controls(
            graph,
            catalog,
            [AppliedControl(control_id="ctl-imaginary", applied_to_asset_ids=["a-web-01"])],
        )
    assert result.model_dump() == graph.model_dump()


def test_a_predicate_control_matches_when_findings_are_supplied(graph, catalog, snapshot):
    """ctl-patch-kev is 'kev==true' at 85%. f-001 is in KEV; the credential
    reuse edge has no finding behind it at all."""
    result = apply_controls(
        graph,
        catalog,
        [
            AppliedControl(
                control_id="ctl-patch-kev", applied_to_asset_ids=["a-web-01", "a-app-01"]
            )
        ],
        findings=snapshot.findings,
    )
    kev_edge = _edge(result, "internet:none", "a-web-01:user")
    assert kev_edge.enabler_finding_id == "f-001"
    assert kev_edge.probability == pytest.approx(0.94 * 0.15)
    assert "ctl-patch-kev" in kev_edge.blocked_by_control_ids

    reuse = _edge(result, "a-jenkins-01:admin", "a-app-01:user")
    assert reuse.probability == pytest.approx(
        _edge(graph, "a-jenkins-01:admin", "a-app-01:user").probability
    )


def test_a_predicate_control_without_findings_says_so(graph, catalog):
    """The frozen signature has no way to reach a Finding, so a predicate-only
    control cannot be evaluated. It must not silently pretend to work."""
    with pytest.warns(RuntimeWarning, match="finding predicate"):
        result = apply_controls(
            graph,
            catalog,
            [AppliedControl(control_id="ctl-patch-kev", applied_to_asset_ids=["a-web-01"])],
        )
    assert result.model_dump() == graph.model_dump()


def test_applying_nothing_still_returns_a_new_graph(graph, catalog):
    result = apply_controls(graph, catalog, [])
    assert result is not graph
    assert result.model_dump() == graph.model_dump()


def test_the_result_can_be_fed_straight_back_into_analyze_paths(graph, catalog, snapshot, paths):
    """What the optimizer actually does: cut the choke point, re-measure."""
    result = apply_controls(
        graph,
        catalog,
        [AppliedControl(control_id="ctl-segment-ci", applied_to_asset_ids=["a-jenkins-01"])],
    )
    after = analyze_paths(result, snapshot)
    before_risk = {r.node_id: r.compromise_probability for r in paths.crown_jewel_reach}
    after_risk = {r.node_id: r.compromise_probability for r in after.crown_jewel_reach}
    assert all(after_risk[k] <= before_risk[k] for k in before_risk)
    assert after_risk["a-db-fin:data_admin"] < before_risk["a-db-fin:data_admin"]


def test_apply_controls_is_deterministic(graph, catalog):
    applications = [AppliedControl(control_id="ctl-waf", applied_to_asset_ids=["a-web-01"])]
    assert (
        apply_controls(graph, catalog, applications).model_dump()
        == apply_controls(graph, catalog, applications).model_dump()
    )


def test_apply_controls_is_fast_enough_for_the_optimizer(large_graph, catalog):
    """The optimizer calls this thousands of times per portfolio. 1000 sequential
    calls on a 200-asset graph must land well inside 10 seconds."""
    assert len(large_graph.edges) > 500, "benchmark graph is too small to be meaningful"
    applications = [
        AppliedControl(
            control_id="ctl-waf", applied_to_asset_ids=[f"a{i}" for i in range(0, 200, 4)]
        ),
        AppliedControl(
            control_id="ctl-pam", applied_to_asset_ids=[f"a{i}" for i in range(1, 200, 4)]
        ),
        AppliedControl(
            control_id="ctl-segment-ci", applied_to_asset_ids=[f"a{i}" for i in range(2, 200, 4)]
        ),
    ]
    started = time.perf_counter()
    for _ in range(1000):
        apply_controls(large_graph, catalog, applications)
    elapsed = time.perf_counter() - started
    assert elapsed < 10.0, f"1000 apply_controls calls took {elapsed:.2f}s"
