"""
Generates the 12-asset toy org fixtures + JSON Schemas.

Run:  python contracts/generate_fixtures.py

These fixtures are what P3 and P4 build against on day 1 while P1 and P2 are
still writing their generators. They are internally consistent: the graph
references real asset ids, the loss result references real node ids, the
portfolio references real controls.
"""
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "packages" / "core"))

from crq_core.schemas import *  # noqa

ROOT = Path(__file__).parent
NOW = datetime(2026, 9, 1, 9, 0, tzinfo=timezone.utc)


def snapshot() -> Snapshot:
    assets = [
        Asset(asset_id="a-web-01", hostname="web-01", asset_type=AssetType.SERVER,
              business_unit="digital", internet_facing=True,
              revenue_dependency_inr_per_hour=180_000, data_classes=[DataClass.PUBLIC],
              criticality_weight=0.5, tags=["dmz"]),
        Asset(asset_id="a-web-02", hostname="web-02", asset_type=AssetType.SERVER,
              business_unit="digital", internet_facing=True,
              revenue_dependency_inr_per_hour=180_000, data_classes=[DataClass.PUBLIC],
              criticality_weight=0.5, tags=["dmz"]),
        Asset(asset_id="a-vpn-01", hostname="vpn-01", asset_type=AssetType.NETWORK_DEVICE,
              business_unit="it", internet_facing=True, criticality_weight=0.6, tags=["dmz"]),
        Asset(asset_id="a-jenkins-01", hostname="jenkins-prod-01", asset_type=AssetType.SERVER,
              business_unit="engineering", revenue_dependency_inr_per_hour=40_000,
              data_classes=[DataClass.CREDENTIALS], criticality_weight=0.8, tags=["internal"]),
        Asset(asset_id="a-app-01", hostname="app-01", asset_type=AssetType.SERVER,
              business_unit="digital", revenue_dependency_inr_per_hour=320_000,
              criticality_weight=0.7, tags=["internal"]),
        Asset(asset_id="a-file-01", hostname="file-01", asset_type=AssetType.SERVER,
              business_unit="operations", data_classes=[DataClass.IP],
              criticality_weight=0.5, tags=["internal"]),
        Asset(asset_id="a-ad-01", hostname="dc-01", asset_type=AssetType.SERVER,
              business_unit="it", data_classes=[DataClass.CREDENTIALS],
              criticality_weight=0.95, tags=["internal", "identity"]),
        Asset(asset_id="a-ws-01", hostname="ws-fin-01", asset_type=AssetType.WORKSTATION,
              business_unit="finance", criticality_weight=0.3),
        Asset(asset_id="a-ws-02", hostname="ws-eng-01", asset_type=AssetType.WORKSTATION,
              business_unit="engineering", criticality_weight=0.3),
        Asset(asset_id="a-db-cust", hostname="db-customer", asset_type=AssetType.DATABASE,
              business_unit="digital", revenue_dependency_inr_per_hour=450_000,
              data_classes=[DataClass.PII, DataClass.FINANCIAL], pii_records_held=1_200_000,
              criticality_weight=1.0, tags=["crown_jewel"]),
        Asset(asset_id="a-db-fin", hostname="db-finance", asset_type=AssetType.DATABASE,
              business_unit="finance", revenue_dependency_inr_per_hour=200_000,
              data_classes=[DataClass.FINANCIAL], criticality_weight=0.9, tags=["crown_jewel"]),
        Asset(asset_id="a-s3-backup", hostname="backup-bucket", asset_type=AssetType.CLOUD_RESOURCE,
              business_unit="it", data_classes=[DataClass.PII], pii_records_held=1_200_000,
              criticality_weight=0.85, tags=["crown_jewel"]),
    ]
    deps = [
        Dependency(from_asset_id="a-web-01", to_asset_id="a-app-01", kind="service"),
        Dependency(from_asset_id="a-web-02", to_asset_id="a-app-01", kind="service"),
        Dependency(from_asset_id="a-app-01", to_asset_id="a-db-cust", kind="data"),
        Dependency(from_asset_id="a-vpn-01", to_asset_id="a-ws-02", kind="network"),
        Dependency(from_asset_id="a-jenkins-01", to_asset_id="a-app-01", kind="trust"),
        Dependency(from_asset_id="a-ws-01", to_asset_id="a-db-fin", kind="data"),
        Dependency(from_asset_id="a-ad-01", to_asset_id="a-db-cust", kind="trust"),
        Dependency(from_asset_id="a-db-cust", to_asset_id="a-s3-backup", kind="data"),
    ]
    ids = [
        Identity(identity_id="i-svc-deploy", home_asset_id="a-jenkins-01",
                 privilege=Privilege.ADMIN, mfa_enabled=False,
                 credential_reused_on=["a-app-01", "a-web-01", "a-web-02"]),
        Identity(identity_id="i-dba", home_asset_id="a-ws-01", privilege=Privilege.DATA_ADMIN,
                 mfa_enabled=False, credential_reused_on=["a-db-fin", "a-db-cust"]),
        Identity(identity_id="i-eng", home_asset_id="a-ws-02", privilege=Privilege.USER,
                 mfa_enabled=True, credential_reused_on=["a-jenkins-01"]),
    ]
    findings = [
        Finding(finding_id="f-001", asset_id="a-web-01", cve_id="CVE-2024-27198",
                cvss_base=9.8, epss=0.94, kev=True, grants_privilege=Privilege.USER,
                source="trivy", first_seen=NOW),
        Finding(finding_id="f-002", asset_id="a-vpn-01", cve_id="CVE-2024-21887",
                cvss_base=9.1, epss=0.87, kev=True, grants_privilege=Privilege.ADMIN,
                source="openvas", first_seen=NOW),
        Finding(finding_id="f-003", asset_id="a-jenkins-01", cve_id="CVE-2024-23897",
                cvss_base=9.8, epss=0.42, kev=True, grants_privilege=Privilege.ADMIN,
                requires_privilege=Privilege.NONE, source="trivy", first_seen=NOW),
        Finding(finding_id="f-004", asset_id="a-ad-01", cve_id="CVE-2021-42287",
                cvss_base=8.8, epss=0.31, kev=True, grants_privilege=Privilege.ADMIN,
                requires_privilege=Privilege.USER, source="openvas", first_seen=NOW),
        Finding(finding_id="f-005", asset_id="a-app-01", cve_id="CVE-2023-4863",
                cvss_base=8.8, epss=0.09, kev=False, grants_privilege=Privilege.USER,
                source="trivy", first_seen=NOW),
        Finding(finding_id="f-006", asset_id="a-s3-backup", cve_id=None, cvss_base=7.5,
                epss=None, kev=False, grants_privilege=Privilege.DATA_READ,
                source="prowler", first_seen=NOW),
        Finding(finding_id="f-007", asset_id="a-ws-02", cve_id="CVE-2024-38063",
                cvss_base=9.8, epss=0.12, kev=False, grants_privilege=Privilege.USER,
                source="wazuh", first_seen=NOW),
        Finding(finding_id="f-008", asset_id="a-db-cust", cve_id="CVE-2024-1597",
                cvss_base=9.8, epss=0.21, kev=False, grants_privilege=Privilege.DATA_ADMIN,
                requires_privilege=Privilege.USER, source="openvas", first_seen=NOW),
    ]
    tele = TelemetryMetrics(
        vulns_identified=340, vulns_mitigated=248, remote_users_total=180,
        remote_users_with_mfa=126, infosec_budget_inr=1_80_00_000, it_budget_inr=24_00_00_000,
        critical_systems_identified=6, systems_integrated_with_soc=9, total_it_systems=12,
        staff_total=420, staff_security_trained=310, incidents_total=54,
        incidents_closed_in_sla=41, assets_with_current_patch=8,
        backups_tested_count=2, backups_total_count=4,
    )
    return Snapshot(
        snapshot_id="SNAP-DEMO-001", created_at=NOW, provenance=Provenance.SYNTHETIC,
        org=OrgProfile(name="Meridian Broking Pvt Ltd", sector="finance",
                       is_sebi_regulated=True, sebi_entity_class="QRE",
                       annual_revenue_inr=8_40_00_00_000, employee_count=420,
                       pii_records_count=1_200_000),
        assets=assets, dependencies=deps, identities=ids, findings=findings,
        existing_controls=[AppliedControl(control_id="ctl-edr", applied_to_asset_ids=["a-ws-01", "a-ws-02"])],
        telemetry=tele,
    )


def graph() -> AttackGraph:
    n = lambda a, p: GraphNode(node_id=f"{a}:{p.value}", asset_id=a, privilege=p)
    nodes = [
        GraphNode(node_id="internet:none", asset_id="internet", privilege=Privilege.NONE, is_entry=True),
        n("a-web-01", Privilege.USER), n("a-vpn-01", Privilege.ADMIN),
        n("a-jenkins-01", Privilege.ADMIN), n("a-app-01", Privilege.USER),
        n("a-ws-02", Privilege.USER), n("a-ad-01", Privilege.ADMIN),
        GraphNode(node_id="a-db-cust:data_admin", asset_id="a-db-cust",
                  privilege=Privilege.DATA_ADMIN, is_crown_jewel=True),
        GraphNode(node_id="a-db-fin:data_admin", asset_id="a-db-fin",
                  privilege=Privilege.DATA_ADMIN, is_crown_jewel=True),
        GraphNode(node_id="a-s3-backup:data_read", asset_id="a-s3-backup",
                  privilege=Privilege.DATA_READ, is_crown_jewel=True),
    ]
    e = lambda i, s, t, tech, f, p, r: GraphEdge(
        edge_id=i, source_node_id=s, target_node_id=t, technique_id=tech,
        enabler_finding_id=f, probability=p, rationale=r)
    edges = [
        e("e-01", "internet:none", "a-web-01:user", "T1190", "f-001", 0.94,
          "CVE-2024-27198 on internet-facing web-01, EPSS 0.94, in CISA KEV"),
        e("e-02", "internet:none", "a-vpn-01:admin", "T1190", "f-002", 0.87,
          "CVE-2024-21887 on internet-facing vpn-01, EPSS 0.87, in CISA KEV"),
        e("e-03", "a-web-01:user", "a-jenkins-01:admin", "T1210", "f-003", 0.42,
          "CVE-2024-23897 unauth RCE on jenkins-prod-01, reachable from web tier"),
        e("e-04", "a-vpn-01:admin", "a-ws-02:user", "T1021", "f-007", 0.55,
          "VPN admin grants network access to engineering workstation subnet"),
        e("e-05", "a-ws-02:user", "a-jenkins-01:admin", "T1078", None, 0.60,
          "Credential i-eng reused on jenkins-prod-01"),
        e("e-06", "a-jenkins-01:admin", "a-app-01:user", "T1078", None, 0.75,
          "Service credential i-svc-deploy reused on app-01, no MFA"),
        e("e-07", "a-app-01:user", "a-db-cust:data_admin", "T1210", "f-008", 0.35,
          "CVE-2024-1597 on db-customer, reachable via app data dependency"),
        e("e-08", "a-jenkins-01:admin", "a-ad-01:admin", "T1068", "f-004", 0.31,
          "CVE-2021-42287 privesc to domain controller, in CISA KEV"),
        e("e-09", "a-ad-01:admin", "a-db-cust:data_admin", "T1078", None, 0.85,
          "Domain admin trust path to customer database"),
        e("e-10", "a-ad-01:admin", "a-db-fin:data_admin", "T1078", None, 0.80,
          "Domain admin trust path to finance database"),
        e("e-11", "a-db-cust:data_admin", "a-s3-backup:data_read", "T1530", "f-006", 0.70,
          "Backup bucket policy permits read from database service role"),
    ]
    return AttackGraph(
        graph_id="GRAPH-DEMO-001", snapshot_id="SNAP-DEMO-001", nodes=nodes, edges=edges,
        entry_node_ids=["internet:none"],
        crown_jewel_node_ids=["a-db-cust:data_admin", "a-db-fin:data_admin", "a-s3-backup:data_read"],
        rules_version="v1",
    )


def paths() -> PathAnalysis:
    return PathAnalysis(
        path_analysis_id="PATH-DEMO-001", graph_id="GRAPH-DEMO-001",
        choke_points=[
            ChokePoint(node_id="a-jenkins-01:admin", asset_id="a-jenkins-01",
                       paths_through_fraction=0.61,
                       crown_jewels_cut_if_removed=["a-db-cust:data_admin", "a-db-fin:data_admin",
                                                    "a-s3-backup:data_read"],
                       reachable_cj_value_inr=42_00_00_000),
            ChokePoint(node_id="a-ad-01:admin", asset_id="a-ad-01",
                       paths_through_fraction=0.44,
                       crown_jewels_cut_if_removed=["a-db-fin:data_admin"],
                       reachable_cj_value_inr=18_00_00_000),
        ],
        crown_jewel_reach=[
            CrownJewelReach(node_id="a-db-cust:data_admin", asset_id="a-db-cust",
                            compromise_probability=0.58, shortest_path_hops=4,
                            top_path_node_ids=["internet:none", "a-web-01:user",
                                               "a-jenkins-01:admin", "a-ad-01:admin",
                                               "a-db-cust:data_admin"]),
            CrownJewelReach(node_id="a-db-fin:data_admin", asset_id="a-db-fin",
                            compromise_probability=0.29, shortest_path_hops=4,
                            top_path_node_ids=["internet:none", "a-web-01:user",
                                               "a-jenkins-01:admin", "a-ad-01:admin",
                                               "a-db-fin:data_admin"]),
            CrownJewelReach(node_id="a-s3-backup:data_read", asset_id="a-s3-backup",
                            compromise_probability=0.41, shortest_path_hops=5,
                            top_path_node_ids=["internet:none", "a-web-01:user",
                                               "a-jenkins-01:admin", "a-ad-01:admin",
                                               "a-db-cust:data_admin", "a-s3-backup:data_read"]),
        ],
        dead_end_node_fraction=0.30,
    )


def loss() -> LossResult:
    curve = [
        ExceedancePoint(loss_inr=1_00_00_000, probability_of_exceeding=0.72),
        ExceedancePoint(loss_inr=5_00_00_000, probability_of_exceeding=0.41),
        ExceedancePoint(loss_inr=10_00_00_000, probability_of_exceeding=0.24),
        ExceedancePoint(loss_inr=25_00_00_000, probability_of_exceeding=0.11),
        ExceedancePoint(loss_inr=50_00_00_000, probability_of_exceeding=0.05),
        ExceedancePoint(loss_inr=1_00_00_00_000, probability_of_exceeding=0.018),
        ExceedancePoint(loss_inr=2_50_00_00_000, probability_of_exceeding=0.004),
    ]
    return LossResult(
        loss_result_id="LOSS-DEMO-001", graph_id="GRAPH-DEMO-001",
        path_analysis_id="PATH-DEMO-001", config=SimConfig(),
        eal_inr=9_84_00_000, median_inr=4_20_00_000, p95_inr=38_60_00_000,
        p99_inr=94_20_00_000, exceedance_curve=curve,
        component_split_inr={
            LossComponent.DOWNTIME: 2_10_00_000,
            LossComponent.BREACH_RESPONSE: 3_40_00_000,
            LossComponent.REGULATORY: 2_90_00_000,
            LossComponent.REPUTATIONAL: 1_44_00_000,
        },
        scenario_contributions=[
            ScenarioContribution(scenario_id="sc-pii-exfil", name="Mass PII exfiltration (customer DB)",
                                 triggering_node_ids=["a-db-cust:data_admin"], annual_frequency=0.58,
                                 eal_inr=6_10_00_000, share_of_total=0.62),
            ScenarioContribution(scenario_id="sc-fin-tamper", name="Finance DB compromise",
                                 triggering_node_ids=["a-db-fin:data_admin"], annual_frequency=0.29,
                                 eal_inr=2_35_00_000, share_of_total=0.24),
            ScenarioContribution(scenario_id="sc-backup-exfil", name="Backup bucket exfiltration",
                                 triggering_node_ids=["a-s3-backup:data_read"], annual_frequency=0.41,
                                 eal_inr=1_39_00_000, share_of_total=0.14),
        ],
        top_drivers=[
            LossDriver(ref_type="node", ref_id="a-jenkins-01:admin", label="jenkins-prod-01 (admin)",
                       attributed_eal_inr=5_02_00_000),
            LossDriver(ref_type="node", ref_id="a-ad-01:admin", label="dc-01 (domain admin)",
                       attributed_eal_inr=2_88_00_000),
            LossDriver(ref_type="finding", ref_id="f-002", label="CVE-2024-21887 on vpn-01",
                       attributed_eal_inr=1_10_00_000),
        ],
        assumptions=[
            Assumption(key="reputational_churn_rate", value=0.012, unit="fraction of annual revenue",
                       source="Team estimate. NO defensible public source exists.",
                       confidence="guess", sensitivity_rank=2),
            Assumption(key="severity_lognormal_sigma", value=2.1, unit="log-scale",
                       source="Cyentia IRIS 2025 median/p95 fit", confidence="public_data",
                       sensitivity_rank=1),
            Assumption(key="breach_response_cost_per_record_inr", value=185.0, unit="INR/record",
                       source="IBM CODB India 2025, adjusted to median", confidence="public_data",
                       sensitivity_rank=3),
            Assumption(key="dpdp_penalty_applied_probability", value=0.25, unit="probability",
                       source="No enforcement history yet under DPDP", confidence="estimated",
                       sensitivity_rank=4),
        ],
    )


def catalog() -> list[ControlCatalogEntry]:
    return [
        ControlCatalogEntry(control_id="ctl-patch-kev", name="Emergency KEV patch programme",
                            description="30-day SLA on all CISA KEV vulnerabilities",
                            nist_800_53_ref="SI-2", cis_control_ref="7.4",
                            cost_inr_per_year=18_00_000, cost_model="flat",
                            blocks_finding_predicate="kev==true", effectiveness=0.85,
                            effectiveness_source="Assumed patch compliance rate",
                            cost_source="2 FTE eng-months + tooling, team estimate"),
        ControlCatalogEntry(control_id="ctl-mfa-priv", name="MFA on all privileged accounts",
                            description="Phishing-resistant MFA for admin and service identities",
                            nist_800_53_ref="IA-2", cis_control_ref="6.5",
                            cost_inr_per_year=9_60_000, cost_model="per_user",
                            blocks_technique_ids=["T1078"], effectiveness=0.80,
                            effectiveness_source="Microsoft 2023 MFA efficacy claim",
                            cost_source="Entra P2 list price INR 800/user/mo"),
        ControlCatalogEntry(control_id="ctl-segment-ci", name="Network segmentation of CI/CD tier",
                            description="Isolate Jenkins from web and identity tiers",
                            nist_800_53_ref="SC-7", cis_control_ref="12.2",
                            cost_inr_per_year=32_00_000, cost_model="flat",
                            blocks_technique_ids=["T1210", "T1021"], effectiveness=0.70,
                            effectiveness_source="Assumed path-cut effectiveness",
                            cost_source="Firewall + 1 FTE quarter, team estimate"),
        ControlCatalogEntry(control_id="ctl-pam", name="Privileged access management",
                            description="Vault service credentials, remove standing reuse",
                            nist_800_53_ref="AC-6", cis_control_ref="5.4",
                            cost_inr_per_year=42_00_000, cost_model="flat",
                            blocks_technique_ids=["T1078"], effectiveness=0.75,
                            effectiveness_source="Assumed credential-reuse elimination",
                            cost_source="CyberArk mid-tier India quote, team estimate"),
        ControlCatalogEntry(control_id="ctl-waf", name="WAF on internet-facing tier",
                            description="Managed WAF in front of web-01 and web-02",
                            nist_800_53_ref="SC-7", cis_control_ref="13.10",
                            cost_inr_per_year=14_00_000, cost_model="flat",
                            blocks_technique_ids=["T1190"], effectiveness=0.55,
                            effectiveness_source="Assumed exploit-blocking rate",
                            cost_source="Cloudflare Business tier, published pricing"),
        ControlCatalogEntry(control_id="ctl-db-monitor", name="Database activity monitoring",
                            description="Alert on bulk reads from customer and finance DBs",
                            nist_800_53_ref="AU-6", cis_control_ref="8.11",
                            cost_inr_per_year=26_00_000, cost_model="flat",
                            blocks_technique_ids=["T1530"], effectiveness=0.45,
                            effectiveness_source="Detection reduces dwell, not access",
                            cost_source="Team estimate, open-source + 0.5 FTE"),
    ]


def portfolio() -> Portfolio:
    return Portfolio(
        portfolio_id="PORT-DEMO-001", loss_result_id="LOSS-DEMO-001",
        budget_inr=1_00_00_000, method="lazy_greedy",
        selected=[
            SelectedControl(control_id="ctl-segment-ci", name="Network segmentation of CI/CD tier",
                            applied_to_asset_ids=["a-jenkins-01"], cost_inr=32_00_000,
                            delta_eal_inr=4_18_00_000, roi_ratio=13.06, selection_rank=1,
                            reason="Cuts the choke point carrying 61% of crown-jewel paths"),
            SelectedControl(control_id="ctl-mfa-priv", name="MFA on all privileged accounts",
                            applied_to_asset_ids=["a-jenkins-01", "a-ad-01", "a-ws-01"],
                            cost_inr=9_60_000, delta_eal_inr=1_64_00_000, roi_ratio=17.08,
                            selection_rank=2,
                            reason="Breaks remaining credential-reuse edges after segmentation"),
            SelectedControl(control_id="ctl-patch-kev", name="Emergency KEV patch programme",
                            applied_to_asset_ids=["a-web-01", "a-vpn-01", "a-ad-01"],
                            cost_inr=18_00_000, delta_eal_inr=1_02_00_000, roi_ratio=5.67,
                            selection_rank=3, reason="Removes both internet-facing entry edges"),
            SelectedControl(control_id="ctl-waf", name="WAF on internet-facing tier",
                            applied_to_asset_ids=["a-web-01", "a-web-02"], cost_inr=14_00_000,
                            delta_eal_inr=31_00_000, roi_ratio=2.21, selection_rank=4,
                            reason="Residual entry-path coverage after patching"),
        ],
        total_cost_inr=73_60_000, baseline_eal_inr=9_84_00_000, residual_eal_inr=2_69_00_000,
        risk_reduction_inr=7_15_00_000, rosi=8.72,
        pareto_curve=[
            ParetoPoint(budget_inr=25_00_000, residual_eal_inr=5_66_00_000, control_count=1),
            ParetoPoint(budget_inr=50_00_000, residual_eal_inr=3_71_00_000, control_count=2),
            ParetoPoint(budget_inr=75_00_000, residual_eal_inr=2_69_00_000, control_count=4),
            ParetoPoint(budget_inr=1_00_00_000, residual_eal_inr=2_69_00_000, control_count=4),
            ParetoPoint(budget_inr=1_50_00_000, residual_eal_inr=2_18_00_000, control_count=5),
            ParetoPoint(budget_inr=2_00_00_000, residual_eal_inr=1_94_00_000, control_count=6),
        ],
        optimality_gap=0.031, solve_ms=412.0,
    )


def run() -> Run:
    return Run(run_id="RUN-DEMO-001", snapshot_id="SNAP-DEMO-001", status=RunStatus.COMPLETE,
               created_at=NOW, graph_id="GRAPH-DEMO-001", path_analysis_id="PATH-DEMO-001",
               loss_result_id="LOSS-DEMO-001", portfolio_ids=["PORT-DEMO-001"])


def trace() -> TraceChain:
    return TraceChain(
        target_ref="loss_driver:LOSS-DEMO-001:a-jenkins-01:admin",
        steps=[
            TraceStep(stage="ingest", artifact_id="SNAP-DEMO-001", element_id="f-003",
                      label="Finding CVE-2024-23897 on jenkins-prod-01",
                      detail="Reported by trivy on 2026-09-01. CVSS 9.8.", inputs=[]),
            TraceStep(stage="enrich", artifact_id="SNAP-DEMO-001", element_id="f-003",
                      label="EPSS 0.42, present in CISA KEV",
                      detail="EPSS v4 daily feed. KEV catalogue.", inputs=["f-003"]),
            TraceStep(stage="graph", artifact_id="GRAPH-DEMO-001", element_id="e-03",
                      label="Edge web-01:user -> jenkins-01:admin, p=0.42",
                      detail="Rule R1 remote exploit. Probability from EPSS.", inputs=["f-003"]),
            TraceStep(stage="paths", artifact_id="PATH-DEMO-001", element_id="a-jenkins-01:admin",
                      label="Choke point: 61% of crown-jewel paths",
                      detail="Removing this node disconnects all three crown jewels.",
                      inputs=["e-03", "e-06", "e-08"]),
            TraceStep(stage="loss", artifact_id="LOSS-DEMO-001", element_id="a-jenkins-01:admin",
                      label="Attributed EAL INR 5.02 crore",
                      detail="Shapley-style attribution across 25,000 trials, seed 42.",
                      inputs=["a-jenkins-01:admin"]),
        ],
    )


def main():
    fx = ROOT / "fixtures"
    sc = ROOT / "schemas"
    fx.mkdir(exist_ok=True)
    sc.mkdir(exist_ok=True)

    artifacts = {
        "snapshot": snapshot(), "graph": graph(), "path_analysis": paths(),
        "loss_result": loss(), "portfolio": portfolio(), "run": run(), "trace": trace(),
    }
    for name, obj in artifacts.items():
        (fx / f"{name}.json").write_text(obj.model_dump_json(indent=2))
        print(f"  fixture  {name}.json")

    cat = catalog()
    (fx / "control_catalog.json").write_text(
        json.dumps([c.model_dump() for c in cat], indent=2))
    print("  fixture  control_catalog.json")

    for model in [Snapshot, AttackGraph, PathAnalysis, LossResult, Portfolio,
                  ControlCatalogEntry, CCIResult, RegulatoryExposure, Run, TraceChain,
                  NLQueryPlan, CalibrationReport]:
        n = model.__name__
        (sc / f"{n}.schema.json").write_text(json.dumps(model.model_json_schema(), indent=2))
        print(f"  schema   {n}.schema.json")


if __name__ == "__main__":
    main()
