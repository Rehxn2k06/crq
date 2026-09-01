"""Referential integrity check across fixtures. Run in CI. Keeps the team honest."""
import json, sys
from pathlib import Path
FX = Path(__file__).parent / "fixtures"
L = lambda n: json.loads((FX / f"{n}.json").read_text())
errs = []
def chk(cond, msg):
    if not cond: errs.append(msg)

snap, g, pa, loss, port, cat = L("snapshot"), L("graph"), L("path_analysis"), L("loss_result"), L("portfolio"), L("control_catalog")
assets = {a["asset_id"] for a in snap["assets"]}
finds  = {f["finding_id"] for f in snap["findings"]}
nodes  = {n["node_id"] for n in g["nodes"]}
ctls   = {c["control_id"] for c in cat}

for a in snap["dependencies"]:
    chk(a["from_asset_id"] in assets and a["to_asset_id"] in assets, f"dep refs unknown asset {a}")
for f in snap["findings"]:
    chk(f["asset_id"] in assets, f"finding {f['finding_id']} refs unknown asset")
for n in g["nodes"]:
    chk(n["asset_id"] in assets or n["asset_id"] == "internet", f"node {n['node_id']} refs unknown asset")
for e in g["edges"]:
    chk(e["source_node_id"] in nodes, f"edge {e['edge_id']} bad source")
    chk(e["target_node_id"] in nodes, f"edge {e['edge_id']} bad target")
    chk(e["enabler_finding_id"] in finds or e["enabler_finding_id"] is None, f"edge {e['edge_id']} bad finding")
    chk(e["rationale"].strip() != "", f"edge {e['edge_id']} missing rationale")
chk(g["snapshot_id"] == snap["snapshot_id"], "graph/snapshot id mismatch")
chk(pa["graph_id"] == g["graph_id"], "paths/graph id mismatch")
for c in pa["choke_points"]: chk(c["node_id"] in nodes, f"chokepoint {c['node_id']} unknown")
for c in pa["crown_jewel_reach"]: chk(c["node_id"] in g["crown_jewel_node_ids"], f"cj {c['node_id']} not a crown jewel")
chk(loss["graph_id"] == g["graph_id"], "loss/graph id mismatch")
shares = sum(s["share_of_total"] for s in loss["scenario_contributions"])
chk(abs(shares - 1.0) < 0.01, f"scenario shares sum to {shares}, not 1.0")
comp = sum(loss["component_split_inr"].values())
chk(abs(comp - loss["eal_inr"]) / loss["eal_inr"] < 0.02, f"component split {comp} != EAL {loss['eal_inr']}")
chk(loss["median_inr"] < loss["eal_inr"] < loss["p95_inr"], "heavy-tail sanity: need median < mean < p95")
prev = 1.0
for p in loss["exceedance_curve"]:
    chk(p["probability_of_exceeding"] <= prev, "exceedance curve must be monotonically decreasing")
    prev = p["probability_of_exceeding"]
chk(port["loss_result_id"] == loss["loss_result_id"], "portfolio/loss id mismatch")
tot = sum(s["cost_inr"] for s in port["selected"])
chk(abs(tot - port["total_cost_inr"]) < 1, f"portfolio cost {tot} != stated {port['total_cost_inr']}")
chk(tot <= port["budget_inr"], "portfolio exceeds budget")
red = sum(s["delta_eal_inr"] for s in port["selected"])
chk(abs(red - port["risk_reduction_inr"]) < 1, f"deltas sum {red} != risk_reduction {port['risk_reduction_inr']}")
chk(abs((port["baseline_eal_inr"] - red) - port["residual_eal_inr"]) < 1, "baseline - reduction != residual")
for s in port["selected"]:
    chk(s["control_id"] in ctls, f"portfolio refs unknown control {s['control_id']}")
    chk(abs(s["roi_ratio"] - s["delta_eal_inr"]/s["cost_inr"]) < 0.05, f"roi_ratio wrong for {s['control_id']}")
pc = port["pareto_curve"]
chk(all(pc[i]["residual_eal_inr"] >= pc[i+1]["residual_eal_inr"] for i in range(len(pc)-1)), "pareto must be non-increasing")
for c in cat: chk(c["cost_source"].strip() != "", f"control {c['control_id']} has no cost source")

if errs:
    print("FAIL")
    [print("  -", e) for e in errs]; sys.exit(1)
print("OK - all fixtures internally consistent")
