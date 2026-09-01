"""
CRQ API. Serves fixtures until the engines land, then swaps to real artifact loads.

P4: run `uvicorn crq_api.main:app --reload`, hit /docs, build the frontend against this.
P1/P2/P3: your job is to make the real engines return objects that fit these responses.
Nothing here changes when you swap fixtures for real data.
"""
import json
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel

from crq_core.schemas import (
    AttackGraph, CCIResult, CalibrationReport, ControlCatalogEntry, LossResult,
    NLQueryRequest, NLQueryResponse, PathAnalysis, Portfolio, RegulatoryExposure,
    Run, Snapshot, TraceChain,
)

FIXTURES = Path(__file__).resolve().parents[3] / "contracts" / "fixtures"
USE_FIXTURES = True

app = FastAPI(
    title="CRQ — Cyber Risk Quantification & Investment Optimization",
    version="0.1.0",
    description="SIH PS 26105. Glass-box risk engine: telemetry -> attack paths -> rupees -> optimal spend.",
)


def fx(name: str) -> dict:
    p = FIXTURES / f"{name}.json"
    if not p.exists():
        raise HTTPException(503, f"fixture {name} not generated yet")
    return json.loads(p.read_text())


# ------------------------------------------------------------- snapshots

class GenerateSnapshotRequest(BaseModel):
    org_name: str = "Demo Enterprise"
    sector: str = "finance"
    asset_count: int = 200
    seed: int = 42


@app.post("/snapshots/generate", response_model=Snapshot, tags=["snapshots"],
          summary="Generate a synthetic enterprise (always labelled provenance=synthetic)")
def generate_snapshot(req: GenerateSnapshotRequest) -> Snapshot:
    return Snapshot(**fx("snapshot"))


@app.get("/snapshots/{snapshot_id}", response_model=Snapshot, tags=["snapshots"])
def get_snapshot(snapshot_id: str) -> Snapshot:
    return Snapshot(**fx("snapshot"))


# ------------------------------------------------------------- runs

class CreateRunRequest(BaseModel):
    snapshot_id: str
    trials: int = 25_000
    seed: int = 42


@app.post("/runs", response_model=Run, status_code=202, tags=["runs"],
          summary="Kick off the pipeline: graph -> paths -> loss")
def create_run(req: CreateRunRequest) -> Run:
    return Run(**fx("run"))


@app.get("/runs/{run_id}", response_model=Run, tags=["runs"])
def get_run(run_id: str) -> Run:
    return Run(**fx("run"))


@app.get("/runs/{run_id}/graph", response_model=AttackGraph, tags=["runs"])
def get_graph(run_id: str) -> AttackGraph:
    return AttackGraph(**fx("graph"))


@app.get("/runs/{run_id}/paths", response_model=PathAnalysis, tags=["runs"],
         summary="Choke points and crown-jewel reachability")
def get_paths(run_id: str) -> PathAnalysis:
    return PathAnalysis(**fx("path_analysis"))


@app.get("/runs/{run_id}/loss", response_model=LossResult, tags=["runs"],
         summary="EAL, VaR, loss-exceedance curve, declared assumptions")
def get_loss(run_id: str) -> LossResult:
    return LossResult(**fx("loss_result"))


# ------------------------------------------------------------- optimizer

class OptimizeRequest(BaseModel):
    budget_inr: float = 1_00_00_000
    method: str = "lazy_greedy"
    include_pareto: bool = True


@app.post("/runs/{run_id}/portfolios", response_model=Portfolio, tags=["optimizer"],
          summary="Best control basket for the budget, plus the investment-vs-risk curve")
def optimize(run_id: str, req: OptimizeRequest) -> Portfolio:
    return Portfolio(**fx("portfolio"))


@app.get("/runs/{run_id}/portfolios/{portfolio_id}", response_model=Portfolio, tags=["optimizer"])
def get_portfolio(run_id: str, portfolio_id: str) -> Portfolio:
    return Portfolio(**fx("portfolio"))


@app.get("/controls", response_model=list[ControlCatalogEntry], tags=["optimizer"],
         summary="Control catalog with sourced India pricing")
def list_controls() -> list[ControlCatalogEntry]:
    return [ControlCatalogEntry(**c) for c in fx("control_catalog")]


# ------------------------------------------------------------- compliance

@app.get("/runs/{run_id}/cci", response_model=CCIResult, tags=["compliance"],
         summary="SEBI CSCRF Cyber Capability Index, 23 weighted parameters from telemetry")
def get_cci(run_id: str) -> CCIResult:
    raise HTTPException(501, "phase 2")


@app.get("/runs/{run_id}/dpdp", response_model=RegulatoryExposure, tags=["compliance"])
def get_dpdp(run_id: str) -> RegulatoryExposure:
    raise HTTPException(501, "phase 2")


# ------------------------------------------------------------- trace + NL

@app.get("/runs/{run_id}/trace", response_model=TraceChain, tags=["explain"],
         summary="Walk any number on screen back to its raw inputs")
def get_trace(run_id: str, target_ref: str = Query(..., description="'{type}:{artifact_id}:{element_id}'")) -> TraceChain:
    return TraceChain(**fx("trace"))


@app.post("/query", response_model=NLQueryResponse, tags=["explain"],
          summary="Natural language question. LLM emits a query plan only, never figures.")
def nl_query(req: NLQueryRequest) -> NLQueryResponse:
    raise HTTPException(501, "phase 3")


@app.get("/validation/calibration", response_model=CalibrationReport, tags=["validation"],
         summary="Backtest against VCDB: Brier score and calibration curve")
def calibration() -> CalibrationReport:
    raise HTTPException(501, "phase 3")


@app.get("/health", tags=["meta"])
def health() -> dict:
    return {"status": "ok", "mode": "fixtures" if USE_FIXTURES else "live"}
