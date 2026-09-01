# CRQ — Cyber Risk Quantification & Investment Optimization

SIH PS 26105. A glass-box engine that turns security telemetry into a rupee loss
*range*, shows which attack paths drive that loss, and picks the best fixes you
can buy for your budget. Every number traces back to its inputs.

**Our thesis, and the answer to the first hard question a judge will ask:**
we do not predict your loss. We bound it, show our working, and optimise spend
against attack paths. An LLM never produces a number in this system.

---

## Repo layout

```
crq/
├── contracts/                  <- FROZEN. Change only by team agreement.
│   ├── FUNCTIONS.md            <- every function signature, per workstream
│   ├── openapi.yaml            <- generated from packages/api
│   ├── schemas/                <- generated JSON Schema, for the frontend
│   ├── fixtures/               <- 12-asset toy org, internally consistent
│   ├── generate_fixtures.py
│   └── validate_fixtures.py    <- referential integrity check, run in CI
├── packages/
│   ├── core/crq_core/
│   │   ├── schemas.py          <- SINGLE SOURCE OF TRUTH for every artifact
│   │   ├── graph.py            <- P2: build_graph, analyze_paths, apply_controls
│   │   ├── loss.py             <- P3: build_scenarios, simulate
│   │   ├── optimize.py         <- P3: optimize (lazy_greedy, then milp)
│   │   └── validate.py         <- P3: backtest
│   ├── ingest/crq_ingest/      <- P1: synthetic generator, connectors, enrichment
│   ├── compliance/crq_compliance/  <- P1 phase 2: compute_cci, dpdp_exposure
│   └── api/crq_api/main.py     <- P4: FastAPI, currently serving fixtures
├── web/                        <- P4: Vite + React + TS + Tailwind + recharts
├── data/                       <- local NVD / EPSS / KEV mirrors (gitignored)
└── docs/
```

## Ownership

| Person | Owns | Produces | Consumes |
|---|---|---|---|
| P1 | `ingest/`, `compliance/` | `Snapshot`, `CCIResult` | raw scanner output, NVD/EPSS/KEV |
| P2 | `core/graph.py` | `AttackGraph`, `PathAnalysis` | `Snapshot` |
| P3 | `core/loss.py`, `core/optimize.py`, `core/validate.py` | `LossResult`, `Portfolio`, `CalibrationReport` | `AttackGraph`, `PathAnalysis`, `Snapshot` |
| P4 | `api/`, `web/` | the demo | everything, via fixtures first |

Nobody waits for anybody. Every workstream starts against `contracts/fixtures/`.

## Day 1

```bash
git clone <repo> && cd crq
pip install -e packages/core -e packages/ingest -e packages/compliance -e packages/api
python contracts/generate_fixtures.py
python contracts/validate_fixtures.py          # must print OK
uvicorn crq_api.main:app --reload --app-dir packages/api
open http://localhost:8000/docs
cd web && npm install && npm run dev
```

If `/docs` renders and `/runs/RUN-DEMO-001/loss` returns a loss result, everyone
is unblocked. That is the day-1 goal and nothing else.

## The Run concept

Every stage takes an input artifact and writes a new immutable one, keeping a
pointer to what it came from:

```
Snapshot --build_graph--> AttackGraph --analyze_paths--> PathAnalysis
         --simulate--> LossResult --optimize--> Portfolio
```

Artifacts are never edited in place. This gives us three things:

- **caching** — unchanged upstream means no re-simulation
- **trace** — the "why is this number what it is" panel is just walking pointers backwards
- **parallel work** — you develop against a fixture artifact, not against a teammate

## Non-negotiables

1. `simulate()` is deterministic given a seed. The optimizer compares candidate control
   sets, and if the simulation wobbles between calls it measures noise instead of signal.
2. Every `GraphEdge` carries a plain-English `rationale`. It renders in the trace panel.
3. Every soft input in `simulate()` is declared in `LossResult.assumptions` with a
   confidence label, including the honest `"guess"` ones.
4. Every control in the catalog has a real `cost_source`. No unsourced prices.
5. `Snapshot.provenance` is displayed in the UI. We never imply synthetic data is real.
6. No LLM output ever becomes a number, a probability, or a score.

## Rules of engagement

- Contracts change only by team agreement, and the changer runs
  `generate_fixtures.py` + `validate_fixtures.py` and tells everyone.
- Branch per workstream: `p1-ingest`, `p2-graph`, `p3-maths`, `p4-api`.
- Merge to `main` at least daily. `validate_fixtures.py` must pass before merge.
- Money fields are floats in rupees, named `*_inr`. Not lakhs. Not crores.
- Probabilities are 0.0-1.0.
