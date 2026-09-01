"""P3. See contracts/FUNCTIONS.md."""
from typing import Literal
from crq_core.schemas import (AttackGraph, ControlCatalogEntry, PathAnalysis,
                              Portfolio, SimConfig, Snapshot)


def optimize(graph: AttackGraph, paths: PathAnalysis, snapshot: Snapshot,
             catalog: list[ControlCatalogEntry], budget_inr: float, config: SimConfig,
             method: Literal["lazy_greedy", "milp"] = "lazy_greedy") -> Portfolio:
    raise NotImplementedError
