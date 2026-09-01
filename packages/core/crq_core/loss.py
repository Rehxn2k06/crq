"""P3. See contracts/FUNCTIONS.md."""
from crq_core.schemas import AttackGraph, LossResult, PathAnalysis, SimConfig, Snapshot


def simulate(graph: AttackGraph, paths: PathAnalysis, snapshot: Snapshot,
             config: SimConfig) -> LossResult:
    """Deterministic given config.seed. Common random numbers depend on this."""
    raise NotImplementedError
