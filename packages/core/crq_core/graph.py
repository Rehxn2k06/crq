"""P2. See contracts/FUNCTIONS.md for the full spec of each function."""
from crq_core.schemas import AppliedControl, AttackGraph, ControlCatalogEntry, PathAnalysis, Snapshot


def build_graph(snapshot: Snapshot, rules_version: str = "v1") -> AttackGraph:
    raise NotImplementedError


def analyze_paths(graph: AttackGraph, snapshot: Snapshot) -> PathAnalysis:
    raise NotImplementedError


def apply_controls(graph: AttackGraph, catalog: list[ControlCatalogEntry],
                   applications: list[AppliedControl]) -> AttackGraph:
    """MUST be pure. Return a new graph. Called thousands of times by the optimizer."""
    raise NotImplementedError
