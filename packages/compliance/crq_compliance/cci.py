"""P1 phase 2. See contracts/FUNCTIONS.md."""
from crq_core.schemas import CCIResult, RegulatoryExposure, Snapshot


def compute_cci(snapshot: Snapshot) -> CCIResult:
    raise NotImplementedError


def dpdp_exposure(snapshot: Snapshot) -> RegulatoryExposure:
    raise NotImplementedError
