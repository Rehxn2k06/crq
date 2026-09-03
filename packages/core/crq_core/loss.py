"""P3, loss side. See contracts/FUNCTIONS.md.

Pure function of its inputs, deterministic given ``SimConfig.seed``. No clock, no
DB, no globals. The optimizer calls this thousands of times and compares the
answers, so any wobble between two calls with the same seed is measured as a
control's effect. There is none: every random number in here comes out of a
``SeedSequence`` derived from ``(seed, scenario index, stream index)``.

How the money is modelled
-------------------------
There is ONE intrusion process for the org, not one per crown jewel::

    N_intrusions ~ Poisson(org_annual_incident_rate * horizon)
    per intrusion, jewel j is reached with probability p_j from analyze_paths
    severity     ~ LogNormal(mu, sigma) per compromise, in INR, calibrated to
                   Cyentia IRIS and scaled by criticality and PII holdings

The base rate is anchored to the org, from an IRIS-style size band and a sector
multiplier -- how often a firm of this size in this sector suffers a significant
incident at all. The path analysis probabilities are then *relative*: given that
someone got in, which crown jewels do they reach. Using them as absolute annual
rates instead double counts, because each one already contains the probability
of getting in, and four jewels then produce four independent intrusions a year.

Modelling it as one process is also what makes the jewels correlated. A single
intrusion can reach several of them, which is what actually happens, and the
annual loss distribution gets the resulting clumping for free.

``severity`` is the *magnitude* of the event. The org's own exposure figures --
revenue per hour, records held, annual revenue, the DPDP ceiling -- set the
*mix*: each of the four components draws a rupee-denominated raw estimate from
its own mechanism, and those raw estimates are the shares the event magnitude is
split across. So the four components always sum to the event total (the
component split reconciles to EAL exactly), while an asset with no revenue
dependency takes no downtime loss and an asset with no PII takes no breach
response and no regulatory penalty.

Regulatory is the one component computed directly in rupees rather than as a
share, because the DPDP ceiling is a rupee bound and has to bite as one. It is
drawn only when a PII data class is touched, correlated with the severity of the
event, and hard-capped at the 250 crore security-safeguards ceiling. The rest of
the event magnitude is split across the other three.

Why the shares are rupee-denominated and then renormalised: IRIS is the best
public evidence on how big a cyber loss is, and it is evidence about the level.
This org's asset register is the best evidence about where the loss lands. Using
each for what it is good at is the honest read, and it is stated out loud in
``assumptions`` under ``severity_model``.

Every soft constant in here appears in ``LossResult.assumptions`` with a
confidence label, and the ones that are genuinely guesses say ``guess``.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, replace

import numpy as np
from scipy.stats import poisson

from crq_core.schemas import (
    Asset,
    Assumption,
    AttackGraph,
    DataClass,
    ExceedancePoint,
    LossComponent,
    LossDriver,
    LossResult,
    PathAnalysis,
    Privilege,
    ScenarioContribution,
    SimConfig,
    Snapshot,
)

# --------------------------------------------------------------------------- #
# ASSUMPTIONS. Every number below is soft. Each one is surfaced in
# LossResult.assumptions with a source and a confidence label, and each one that
# is a real uncertainty is perturbed +/-20% for the sensitivity ranking.
# --------------------------------------------------------------------------- #

#: INR per USD. Declared because the whole IRIS calibration is denominated in
#: dollars and every money field in the contract is rupees.
USD_INR_RATE = 88.0

#: Cyentia IRIS 2025 per-event loss distribution, the two points we fit to.
IRIS_MEDIAN_USD = 600_000.0
IRIS_P95_USD = 32_000_000.0
#: Standard normal 95th percentile, used to turn (median, p95) into sigma.
Z95 = 1.6448536269514722

#: Recovery duration for the downtime component. Median one day, p95 one week.
RECOVERY_HOURS_MEDIAN = 24.0
RECOVERY_HOURS_P95 = 168.0

#: Breach response, per record. IBM's India report publishes a total cost and an
#: average breach size, not a per-record figure; this is the quotient.
BREACH_COST_PER_RECORD_INR = 185.0
#: What share of the records an asset holds actually walk out the door.
RECORDS_EXPOSED_FRACTION_MEDIAN = 0.6
RECORDS_EXPOSED_FRACTION_SIGMA = 0.5

#: DPDP Act 2023, Schedule: 250 crore for failure to take reasonable security
#: safeguards. Per instance, no turnover linkage.
DPDP_SECURITY_CEILING_INR = 250_00_00_000.0
#: The Board has issued no penalties yet, so both of these are estimates.
DPDP_PENALTY_APPLIED_PROBABILITY = 0.25
DPDP_CEILING_SHARE_MEDIAN = 0.12
DPDP_CEILING_SHARE_SIGMA = 0.7

#: Reputational. This one is a guess and is labelled as one.
REPUTATIONAL_CHURN_RATE = 0.012
REPUTATIONAL_CHURN_SIGMA = 0.6

#: A single event cannot cost a going concern more than a year of revenue. An
#: uncapped lognormal with the IRIS tail will happily print numbers no firm has
#: ever survived, which is not a forecast, it is an artefact of the fit.
#:
#: Applied as a smooth saturation rather than a `min`, because a hard clip piles
#: a point mass on the cap and then reports it as the p95 -- a headline number
#: that is an artefact of the truncation, not of the risk. Losses below the knee
#: are untouched; above it they bend over towards the cap and never reach it.
EVENT_CAP_MULTIPLE_OF_REVENUE = 1.0
SEVERITY_SATURATION_KNEE = 0.5

#: How often a firm of a given headcount suffers a significant cyber incident at
#: all, in a year. IRIS-style size bands: (employees_below, annual rate).
SIZE_BAND_INCIDENT_RATE: tuple[tuple[float, float], ...] = (
    (50, 0.02),
    (250, 0.05),
    (1_000, 0.08),
    (10_000, 0.14),
    (math.inf, 0.22),
)
#: VCDB shows some sectors carrying far more than their share of incidents.
SECTOR_INCIDENT_MULTIPLIER: dict[str, float] = {
    "finance": 1.5,
    "healthcare": 1.4,
    "public": 1.3,
    "retail": 1.2,
    "technology": 1.1,
}
DEFAULT_SECTOR_MULTIPLIER = 1.0

#: The share of the IRIS log-variance that is variation between events at ONE
#: firm, rather than variation between firms. IRIS pools firms spanning several
#: orders of magnitude of revenue, and most of that spread is the firms differing
#: in size, not one firm's losses differing from each other. We have already
#: conditioned on this firm -- its revenue, its records, its asset criticality
#: are all inputs -- so applying the full population sigma on top double counts
#: the between-firm spread and pushes single events past the size of the firm.
WITHIN_FIRM_VARIANCE_SHARE = 0.35

#: Bounds on the asset scale factor, so one asset holding every record in the
#: org cannot run away with the model.
ASSET_SCALE_BOUNDS = (0.1, 3.0)

#: Sensitivity perturbation, per FUNCTIONS.md.
PERTURBATION = 0.20

#: Exceedance curve is reported at these quantiles of the trial distribution.
#: Weighted towards the top because an org that suffers a significant incident
#: once every eight years spends most of its quantiles on zero.
EXCEEDANCE_QUANTILES = (
    0.10, 0.25, 0.50, 0.75, 0.90, 0.95, 0.96, 0.97, 0.98, 0.99, 0.995, 0.999, 0.9995,
)

#: How many of each kind of driver make it into top_drivers.
MAX_NODE_DRIVERS = 10
MAX_FINDING_DRIVERS = 10

#: Headroom on the pre-drawn intrusion pool, so a +20% perturbation of the base
#: rate still reads a prefix of the same random numbers (common random numbers).
POOL_LAMBDA_HEADROOM = 1.35
POOL_SIGMA_MARGIN = 12.0


def _saturate(values: np.ndarray, cap: float) -> np.ndarray:
    """Identity below the knee, then an exponential bend onto `cap` as an
    asymptote. Continuous and smooth at the knee (the derivative is 1 on both
    sides), increasing, and bounded above by `cap`.

    The cap is approached rather than reached, which is the whole reason this is
    not a `min`: a hard clip puts several percent of events on one value and then
    reports it as the p95. There is still a tie at the very end of the tail, for
    an arithmetic reason rather than a modelling one -- about 37 spans above the
    knee the correction falls below one ulp of `cap` and the sum rounds to it.
    On a 840 crore cap that is a raw draw over roughly 15,900 crore, a little
    over 3 sigma, some 0.12% of events. Far too little to raise a point mass at
    any quantile the result reports, but it is a tie, not an asymptote.
    """
    if cap <= 0.0:
        return np.zeros_like(values)
    knee = SEVERITY_SATURATION_KNEE * cap
    span = cap - knee
    if span <= 0.0:
        return np.minimum(values, cap)
    bent = cap - span * np.exp(-(values - knee) / span)
    return np.where(values <= knee, values, bent)


# --------------------------------------------------------------------------- #
# parameters (everything perturbable lives here, so sensitivity is a `replace`)
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class _Params:
    usd_inr_rate: float = USD_INR_RATE
    iris_median_usd: float = IRIS_MEDIAN_USD
    iris_p95_usd: float = IRIS_P95_USD
    recovery_hours_median: float = RECOVERY_HOURS_MEDIAN
    recovery_hours_p95: float = RECOVERY_HOURS_P95
    breach_cost_per_record_inr: float = BREACH_COST_PER_RECORD_INR
    records_exposed_fraction_median: float = RECORDS_EXPOSED_FRACTION_MEDIAN
    dpdp_penalty_applied_probability: float = DPDP_PENALTY_APPLIED_PROBABILITY
    dpdp_ceiling_share_median: float = DPDP_CEILING_SHARE_MEDIAN
    dpdp_security_ceiling_inr: float = DPDP_SECURITY_CEILING_INR
    reputational_churn_rate: float = REPUTATIONAL_CHURN_RATE
    event_cap_multiple_of_revenue: float = EVENT_CAP_MULTIPLE_OF_REVENUE
    within_firm_variance_share: float = WITHIN_FIRM_VARIANCE_SHARE
    #: Derived from the snapshot in `simulate`; the default is only a placeholder
    #: for the size band a mid-size firm falls in.
    org_annual_incident_rate: float = 0.08

    @property
    def iris_median_inr(self) -> float:
        return self.iris_median_usd * self.usd_inr_rate

    @property
    def iris_population_sigma(self) -> float:
        """Fitted from the two IRIS points: sigma = ln(p95 / median) / z95.
        This is the spread across every firm in the IRIS population."""
        ratio = max(self.iris_p95_usd / self.iris_median_usd, 1.000001)
        return math.log(ratio) / Z95

    @property
    def severity_sigma(self) -> float:
        """The within-firm part of that spread. Variances add, so the share is
        taken under a square root."""
        return self.iris_population_sigma * math.sqrt(max(self.within_firm_variance_share, 1e-9))

    @property
    def recovery_sigma(self) -> float:
        ratio = max(self.recovery_hours_p95 / self.recovery_hours_median, 1.000001)
        return math.log(ratio) / Z95


#: (params field, assumption key) for the one-at-a-time sensitivity sweep. Only
#: genuine uncertainties are in here: the DPDP ceiling is statute, so it is
#: declared as an assumption but never perturbed.
PERTURBABLE: tuple[tuple[str, str], ...] = (
    ("usd_inr_rate", "usd_inr_rate"),
    ("iris_median_usd", "iris_severity_median_usd"),
    ("iris_p95_usd", "iris_severity_p95_usd"),
    ("recovery_hours_median", "recovery_hours_median"),
    ("breach_cost_per_record_inr", "breach_response_cost_per_record_inr"),
    ("records_exposed_fraction_median", "records_exposed_fraction_median"),
    ("dpdp_penalty_applied_probability", "dpdp_penalty_applied_probability"),
    ("dpdp_ceiling_share_median", "dpdp_ceiling_share_median"),
    ("reputational_churn_rate", "reputational_churn_rate"),
    ("event_cap_multiple_of_revenue", "event_cap_multiple_of_revenue"),
    ("within_firm_variance_share", "within_firm_variance_share"),
    ("org_annual_incident_rate", "org_annual_incident_rate"),
)


def _base_incident_rate(snapshot: Snapshot) -> float:
    """Expected significant cyber incidents per year for this org, before any
    consideration of what an intruder can reach once inside.

    Size band from headcount, then a sector multiplier. Deliberately coarse:
    there is no firm-specific incident history to fit to, and pretending
    otherwise by adding decimal places would be the dishonest part.
    """
    employees = max(snapshot.org.employee_count, 1)
    rate = SIZE_BAND_INCIDENT_RATE[-1][1]
    for ceiling, band_rate in SIZE_BAND_INCIDENT_RATE:
        if employees < ceiling:
            rate = band_rate
            break
    multiplier = SECTOR_INCIDENT_MULTIPLIER.get(
        snapshot.org.sector.strip().lower(), DEFAULT_SECTOR_MULTIPLIER
    )
    return rate * multiplier


# --------------------------------------------------------------------------- #
# scenarios
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class _Scenario:
    """Internal only. ``Scenario`` is not a shape in schemas.py, and schemas.py is
    the single source of truth for artifact shapes, so this never leaves the
    module -- it is projected into ``ScenarioContribution`` on the way out."""
    scenario_id: str
    name: str
    node_id: str
    asset: Asset
    compromise_probability: float
    asset_scale: float
    pii_touched: bool
    path_node_ids: tuple[str, ...]


def _scenario_name(asset: Asset, privilege: Privilege) -> str:
    """Named for what the board loses, not for the privilege the attacker gains."""
    if asset.pii_records_held > 0 and DataClass.PII in asset.data_classes:
        head = "Mass PII exfiltration"
    elif DataClass.PII in asset.data_classes:
        head = "Personal data compromise"
    elif DataClass.FINANCIAL in asset.data_classes:
        head = "Financial data compromise"
    elif DataClass.CREDENTIALS in asset.data_classes:
        head = "Credential store compromise"
    elif DataClass.IP in asset.data_classes:
        head = "Intellectual property theft"
    elif privilege in (Privilege.ADMIN, Privilege.DATA_ADMIN):
        head = "Crown jewel takeover"
    else:
        head = "Crown jewel compromise"
    return f"{head} ({asset.hostname})"


def _asset_scale(asset: Asset, snapshot: Snapshot) -> float:
    """IRIS is a distribution over all breaches at all firms. This is the factor
    that moves it onto one asset: how critical the asset is, and how much of the
    org's personal data sits on it."""
    org_records = max(snapshot.org.pii_records_count, 1)
    pii_share = min(asset.pii_records_held / org_records, 1.0)
    scale = max(asset.criticality_weight, 0.0) * (1.0 + pii_share)
    low, high = ASSET_SCALE_BOUNDS
    return float(min(max(scale, low), high))


def _build_scenarios(
    graph: AttackGraph, paths: PathAnalysis, snapshot: Snapshot
) -> list[_Scenario]:
    """Crown-jewel compromises the attacker can actually reach become scenarios.
    A crown jewel with zero compromise probability contributes zero loss, so it
    is dropped rather than carried as a row of zeroes."""
    assets = {a.asset_id: a for a in snapshot.assets}
    node_index = {n.node_id: n for n in graph.nodes}

    scenarios: list[_Scenario] = []
    for reach in paths.crown_jewel_reach:
        asset = assets.get(reach.asset_id)
        if asset is None or reach.compromise_probability <= 0.0:
            continue
        node = node_index.get(reach.node_id)
        privilege = node.privilege if node else Privilege.DATA_ADMIN

        scenarios.append(
            _Scenario(
                scenario_id=f"sc-{reach.node_id.replace(':', '-')}",
                name=_scenario_name(asset, privilege),
                node_id=reach.node_id,
                asset=asset,
                compromise_probability=min(reach.compromise_probability, 1.0),
                asset_scale=_asset_scale(asset, snapshot),
                pii_touched=DataClass.PII in asset.data_classes and asset.pii_records_held > 0,
                path_node_ids=tuple(reach.top_path_node_ids),
            )
        )
    scenarios.sort(key=lambda s: s.scenario_id)
    return scenarios


# --------------------------------------------------------------------------- #
# random draws (common random numbers)
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class _IntrusionDraws:
    """The org-level intrusion process, shared by every scenario.

    ``u_counts`` feeds an inverse-CDF Poisson, so moving the base rate moves the
    counts deterministically off the same uniforms instead of redrawing them.
    The pool is sized for the largest rate any perturbation can ask for; a
    smaller rate reads a prefix of the same numbers. That is what makes a +/-20%
    swing a signal rather than Monte Carlo noise.
    """
    u_counts: np.ndarray      # (trials,)  uniform, inverse-CDF Poisson
    pool: int


@dataclass(frozen=True)
class _Draws:
    """One scenario's random numbers, indexed by intrusion. Drawn once, reused by
    every perturbation.

    Every array is aligned to the shared intrusion pool: element j describes what
    happens to THIS crown jewel during intrusion j. ``u_reach`` decides whether
    the intruder gets to it at all.
    """
    u_reach: np.ndarray       # (pool,)    uniform, is this jewel reached
    z_severity: np.ndarray    # (pool,)    standard normal, event magnitude
    z_recovery: np.ndarray    # (pool,)    standard normal, outage hours
    z_exposed: np.ndarray     # (pool,)    standard normal, records exfiltrated
    z_churn: np.ndarray       # (pool,)    standard normal, churn rate
    z_penalty: np.ndarray     # (pool,)    standard normal, DPDP share of ceiling
    u_penalty: np.ndarray     # (pool,)    uniform, is a penalty levied at all


#: Scenario index reserved for the org-level intrusion process.
_INTRUSION_STREAM = 9_999


def _stream(seed: int, scenario_index: int, stream_index: int) -> np.random.Generator:
    """One independent generator per (scenario, purpose). Deriving them from a
    SeedSequence rather than one shared generator is what lets a perturbation
    change the length of one array without disturbing any of the others."""
    return np.random.default_rng(np.random.SeedSequence([seed, scenario_index, stream_index]))


def _pool_size(rate: float, trials: int) -> int:
    """Enough intrusions for the fattest rate a perturbation can produce, plus a
    wide margin. The sum of `trials` Poissons has sd sqrt(trials * rate)."""
    expected = trials * rate * POOL_LAMBDA_HEADROOM
    return int(math.ceil(expected + POOL_SIGMA_MARGIN * math.sqrt(max(expected, 1.0)))) + 64


def _draw(
    scenarios: list[_Scenario], params: _Params, config: SimConfig
) -> tuple[_IntrusionDraws, list[_Draws]]:
    horizon = config.horizon_days / 365.0
    pool = _pool_size(params.org_annual_incident_rate * horizon, config.trials)
    intrusions = _IntrusionDraws(
        u_counts=_stream(config.seed, _INTRUSION_STREAM, 0).random(config.trials),
        pool=pool,
    )
    draws = [
        _Draws(
            u_reach=_stream(config.seed, i, 0).random(pool),
            z_severity=_stream(config.seed, i, 1).standard_normal(pool),
            z_recovery=_stream(config.seed, i, 2).standard_normal(pool),
            z_exposed=_stream(config.seed, i, 3).standard_normal(pool),
            z_churn=_stream(config.seed, i, 4).standard_normal(pool),
            z_penalty=_stream(config.seed, i, 5).standard_normal(pool),
            u_penalty=_stream(config.seed, i, 6).random(pool),
        )
        for i in range(len(scenarios))
    ]
    return intrusions, draws


# --------------------------------------------------------------------------- #
# the simulation itself
# --------------------------------------------------------------------------- #

_COMPONENT_ORDER = (
    LossComponent.DOWNTIME,
    LossComponent.BREACH_RESPONSE,
    LossComponent.REGULATORY,
    LossComponent.REPUTATIONAL,
)


@dataclass
class _Sample:
    total: np.ndarray                            # (trials,) aggregate annual loss
    components: dict[LossComponent, np.ndarray]  # (trials,) each, summing to total
    per_scenario: list[np.ndarray]               # one (trials,) array per scenario
    event_counts: list[int]


def _intrusion_index(
    intrusions: _IntrusionDraws,
    rate: float,
    trials: int,
    cache: dict[tuple[int, float], tuple[np.ndarray, int]],
) -> tuple[np.ndarray, int]:
    """Inverse-CDF Poisson counts, flattened to one trial index per intrusion.

    Cached on (draw identity, rate). The sensitivity sweep re-evaluates the model
    24 times and only one of the twelve perturbed parameters moves the rate, so
    without this the scipy ppf -- easily the most expensive call in the module --
    would run 25 times to produce the same answer.
    """
    key = (id(intrusions), rate)
    hit = cache.get(key)
    if hit is not None:
        return hit
    counts = poisson.ppf(intrusions.u_counts, rate).astype(np.int64)
    n = int(counts.sum())
    if n > intrusions.pool:  # pragma: no cover - the pool carries a 12-sigma margin
        raise RuntimeError(
            f"intrusion pool exhausted: {n} > {intrusions.pool}. Raise POOL_LAMBDA_HEADROOM."
        )
    value = (np.repeat(np.arange(trials), counts), n)
    cache[key] = value
    return value


def _evaluate(
    scenarios: list[_Scenario],
    intrusions: _IntrusionDraws,
    draws: list[_Draws],
    snapshot: Snapshot,
    params: _Params,
    config: SimConfig,
    cache: dict[tuple[int, float], tuple[np.ndarray, int]] | None = None,
) -> _Sample:
    """Vectorised over every event in every trial at once. The only Python loop
    is over scenarios, of which there are a handful."""
    trials = config.trials
    if cache is None:
        cache = {}
    horizon = config.horizon_days / 365.0

    total = np.zeros(trials)
    components = {c: np.zeros(trials) for c in _COMPONENT_ORDER}
    per_scenario: list[np.ndarray] = []
    event_counts: list[int] = []

    sigma_sev = params.severity_sigma
    sigma_rec = params.recovery_sigma
    mu_sev_base = math.log(max(params.iris_median_inr, 1e-9))
    mu_rec = math.log(max(params.recovery_hours_median, 1e-9))
    mu_exp = math.log(max(params.records_exposed_fraction_median, 1e-9))
    mu_churn = math.log(max(params.reputational_churn_rate, 1e-12))
    mu_pen = math.log(max(params.dpdp_ceiling_share_median, 1e-9))
    event_cap = params.event_cap_multiple_of_revenue * snapshot.org.annual_revenue_inr
    annual_revenue = snapshot.org.annual_revenue_inr

    # ---- frequency: ONE intrusion process for the whole org ---------------
    # Anchored to the org's own base rate. The path analysis probabilities are
    # applied below as conditional reach, not as rates of their own.
    rate = params.org_annual_incident_rate * horizon
    trial_of_intrusion, intrusion_count = _intrusion_index(intrusions, rate, trials, cache)

    for sc, dr in zip(scenarios, draws):
        # ---- reach: given an intrusion, is THIS jewel compromised ----------
        # Drawn per intrusion, so one intrusion can reach several jewels and the
        # losses land in the same trial. That correlation is the point.
        reached = np.flatnonzero(dr.u_reach[:intrusion_count] < sc.compromise_probability)
        n = int(reached.size)
        event_counts.append(n)
        if n == 0:
            per_scenario.append(np.zeros(trials))
            continue
        trial_of_event = trial_of_intrusion[reached]

        # ---- severity: the IRIS lognormal, moved onto this asset -----------
        mu_sev = mu_sev_base + math.log(sc.asset_scale)
        severity = np.exp(mu_sev + sigma_sev * dr.z_severity[reached])
        severity = _saturate(severity, event_cap)

        # ---- regulatory: direct in rupees, DPDP-ceiling-bounded ------------
        # Only when a PII data class is touched. Correlated with how bad the
        # event was, on a square root so a 50x event is a 7x fine, then hard
        # capped at the 250 crore security-safeguards ceiling.
        if sc.pii_touched:
            ratio = np.sqrt(np.maximum(severity, 1.0) / max(math.exp(mu_sev), 1.0))
            share = np.exp(mu_pen + DPDP_CEILING_SHARE_SIGMA * dr.z_penalty[reached]) * ratio
            share = np.clip(share, 0.0, 1.0)
            levied = dr.u_penalty[reached] < params.dpdp_penalty_applied_probability
            regulatory = np.where(levied, params.dpdp_security_ceiling_inr * share, 0.0)
            regulatory = np.minimum(regulatory, params.dpdp_security_ceiling_inr)
        else:
            regulatory = np.zeros(n)

        # ---- the other three: rupee mechanisms, used as shares of the rest --
        hours = np.exp(mu_rec + sigma_rec * dr.z_recovery[reached])
        downtime_raw = (
            sc.asset.revenue_dependency_inr_per_hour * hours * sc.asset.criticality_weight
        )

        if sc.asset.pii_records_held > 0:
            exposed = np.clip(
                np.exp(mu_exp + RECORDS_EXPOSED_FRACTION_SIGMA * dr.z_exposed[reached]), 0.0, 1.0
            )
            breach_raw = params.breach_cost_per_record_inr * sc.asset.pii_records_held * exposed
        else:
            breach_raw = np.zeros(n)

        churn = np.exp(mu_churn + REPUTATIONAL_CHURN_SIGMA * dr.z_churn[reached])
        reputational_raw = churn * annual_revenue * sc.asset.criticality_weight

        # The event total is the severity draw, unless the fine alone exceeds it.
        event_total = np.maximum(severity, regulatory)
        remainder = event_total - regulatory

        raw_sum = downtime_raw + breach_raw + reputational_raw
        # An asset with no revenue dependency, no records and zero criticality
        # has no mechanism to split on; the remainder lands on reputational,
        # the only component that does not need an attribute of the asset.
        degenerate = raw_sum <= 0.0
        safe_sum = np.where(degenerate, 1.0, raw_sum)
        downtime = remainder * np.where(degenerate, 0.0, downtime_raw / safe_sum)
        breach = remainder * np.where(degenerate, 0.0, breach_raw / safe_sum)
        reputational = remainder * np.where(degenerate, 1.0, reputational_raw / safe_sum)

        scenario_total = np.zeros(trials)
        for component, values in (
            (LossComponent.DOWNTIME, downtime),
            (LossComponent.BREACH_RESPONSE, breach),
            (LossComponent.REGULATORY, regulatory),
            (LossComponent.REPUTATIONAL, reputational),
        ):
            binned = np.bincount(trial_of_event, weights=values, minlength=trials)
            components[component] += binned
            scenario_total += binned

        per_scenario.append(scenario_total)
        total += scenario_total

    return _Sample(
        total=total, components=components, per_scenario=per_scenario, event_counts=event_counts
    )


# --------------------------------------------------------------------------- #
# exceedance curve
# --------------------------------------------------------------------------- #

def _exceedance_curve(total: np.ndarray) -> list[ExceedancePoint]:
    """Loss levels taken from the trial quantiles, then the exceedance at each
    read straight off the empirical distribution, so the curve is consistent
    with the sample rather than with the quantile grid that produced it.

    Strictly decreasing by construction: duplicate loss levels (a heavy point
    mass at zero produces them) and duplicate probabilities are dropped.
    """
    if total.size == 0:
        return []
    ordered = np.sort(total)
    levels = np.quantile(ordered, EXCEEDANCE_QUANTILES)

    points: list[ExceedancePoint] = []
    seen_loss: set[float] = set()
    last_probability = 1.1
    for level in levels:
        loss = round(float(level), 2)
        if loss <= 0.0 or loss in seen_loss:
            continue
        # P(L > loss). searchsorted 'right' counts everything <= loss.
        probability = 1.0 - float(np.searchsorted(ordered, level, side="right")) / ordered.size
        probability = round(min(max(probability, 0.0), 1.0), 6)
        if probability >= last_probability:
            continue
        seen_loss.add(loss)
        last_probability = probability
        points.append(ExceedancePoint(loss_inr=loss, probability_of_exceeding=probability))
    return points


# --------------------------------------------------------------------------- #
# attribution: EAL back onto nodes and findings
# --------------------------------------------------------------------------- #

def _best_edges(graph: AttackGraph) -> dict[tuple[str, str], object]:
    """Highest-probability edge for each (source, target). The trace panel walks
    the most likely story, so attribution follows the same edge."""
    best: dict[tuple[str, str], object] = {}
    for edge in graph.edges:
        key = (edge.source_node_id, edge.target_node_id)
        current = best.get(key)
        if current is None or edge.probability > current.probability:  # type: ignore[attr-defined]
            best[key] = edge
    return best


def _top_drivers(
    graph: AttackGraph,
    paths: PathAnalysis,
    snapshot: Snapshot,
    scenarios: list[_Scenario],
    scenario_eal: list[float],
) -> list[LossDriver]:
    """Push each scenario's EAL back down its highest-probability path.

    Node attribution is a partition: the weights along one path are normalised,
    so the node rows sum to the total EAL and the trace panel can say "this much
    of the number came through this state". Weights are the choke-point share
    where ``analyze_paths`` computed one -- a node that sits on most of the
    crown-jewel-reaching paths earns more of the blame than one that sits on a
    single path -- and a flat share otherwise.

    Finding attribution re-projects the same rupees onto the enabler finding of
    the edge that entered each node, so the two views do not add together.
    """
    choke = {c.node_id: c.paths_through_fraction for c in paths.choke_points}
    node_index = {n.node_id: n for n in graph.nodes}
    assets = {a.asset_id: a for a in snapshot.assets}
    findings = {f.finding_id: f for f in snapshot.findings}
    edges = _best_edges(graph)

    node_eal: dict[str, float] = {}
    finding_eal: dict[str, float] = {}

    for sc, eal in zip(scenarios, scenario_eal):
        if eal <= 0.0:
            continue
        # The entry state is the internet, which is not something anyone can fix.
        path = [n for n in sc.path_node_ids if n in node_index] or [sc.node_id]
        chain = [n for n in path if n not in graph.entry_node_ids] or [sc.node_id]

        weights = [max(choke.get(n, 0.0), 0.0) for n in chain]
        if sum(weights) <= 0.0:
            weights = [1.0] * len(chain)
        # The crown jewel itself is never a choke point (analyze_paths excludes
        # it), but it is where the loss lands, so it gets the mean weight.
        mean_weight = sum(weights) / len(weights)
        weights = [
            w if w > 0.0 else mean_weight for w in weights
        ]
        denominator = sum(weights)

        for position, node_id in enumerate(chain):
            share = eal * weights[position] / denominator
            node_eal[node_id] = node_eal.get(node_id, 0.0) + share

            # The action that put the attacker into this state.
            previous = path[path.index(node_id) - 1] if path.index(node_id) > 0 else None
            edge = edges.get((previous, node_id)) if previous else None
            finding_id = getattr(edge, "enabler_finding_id", None)
            if finding_id:
                finding_eal[finding_id] = finding_eal.get(finding_id, 0.0) + share

    drivers: list[LossDriver] = []

    for node_id, amount in sorted(node_eal.items(), key=lambda kv: (-kv[1], kv[0]))[
        :MAX_NODE_DRIVERS
    ]:
        node = node_index[node_id]
        asset = assets.get(node.asset_id)
        hostname = asset.hostname if asset else node.asset_id
        drivers.append(
            LossDriver(
                ref_type="node",
                ref_id=node_id,
                label=f"{hostname} ({node.privilege.value})",
                attributed_eal_inr=round(amount, 2),
            )
        )

    for finding_id, amount in sorted(finding_eal.items(), key=lambda kv: (-kv[1], kv[0]))[
        :MAX_FINDING_DRIVERS
    ]:
        finding = findings.get(finding_id)
        if finding is None:
            label = finding_id
        else:
            asset = assets.get(finding.asset_id)
            hostname = asset.hostname if asset else finding.asset_id
            label = f"{finding.cve_id or finding_id} on {hostname}"
        drivers.append(
            LossDriver(
                ref_type="finding",
                ref_id=finding_id,
                label=label,
                attributed_eal_inr=round(amount, 2),
            )
        )

    drivers.sort(key=lambda d: (-d.attributed_eal_inr, d.ref_type, d.ref_id))
    return drivers


# --------------------------------------------------------------------------- #
# assumptions + sensitivity
# --------------------------------------------------------------------------- #

def _assumption_rows(params: _Params, snapshot: Snapshot) -> list[Assumption]:
    """Every soft input, with an honest confidence label. `measured` is reserved
    for things read straight off the snapshot; nothing in this list qualifies,
    because the snapshot values are inputs, not assumptions."""
    sigma = params.severity_sigma
    return [
        Assumption(
            key="severity_model",
            value=(
                "IRIS lognormal sets the event magnitude; the org's own exposure "
                "figures set the split across the four components"
            ),
            unit=None,
            source="Design decision, stated in packages/core/crq_core/loss.py",
            confidence="estimated",
        ),
        Assumption(
            key="usd_inr_rate",
            value=params.usd_inr_rate,
            unit="INR per USD",
            source="Declared conversion rate for the USD-denominated IRIS calibration",
            confidence="estimated",
        ),
        Assumption(
            key="iris_severity_median_usd",
            value=params.iris_median_usd,
            unit="USD",
            source="Cyentia IRIS 2025, median per-event loss",
            confidence="public_data",
        ),
        Assumption(
            key="iris_severity_p95_usd",
            value=params.iris_p95_usd,
            unit="USD",
            source="Cyentia IRIS 2025, 95th percentile per-event loss",
            confidence="public_data",
        ),
        Assumption(
            key="severity_lognormal_sigma",
            value=round(sigma, 4),
            unit="log-scale",
            source=(
                "Derived: iris_population_sigma * sqrt(within_firm_variance_share). "
                "Variances add, so the share is taken under a square root."
            ),
            confidence="estimated",
        ),
        Assumption(
            key="severity_lognormal_median_inr",
            value=round(params.iris_median_inr, 2),
            unit="INR per event at asset scale 1.0",
            source="IRIS median converted at the declared USD/INR rate",
            confidence="public_data",
        ),
        Assumption(
            key="asset_scale_formula",
            value="criticality_weight * (1 + pii_records_held / org.pii_records_count)",
            unit=f"clipped to {ASSET_SCALE_BOUNDS}",
            source="Team model. Moves the IRIS distribution onto one asset.",
            confidence="estimated",
        ),
        Assumption(
            key="org_annual_incident_rate",
            value=round(params.org_annual_incident_rate, 4),
            unit="significant cyber incidents per year",
            source=(
                f"IRIS/VCDB-style base rate for a {snapshot.org.employee_count}-employee "
                f"'{snapshot.org.sector}' firm: size-band rate for the "
                "250-1,000 headcount range, times a sector multiplier. VCDB shows "
                "financial services carrying about half again its share of recorded "
                "incidents. Anchors the whole frequency model."
            ),
            confidence="public_data",
        ),
        Assumption(
            key="frequency_model",
            value=(
                "one Poisson intrusion process at org_annual_incident_rate; "
                "path probabilities decide which jewels each intrusion reaches"
            ),
            unit=None,
            source=(
                "Path analysis probabilities are conditional on an intrusion, not "
                "annual rates. Using them as rates counts the probability of "
                "getting in once per crown jewel."
            ),
            confidence="estimated",
        ),
        Assumption(
            key="within_firm_variance_share",
            value=params.within_firm_variance_share,
            unit="share of IRIS log-variance that is within-firm",
            source=(
                "IRIS pools firms across several orders of magnitude of revenue, so "
                "most of its spread is between firms. This snapshot already fixes "
                "the firm, so only the within-firm part applies. Split is a team "
                "estimate; no published decomposition exists."
            ),
            confidence="estimated",
        ),
        Assumption(
            key="iris_population_sigma",
            value=round(params.iris_population_sigma, 4),
            unit="log-scale",
            source="Derived: ln(p95 / median) / 1.6449 over the two IRIS points",
            confidence="public_data",
        ),
        Assumption(
            key="recovery_hours_median",
            value=params.recovery_hours_median,
            unit="hours",
            source="Team estimate for a crown-jewel outage. No incident history to fit.",
            confidence="estimated",
        ),
        Assumption(
            key="recovery_hours_p95",
            value=params.recovery_hours_p95,
            unit="hours",
            source="Team estimate. Sets the downtime lognormal sigma with the median.",
            confidence="estimated",
        ),
        Assumption(
            key="breach_response_cost_per_record_inr",
            value=params.breach_cost_per_record_inr,
            unit="INR per record",
            source=(
                "IBM Cost of a Data Breach, India 2025: average breach cost divided "
                "by average breach size. IBM does not publish a per-record figure."
            ),
            confidence="public_data",
        ),
        Assumption(
            key="records_exposed_fraction_median",
            value=params.records_exposed_fraction_median,
            unit="fraction of records held on the asset",
            source="Team estimate. A data_admin compromise rarely takes the whole store.",
            confidence="estimated",
        ),
        Assumption(
            key="dpdp_security_ceiling_inr",
            value=params.dpdp_security_ceiling_inr,
            unit="INR per instance",
            source="DPDP Act 2023, Schedule: failure to take reasonable security safeguards",
            confidence="public_data",
        ),
        Assumption(
            key="dpdp_penalty_applied_probability",
            value=params.dpdp_penalty_applied_probability,
            unit="probability a penalty is levied at all",
            source="The Data Protection Board has no enforcement history to fit to.",
            confidence="guess",
        ),
        Assumption(
            key="dpdp_ceiling_share_median",
            value=params.dpdp_ceiling_share_median,
            unit="fraction of the 250 crore ceiling",
            source="No enforcement history. Scaled with event severity, hard-capped.",
            confidence="guess",
        ),
        Assumption(
            key="reputational_churn_rate",
            value=params.reputational_churn_rate,
            unit="fraction of annual revenue lost to churn",
            source=(
                "Team estimate. NO defensible public source exists for Indian broking "
                "customer churn after a breach. This is a guess and is labelled one."
            ),
            confidence="guess",
        ),
        Assumption(
            key="event_cap_multiple_of_revenue",
            value=params.event_cap_multiple_of_revenue,
            unit=f"x annual revenue (INR {snapshot.org.annual_revenue_inr:,.0f})",
            source=(
                "Team judgement: a single event cannot cost a going concern more "
                "than a year of revenue. Truncates an artefact of the lognormal tail."
            ),
            confidence="estimated",
        ),
    ]


def _rank_sensitivity(
    assumptions: list[Assumption],
    scenarios: list[_Scenario],
    intrusions: _IntrusionDraws,
    draws: list[_Draws],
    snapshot: Snapshot,
    base: _Params,
    config: SimConfig,
    cache: dict[tuple[int, float], tuple[np.ndarray, int]],
) -> None:
    """One-at-a-time +/-20%, ranked by the swing in EAL. Mutates the rows in
    place, because the ranking is a property of the assumption, not a separate
    artifact.

    Every perturbation reads the same random numbers as the baseline, so the
    swing is the parameter's effect and not Monte Carlo noise.
    """
    swings: list[tuple[str, float]] = []
    for field, key in PERTURBABLE:
        current = getattr(base, field)
        highs = _evaluate(
            scenarios, intrusions, draws, snapshot,
            replace(base, **{field: current * (1 + PERTURBATION)}), config, cache,
        )
        lows = _evaluate(
            scenarios, intrusions, draws, snapshot,
            replace(base, **{field: current * (1 - PERTURBATION)}), config, cache,
        )
        swings.append((key, abs(float(highs.total.mean()) - float(lows.total.mean()))))

    swings.sort(key=lambda kv: (-kv[1], kv[0]))
    ranks = {key: i + 1 for i, (key, _) in enumerate(swings)}
    for assumption in assumptions:
        assumption.sensitivity_rank = ranks.get(assumption.key)


# --------------------------------------------------------------------------- #
# simulate
# --------------------------------------------------------------------------- #

def simulate(graph: AttackGraph, paths: PathAnalysis, snapshot: Snapshot,
             config: SimConfig) -> LossResult:
    """Deterministic given config.seed. Common random numbers depend on this."""
    if config.trials < 1:
        raise ValueError("SimConfig.trials must be positive")
    if config.horizon_days < 1:
        raise ValueError("SimConfig.horizon_days must be positive")

    params = _Params(org_annual_incident_rate=_base_incident_rate(snapshot))
    scenarios = _build_scenarios(graph, paths, snapshot)
    intrusions, draws = _draw(scenarios, params, config)
    # Shared across the baseline run and every sensitivity perturbation, so the
    # Poisson inversion happens once per base rate rather than once per
    # evaluation. `intrusions` is held for the lifetime of the call, so keying
    # the cache on object identity is safe.
    cache: dict[tuple[int, float], tuple[np.ndarray, int]] = {}
    sample = _evaluate(scenarios, intrusions, draws, snapshot, params, config, cache)

    total = sample.total
    eal = float(total.mean())

    # ---- scenario contributions ------------------------------------------ #
    # Trial totals are the sum of the per-scenario trial totals, so the scenario
    # EALs sum to the overall EAL exactly and the shares sum to 1.0.
    scenario_eal = [float(s.mean()) for s in sample.per_scenario]
    eal_sum = sum(scenario_eal)
    contributions: list[ScenarioContribution] = []
    if scenario_eal:
        shares = [(v / eal_sum) if eal_sum > 0 else 0.0 for v in scenario_eal]
        # Round-then-fix so the shares still sum to exactly 1.0 after rounding.
        rounded = [round(s, 6) for s in shares]
        if rounded:
            leader = max(range(len(rounded)), key=lambda i: rounded[i])
            rounded[leader] = round(rounded[leader] + (1.0 - sum(rounded)), 6)
        for sc, value, share in zip(scenarios, scenario_eal, rounded):
            contributions.append(
                ScenarioContribution(
                    scenario_id=sc.scenario_id,
                    name=sc.name,
                    triggering_node_ids=[sc.node_id],
                    annual_frequency=round(
                        params.org_annual_incident_rate * sc.compromise_probability, 6
                    ),
                    eal_inr=round(value, 2),
                    share_of_total=min(max(share, 0.0), 1.0),
                )
            )
        contributions.sort(key=lambda c: (-c.eal_inr, c.scenario_id))

    # ---- component split -------------------------------------------------- #
    # Same trick: the components are a partition of every event, so their means
    # sum to the EAL. Rounded to paise, with the residual pushed onto the
    # largest so the reconciliation survives the rounding.
    component_means = {c: float(sample.components[c].mean()) for c in _COMPONENT_ORDER}
    component_split = {c: round(v, 2) for c, v in component_means.items()}
    if component_split:
        largest = max(component_split, key=lambda c: component_split[c])
        component_split[largest] = round(
            component_split[largest] + (round(eal, 2) - sum(component_split.values())), 2
        )

    assumptions = _assumption_rows(params, snapshot)
    _rank_sensitivity(assumptions, scenarios, intrusions, draws, snapshot, params, config, cache)

    stem = graph.graph_id[len("GRAPH-"):] if graph.graph_id.startswith("GRAPH-") else graph.graph_id

    return LossResult(
        loss_result_id=f"LOSS-{stem}",
        graph_id=graph.graph_id,
        path_analysis_id=paths.path_analysis_id,
        config=config,
        eal_inr=round(eal, 2),
        median_inr=round(float(np.median(total)), 2),
        p95_inr=round(float(np.quantile(total, 0.95)), 2),
        p99_inr=round(float(np.quantile(total, 0.99)), 2),
        exceedance_curve=_exceedance_curve(total),
        component_split_inr=component_split,
        scenario_contributions=contributions,
        top_drivers=_top_drivers(graph, paths, snapshot, scenarios, scenario_eal),
        assumptions=assumptions,
    )
