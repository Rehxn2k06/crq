"""P1. Synthetic enterprise generator. See contracts/FUNCTIONS.md.

``generate_enterprise`` builds a Snapshot that looks like a mid-size SEBI-regulated
broking house: a DMZ that faces the internet, an internal tier that does the work,
an identity tier with a domain controller, and a data tier holding the crown jewels.

Three things this module is careful about, because everything downstream depends
on them:

* **Determinism.** Every random draw comes from one ``random.Random(seed)`` that
  is consumed in a fixed order, and ``created_at`` is a fixed constant rather
  than the clock. Same ``(profile, asset_count, seed)`` in, byte-identical
  Snapshot out. P3's common-random-numbers argument only works if the input is
  stable too.
* **Graph behaviour.** A synthetic org is only useful if ``build_graph`` +
  ``analyze_paths`` produce an interesting answer over it. A topology with no
  credential reuse gives crown-jewel compromise probabilities of ~0; one with
  reuse everywhere and no compensating controls gives ~1. Both are useless. The
  tunables below are set so the crown jewels land inside ``CJ_PROBABILITY_BAND``;
  ``packages/ingest/tests/test_synthetic.py`` asserts it.
* **Honesty about what is fabricated.** ``provenance`` is SYNTHETIC and every
  ``Finding.source`` is ``"synthetic"`` -- this data never touched a scanner and
  does not claim to. The KEV findings carry *real* CVE ids with their real
  CVSS/EPSS/KEV status, because a demo that says "Citrix Bleed" should mean it.
  Everything else carries a deliberately non-CVE-shaped ``SYN-<year>-<n>`` id so
  nothing downstream can mistake filler for a real advisory.

Topology, and why it is shaped this way
---------------------------------------
The attack story the graph should find is the one a broking firm actually loses
sleep over::

    internet -> DMZ front-end (R1, unpatched edge device)
             -> internal application tier (R4, the service credential the
                dependency implies)
             -> database (R4 data dependency, then a local escalation on the
                box lands the attacker as data_admin)

plus two alternatives the graph also finds. The build server holds a database
account with full rights on production, so admin there is the data (R3); and
admin on a credential-storing host yields a domain account, which leads to the
domain controller and from there to an impersonation of anyone (R3b/R3c). All
of them are throttled by the controls a SEBI-regulated firm is required to have
-- PAM on the data tier, MFA on privileged accounts, a WAF in front of the DMZ
-- which is why the probabilities come out interesting rather than saturated.

One route in here is deliberately present but dormant: the DBA's own account,
homed on an admin workstation and reused across the databases. The v1 rule set
has no initial-access-on-a-workstation rule -- no phishing, no malicious
attachment -- so the office fleet is never reached and that credential never
fires. It is generated anyway because it is real, it is what a phishing rule
would light up the moment P2 adds one, and it is a large part of why
``dead_end_node_fraction`` sits around 0.5 rather than near zero.

Assumptions are named constants with a comment. Nothing here is a magic number
sitting inline.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

from crq_core.schemas import (
    AppliedControl,
    Asset,
    AssetType,
    DataClass,
    Dependency,
    Finding,
    Identity,
    OrgProfile,
    Privilege,
    Provenance,
    Snapshot,
    TelemetryMetrics,
)

# --------------------------------------------------------------------------- #
# TUNABLES. Changing any of these moves the graph, so re-run the validation gate
# in tests/test_synthetic.py::test_crown_jewel_probabilities_are_in_band.
#
# These are calibrated for an estate of roughly 200 assets, which is the size
# the demo org is. The generator scales to any size and stays internally
# consistent, but the crown-jewel probabilities drift upwards as it grows: more
# assets means more instances of each role, and every extra front-end or
# application server is another parallel route that the noisy-OR in
# analyze_paths adds to the total. Measured over 25 seeds per size, the band
# holds comfortably at 80-350 assets and the top of the range starts crossing
# 0.6 at around 500. Re-tune CROWN_JEWEL_ESCALATION_EPSS if a much larger
# estate is needed; the honest fix is to model a web farm behind a load
# balancer as one route rather than N, which is a change to the topology and
# not to a constant.
# --------------------------------------------------------------------------- #

#: Snapshots are timestamped, not clocked. A generator that called now() would
#: not be reproducible.
SNAPSHOT_EPOCH = datetime(2026, 3, 31, 18, 30, tzinfo=timezone.utc)

#: FUNCTIONS.md: "~15% of assets internet-facing at most". We sit under it and
#: assert the cap before returning.
MAX_INTERNET_FACING_FRACTION = 0.15
DMZ_FRACTION = 0.12
IDENTITY_FRACTION = 0.04
DATA_FRACTION = 0.14

#: 3-5 crown jewels, all holding PII. Fewer and the loss model has nothing to
#: aim at; more and every path analysis looks the same.
CROWN_JEWEL_COUNT = 4

#: Findings per asset by tier. Edge devices and databases get scanned harder
#: than a dealer workstation does.
FINDINGS_PER_ASSET = {"dmz": 2.2, "internal": 1.35, "identity": 2.5, "data": 2.8}
#: The brief's range. The plan is trimmed to hit FINDINGS_PER_ASSET_TARGET
#: exactly, clamped into these.
FINDINGS_FLOOR = 250
FINDINGS_CEILING = 400
FINDINGS_PER_ASSET_TARGET = 1.7

#: Share of findings already closed. Doubles as the CCI vulnerability-management
#: numerator, so it is the same number the compliance score sees.
MITIGATED_FRACTION = 0.62

#: Which roles still carry something exploitable with no credentials at all.
#: This is the width of the front door and the biggest single lever on the
#: crown-jewel probabilities.
#:
#: One host per exposure class rather than N hosts at random: an internet-facing
#: estate this size always has something unpatched in each class, and choosing at
#: random leaves whole routes with no front door on some seeds -- which makes the
#: validation gate depend on the dice rather than on the topology. The seed still
#: picks *which* instance of the role and what its score is.
DMZ_ENTRY_ROLES = ("trade-web", "client-portal", "api-gw", "kyc-upload", "mktg-site")
#: Internal roles with a no-credentials-needed bug, so a pivot has something to
#: land on besides a replayed service credential.
INTERNAL_ENTRY_ROLES = ("app-oms", "app-kyc", "jump-host", "file-share")
#: Share of an eligible host's findings that come out as the remote kind.
REMOTE_FINDING_SHARE = 0.45

#: Roles on the route to the crown jewels. build_graph *folds* a local privilege
#: escalation into whichever edge arrives on a host, so an unpatched low-EPSS
#: privesc sitting on a pivot host does not add a step to the path -- it
#: multiplies the whole remainder of the route by that finding's probability and
#: makes the route vanish. Which is also true in life, and these are the hosts a
#: regulated broker actually patches. The long tail of privilege escalation
#: lives on the office fleet, the identity tier and the secondary data stores.
_SPINE_STEMS = frozenset(
    {"trade-web", "client-portal", "api-gw", "kyc-upload", "mail-gw", "vpn", "edge-lb",
     "sftp-partner", "crm-saas", "mktg-site",
     "app-oms", "app-rms", "app-trade", "app-backoffice", "app-kyc", "analytics-etl",
     "jump-host",
     "db-customer", "db-kyc", "db-settlement", "s3-archive"}
)

#: Every crown jewel carries one unpatched escalation from a login on the box to
#: control of the data on it. This is the last hop of the main attack path and
#: the dominant term in the crown-jewel probabilities, so it is planted rather
#: than left to the dice -- and it is what a data store that is one patch cycle
#: behind actually looks like. Tune this first if the validation gate moves.
CROWN_JEWEL_ESCALATION_EPSS = 0.38
CROWN_JEWEL_ESCALATION_CVSS = 8.8

#: EPSS mixture, (weight, low, high). "most under 0.1, a handful above 0.8".
#: The real KEV entries below add their own high scores on top of this.
EPSS_MIXTURE = (
    (0.87, 0.00005, 0.10),
    (0.09, 0.10, 0.40),
    (0.03, 0.40, 0.80),
    (0.01, 0.80, 0.97),
)
#: Findings with no EPSS at all -- hardening and configuration issues that never
#: got a CVE. build_graph falls back to cvss_base/10*0.1 for these.
NO_EPSS_FRACTION = 0.18

#: EPSS for a still-open bug that needs no credentials. Anything unauthenticated
#: and exposed that has survived a patch cycle is, in practice, something that is
#: actively scanned for. Drawing these from the general mixture instead produces
#: front doors with EPSS 0.001, which is not what an exposed estate looks like
#: and makes the crown-jewel probabilities a lottery on which host got which draw.
#: The band is deliberately narrow: these findings sit at the head of every path,
#: so their spread is multiplied through the whole analysis.
ENTRY_FINDING_EPSS_RANGE = (0.30, 0.50)

#: The validation gate. Outside this band the topology is wrong, not the graph.
CJ_PROBABILITY_BAND = (0.05, 0.60)

#: Telemetry is generated so every Annexure-K ratio lands at this share of its
#: target, which puts the CCI in the band the brief asks for. See
#: ``indicative_cci_score``.
CCI_TARGET_RATIO = 0.63
#: SEBI expects information security to be a stated share of the IT budget.
#: The 10% figure is the commonly cited supervisory expectation, not a hard
#: CSCRF number -- flagged as an assumption for whoever writes compute_cci.
INFOSEC_BUDGET_TARGET_SHARE = 0.10
#: IT budget as a share of revenue, and the counters derived from headcount.
#: Broking-house rules of thumb, declared here rather than buried inline.
IT_BUDGET_REVENUE_SHARE = 0.035
REMOTE_USER_SHARE_OF_STAFF = 0.42
INCIDENTS_PER_HEAD = 0.13


# --------------------------------------------------------------------------- #
# role tables. Each row is (stem, asset_type, business_unit, data_classes,
# revenue_inr_per_hour, criticality, weight). `weight` is how often the row is
# used when the tier is filled by cycling.
# --------------------------------------------------------------------------- #

_DMZ_ROLES = [
    ("trade-web", AssetType.SERVER, "digital", [DataClass.PUBLIC], 420_000, 0.75, 3),
    ("client-portal", AssetType.SERVER, "digital", [DataClass.PUBLIC], 380_000, 0.70, 2),
    ("api-gw", AssetType.SERVER, "digital", [DataClass.PUBLIC], 500_000, 0.80, 2),
    ("kyc-upload", AssetType.SERVER, "operations", [DataClass.PII], 90_000, 0.60, 1),
    ("mail-gw", AssetType.SERVER, "it", [], 40_000, 0.45, 1),
    ("vpn", AssetType.NETWORK_DEVICE, "it", [], 0, 0.65, 2),
    ("edge-lb", AssetType.NETWORK_DEVICE, "it", [], 0, 0.50, 1),
    ("sftp-partner", AssetType.SERVER, "operations", [DataClass.FINANCIAL], 60_000, 0.55, 1),
    ("crm-saas", AssetType.SAAS, "sales", [DataClass.PII], 0, 0.50, 1),
    ("mktg-site", AssetType.SERVER, "marketing", [DataClass.PUBLIC], 15_000, 0.25, 1),
]

_INTERNAL_ROLES = [
    ("app-oms", AssetType.SERVER, "trading", [], 620_000, 0.90, 2),
    ("app-rms", AssetType.SERVER, "risk", [], 480_000, 0.88, 1),
    ("app-trade", AssetType.SERVER, "trading", [], 700_000, 0.92, 2),
    ("app-backoffice", AssetType.SERVER, "operations", [], 260_000, 0.75, 2),
    ("app-kyc", AssetType.SERVER, "compliance", [DataClass.PII], 120_000, 0.72, 1),
    ("analytics-etl", AssetType.SERVER, "research", [], 60_000, 0.60, 1),
    ("ci-build", AssetType.SERVER, "engineering", [DataClass.CREDENTIALS], 40_000, 0.80, 1),
    ("jump-host", AssetType.SERVER, "it", [], 0, 0.70, 1),
    ("file-share", AssetType.SERVER, "operations", [DataClass.IP], 30_000, 0.55, 1),
    ("intranet", AssetType.SERVER, "hr", [], 10_000, 0.35, 1),
    ("monitor", AssetType.SERVER, "security", [], 0, 0.55, 1),
    ("core-switch", AssetType.NETWORK_DEVICE, "it", [], 0, 0.60, 2),
    ("ws-dealer", AssetType.WORKSTATION, "trading", [], 45_000, 0.40, 9),
    ("ws-ops", AssetType.WORKSTATION, "operations", [], 0, 0.30, 6),
    ("ws-fin", AssetType.WORKSTATION, "finance", [], 0, 0.32, 4),
    ("ws-research", AssetType.WORKSTATION, "research", [], 0, 0.28, 3),
    ("ws-hr", AssetType.WORKSTATION, "hr", [], 0, 0.25, 2),
    ("ws-compliance", AssetType.WORKSTATION, "compliance", [], 0, 0.35, 2),
    ("ws-it-admin", AssetType.WORKSTATION, "it", [DataClass.CREDENTIALS], 0, 0.65, 1),
    ("ws-dba", AssetType.WORKSTATION, "it", [], 0, 0.68, 1),
]

_IDENTITY_ROLES = [
    ("dc", AssetType.SERVER, "it", [DataClass.CREDENTIALS], 0, 0.95, 2),
    ("pam-vault", AssetType.SERVER, "security", [DataClass.CREDENTIALS], 0, 0.92, 1),
    ("adfs", AssetType.SERVER, "it", [DataClass.CREDENTIALS], 0, 0.85, 1),
    ("mfa-gw", AssetType.SERVER, "security", [], 0, 0.80, 1),
    ("pki-ca", AssetType.SERVER, "security", [DataClass.CREDENTIALS], 0, 0.85, 1),
    ("iam-saas", AssetType.SAAS, "it", [], 0, 0.75, 1),
]

#: The crown jewels, in order. Every one holds PII, per the brief. Last column
#: is pii_records_held rather than a cycling weight.
_CROWN_JEWEL_ROLES = [
    ("db-customer", AssetType.DATABASE, "digital",
     [DataClass.PII, DataClass.FINANCIAL], 620_000, 1.00, 2_400_000),
    ("db-kyc", AssetType.DATABASE, "compliance",
     [DataClass.PII], 210_000, 0.95, 1_600_000),
    ("db-settlement", AssetType.DATABASE, "finance",
     [DataClass.PII, DataClass.FINANCIAL], 540_000, 0.96, 900_000),
    ("s3-archive", AssetType.CLOUD_RESOURCE, "it",
     [DataClass.PII, DataClass.FINANCIAL], 0, 0.88, 2_400_000),
]

_DATA_ROLES = [
    ("db-trading", AssetType.DATABASE, "trading", [DataClass.FINANCIAL], 700_000, 0.90, 2),
    ("db-reference", AssetType.DATABASE, "operations", [], 80_000, 0.55, 2),
    ("db-report", AssetType.DATABASE, "finance", [DataClass.FINANCIAL], 120_000, 0.60, 1),
    ("dw-analytics", AssetType.CLOUD_RESOURCE, "research", [], 40_000, 0.62, 1),
    ("blob-logs", AssetType.CLOUD_RESOURCE, "security", [], 0, 0.45, 1),
    ("db-hrms", AssetType.DATABASE, "hr", [DataClass.PII], 0, 0.50, 1),
]
#: Non-jewel data stores that still hold PII get a token record count, so the
#: estate does not look like all of the PII lives in four boxes.
NON_JEWEL_PII_RECORDS = 40_000

#: Real CISA KEV entries with their real CVSS/EPSS, placed on the role each CVE
#: actually affects. Works out at ~5% of findings.
#: (stem, cve, cvss, epss, grants, requires, title)
_KEV_POOL = [
    ("vpn", "CVE-2024-21887", 9.1, 0.97, Privilege.ADMIN, Privilege.NONE,
     "Ivanti Connect Secure command injection"),
    ("vpn", "CVE-2024-3400", 10.0, 0.94, Privilege.ADMIN, Privilege.NONE,
     "PAN-OS GlobalProtect command injection"),
    ("edge-lb", "CVE-2023-4966", 9.4, 0.96, Privilege.USER, Privilege.NONE,
     "Citrix Bleed session token disclosure"),
    ("edge-lb", "CVE-2022-1388", 9.8, 0.97, Privilege.ADMIN, Privilege.NONE,
     "F5 BIG-IP iControl REST auth bypass"),
    ("api-gw", "CVE-2021-44228", 10.0, 0.97, Privilege.USER, Privilege.NONE,
     "Log4Shell JNDI injection"),
    ("trade-web", "CVE-2023-3519", 9.8, 0.96, Privilege.USER, Privilege.NONE,
     "Citrix ADC unauthenticated RCE"),
    ("sftp-partner", "CVE-2023-34362", 9.8, 0.97, Privilege.USER, Privilege.NONE,
     "MOVEit Transfer SQL injection"),
    ("mail-gw", "CVE-2023-2868", 9.8, 0.97, Privilege.USER, Privilege.NONE,
     "Barracuda ESG command injection"),
    ("ci-build", "CVE-2024-23897", 9.8, 0.90, Privilege.ADMIN, Privilege.NONE,
     "Jenkins arbitrary file read"),
    ("ci-build", "CVE-2024-27198", 9.8, 0.94, Privilege.ADMIN, Privilege.NONE,
     "TeamCity authentication bypass"),
    ("dc", "CVE-2020-1472", 10.0, 0.97, Privilege.ADMIN, Privilege.USER,
     "Zerologon Netlogon privilege escalation"),
    ("dc", "CVE-2021-42287", 8.8, 0.31, Privilege.ADMIN, Privilege.USER,
     "Active Directory sAMAccountName spoofing"),
    ("pki-ca", "CVE-2022-26923", 8.8, 0.01, Privilege.ADMIN, Privilege.USER,
     "AD CS certificate template privilege escalation"),
    ("ws-it-admin", "CVE-2021-34527", 8.8, 0.94, Privilege.ADMIN, Privilege.USER,
     "PrintNightmare print spooler RCE"),
    ("ws-dealer", "CVE-2023-28252", 7.8, 0.01, Privilege.ADMIN, Privilege.USER,
     "Windows CLFS driver privilege escalation"),
    ("ws-ops", "CVE-2023-21746", 7.8, 0.001, Privilege.ADMIN, Privilege.USER,
     "Windows LSA local privilege escalation"),
    ("app-backoffice", "CVE-2024-26169", 7.8, 0.005, Privilege.ADMIN, Privilege.USER,
     "Windows Error Reporting privilege escalation"),
]
#: How many known-exploited bugs are still open on the internet-facing estate.
#: Exactly this many survive rather than each surviving on its own coin flip: a
#: KEV listing floors an edge at 0.6 probability all by itself, so the count left
#: open swings the entire analysis and a binomial draw on it is variance the
#: demo cannot use.
#:
#: Five is not a flattering number, and it is meant to match the rest of the
#: picture rather than a story about emergency patching: this org scores in the
#: Developing band on the CCI and has closed 62% of its findings, so a standing
#: KEV backlog on the perimeter is exactly what it should look like. A firm that
#: patches the edge inside the week does not score 58.
KEV_EDGE_STILL_OPEN = 5

#: KEV entries that stay open whatever the mitigation lottery rolls, because
#: which ones survive decides the shape of the whole analysis rather than just
#: its detail:
#:
#: * the build server is the one internal host the story needs to be
#:   compromisable -- unsegmented, deploying to production, holding a database
#:   account with full rights -- and it is the choke point most paths run through;
#: * the VPN concentrator and the partner file transfer are the two perimeter
#:   holes that lead anywhere. build_graph does not pivot between internet-facing
#:   hosts, so the mail gateway and the load balancer are dead ends by
#:   construction, and a seed that leaves only those open has a perimeter full of
#:   holes that go nowhere and crown-jewel probabilities near zero.
#:
#: All three are the honest ones to pin. Ivanti Connect Secure sat unpatched
#: across the industry for months, unpatched managed file transfer is the
#: most-exploited pattern of the last three years, and the CI box nobody owns is
#: the last thing to get an emergency patch window.
_KEV_ALWAYS_OPEN = frozenset(
    {
        ("ci-build", "CVE-2024-23897"),
        ("vpn", "CVE-2024-21887"),
        ("sftp-partner", "CVE-2023-34362"),
    }
)

#: Controls the org already runs, by hostname prefix. Ids match
#: EXISTING_CONTROL_EFFECTS in crq_core.graph -- an id that module does not know
#: is silently ignored, so inventing new ones here would be a control that does
#: nothing at all.
_EXISTING_CONTROL_PLAN = [
    ("ctl-waf", ("trade-web", "client-portal", "api-gw", "kyc-upload", "mktg-site")),
    ("ctl-edr", ("ws-", "app-", "jump-host", "file-share", "intranet", "ci-build",
                 "analytics-etl")),
    ("ctl-mfa-priv", ("dc-", "pam-vault", "adfs", "mfa-gw", "pki-ca", "iam-saas")),
    ("ctl-pam", ("db-", "s3-", "dw-", "blob-")),
    ("ctl-db-monitor", ("db-customer", "db-kyc", "db-settlement", "s3-archive")),
    # Deliberately no ctl-segment-ci. The build server sits flat on the internal
    # network, which is both the commonest real gap in a firm this size and the
    # single control the optimizer should be able to find and recommend. An org
    # that already has every control is a boring demo and a useless benchmark.
]

#: Which application each internet-facing role proxies to. A front-end talks to
#: the service it fronts, not to all of them -- but the client portal and the
#: API gateway genuinely do fan out, which is what gives every crown jewel more
#: than one route in.
_FRONT_END_BACKENDS = {
    "trade-web": ("app-oms",),
    "client-portal": ("app-oms", "app-kyc"),
    "api-gw": ("app-oms", "app-rms"),
    "kyc-upload": ("app-kyc",),
}

#: East-west service calls inside the application tier.
_APP_TIER_CALLS = (
    ("app-oms", "app-rms"),
    ("app-oms", "app-backoffice"),
    ("app-kyc", "app-backoffice"),
)


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def _expand(roles: list[tuple], count: int) -> list[tuple]:
    """Repeat each role by its weight, then cycle to exactly `count` rows.

    Deterministic and independent of the rng, so the cast of an org is a
    function of its size alone; the seed only moves the numbers on it.
    """
    pattern: list[tuple] = []
    for row in roles:
        pattern.extend([row] * int(row[-1]))
    return [pattern[i % len(pattern)] for i in range(count)]


def _jitter(rng: random.Random, value: float, spread: float = 0.25) -> float:
    """+/- `spread` around `value`. Keeps two hosts in the same role from looking
    like clones without making the totals unpredictable."""
    if value == 0:
        return 0.0
    return round(value * (1.0 + rng.uniform(-spread, spread)), 2)


def _stem_of(asset: Asset) -> str:
    """'app-oms-003' -> 'app-oms'. Roles are how everything downstream in this
    module refers to a group of hosts."""
    return asset.hostname.rsplit("-", 1)[0]


def _draw_epss(rng: random.Random) -> float:
    """One draw from EPSS_MIXTURE, skewed towards the bottom of whichever band it
    lands in. A uniform draw inside the low band would put far too much mass just
    under 0.1; real EPSS is a long tail with almost everything near zero."""
    roll = rng.random()
    cumulative = 0.0
    low, high = EPSS_MIXTURE[-1][1], EPSS_MIXTURE[-1][2]
    for weight, band_low, band_high in EPSS_MIXTURE:
        cumulative += weight
        if roll <= cumulative:
            low, high = band_low, band_high
            break
    return round(low + (high - low) * rng.random() ** 2.2, 5)


def _by_stem(assets: list[Asset]) -> dict[str, list[Asset]]:
    index: dict[str, list[Asset]] = {}
    for asset in assets:
        index.setdefault(_stem_of(asset), []).append(asset)
    return index


def _pick(stems: dict[str, list[Asset]], *names: str) -> list[Asset]:
    """Every asset in the named roles, in estate order."""
    out: list[Asset] = []
    for name in names:
        out.extend(stems.get(name, []))
    return out


# --------------------------------------------------------------------------- #
# tiers
# --------------------------------------------------------------------------- #

def _build_assets(
    rng: random.Random, asset_count: int
) -> tuple[list[Asset], dict[str, list[Asset]]]:
    """The estate, in four tiers. Returns the assets and a tier index."""
    n_dmz = min(
        max(3, round(asset_count * DMZ_FRACTION)),
        int(asset_count * MAX_INTERNET_FACING_FRACTION),
    )
    n_identity = max(len(_IDENTITY_ROLES), round(asset_count * IDENTITY_FRACTION))
    n_data = max(CROWN_JEWEL_COUNT + 2, round(asset_count * DATA_FRACTION))
    n_internal = asset_count - n_dmz - n_identity - n_data
    if n_internal < len(_INTERNAL_ROLES):
        raise ValueError(
            f"asset_count={asset_count} is too small for a four-tier org: the internal "
            f"tier would hold {n_internal} assets and needs at least "
            f"{len(_INTERNAL_ROLES)}. Minimum workable size is "
            f"{len(_INTERNAL_ROLES) + n_dmz + n_identity + n_data}."
        )

    assets: list[Asset] = []
    tiers: dict[str, list[Asset]] = {"dmz": [], "internal": [], "identity": [], "data": []}
    counters: dict[str, int] = {}

    def add(
        stem: str,
        asset_type: AssetType,
        business_unit: str,
        data_classes: list[DataClass],
        revenue: float,
        criticality: float,
        tier: str,
        tags: list[str],
        pii_records: int = 0,
        internet_facing: bool = False,
    ) -> Asset:
        counters[stem] = counters.get(stem, 0) + 1
        hostname = f"{stem}-{counters[stem]:03d}"
        asset = Asset(
            asset_id=f"a-{hostname}",
            hostname=hostname,
            asset_type=asset_type,
            business_unit=business_unit,
            internet_facing=internet_facing,
            revenue_dependency_inr_per_hour=_jitter(rng, revenue),
            data_classes=list(data_classes),
            pii_records_held=pii_records,
            criticality_weight=round(min(1.0, max(0.0, criticality + rng.uniform(-0.05, 0.05))), 2),
            tags=tags,
        )
        assets.append(asset)
        tiers[tier].append(asset)
        return asset

    # -- DMZ. Everything here faces the internet; that is what makes it the DMZ.
    for stem, atype, bu, classes, rev, crit, _w in _expand(_DMZ_ROLES, n_dmz):
        add(stem, atype, bu, classes, rev, crit, "dmz", ["dmz"], internet_facing=True)

    # -- internal.
    for stem, atype, bu, classes, rev, crit, _w in _expand(_INTERNAL_ROLES, n_internal):
        add(stem, atype, bu, classes, rev, crit, "internal", ["internal"])

    # -- identity. Only the primary DC carries the 'identity' tag: crq_core.graph
    #    fans R3b/R3c out over every tagged asset, and a six-way identity provider
    #    is not a real domain, it is a probability multiplier.
    for i, (stem, atype, bu, classes, rev, crit, _w) in enumerate(
        _expand(_IDENTITY_ROLES, n_identity)
    ):
        tags = ["internal", "identity_tier"] + (["identity"] if i == 0 else [])
        add(stem, atype, bu, classes, rev, crit, "identity", tags)

    # -- data. Crown jewels first, then the rest of the estate's data stores.
    for stem, atype, bu, classes, rev, crit, pii in _CROWN_JEWEL_ROLES[:CROWN_JEWEL_COUNT]:
        add(stem, atype, bu, classes, rev, crit, "data", ["data", "crown_jewel"],
            pii_records=pii)
    for stem, atype, bu, classes, rev, crit, _w in _expand(
        _DATA_ROLES, n_data - CROWN_JEWEL_COUNT
    ):
        pii = NON_JEWEL_PII_RECORDS if DataClass.PII in classes else 0
        add(stem, atype, bu, classes, rev, crit, "data", ["data"], pii_records=pii)

    return assets, tiers


# --------------------------------------------------------------------------- #
# dependencies
# --------------------------------------------------------------------------- #

def _build_dependencies(
    tiers: dict[str, list[Asset]], stems: dict[str, list[Asset]]
) -> list[Dependency]:
    """Who talks to whom.

    Dependency *kind* is the lever that matters most here. R4 in crq_core.graph
    treats data/service/trust as "the caller holds a working credential for the
    callee" and hands out a foothold at 0.6 for free; a `network` dependency only
    helps if the far side has something exploitable on it. So the credential-
    bearing kinds are reserved for the flows that really do carry a secret --
    web to app, app to database, CI to app -- and the office LAN is `network`.
    """
    deps: list[Dependency] = []
    seen: set[tuple[str, str]] = set()

    def link(src: Asset, dst: Asset, kind: str, note: str) -> None:
        key = (src.asset_id, dst.asset_id)
        if src.asset_id == dst.asset_id or key in seen:
            return
        seen.add(key)
        deps.append(
            Dependency(from_asset_id=src.asset_id, to_asset_id=dst.asset_id, kind=kind, note=note)
        )

    app_tier = _pick(stems, "app-oms", "app-rms", "app-trade", "app-backoffice", "app-kyc")
    crown_jewels = [a for a in tiers["data"] if "crown_jewel" in a.tags]

    # DMZ -> application tier.
    for front_stem, backend_stems in _FRONT_END_BACKENDS.items():
        for i, front in enumerate(_pick(stems, front_stem)):
            for backend_stem in backend_stems:
                backends = _pick(stems, backend_stem)
                if backends:
                    link(front, backends[i % len(backends)], "service",
                         "front-end proxies to the application tier with a service account")

    # East-west inside the application tier.
    for caller_stem, callee_stem in _APP_TIER_CALLS:
        for i, caller in enumerate(_pick(stems, caller_stem)):
            callees = _pick(stems, callee_stem)
            if callees:
                link(caller, callees[i % len(callees)], "service",
                     "internal service call carrying a shared application credential")

    # Remote access lands on the jump host, and nowhere else.
    for vpn in _pick(stems, "vpn"):
        for jump in _pick(stems, "jump-host"):
            link(vpn, jump, "network", "remote access terminates on the jump host")
    # The jump host is where the administrative credentials for the application
    # tier actually live, so this is a trust relationship and not merely a route.
    for jump in _pick(stems, "jump-host"):
        for app in app_tier[:3]:
            link(jump, app, "trust",
                 "administrators hold standing credentials for this host on the jump box")

    # Partner file transfer feeds back-office.
    for sftp in _pick(stems, "sftp-partner"):
        for app in _pick(stems, "app-backoffice"):
            link(sftp, app, "service", "partner files are picked up by the back-office job")

    # Application tier -> its own database. This is the narrative route to the
    # crown jewels, so it is wired explicitly rather than at random.
    narrative = [
        ("app-oms", "db-customer"),
        ("app-kyc", "db-kyc"),
        ("app-backoffice", "db-settlement"),
        # Back-office reconciliation reads the KYC store for regulatory
        # reporting and the customer master for settlement instructions. Those
        # are the second way in to both, and the reason neither jewel hangs off
        # a single application.
        ("app-backoffice", "db-kyc"),
        ("app-backoffice", "db-customer"),
        ("analytics-etl", "s3-archive"),
    ]
    for app_stem, db_stem in narrative:
        for app in _pick(stems, app_stem):
            for db in _pick(stems, db_stem):
                link(app, db, "data", "application holds the database credential in its config")

    # The rest of the application tier talks to the non-jewel data stores.
    for i, app in enumerate(_pick(stems, "app-rms", "app-trade")):
        for db in _pick(stems, "db-trading", "db-reference")[i % 2 :: 2]:
            link(app, db, "data", "trading application reads reference and order data")

    # CI pushes to production. Classic trust relationship, classic problem.
    for ci in _pick(stems, "ci-build"):
        for app in app_tier[:4]:
            link(ci, app, "trust", "the build server deploys to this host with a standing key")

    # Backups pull from the databases. A copy of the data is still the data.
    for db in crown_jewels:
        for archive in _pick(stems, "s3-archive"):
            link(db, archive, "data", "nightly backup writes to object storage")

    # Reporting reads a replica, not the system of record.
    for etl in _pick(stems, "analytics-etl"):
        for db in _pick(stems, "db-report", "dw-analytics"):
            link(etl, db, "data", "ETL job loads the reporting warehouse")

    # The office LAN. Plain network reachability -- no credential travels here.
    lan_targets = _pick(stems, "file-share", "intranet", "core-switch")
    workstations = [a for a in tiers["internal"] if a.asset_type == AssetType.WORKSTATION]
    for i, ws in enumerate(workstations):
        link(ws, lan_targets[i % len(lan_targets)], "network", "office LAN reachability")

    # Monitoring scrapes the estate. Read-only, and only over the network.
    for monitor in _pick(stems, "monitor"):
        for target in app_tier + tiers["identity"][:2]:
            link(monitor, target, "network", "monitoring agent scrapes metrics")

    # The identity tier replicates internally.
    identity = tiers["identity"]
    for a, b in zip(identity, identity[1:]):
        link(a, b, "network", "identity tier replication")

    return deps


# --------------------------------------------------------------------------- #
# identities
# --------------------------------------------------------------------------- #

def _build_identities(
    rng: random.Random, tiers: dict[str, list[Asset]], stems: dict[str, list[Asset]]
) -> list[Identity]:
    """Accounts, and where their credentials also happen to work.

    Credential reuse is what stitches the tiers together -- without it the data
    tier is only reachable through a service dependency and the graph is a
    straight line. Each bridge below is a real pattern:

      DMZ -> internal      a web tier service account that also logs in to the app
      internal -> internal a deployment key that works on everything it deploys
      internal -> identity a helpdesk admin account, reused across the fleet
      internal -> data     the DBA's account, reused across the databases

    MFA is on the accounts a broking firm is actually made to protect: the DBA,
    the domain admin, remote staff. It is off on the service accounts, which is
    both realistic and the reason the graph finds them.
    """
    identities: list[Identity] = []
    seq = 0

    def add(home: Asset, privilege: Privilege, reused_on: list[Asset], mfa: bool,
            label: str) -> None:
        nonlocal seq
        seq += 1
        identities.append(
            Identity(
                identity_id=f"i-{label}-{seq:03d}",
                home_asset_id=home.asset_id,
                privilege=privilege,
                mfa_enabled=mfa,
                credential_reused_on=[a.asset_id for a in reused_on],
            )
        )

    app_tier = _pick(stems, "app-oms", "app-rms", "app-trade", "app-backoffice", "app-kyc")
    databases = [a for a in tiers["data"] if a.asset_type == AssetType.DATABASE]
    crown_jewels = [a for a in tiers["data"] if "crown_jewel" in a.tags]
    workstations = [a for a in tiers["internal"] if a.asset_type == AssetType.WORKSTATION]

    # DMZ -> internal. The web tier's service account is accepted on the app it
    # fronts. No MFA: nothing prompts a service account.
    for i, front in enumerate(_pick(stems, "trade-web", "client-portal", "api-gw")[:4]):
        add(front, Privilege.USER, [app_tier[i % len(app_tier)]], False, "svc-web")

    # internal -> internal. The deploy key.
    for ci in _pick(stems, "ci-build"):
        add(ci, Privilege.ADMIN, app_tier[:3], False, "svc-deploy")

    # internal -> data, and the one that matters. The build server runs schema
    # migrations, so it holds a standing database account with full rights on
    # the production stores. No human logs in with it, so nothing prompts for
    # MFA and nobody rotates it. This is the credential that links the internal
    # tier to the crown jewels: take it out and the data tier is only reachable
    # through the application's own connection string.
    for ci in _pick(stems, "ci-build"):
        add(ci, Privilege.DATA_ADMIN, crown_jewels, False, "svc-migrate")

    # internal -> identity. Helpdesk admin, reused across the workstation fleet
    # and the ADFS box. This is the route that eventually reaches the DC.
    for admin_ws in _pick(stems, "ws-it-admin"):
        add(admin_ws, Privilege.ADMIN, workstations[:6] + _pick(stems, "adfs"), False, "helpdesk")

    # internal -> data. The DBA. MFA is on, which is the only reason this route
    # does not dominate the whole analysis.
    for dba_ws in _pick(stems, "ws-dba"):
        add(dba_ws, Privilege.DATA_ADMIN, databases[:3], True, "dba")

    # Backup service account: data_admin on the archive, homed on the ETL host.
    for etl in _pick(stems, "analytics-etl"):
        add(etl, Privilege.DATA_ADMIN, _pick(stems, "s3-archive"), False, "svc-backup")

    # Domain admin, homed on the DC. MFA enforced.
    for dc in _pick(stems, "dc")[:1]:
        add(dc, Privilege.ADMIN, _pick(stems, "pam-vault", "adfs", "pki-ca"), True, "domain-admin")

    # Ordinary staff accounts. No reuse, no lateral movement -- they are here so
    # the identity inventory is not made entirely of the interesting cases.
    for ws in workstations[::4]:
        add(ws, Privilege.USER, [], rng.random() < 0.55, "staff")

    return identities


# --------------------------------------------------------------------------- #
# findings
# --------------------------------------------------------------------------- #

def _finding_plan(
    rng: random.Random, assets: list[Asset], tiers: dict[str, list[Asset]], reserved: int
) -> dict[str, int]:
    """How many findings each asset gets, trimmed so that the plan plus the
    ``reserved`` findings already planted lands inside 250-400."""
    tier_of = {a.asset_id: tier for tier, group in tiers.items() for a in group}
    plan: dict[str, int] = {}
    for asset in assets:
        rate = FINDINGS_PER_ASSET[tier_of[asset.asset_id]]
        base = int(rate)
        plan[asset.asset_id] = base + (1 if rng.random() < rate - base else 0)

    target = min(
        FINDINGS_CEILING, max(FINDINGS_FLOOR, round(len(assets) * FINDINGS_PER_ASSET_TARGET))
    ) - reserved
    total = sum(plan.values())
    # Trim or top up on the office estate first: the DMZ, the identity tier and
    # the data tier are scanned to a schedule, the workstation fleet is where the
    # count actually moves. On a large estate the office tier alone cannot absorb
    # the whole overshoot, so the other tiers follow -- but never below one
    # finding each, because an asset the scanner has nothing at all to say about
    # is a hole in the inventory rather than a clean host.
    internal = [a.asset_id for a in tiers["internal"]]
    rest = [a.asset_id for tier, group in tiers.items() if tier != "internal" for a in group]
    pool = internal + rest
    floor = {asset_id: (0 if asset_id in set(internal) else 1) for asset_id in pool}

    i = 0
    while total != target and pool and i < 20 * len(pool):
        asset_id = pool[i % len(pool)]
        if total < target:
            plan[asset_id] += 1
            total += 1
        elif plan[asset_id] > floor[asset_id]:
            plan[asset_id] -= 1
            total -= 1
        i += 1
    return plan


def _build_findings(
    rng: random.Random,
    assets: list[Asset],
    tiers: dict[str, list[Asset]],
    stems: dict[str, list[Asset]],
) -> list[Finding]:
    """Findings, placed so the graph has a story rather than a uniform fog.

    Four kinds, and which one an asset can get is deliberate:

    ``remote``   needs no credentials, so R1 turns it into a front door and R4
                 turns it into a lateral exploit. Only assets in the
                 ``remote_exploitable`` set get one, because the width of the
                 front door is the biggest single driver of the crown-jewel
                 probabilities.
    ``privesc``  needs user, grants admin. build_graph folds it into the arriving
                 edge, so it prices the last step of a pivot.
    ``escalate`` needs user, grants data_admin. Data tier only: this is how an
                 attacker who lands on a database box ends up holding the data.
    ``config``   grants no more than it needs. Real inventory noise; it shows up
                 in the vulnerability counts and in the CCI without moving the
                 graph at all.
    """
    findings: list[Finding] = []
    seq = 0
    tier_of = {a.asset_id: tier for tier, group in tiers.items() for a in group}
    by_id = {a.asset_id: a for a in assets}

    def add(asset: Asset, cve_id: str | None, cvss: float, epss: float | None, kev: bool,
            grants: Privilege, requires: Privilege) -> str:
        nonlocal seq
        seq += 1
        findings.append(
            Finding(
                finding_id=f"f-{seq:04d}",
                asset_id=asset.asset_id,
                cve_id=cve_id,
                cvss_base=cvss,
                epss=epss,
                kev=kev,
                grants_privilege=grants,
                requires_privilege=requires,
                # Never claim a scanner we did not run. The whole snapshot is
                # SYNTHETIC and every finding in it says so.
                source="synthetic",
                first_seen=SNAPSHOT_EPOCH - timedelta(days=rng.randint(3, 400)),
                status="open",
            )
        )
        return findings[-1].finding_id

    # -- the KEV pool, placed on the role each CVE actually affects ---------- #
    kev_hosts: set[str] = set()
    planted: set[str] = set()
    for stem, cve, cvss, epss, grants, requires, _title in _KEV_POOL:
        hosts = stems.get(stem, [])
        if not hosts:
            continue
        finding_id = add(hosts[0], cve, cvss, epss, True, grants, requires)
        kev_hosts.add(hosts[0].asset_id)
        if (stem, cve) in _KEV_ALWAYS_OPEN:
            planted.add(finding_id)

    # -- the last hop. One unpatched escalation per crown jewel, always open -- #
    for i, jewel in enumerate(a for a in tiers["data"] if "crown_jewel" in a.tags):
        planted.add(
            add(jewel, f"SYN-2025-{90_000 + i:05d}", CROWN_JEWEL_ESCALATION_CVSS,
                CROWN_JEWEL_ESCALATION_EPSS, False, Privilege.DATA_ADMIN, Privilege.USER)
        )

    # -- who is allowed a no-credentials-needed bug -------------------------- #
    remote_exploitable: set[str] = set()
    for role in DMZ_ENTRY_ROLES + INTERNAL_ENTRY_ROLES:
        candidates = [a for a in stems.get(role, []) if a.asset_id not in kev_hosts]
        if candidates:
            remote_exploitable.add(rng.choice(candidates).asset_id)

    # -- the rest of the inventory ------------------------------------------ #
    plan = _finding_plan(rng, assets, tiers, reserved=len(findings))
    for asset in assets:
        tier = tier_of[asset.asset_id]
        on_spine = _stem_of(asset) in _SPINE_STEMS
        for slot in range(plan[asset.asset_id]):
            roll = rng.random()
            # A host in the entry set always gets its unpatched remote bug, and
            # that one stays open: the point of the set is that the route exists,
            # not that it might.
            is_entry_bug = asset.asset_id in remote_exploitable and (
                slot == 0 or roll < REMOTE_FINDING_SHARE
            )
            if is_entry_bug:
                grants, requires = Privilege.USER, Privilege.NONE
                cvss = round(rng.uniform(7.5, 9.8), 1)
            elif tier == "data" and not on_spine and roll < 0.30:
                grants, requires = Privilege.DATA_ADMIN, Privilege.USER
                cvss = round(rng.uniform(6.5, 9.1), 1)
            elif not on_spine and roll < 0.55:
                grants, requires = Privilege.ADMIN, Privilege.USER
                cvss = round(rng.uniform(5.5, 8.8), 1)
            else:
                grants, requires = Privilege.USER, Privilege.USER
                cvss = round(rng.uniform(3.1, 7.0), 1)

            if is_entry_bug:
                cve_id = f"SYN-{2024 + seq % 2}-{seq + 10_000:05d}"
                epss = round(rng.uniform(*ENTRY_FINDING_EPSS_RANGE), 5)
            elif rng.random() < NO_EPSS_FRACTION:
                cve_id, epss = None, None
            else:
                cve_id = f"SYN-{2024 + seq % 2}-{seq + 10_000:05d}"
                epss = _draw_epss(rng)
            finding_id = add(asset, cve_id, cvss, epss, False, grants, requires)
            if is_entry_bug and slot == 0:
                planted.add(finding_id)

    # -- open vs mitigated --------------------------------------------------- #
    # What is left open is the demo: a handful of known-exploited bugs on the
    # edge, and a long tail of low-EPSS privilege escalation behind them.
    edge_kev = sorted(
        f.finding_id for f in findings if f.kev and by_id[f.asset_id].internet_facing
    )
    pinned = set(edge_kev) & planted
    pool = [f for f in edge_kev if f not in pinned]
    survivors = pinned | set(
        rng.sample(pool, max(0, min(KEV_EDGE_STILL_OPEN - len(pinned), len(pool))))
    )
    keep_open = set(planted) | survivors
    # The edge KEVs that did not survive are closed outright rather than dropped
    # back into the lottery, so the count above is the count the graph sees.
    forced_mitigated = set(edge_kev) - survivors

    target_mitigated = round(len(findings) * MITIGATED_FRACTION)
    candidates = sorted(
        f.finding_id
        for f in findings
        if f.finding_id not in keep_open and f.finding_id not in forced_mitigated
    )
    mitigated = forced_mitigated | set(
        rng.sample(candidates, min(target_mitigated - len(forced_mitigated), len(candidates)))
    )
    return [
        f if f.finding_id not in mitigated else f.model_copy(update={"status": "mitigated"})
        for f in findings
    ]


# --------------------------------------------------------------------------- #
# controls + telemetry
# --------------------------------------------------------------------------- #

def _build_controls(assets: list[Asset]) -> list[AppliedControl]:
    """The controls the firm already runs. These are not decoration: they are why
    the crown-jewel probabilities come out interesting instead of saturated, and
    a SEBI-regulated broker is expected to have every one of them."""
    controls: list[AppliedControl] = []
    for control_id, prefixes in _EXISTING_CONTROL_PLAN:
        applied = [a.asset_id for a in assets if a.hostname.startswith(prefixes)]
        if applied:
            controls.append(
                AppliedControl(
                    control_id=control_id,
                    applied_to_asset_ids=applied,
                    evidence_ref=f"synthetic://control-attestation/{control_id}",
                )
            )
    return controls


def _build_telemetry(
    profile: OrgProfile, assets: list[Asset], findings: list[Finding]
) -> TelemetryMetrics:
    """SOC and programme counters.

    Set so that every Annexure-K ratio lands near ``CCI_TARGET_RATIO`` of its
    target, which is what puts the CCI in the 55-70 range the brief asks for --
    a firm that is doing the work but is not finished. Where a counter can be
    derived from the snapshot itself (vulnerabilities, systems, staff) it is, so
    compute_cci ends up scoring the same estate the graph is walking rather than
    a set of numbers invented alongside it.
    """
    r = CCI_TARGET_RATIO
    total_systems = len(assets)
    critical = [a for a in assets if a.criticality_weight >= 0.70 or "crown_jewel" in a.tags]
    remote_users = max(1, round(profile.employee_count * REMOTE_USER_SHARE_OF_STAFF))
    incidents = max(1, round(profile.employee_count * INCIDENTS_PER_HEAD))
    databases = [a for a in assets if a.asset_type == AssetType.DATABASE]
    backups_total = max(1, len(databases) + 8)
    it_budget = round(profile.annual_revenue_inr * IT_BUDGET_REVENUE_SHARE, 2)

    return TelemetryMetrics(
        vulns_identified=len(findings),
        vulns_mitigated=sum(1 for f in findings if f.status == "mitigated"),
        remote_users_total=remote_users,
        remote_users_with_mfa=round(remote_users * r),
        # What CCI scores is infosec as a share of IT, against a 10% expectation.
        infosec_budget_inr=round(it_budget * INFOSEC_BUDGET_TARGET_SHARE * r, 2),
        it_budget_inr=it_budget,
        critical_systems_identified=len(critical),
        systems_integrated_with_soc=round(len(critical) * r),
        total_it_systems=total_systems,
        staff_total=profile.employee_count,
        staff_security_trained=round(profile.employee_count * r),
        incidents_total=incidents,
        incidents_closed_in_sla=round(incidents * r),
        assets_with_current_patch=round(total_systems * r),
        backups_tested_count=round(backups_total * r),
        backups_total_count=backups_total,
    )


def indicative_cci_score(telemetry: TelemetryMetrics) -> float:
    """A stand-in for ``crq_compliance.compute_cci`` while that is unimplemented.

    NOT the SEBI score. It is the unweighted mean of the Annexure-K-style ratios
    that TelemetryMetrics can actually form, each capped at its target, which is
    enough to say which band the real 23-parameter weighted score will land in.
    Both readings of SOC coverage -- against critical systems and against the
    whole estate -- are included, so the number does not depend on guessing which
    denominator compute_cci settles on.

    Delete this the day compute_cci lands and point the test at that instead.
    """
    t = telemetry

    def ratio(numerator: float, denominator: float, target: float = 1.0) -> float:
        # SEBI's June 2025 FAQ: an undefined parameter takes the parameter max.
        if denominator <= 0:
            return 100.0
        return min(1.0, (numerator / denominator) / target) * 100.0

    parameters = [
        ratio(t.vulns_mitigated, t.vulns_identified),
        ratio(t.remote_users_with_mfa, t.remote_users_total),
        ratio(t.infosec_budget_inr, t.it_budget_inr, INFOSEC_BUDGET_TARGET_SHARE),
        ratio(t.systems_integrated_with_soc, t.critical_systems_identified),
        ratio(t.systems_integrated_with_soc, t.total_it_systems),
        ratio(t.staff_security_trained, t.staff_total),
        ratio(t.incidents_closed_in_sla, t.incidents_total),
        ratio(t.assets_with_current_patch, t.total_it_systems),
        ratio(t.backups_tested_count, t.backups_total_count),
    ]
    return round(sum(parameters) / len(parameters), 2)


# --------------------------------------------------------------------------- #
# the entry point
# --------------------------------------------------------------------------- #

def generate_enterprise(profile: OrgProfile, asset_count: int, seed: int) -> Snapshot:
    """Synthetic org. provenance MUST be SYNTHETIC.

    Pure and reproducible: the only entropy is ``seed``, and the timestamp is a
    constant. See the module docstring for the topology and the tuning notes.
    """
    if asset_count < 1:
        raise ValueError("asset_count must be positive")

    rng = random.Random(seed)

    assets, tiers = _build_assets(rng, asset_count)
    stems = _by_stem(assets)
    dependencies = _build_dependencies(tiers, stems)
    identities = _build_identities(rng, tiers, stems)
    findings = _build_findings(rng, assets, tiers, stems)
    controls = _build_controls(assets)
    telemetry = _build_telemetry(profile, assets, findings)

    internet_facing = sum(1 for a in assets if a.internet_facing)
    if internet_facing > asset_count * MAX_INTERNET_FACING_FRACTION:
        raise AssertionError(
            f"{internet_facing}/{asset_count} assets are internet-facing, over the "
            f"{MAX_INTERNET_FACING_FRACTION:.0%} cap in FUNCTIONS.md"
        )

    return Snapshot(
        snapshot_id=f"SNAP-SYN-{asset_count:04d}-{seed:06d}",
        created_at=SNAPSHOT_EPOCH,
        provenance=Provenance.SYNTHETIC,
        org=profile,
        assets=assets,
        dependencies=dependencies,
        identities=identities,
        findings=findings,
        existing_controls=controls,
        telemetry=telemetry,
    )
