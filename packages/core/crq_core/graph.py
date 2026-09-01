"""P2. See contracts/FUNCTIONS.md for the full spec of each function.

Everything in here is a pure function of its inputs. No DB, no globals, no clock.
Same Snapshot in, same AttackGraph out, byte for byte.

Modelling notes, kept here because the trace panel and the judges both ask:

* A node is an attacker *state*: "I hold privilege P on asset A". States are
  materialised lazily -- a state only exists once some rule can actually put an
  attacker in it -- plus the ``internet:none`` entry state and the crown-jewel
  objective states, which are always present so the objective is visible even
  when nothing reaches it.
* An edge is one action. Its probability is the chance the action succeeds given
  the attacker already holds the source state. Edges are treated as independent;
  path probability is the product along the path.
* Every soft constant in this module is collected in the ASSUMPTIONS block below
  so P3 can lift it into ``LossResult.assumptions``. If a number here has no
  source, it says so.
"""

from __future__ import annotations

import warnings
from typing import Iterable

import networkx as nx

from crq_core.schemas import (
    AppliedControl,
    Asset,
    AttackGraph,
    ChokePoint,
    ControlCatalogEntry,
    CrownJewelReach,
    DataClass,
    Finding,
    GraphEdge,
    GraphNode,
    Identity,
    PathAnalysis,
    Privilege,
    Snapshot,
)

# --------------------------------------------------------------------------- #
# ASSUMPTIONS. Every one of these is a v1 team estimate unless a source is named.
# --------------------------------------------------------------------------- #

#: Ordering used for "does the attacker already hold enough privilege here".
#: Data privileges sit between user and admin: admin on the box implies you can
#: reach the data, but a data_admin grant does not give you the operating system.
PRIVILEGE_RANK: dict[Privilege, int] = {
    Privilege.NONE: 0,
    Privilege.USER: 1,
    Privilege.DATA_READ: 2,
    Privilege.DATA_ADMIN: 3,
    Privilege.ADMIN: 4,
}

#: R1 falls back to this when a finding has no EPSS score, per FUNCTIONS.md.
CVSS_TO_PROBABILITY = 0.1
#: A KEV listing floors the probability: it is being exploited in the wild today.
KEV_PROBABILITY_FLOOR = 0.6

#: R3. A standing credential that is reused elsewhere usually just works.
CREDENTIAL_REUSE_BASE = 0.75
#: MFA on the reused credential. Microsoft's published efficacy claim is higher;
#: we discount it because MFA fatigue and token theft are routine.
MFA_EFFECTIVENESS = 0.6
#: R3b. Pulling a domain account off a host that stores credentials.
DOMAIN_CREDENTIAL_HARVEST_BASE = 0.7
#: R3c. Domain admin can mint a ticket for any identity. No MFA discount applies:
#: a forged Kerberos ticket never sees an MFA prompt.
DOMAIN_IMPERSONATION_BASE = 0.85
#: R4. A service/data/trust dependency means the caller holds a credential for
#: the callee, in a config file, a CI secret or an instance role.
SERVICE_CREDENTIAL_BASE = 0.6
#: R5. Admin on the host that stores the data is data access, near enough.
DATA_ACCESS_BASE = 0.9

#: Edges below this are dropped: a fully blocked action is not an action.
MIN_EDGE_PROBABILITY = 1e-6

#: Controls already in place in the Snapshot. Snapshot.existing_controls carries
#: only an id, so the blocking behaviour has to live somewhere -- here.
#: Effectiveness mirrors contracts/fixtures/control_catalog.json where the id
#: exists there. Unknown control ids are ignored rather than silently guessed at.
EXISTING_CONTROL_EFFECTS: dict[str, dict] = {
    "ctl-edr": {
        "techniques": {"T1210", "T1021", "T1068", "T1078"},
        "predicate": None,
        "effectiveness": 0.4,
        "label": "endpoint detection and response",
    },
    "ctl-waf": {
        "techniques": {"T1190"},
        "predicate": None,
        "effectiveness": 0.55,
        "label": "web application firewall",
    },
    "ctl-mfa-priv": {
        "techniques": {"T1078"},
        "predicate": None,
        "effectiveness": 0.8,
        "label": "MFA on privileged accounts",
    },
    "ctl-pam": {
        "techniques": {"T1078"},
        "predicate": None,
        "effectiveness": 0.75,
        "label": "privileged access management",
    },
    "ctl-segment-ci": {
        "techniques": {"T1210", "T1021"},
        "predicate": None,
        "effectiveness": 0.7,
        "label": "network segmentation",
    },
    "ctl-db-monitor": {
        "techniques": {"T1530"},
        "predicate": None,
        "effectiveness": 0.45,
        "label": "database activity monitoring",
    },
    "ctl-patch-kev": {
        "techniques": set(),
        "predicate": "kev==true",
        "effectiveness": 0.85,
        "label": "emergency KEV patching",
    },
}

#: analyze_paths. FUNCTIONS.md fixes the depth cap at 6 hops.
MAX_PATH_HOPS = 6
#: Belt and braces for dense graphs, so the API stays responsive. A graph dense
#: enough to hit this is enumerated only in part, and the analysis says so out
#: loud -- PathAnalysis is a frozen contract with nowhere to record it.
MAX_PATHS_ENUMERATED = 20_000
#: Crown-jewel value, used only to rank choke points against each other.
#: Not a loss figure -- P3's simulate() owns those.
OUTAGE_HOURS = 72.0
PII_RECORD_COST_INR = 150.0

INTERNET_ASSET_ID = "internet"
INTERNET_NODE_ID = "internet:none"


# --------------------------------------------------------------------------- #
# small helpers
# --------------------------------------------------------------------------- #

def _rank(privilege: Privilege) -> int:
    return PRIVILEGE_RANK[Privilege(privilege)]


def _node_id(asset_id: str, privilege: Privilege) -> str:
    return f"{asset_id}:{Privilege(privilege).value}"


def _is_open(finding: Finding) -> bool:
    return finding.status == "open"


def _finding_base_probability(finding: Finding) -> float:
    """base = epss if present, else cvss_base/10 * 0.1; KEV floors it at 0.6."""
    if finding.epss is not None:
        base = float(finding.epss)
    elif finding.cvss_base is not None:
        base = (float(finding.cvss_base) / 10.0) * CVSS_TO_PROBABILITY
    else:
        base = 0.0
    if finding.kev:
        base = max(base, KEV_PROBABILITY_FLOOR)
    return min(max(base, 0.0), 1.0)


def _finding_evidence(finding: Finding) -> str:
    """'CVE-2024-27198 (EPSS 0.94, in CISA KEV)' -- the bit that goes in a rationale."""
    name = finding.cve_id or finding.finding_id
    bits: list[str] = []
    if finding.epss is not None:
        bits.append(f"EPSS {finding.epss:.2f}")
    elif finding.cvss_base is not None:
        bits.append(f"CVSS {finding.cvss_base:.1f}, no EPSS score")
    if finding.kev:
        bits.append("in CISA KEV")
    return f"{name} ({', '.join(bits)})" if bits else name


def _predicate_matches(predicate: str | None, finding: Finding | None) -> bool:
    """The tiny DSL from ControlCatalogEntry: 'kev==true', 'cvss_base>=9.0'."""
    if not predicate or finding is None:
        return False
    for op in (">=", "<=", "==", "!=", ">", "<"):
        if op not in predicate:
            continue
        field, raw = (part.strip() for part in predicate.split(op, 1))
        actual = getattr(finding, field, None)
        if actual is None:
            return False
        lowered = raw.lower()
        if lowered in ("true", "false"):
            expected: object = lowered == "true"
        else:
            try:
                expected = float(raw)
                actual = float(actual)
            except (TypeError, ValueError):
                expected = raw.strip("'\"")
                actual = str(actual)
        if op == "==":
            return actual == expected
        if op == "!=":
            return actual != expected
        if not isinstance(actual, float) or not isinstance(expected, float):
            return False
        if op == ">=":
            return actual >= expected
        if op == "<=":
            return actual <= expected
        if op == ">":
            return actual > expected
        return actual < expected
    return False


def _crown_jewel_asset_ids(snapshot: Snapshot) -> list[str]:
    """Tagged crown jewels win. Absent any tag, fall back to a value heuristic so
    a generated snapshot still has objectives."""
    tagged = [a.asset_id for a in snapshot.assets if "crown_jewel" in a.tags]
    if tagged:
        return tagged
    return [
        a.asset_id
        for a in snapshot.assets
        if a.pii_records_held > 0
        or a.criticality_weight >= 0.85
        or DataClass.PII in a.data_classes
    ]


def _objective_privilege(asset: Asset, snapshot: Snapshot) -> Privilege:
    """The worst thing that can happen on this asset: the highest privilege any
    rule in the set could ever grant there.

    For anything that stores data the objective is stated in the data plane, not
    as host admin -- what the board cares about is the records walking out the
    door, and R5 is the last hop from admin to that. Host admin outranks
    data_admin in PRIVILEGE_RANK, so this has to be said explicitly.
    """
    candidates: list[Privilege] = [Privilege.USER]
    candidates += [
        f.grants_privilege
        for f in snapshot.findings
        if f.asset_id == asset.asset_id and _is_open(f)
    ]
    candidates += [
        i.privilege for i in snapshot.identities if asset.asset_id in i.credential_reused_on
    ]
    data_candidates = [p for p in candidates if p in (Privilege.DATA_READ, Privilege.DATA_ADMIN)]
    if asset.asset_type.value == "database":
        data_candidates.append(Privilege.DATA_ADMIN)
    if data_candidates:
        return max(data_candidates, key=_rank)
    return max(candidates, key=_rank)


def _asset_value_inr(asset: Asset) -> float:
    """Standing value of an asset, used only to rank choke points against each
    other. Deliberately crude: the real money is modelled in packages/core/loss.py."""
    return (
        asset.revenue_dependency_inr_per_hour * OUTAGE_HOURS * asset.criticality_weight
        + asset.pii_records_held * PII_RECORD_COST_INR
    )


def _identity_asset_ids(snapshot: Snapshot) -> set[str]:
    """The identity provider tier. The tag wins; otherwise a credential-storing IT
    server is the domain controller in all but name."""
    tagged = {a.asset_id for a in snapshot.assets if "identity" in a.tags}
    if tagged:
        return tagged
    return {
        a.asset_id
        for a in snapshot.assets
        if DataClass.CREDENTIALS in a.data_classes
        and a.asset_type.value == "server"
        and a.business_unit.lower() in ("it", "security")
    }


# --------------------------------------------------------------------------- #
# build_graph
# --------------------------------------------------------------------------- #

class _GraphBuilder:
    """Applies R1-R5 to a fixpoint. A rule only ever fires from a state that
    already exists, so the graph grows outwards from the internet and stops."""

    MAX_ROUNDS = 64

    def __init__(self, snapshot: Snapshot, rules_version: str) -> None:
        self.snapshot = snapshot
        self.rules_version = rules_version
        self.assets: dict[str, Asset] = {a.asset_id: a for a in snapshot.assets}

        self.findings_by_asset: dict[str, list[Finding]] = {}
        for finding in snapshot.findings:
            if _is_open(finding) and finding.asset_id in self.assets:
                self.findings_by_asset.setdefault(finding.asset_id, []).append(finding)

        self.controls_by_asset: dict[str, list[AppliedControl]] = {}
        for control in snapshot.existing_controls:
            for asset_id in control.applied_to_asset_ids:
                self.controls_by_asset.setdefault(asset_id, []).append(control)

        self.identity_assets = _identity_asset_ids(snapshot)

        # asset_id -> {asset_id, ...} reachable over the network. A dependency is
        # a service call in one direction, but IP reachability is symmetric: if
        # web-01 can call app-01 then an attacker on either can attack the other.
        self.adjacency: dict[str, set[str]] = {}
        for dep in snapshot.dependencies:
            if dep.from_asset_id in self.assets and dep.to_asset_id in self.assets:
                self.adjacency.setdefault(dep.from_asset_id, set()).add(dep.to_asset_id)
                self.adjacency.setdefault(dep.to_asset_id, set()).add(dep.from_asset_id)

        self.nodes: dict[str, GraphNode] = {}
        self.edges: dict[tuple[str, str], GraphEdge] = {}
        self._edge_seq = 0

    # -- state / edge plumbing ---------------------------------------------- #

    def _state(self, asset_id: str, privilege: Privilege) -> str:
        node_id = _node_id(asset_id, privilege)
        if node_id not in self.nodes:
            self.nodes[node_id] = GraphNode(
                node_id=node_id,
                asset_id=asset_id,
                privilege=privilege,
                is_entry=node_id == INTERNET_NODE_ID,
                is_crown_jewel=False,
            )
        return node_id

    def _states_of(self, asset_id: str, min_privilege: Privilege) -> list[GraphNode]:
        floor = _rank(min_privilege)
        return [
            n
            for n in list(self.nodes.values())
            if n.asset_id == asset_id and _rank(n.privilege) >= floor
        ]

    def _has_state(self, asset_id: str, privilege: Privilege) -> bool:
        return _node_id(asset_id, privilege) in self.nodes

    def _blocking_controls(
        self,
        source_asset_id: str,
        target_asset_id: str,
        technique_id: str | None,
        finding: Finding | None,
    ) -> list[tuple[str, float, str]]:
        """Existing controls on either end of the action that blunt it. Endpoint
        and network controls sit on a host, not on a direction of travel."""
        hits: list[tuple[str, float, str]] = []
        seen: set[str] = set()
        for asset_id in (target_asset_id, source_asset_id):
            for control in self.controls_by_asset.get(asset_id, []):
                effect = EXISTING_CONTROL_EFFECTS.get(control.control_id)
                if effect is None or control.control_id in seen:
                    continue
                blocks = (
                    technique_id is not None and technique_id in effect["techniques"]
                ) or _predicate_matches(effect["predicate"], finding)
                if blocks:
                    seen.add(control.control_id)
                    hits.append(
                        (control.control_id, float(effect["effectiveness"]), str(effect["label"]))
                    )
        return hits

    def _escalation_chain(
        self, asset_id: str, landing: Privilege
    ) -> list[tuple[Finding, float]]:
        """Findings on this asset that an attacker landing at `landing` can fire
        straight away, highest grant first, each with its own probability.

        Folding these into the arriving edge is a deliberate modelling choice: a
        node is "the privilege the attacker ends up holding on this asset", not
        every rung of the ladder they climbed to get there. It keeps one state
        per asset per distinct outcome, which matters twice over -- the optimizer
        re-walks this graph thousands of times, and analyze_paths only has a
        6-hop budget to spend, which should be spent on lateral movement rather
        than on bookkeeping.

        This is where R2 does its work in practice. ``_r2_local_privesc`` stays
        in the rule loop as the backstop for a state that ends up below an
        escalation it cannot fire on arrival; folding is the common case, and it
        keeps the enabling finding on the edge either way.
        """
        chain: list[tuple[Finding, float]] = []
        current = landing
        while True:
            candidates = [
                f
                for f in self.findings_by_asset.get(asset_id, [])
                if _rank(f.requires_privilege) <= _rank(current) < _rank(f.grants_privilege)
            ]
            if not candidates:
                return chain
            best = max(
                candidates, key=lambda f: (_rank(f.grants_privilege), _finding_base_probability(f))
            )
            probability = _finding_base_probability(best)
            for _control_id, effectiveness, _label in self._blocking_controls(
                asset_id, asset_id, "T1068", best
            ):
                probability *= 1.0 - effectiveness
            if probability < MIN_EDGE_PROBABILITY:
                # An escalation nobody can actually pull off must not take the
                # arrival with it. Land at the lower privilege and stop.
                return chain
            chain.append((best, probability))
            current = best.grants_privilege

    def _add_edge(
        self,
        source_node_id: str,
        target_asset_id: str,
        target_privilege: Privilege,
        technique_id: str,
        base_probability: float,
        rationale: str,
        finding: Finding | None = None,
    ) -> bool:
        """Add (or strengthen) one action. Returns True if the graph changed."""
        source = self.nodes[source_node_id]
        probability = min(max(base_probability, 0.0), 1.0)
        blocked_by: list[str] = []
        for control_id, effectiveness, label in self._blocking_controls(
            source.asset_id, target_asset_id, technique_id, finding
        ):
            probability *= 1.0 - effectiveness
            blocked_by.append(control_id)
            rationale += (
                f" Existing control {control_id} ({label}) covers this action, so the "
                f"probability is cut by {effectiveness:.0%}."
            )

        # Anything the attacker can escalate to the moment they land is part of
        # the same move, priced as such. A move that stays on one asset (R2, R5)
        # is already an escalation and is not folded again.
        target = self.assets.get(target_asset_id)
        chain = (
            []
            if target_asset_id == source.asset_id
            else self._escalation_chain(target_asset_id, target_privilege)
        )
        for escalation, escalation_probability in chain:
            probability *= escalation_probability
            rationale += (
                f" Once on {target.hostname if target else target_asset_id}, "
                f"{_finding_evidence(escalation)} escalates that "
                f"{target_privilege.value} access to {escalation.grants_privilege.value} "
                f"immediately, so the attacker lands as "
                f"{escalation.grants_privilege.value}."
            )
            target_privilege = escalation.grants_privilege
            finding = finding or escalation

        if probability < MIN_EDGE_PROBABILITY:
            return False

        target_node_id = _node_id(target_asset_id, target_privilege)
        if source_node_id == target_node_id:
            return False

        key = (source_node_id, target_node_id)
        existing = self.edges.get(key)
        if existing is not None:
            # Two rules can describe the same move. Keep the stronger claim and
            # the original edge id, so ids stay stable within a build.
            if probability <= existing.probability:
                return False
            self.edges[key] = existing.model_copy(
                update={
                    "technique_id": technique_id,
                    "enabler_finding_id": finding.finding_id if finding else None,
                    "probability": round(probability, 6),
                    "rationale": rationale,
                    "blocked_by_control_ids": blocked_by,
                }
            )
            return True

        self._state(target_asset_id, target_privilege)
        self._edge_seq += 1
        self.edges[key] = GraphEdge(
            edge_id=f"e-{self._edge_seq:03d}",
            source_node_id=source_node_id,
            target_node_id=target_node_id,
            technique_id=technique_id,
            enabler_finding_id=finding.finding_id if finding else None,
            probability=round(probability, 6),
            rationale=rationale,
            blocked_by_control_ids=blocked_by,
        )
        return True

    # -- the rules ----------------------------------------------------------- #

    def _r1_remote_exploit(self) -> bool:
        """R1. internet_facing asset + open finding needing no privilege -> foothold."""
        changed = False
        entry = self._state(INTERNET_ASSET_ID, Privilege.NONE)
        for asset in self.snapshot.assets:
            if not asset.internet_facing:
                continue
            for finding in self.findings_by_asset.get(asset.asset_id, []):
                if finding.requires_privilege != Privilege.NONE:
                    continue
                rationale = (
                    f"{_finding_evidence(finding)} is exploitable over the internet against "
                    f"{asset.hostname}, which is internet-facing, and needs no prior access. "
                    f"Success gives the attacker {finding.grants_privilege.value} on "
                    f"{asset.hostname}."
                )
                changed |= self._add_edge(
                    entry,
                    asset.asset_id,
                    finding.grants_privilege,
                    "T1190",
                    _finding_base_probability(finding),
                    rationale,
                    finding,
                )
        return changed

    def _r2_local_privesc(self) -> bool:
        """R2. (asset, p) + a finding that grants more than p -> (asset, higher).

        Most privesc is folded into the arriving edge instead (see
        ``_escalation_chain``), so on a typical snapshot this rule fires rarely:
        a state that arrives below an escalation it can fire has already been
        escalated on arrival. It stays in the loop for the cases folding cannot
        reach -- an escalation nobody can pull off, so the attacker really does
        sit at the lower privilege, and an asset that ends up with two different
        attainable states.
        """
        changed = False
        for asset in self.snapshot.assets:
            for finding in self.findings_by_asset.get(asset.asset_id, []):
                grants, requires = finding.grants_privilege, finding.requires_privilege
                if _rank(grants) <= _rank(requires):
                    continue
                for node in self._states_of(asset.asset_id, requires):
                    if _rank(node.privilege) >= _rank(grants):
                        continue
                    rationale = (
                        f"With {node.privilege.value} access on {asset.hostname}, "
                        f"{_finding_evidence(finding)} escalates locally to {grants.value}."
                    )
                    changed |= self._add_edge(
                        node.node_id,
                        asset.asset_id,
                        grants,
                        "T1068",
                        _finding_base_probability(finding),
                        rationale,
                        finding,
                    )
        return changed

    def _reuse_privilege(self, identity: Identity) -> Privilege:
        """What a replayed credential actually gets you on the far side. A data
        grant travels with the credential; host admin does not -- you land as an
        interactive user and escalate again from there, which is R2's job."""
        if identity.privilege in (Privilege.DATA_READ, Privilege.DATA_ADMIN):
            return identity.privilege
        return Privilege.USER

    def _r3_credential_reuse(self) -> bool:
        """R3. (home asset, >= identity privilege) + identity reused on b -> (b, ...)."""
        changed = False
        for identity in self.snapshot.identities:
            home = self.assets.get(identity.home_asset_id)
            if home is None:
                continue
            base = CREDENTIAL_REUSE_BASE
            mfa_note = ""
            if identity.mfa_enabled:
                base *= 1.0 - MFA_EFFECTIVENESS
                mfa_note = " MFA on the account makes the replay harder but not impossible."
            for target_asset_id in identity.credential_reused_on:
                target = self.assets.get(target_asset_id)
                if target is None:
                    continue
                granted = self._reuse_privilege(identity)
                for node in self._states_of(identity.home_asset_id, identity.privilege):
                    rationale = (
                        f"Identity {identity.identity_id} lives on {home.hostname} and the same "
                        f"credential is accepted on {target.hostname}. An attacker holding "
                        f"{node.privilege.value} on {home.hostname} can read or reuse it and log "
                        f"in to {target.hostname} as {granted.value}.{mfa_note}"
                    )
                    changed |= self._add_edge(
                        node.node_id, target_asset_id, granted, "T1078", base, rationale
                    )
        return changed

    def _r3b_domain_credential_harvest(self) -> bool:
        """R3 extension. Admin on a host that stores credentials yields a domain
        account on the identity tier. Without this the identity provider is only
        reachable if some dependency happens to point at it, which is not how a
        domain works -- every joined host must talk to it to authenticate."""
        changed = False
        for asset in self.snapshot.assets:
            if DataClass.CREDENTIALS not in asset.data_classes:
                continue
            if asset.asset_id in self.identity_assets:
                continue
            if not self._has_state(asset.asset_id, Privilege.ADMIN):
                continue
            source = _node_id(asset.asset_id, Privilege.ADMIN)
            for idp_asset_id in sorted(self.identity_assets):
                idp = self.assets[idp_asset_id]
                rationale = (
                    f"{asset.hostname} stores credentials, so admin there yields a working "
                    f"domain account. Every domain-joined host has to reach {idp.hostname} to "
                    f"authenticate, which puts the attacker on the identity tier as a user."
                )
                changed |= self._add_edge(
                    source,
                    idp_asset_id,
                    Privilege.USER,
                    "T1078",
                    DOMAIN_CREDENTIAL_HARVEST_BASE,
                    rationale,
                )
        return changed

    def _r3c_domain_impersonation(self) -> bool:
        """R3 extension. Admin on the identity provider is every identity at once."""
        changed = False
        for idp_asset_id in sorted(self.identity_assets):
            if not self._has_state(idp_asset_id, Privilege.ADMIN):
                continue
            source = _node_id(idp_asset_id, Privilege.ADMIN)
            idp = self.assets[idp_asset_id]
            for identity in self.snapshot.identities:
                for target_asset_id in identity.credential_reused_on:
                    target = self.assets.get(target_asset_id)
                    if target is None or target_asset_id == idp_asset_id:
                        continue
                    granted = self._reuse_privilege(identity)
                    rationale = (
                        f"Admin on {idp.hostname} is admin over the identity provider, so the "
                        f"attacker can issue a ticket for any account it serves. "
                        f"{identity.identity_id} is accepted on {target.hostname} as "
                        f"{granted.value}, and a forged ticket never sees an MFA prompt."
                    )
                    changed |= self._add_edge(
                        source,
                        target_asset_id,
                        granted,
                        "T1078",
                        DOMAIN_IMPERSONATION_BASE,
                        rationale,
                    )
        return changed

    def _r4_network_pivot(self) -> bool:
        """R4. (asset_a, >= user) + a network dependency a<->b -> a foothold on b.

        Two ways across, and they are different actions:
          * exploit -- b has a finding that needs no credentials (T1210 / T1021)
          * replay  -- the dependency itself carries a service credential (T1078)

        Internet-facing hosts are skipped as pivot targets: R1 already reaches
        them straight off the internet, so a pivot in adds no state the graph
        does not already have.
        """
        changed = False
        dependency_kind: dict[tuple[str, str], str] = {
            (d.from_asset_id, d.to_asset_id): d.kind for d in self.snapshot.dependencies
        }
        for node in list(self.nodes.values()):
            if node.asset_id == INTERNET_ASSET_ID or _rank(node.privilege) < _rank(Privilege.USER):
                continue
            source_asset = self.assets.get(node.asset_id)
            if source_asset is None:
                continue
            for target_asset_id in sorted(self.adjacency.get(node.asset_id, set())):
                target = self.assets[target_asset_id]
                if target.internet_facing:
                    continue
                kind = dependency_kind.get((node.asset_id, target_asset_id))

                # (a) exploit something on the far side that needs no credentials
                for finding in self.findings_by_asset.get(target_asset_id, []):
                    if finding.requires_privilege != Privilege.NONE:
                        continue
                    technique = "T1021" if kind == "network" else "T1210"
                    rationale = (
                        f"{source_asset.hostname} and {target.hostname} talk to each other over a "
                        f"{kind or 'network'} dependency, so a foothold on "
                        f"{source_asset.hostname} can reach {target.hostname} directly and "
                        f"exploit {_finding_evidence(finding)}, which needs no credentials, for "
                        f"{finding.grants_privilege.value}."
                    )
                    changed |= self._add_edge(
                        node.node_id,
                        target_asset_id,
                        finding.grants_privilege,
                        technique,
                        _finding_base_probability(finding),
                        rationale,
                        finding,
                    )

                # (b) replay the service credential the dependency implies
                if kind in ("data", "service", "trust"):
                    if target.asset_type.value in ("database", "cloud_resource"):
                        granted, technique = Privilege.DATA_READ, "T1530"
                    else:
                        granted, technique = Privilege.USER, "T1078"
                    rationale = (
                        f"{source_asset.hostname} calls {target.hostname} over a {kind} "
                        f"dependency, so it holds a working credential for it in config, CI "
                        f"secrets or an instance role. An attacker on {source_asset.hostname} "
                        f"replays that credential and lands on {target.hostname} as "
                        f"{granted.value}."
                    )
                    changed |= self._add_edge(
                        node.node_id,
                        target_asset_id,
                        granted,
                        technique,
                        SERVICE_CREDENTIAL_BASE,
                        rationale,
                    )
        return changed

    def _r5_data_access(self) -> bool:
        """R5. (db asset, admin) -> (db asset, data_admin)."""
        changed = False
        for asset in self.snapshot.assets:
            if asset.asset_type.value not in ("database", "cloud_resource"):
                continue
            if not self._has_state(asset.asset_id, Privilege.ADMIN):
                continue
            rationale = (
                f"Admin on {asset.hostname} is admin over the data store itself: the attacker "
                f"can read, dump or alter everything it holds."
            )
            changed |= self._add_edge(
                _node_id(asset.asset_id, Privilege.ADMIN),
                asset.asset_id,
                Privilege.DATA_ADMIN,
                "T1530",
                DATA_ACCESS_BASE,
                rationale,
            )
        return changed

    # -- drive ---------------------------------------------------------------- #

    def build(self) -> AttackGraph:
        self._state(INTERNET_ASSET_ID, Privilege.NONE)
        for _ in range(self.MAX_ROUNDS):
            changed = False
            changed |= self._r1_remote_exploit()
            changed |= self._r2_local_privesc()
            changed |= self._r3_credential_reuse()
            changed |= self._r3b_domain_credential_harvest()
            changed |= self._r3c_domain_impersonation()
            changed |= self._r4_network_pivot()
            changed |= self._r5_data_access()
            if not changed:
                break

        # The objectives are always on the board, reachable or not.
        crown_jewel_node_ids: list[str] = []
        for asset_id in _crown_jewel_asset_ids(self.snapshot):
            asset = self.assets.get(asset_id)
            if asset is None:
                continue
            node_id = self._state(asset_id, _objective_privilege(asset, self.snapshot))
            self.nodes[node_id] = self.nodes[node_id].model_copy(update={"is_crown_jewel": True})
            crown_jewel_node_ids.append(node_id)

        snapshot_id = self.snapshot.snapshot_id
        stem = snapshot_id[len("SNAP-"):] if snapshot_id.startswith("SNAP-") else snapshot_id
        return AttackGraph(
            graph_id=f"GRAPH-{stem}",
            snapshot_id=snapshot_id,
            nodes=list(self.nodes.values()),
            edges=list(self.edges.values()),
            entry_node_ids=[INTERNET_NODE_ID],
            crown_jewel_node_ids=crown_jewel_node_ids,
            rules_version=self.rules_version,
        )


def build_graph(snapshot: Snapshot, rules_version: str = "v1") -> AttackGraph:
    """Snapshot -> attack graph. R1-R5 and the probability formula are specified
    in contracts/FUNCTIONS.md; the deviations and extensions are documented on
    the rule methods above.

    Pure and deterministic: rules fire in a fixed order over snapshot order, so
    the same Snapshot always produces the same node ids, edge ids and rationales.
    """
    if rules_version != "v1":
        raise ValueError(f"unknown rules_version {rules_version!r}; this module implements 'v1'")
    return _GraphBuilder(snapshot, rules_version).build()


# --------------------------------------------------------------------------- #
# analyze_paths
# --------------------------------------------------------------------------- #

def _to_nx(graph: AttackGraph) -> nx.DiGraph:
    G = nx.DiGraph()
    for node in graph.nodes:
        G.add_node(node.node_id, asset_id=node.asset_id, privilege=node.privilege)
    for edge in graph.edges:
        if edge.source_node_id in G and edge.target_node_id in G:
            G.add_edge(
                edge.source_node_id,
                edge.target_node_id,
                probability=edge.probability,
                edge_id=edge.edge_id,
            )
    return G


def _path_probability(G: nx.DiGraph, path: list[str]) -> float:
    probability = 1.0
    for source, target in zip(path, path[1:]):
        probability *= G[source][target]["probability"]
    return probability


def _reachable_within(G: nx.DiGraph, sources: Iterable[str], hops: int) -> set[str]:
    """Plain BFS with a hop budget, used to test what removing a node really cuts."""
    seen: set[str] = set()
    frontier = [s for s in sources if s in G]
    seen.update(frontier)
    for _ in range(hops):
        nxt: list[str] = []
        for node in frontier:
            for successor in G.successors(node):
                if successor not in seen:
                    seen.add(successor)
                    nxt.append(successor)
        if not nxt:
            break
        frontier = nxt
    return seen


def analyze_paths(graph: AttackGraph, snapshot: Snapshot) -> PathAnalysis:
    """Reachability from the entry nodes to the crown jewels, capped at 6 hops.

    Enumerates every simple path entry -> crown jewel within the cap and weights
    it by the product of its edge probabilities. Choke points are ranked by the
    share of those paths they sit on: a node on most of them is where the money
    goes first. Crown-jewel compromise probability is a noisy-OR over the
    enumerated paths, which is an upper bound because the paths share edges.
    """
    G = _to_nx(graph)
    assets = {a.asset_id: a for a in snapshot.assets}
    node_index = {n.node_id: n for n in graph.nodes}

    entries = [n for n in graph.entry_node_ids if n in G]
    crown_jewels = [n for n in graph.crown_jewel_node_ids if n in G]

    paths: list[list[str]] = []
    weights: list[float] = []
    truncated = False
    for entry in entries:
        for target in crown_jewels:
            if entry == target or truncated:
                continue
            for path in nx.all_simple_paths(G, entry, target, cutoff=MAX_PATH_HOPS):
                paths.append(path)
                weights.append(_path_probability(G, path))
                if len(paths) >= MAX_PATHS_ENUMERATED:
                    truncated = True
                    break

    if truncated:
        warnings.warn(
            f"path enumeration hit the {MAX_PATHS_ENUMERATED} path cap on graph "
            f"{graph.graph_id}; choke point shares are computed over the paths that "
            f"were enumerated, not all of them",
            RuntimeWarning,
            stacklevel=2,
        )

    total_paths = len(paths)
    total_weight = sum(weights)

    # One pass over the paths builds every index the rest of this needs. Walking
    # the path list once per node instead is O(nodes x paths), which is seconds
    # rather than milliseconds on a dense graph.
    on_a_path: set[str] = set()
    through_count: dict[str, int] = {}
    through_weight: dict[str, float] = {}
    jewels_behind: dict[str, set[str]] = {}
    paths_to_jewel: dict[str, list[int]] = {}
    for i, path in enumerate(paths):
        on_a_path.update(path)
        jewel = path[-1]
        paths_to_jewel.setdefault(jewel, []).append(i)
        for node_id in path:
            through_count[node_id] = through_count.get(node_id, 0) + 1
            through_weight[node_id] = through_weight.get(node_id, 0.0) + weights[i]
            jewels_behind.setdefault(node_id, set()).add(jewel)

    # ---- choke points ----------------------------------------------------- #
    choke_points: list[ChokePoint] = []
    ranking: dict[str, float] = {}
    if total_paths and total_weight > 0.0:
        entry_set, cj_set = set(entries), set(crown_jewels)
        for node_id in [n.node_id for n in graph.nodes]:
            # An entry node is on every path by construction and a crown jewel is
            # on every path to itself. Neither is a finding.
            if node_id in entry_set or node_id in cj_set or node_id not in on_a_path:
                continue
            count = through_count.get(node_id, 0)
            if not count:
                continue

            # What actually goes dark if the attacker is denied this state.
            surviving = _reachable_within(G.subgraph(set(G) - {node_id}), entries, MAX_PATH_HOPS)
            cut = [cj for cj in crown_jewels if cj in on_a_path and cj not in surviving]

            value = 0.0
            for cj in sorted(jewels_behind.get(node_id, set())):
                asset = assets.get(node_index[cj].asset_id) if cj in node_index else None
                if asset is not None:
                    value += _asset_value_inr(asset)

            # FUNCTIONS.md defines this as the fraction of crown-jewel-reaching
            # paths the node sits on, so it is a share of paths. Ties are broken
            # by the probability-weighted share, which is the more interesting
            # number when two nodes sit on the same count of paths: it says how
            # much of the actual crown-jewel risk flows through this state.
            share = count / total_paths
            weighted_share = through_weight[node_id] / total_weight
            choke_points.append(
                ChokePoint(
                    node_id=node_id,
                    asset_id=node_index[node_id].asset_id,
                    paths_through_fraction=round(share, 4),
                    crown_jewels_cut_if_removed=cut,
                    reachable_cj_value_inr=round(value, 2),
                )
            )
            ranking[node_id] = weighted_share
        choke_points.sort(
            key=lambda c: (-c.paths_through_fraction, -ranking[c.node_id], c.node_id)
        )

    # ---- crown jewel reach ------------------------------------------------ #
    crown_jewel_reach: list[CrownJewelReach] = []
    for cj in graph.crown_jewel_node_ids:
        node = node_index.get(cj)
        asset_id = node.asset_id if node else cj.rsplit(":", 1)[0]
        indices = paths_to_jewel.get(cj, [])
        if indices:
            miss = 1.0
            for i in indices:
                miss *= 1.0 - weights[i]
            probability = 1.0 - miss
            best = max(indices, key=lambda i: (weights[i], -len(paths[i])))
            top_path: list[str] = paths[best]
            shortest: int | None = min(len(paths[i]) - 1 for i in indices)
        else:
            probability, top_path, shortest = 0.0, [], None
        crown_jewel_reach.append(
            CrownJewelReach(
                node_id=cj,
                asset_id=asset_id,
                compromise_probability=round(min(max(probability, 0.0), 1.0), 4),
                shortest_path_hops=shortest,
                top_path_node_ids=list(top_path),
            )
        )

    total_nodes = len(graph.nodes)
    dead_end_fraction = ((total_nodes - len(on_a_path)) / total_nodes) if total_nodes else 0.0

    stem = (
        graph.graph_id[len("GRAPH-"):] if graph.graph_id.startswith("GRAPH-") else graph.graph_id
    )
    return PathAnalysis(
        path_analysis_id=f"PATH-{stem}",
        graph_id=graph.graph_id,
        choke_points=choke_points,
        crown_jewel_reach=crown_jewel_reach,
        dead_end_node_fraction=round(dead_end_fraction, 4),
    )


def apply_controls(graph: AttackGraph, catalog: list[ControlCatalogEntry],
                   applications: list[AppliedControl]) -> AttackGraph:
    """MUST be pure. Return a new graph. Called thousands of times by the optimizer."""
    raise NotImplementedError
