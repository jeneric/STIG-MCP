import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

EDGE_NOT_TECHNIQUES = "not-techniques"
EDGE_LIVE_SOURCE = "live-source"

# re.ASCII, as upstream._DATE_RE: created is compared as a string against ASCII release dates.
_CREATED_RE = re.compile(r"\d{4}-\d{2}-\d{2}", re.ASCII)


@dataclass
class Technique:
    technique_id: str
    name: str
    is_subtechnique: bool
    parent_id: str | None
    tactics: list = field(default_factory=list)
    created: str | None = None


@dataclass
class Actor:
    actor_id: str
    name: str
    aliases: list = field(default_factory=list)
    technique_ids: list = field(default_factory=list)


@dataclass
class Revocation:
    """A technique ATT&CK retired, and the live technique that replaced it."""

    revoked_id: str
    replacement_id: str
    revoked_name: str


@dataclass
class AttackData:
    version: str
    techniques: list = field(default_factory=list)
    actors: list = field(default_factory=list)
    revocations: list = field(default_factory=list)


def _attack_id(obj):
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def _tactics(obj):
    return [
        phase["phase_name"]
        for phase in obj.get("kill_chain_phases", [])
        if phase.get("kill_chain_name") == "mitre-attack"
    ]


def _resolve_revocations(edges, names, live_ids):
    """Follow each revoked-by edge to a fixed point, keeping only entries that land on a
    live technique. Chains are real (a replacement is sometimes revoked in turn), and a
    cycle would otherwise loop forever, so both are handled explicitly."""
    resolved, cycles, dead_ends = [], 0, 0
    for revoked_id in sorted(edges):
        seen, current = {revoked_id}, edges[revoked_id]
        while current in edges:
            if current in seen:
                current = None
                break
            seen.add(current)
            current = edges[current]
        if current is None:
            cycles += 1
            continue
        if current not in live_ids:
            dead_ends += 1
            continue
        resolved.append(Revocation(revoked_id, current, names.get(revoked_id, "")))
    if cycles or dead_ends:
        logger.warning(
            "Ignored %d revoked-by chain(s) that cycle and %d that end on a technique "
            "this bundle does not define; mappings on those ids cannot be recovered.",
            cycles,
            dead_ends,
        )
    return resolved


def _record_attack_pattern(obj, pattern_ids, pattern_names, stix_to_attack, techniques):
    attack_id = _attack_id(obj)
    if not attack_id:
        return
    # Recorded for every attack-pattern, revoked ones included, because a
    # revoked-by edge names STIX ids and both of its ends need translating.
    pattern_ids[obj["id"]] = attack_id
    pattern_names[attack_id] = obj.get("name", "")
    if obj.get("revoked") or obj.get("x_mitre_deprecated"):
        return
    stix_to_attack[obj["id"]] = attack_id
    is_sub = bool(obj.get("x_mitre_is_subtechnique"))
    parent = attack_id.split(".")[0] if is_sub else None
    created = obj.get("created")
    created = created[:10] if isinstance(created, str) and _CREATED_RE.fullmatch(created[:10]) else None
    techniques.append(Technique(attack_id, obj.get("name", ""), is_sub, parent, _tactics(obj), created))


def _record_intrusion_set(obj, stix_to_attack, actors):
    if obj.get("revoked") or obj.get("x_mitre_deprecated"):
        return
    attack_id = _attack_id(obj)
    if attack_id:
        stix_to_attack[obj["id"]] = attack_id
        actors.append(Actor(attack_id, obj.get("name", ""), list(obj.get("aliases", []))))


def _record_revocation_edge(obj, pattern_ids, live_ids, revoked_edges):
    """Record a revoked-by edge, returning why it was rejected or None once recorded. An
    edge whose source is a technique this bundle still defines as live is refused: applying
    it would move that technique's mappings onto another id while the technique itself kept
    answering queries, and no redirect would fire to explain where they went."""
    src, tgt = obj.get("source_ref"), obj.get("target_ref")
    if src not in pattern_ids or tgt not in pattern_ids:
        return EDGE_NOT_TECHNIQUES
    if pattern_ids[src] in live_ids:
        return EDGE_LIVE_SOURCE
    revoked_edges[pattern_ids[src]] = pattern_ids[tgt]
    return None


def _log_rejected_edges(rejections):
    if rejections[EDGE_NOT_TECHNIQUES]:
        logger.debug(
            "Skipped %d revoked-by relationship(s) whose ends are not both techniques.",
            rejections[EDGE_NOT_TECHNIQUES],
        )
    if rejections[EDGE_LIVE_SOURCE]:
        logger.warning(
            "Ignored %d revoked-by relationship(s) whose source technique this bundle still "
            "defines as live. Mappings on those ids are left where they are; check the ATT&CK "
            "bundle in stig_mcp/data/sources/ against the release notes.",
            rejections[EDGE_LIVE_SOURCE],
        )


def _record_actor_use(obj, actor_by_stix, stix_to_attack, actor_lookup):
    src, tgt = obj.get("source_ref"), obj.get("target_ref")
    if src not in actor_by_stix or tgt not in stix_to_attack:
        return
    actor_id = stix_to_attack.get(src)
    actor = actor_lookup.get(actor_id)
    technique_id = stix_to_attack.get(tgt)
    if actor is not None and technique_id and technique_id.startswith("T"):
        actor.technique_ids.append(technique_id)


def parse_attack(path):
    objects = json.loads(Path(path).read_text())["objects"]
    version = ""
    techniques, actors = [], []
    stix_to_attack = {}
    pattern_ids, pattern_names = {}, {}
    revoked_edges = {}
    rejections = {EDGE_NOT_TECHNIQUES: 0, EDGE_LIVE_SOURCE: 0}

    for obj in objects:
        otype = obj.get("type")
        if otype == "x-mitre-collection":
            version = obj.get("x_mitre_version", version)
        elif otype == "attack-pattern":
            _record_attack_pattern(obj, pattern_ids, pattern_names, stix_to_attack, techniques)
        elif otype == "intrusion-set":
            _record_intrusion_set(obj, stix_to_attack, actors)

    actor_by_stix = {obj["id"]: obj for obj in objects if obj.get("type") == "intrusion-set"}
    actor_lookup = {a.actor_id: a for a in actors}
    live_ids = {t.technique_id for t in techniques}
    for obj in objects:
        if obj.get("type") != "relationship":
            continue
        rel_type = obj.get("relationship_type")
        if rel_type == "revoked-by":
            rejected = _record_revocation_edge(obj, pattern_ids, live_ids, revoked_edges)
            if rejected:
                rejections[rejected] += 1
            continue
        if rel_type != "uses":
            continue
        _record_actor_use(obj, actor_by_stix, stix_to_attack, actor_lookup)

    _log_rejected_edges(rejections)
    revocations = _resolve_revocations(revoked_edges, pattern_names, live_ids)
    return AttackData(version=version, techniques=techniques, actors=actors, revocations=revocations)
