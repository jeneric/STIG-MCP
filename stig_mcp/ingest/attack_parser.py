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
class Mitigation:
    mitigation_id: str
    name: str
    description: str


@dataclass
class TechniqueMitigation:
    """One mitigates edge, with MITRE's text about this mitigation on this technique."""

    technique_id: str
    mitigation_id: str
    description: str


@dataclass
class LogSource:
    name: str
    channel: str
    data_component_id: str | None


@dataclass
class Analytic:
    analytic_id: str
    detection_strategy_id: str
    name: str
    description: str
    platforms: list = field(default_factory=list)
    log_sources: list = field(default_factory=list)
    mutable_elements: list = field(default_factory=list)


@dataclass
class DetectionStrategy:
    detection_strategy_id: str
    technique_id: str
    name: str


@dataclass
class DataComponent:
    data_component_id: str
    name: str
    description: str


@dataclass
class AttackData:
    version: str
    spec_version: str = ""
    techniques: list = field(default_factory=list)
    actors: list = field(default_factory=list)
    revocations: list = field(default_factory=list)
    mitigations: list = field(default_factory=list)
    technique_mitigations: list = field(default_factory=list)
    detection_strategies: list = field(default_factory=list)
    analytics: list = field(default_factory=list)
    data_components: list = field(default_factory=list)


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


def _record_course_of_action(obj, mitigation_by_stix, mitigations):
    """Only live M-id mitigations are kept, returning whether this one was. Before 2019 ATT&CK
    shipped one deprecated mitigation per technique under the technique's own T-id; those
    carry no M-id."""
    if obj.get("revoked") or obj.get("x_mitre_deprecated"):
        return False
    attack_id = _attack_id(obj)
    if not attack_id or not attack_id.startswith("M"):
        return False
    mitigation_by_stix[obj["id"]] = attack_id
    mitigations.append(Mitigation(attack_id, obj.get("name", ""), obj.get("description", "")))
    return True


def _live_target(target_ref, stix_to_attack, pattern_ids, replacement):
    """The live technique id a relationship target names, following a revoked technique to
    its resolved replacement, or None when it names nothing that answers queries."""
    # stix_to_attack also holds intrusion sets, so only an attack-pattern target is looked up.
    if target_ref not in pattern_ids:
        return None
    return stix_to_attack.get(target_ref) or replacement.get(pattern_ids[target_ref])


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


def _live(obj):
    return not obj.get("revoked") and not obj.get("x_mitre_deprecated")


def _analytic_from(obj, strategy_id, component_by_stix):
    sources = [
        # Stripped as tools._check_list strips the caller's names; ATT&CK 19.2 ships 'firmware:integrity '.
        LogSource(
            (ref.get("name") or "").strip(),
            (ref.get("channel") or "").strip(),
            component_by_stix.get(ref.get("x_mitre_data_component_ref")),
        )
        for ref in obj.get("x_mitre_log_source_references", [])
    ]
    return Analytic(
        _attack_id(obj),
        strategy_id,
        obj.get("name", ""),
        obj.get("description", ""),
        list(obj.get("x_mitre_platforms", [])),
        sources,
        list(obj.get("x_mitre_mutable_elements", [])),
    )


def _attach_analytics(strategy_obj, strategy_id, analytic_by_stix, component_by_stix, analytics):
    """Returns how many of the strategy's analytic refs named nothing live."""
    skipped = 0
    for ref in strategy_obj.get("x_mitre_analytic_refs", []):
        analytic = analytic_by_stix.get(ref)
        if analytic is None:
            skipped += 1
            continue
        analytics.append(_analytic_from(analytic, strategy_id, component_by_stix))
    return skipped


def _record_objects(objects):
    """Everything the relationship pass needs, keyed by STIX id, in one walk of the bundle."""
    found = {
        "version": "",
        "spec_version": "",
        "techniques": [],
        "actors": [],
        "mitigations": [],
        "data_components": [],
        "stix_to_attack": {},
        "pattern_ids": {},
        "pattern_names": {},
        "mitigation_by_stix": {},
        "component_by_stix": {},
        "analytic_by_stix": {},
        "strategy_objs": {},
        "skipped_courses_of_action": 0,
    }
    for obj in objects:
        otype = obj.get("type")
        if otype == "x-mitre-collection":
            found["version"] = obj.get("x_mitre_version", found["version"])
            found["spec_version"] = obj.get("x_mitre_attack_spec_version", found["spec_version"])
        elif otype == "attack-pattern":
            _record_attack_pattern(
                obj, found["pattern_ids"], found["pattern_names"], found["stix_to_attack"], found["techniques"]
            )
        elif otype == "intrusion-set":
            _record_intrusion_set(obj, found["stix_to_attack"], found["actors"])
        elif otype == "course-of-action":
            if not _record_course_of_action(obj, found["mitigation_by_stix"], found["mitigations"]):
                found["skipped_courses_of_action"] += 1
        else:
            _record_detection_object(obj, found)
    if found["skipped_courses_of_action"]:
        logger.debug(
            "Skipped %d course-of-action object(s) that are deprecated, revoked or carry no M-id.",
            found["skipped_courses_of_action"],
        )
    return found


def _record_detection_object(obj, found):
    if not _live(obj) or not _attack_id(obj):
        return
    otype = obj.get("type")
    if otype == "x-mitre-data-component":
        found["component_by_stix"][obj["id"]] = _attack_id(obj)
        found["data_components"].append(DataComponent(_attack_id(obj), obj.get("name", ""), obj.get("description", "")))
    elif otype == "x-mitre-analytic":
        found["analytic_by_stix"][obj["id"]] = obj
    elif otype == "x-mitre-detection-strategy":
        found["strategy_objs"][obj["id"]] = obj


def _mitigation_pair(obj, technique_id, found, seen_pairs):
    """The first edge in file order wins when a pair repeats."""
    mitigation_id = found["mitigation_by_stix"].get(obj.get("source_ref"))
    if mitigation_id is None or technique_id is None or (technique_id, mitigation_id) in seen_pairs:
        return None
    seen_pairs.add((technique_id, mitigation_id))
    return TechniqueMitigation(technique_id, mitigation_id, obj.get("description", ""))


def _detection_strategy(obj, technique_id, found, analytics, seen_strategies):
    """None when the edge is not a live strategy detecting a live technique, or the
    strategy was already taken from an earlier edge (the first edge wins)."""
    strategy_obj = found["strategy_objs"].get(obj.get("source_ref"))
    if strategy_obj is None or technique_id is None:
        return None
    strategy_id = _attack_id(strategy_obj)
    if strategy_id in seen_strategies:
        logger.debug("%s already attached to a technique; later detects edge ignored.", strategy_id)
        return None
    seen_strategies.add(strategy_id)
    skipped = _attach_analytics(
        strategy_obj, strategy_id, found["analytic_by_stix"], found["component_by_stix"], analytics
    )
    if skipped:
        logger.warning(
            "%s names %d analytic reference(s) that are deprecated or absent from this bundle; "
            "those analytics are left out.",
            strategy_id,
            skipped,
        )
    return DetectionStrategy(strategy_id, technique_id, strategy_obj.get("name", ""))


def _collect_defense_edges(objects, found, replacement):
    """mitigates and detects edges, after revocations are resolved so a revoked target lands
    on the technique that answers for it."""
    pairs, seen_pairs, seen_strategies, strategies, analytics = [], set(), set(), [], []
    old_model = 0
    for obj in objects:
        if obj.get("type") != "relationship":
            continue
        rel_type = obj.get("relationship_type")
        technique_id = _live_target(obj.get("target_ref"), found["stix_to_attack"], found["pattern_ids"], replacement)
        if rel_type == "mitigates":
            pair = _mitigation_pair(obj, technique_id, found, seen_pairs)
            if pair:
                pairs.append(pair)
        elif rel_type == "detects":
            strategy = _detection_strategy(obj, technique_id, found, analytics, seen_strategies)
            if strategy:
                strategies.append(strategy)
            elif obj.get("source_ref") in found["component_by_stix"]:
                old_model += 1
    if old_model:
        logger.debug(
            "Skipped %d detects relationship(s) from the pre-v18 data-component model; detection "
            "strategies carry detections now.",
            old_model,
        )
    return pairs, strategies, analytics


def parse_attack(path):
    objects = json.loads(Path(path).read_text())["objects"]
    found = _record_objects(objects)
    actor_by_stix = {obj["id"]: obj for obj in objects if obj.get("type") == "intrusion-set"}
    actor_lookup = {a.actor_id: a for a in found["actors"]}
    live_ids = {t.technique_id for t in found["techniques"]}
    revoked_edges = {}
    rejections = {EDGE_NOT_TECHNIQUES: 0, EDGE_LIVE_SOURCE: 0}
    for obj in objects:
        if obj.get("type") != "relationship":
            continue
        rel_type = obj.get("relationship_type")
        if rel_type == "revoked-by":
            rejected = _record_revocation_edge(obj, found["pattern_ids"], live_ids, revoked_edges)
            if rejected:
                rejections[rejected] += 1
        elif rel_type == "uses":
            _record_actor_use(obj, actor_by_stix, found["stix_to_attack"], actor_lookup)
    _log_rejected_edges(rejections)
    revocations = _resolve_revocations(revoked_edges, found["pattern_names"], live_ids)
    replacement = {r.revoked_id: r.replacement_id for r in revocations}
    pairs, strategies, analytics = _collect_defense_edges(objects, found, replacement)
    return AttackData(
        version=found["version"],
        spec_version=found["spec_version"],
        techniques=found["techniques"],
        actors=found["actors"],
        revocations=revocations,
        mitigations=found["mitigations"],
        technique_mitigations=pairs,
        detection_strategies=strategies,
        analytics=analytics,
        data_components=found["data_components"],
    )


KNOWN_SPEC_MAJOR = "3"


class AttackDefensesMissing(ValueError):
    """The bundle parsed but yielded none of the defensive objects the knowledge base needs.
    Raised at ingest so an unattended build stops instead of publishing empty tables."""


def require_defenses(data, path):
    # A strategy enters AttackData only through its detects edge, so one count covers both
    # "no strategy objects" and "no detects edges"; the message names the pair.
    counts = {
        "live mitigations": len(data.mitigations),
        "detection strategies attached to a technique by a detects edge": len(data.detection_strategies),
    }
    empty = [f"{n} {label}" for label, n in counts.items() if n == 0]
    if empty:
        raise AttackDefensesMissing(
            f"{path} yields {', '.join(empty)}. ATT&CK publishes mitigations as course-of-action objects "
            f"with M-ids and detections as x-mitre-detection-strategy objects joined to techniques by "
            f"'detects' relationships; a bundle with none of one kind means the data model changed. "
            f"Read attack.mitre.org/resources/updates/ for the release that did it, update the "
            f"parser, and re-run stig-mcp-ingest."
        )
    major = data.spec_version.split(".")[0] if data.spec_version else ""
    if major != KNOWN_SPEC_MAJOR:
        logger.warning(
            "ATT&CK spec version %s is not the %s.x this parser was written against; the object counts "
            "look healthy, so the build continues. Check the release notes for shape changes.",
            data.spec_version or "(absent)",
            KNOWN_SPEC_MAJOR,
        )
