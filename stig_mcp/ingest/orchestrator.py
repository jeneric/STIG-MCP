import argparse
import hashlib
import json
import logging
import re
import shutil
import tempfile
from collections import defaultdict
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from importlib.metadata import distributions
from pathlib import Path

from stig_mcp import applicability
from stig_mcp.ingest import config, id_corrections, inventory, upstream
from stig_mcp.ingest.attack_parser import parse_attack
from stig_mcp.ingest.cci_parser import cci_list_version, parse_cci_list
from stig_mcp.ingest.control_catalog import catalog_version, parse_control_catalog
from stig_mcp.ingest.mapping_loader import (
    OVERRIDE_VERSION_DEFAULT,
    MappingSet,
    load_ctid_mappings,
    load_overrides,
)
from stig_mcp.ingest.severity import is_known_level
from stig_mcp.ingest.stig_parser import document_kind, parse_stig
from stig_mcp.kb.db import SCHEMA_VERSION, create_db

# The first and only import edge from the ingest to the resolver, spent deliberately. These
# two packages otherwise have no edge in either direction, which is why
# stig_mcp/applicability.py exists as a leaf module both can use; that property is what this
# import gives up. It buys coverage: a token crosses the distinctiveness gate when an
# operator ingests a newer DISA library, and that operator never runs tools/, so a check
# living there would not fire for the person who causes the crossing. The rule itself stays
# in the resolver, which owns the gate, so there is no second copy of it here.
from stig_mcp.resolver.resolver import _DISTINCTIVE_DF_RATIO, distinctiveness_margin

logger = logging.getLogger(__name__)


@dataclass
class IngestSources:
    benchmarks: list
    cci_path: Path
    attack_path: Path
    ctid_path: Path
    overrides_path: Path | None = None
    catalog_path: Path | None = None
    # The library compilation's filename as classify() identified it, independent of
    # whether it ended up contributing anything to benchmarks. None when classify found
    # no library artifact at all. main() sets this; callers that build IngestSources by
    # hand and leave it None fall back to being inferred from benchmark origins, see
    # _library_artifact below.
    library_artifact: str | None = None
    # Set by main() from the attack_index.json stig-mcp-fetch saves, but the ingest
    # must run cleanly without one: hand-placed sources are a first-class path and rarely
    # carry it. See _attack_release_dates.
    attack_index_path: Path | None = None
    # Every file classify() found, for provenance only: build_kb hashes these into
    # source_files and reads nothing from them itself. main() sets it; a caller building
    # IngestSources by hand may leave it empty, and only the supporting sources are recorded.
    artifact_paths: tuple = ()


def _require(path):
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(
            f"Required ingest artifact not found: {path}. Place the downloaded source in "
            f"{config.SOURCES_DIR} before running the ETL. docs/operations.md, section "
            f"'Build the knowledge base', lists every source and where to get it."
        )
    return path


def _keywords(title, stig_id):
    # Fold the benchmark id into the searchable keywords so the resolver can
    # fuzzy-match on tokens the prose title omits (e.g. "rhel", "2022").
    humanized = stig_id.replace("_", " ").replace("-", " ")
    return f"{title} {humanized}".lower()


def _version_key(parsed):
    """Sort key for picking the newest of several files sharing a benchmark id:
    (major version, release number). E.g. V2R4 -> (2, 4) beats V1R1 -> (1, 1)."""
    try:
        major = int(parsed.version or 0)
    except (TypeError, ValueError):
        major = 0
    match = re.search(r"Release:\s*(\d+)", parsed.release_info or "")
    release = int(match.group(1)) if match else 0
    return (major, release)


def discover_stig_paths(sources_dir):
    """XCCDF benchmark files in sources_dir, matched case-insensitively
    (DISA ships some benchmarks as *-xccdf.XML)."""
    sources_dir = Path(sources_dir)
    return sorted(p for p in sources_dir.iterdir() if p.is_file() and p.name.lower().endswith("xccdf.xml"))


def _sourced_pairs(ctid, overrides):
    """Every candidate pair with the version of the file it came from, in a deterministic
    order so that which pair wins a collision never depends on file ordering."""
    pairs = [(pair, ctid.version) for pair in ctid.pairs]
    pairs += [(pair, overrides.version) for pair in overrides.pairs if not pair.suppressed]
    return sorted(pairs, key=lambda item: (item[0].technique_id, item[0].control_id, item[0].source))


def _count_remap(pair, replacement_id, summary):
    """An override naming a revoked id is worth telling the operator about: the pair is
    saved, but their file still names an id ATT&CK retired. A CTID pair is upstream data
    they cannot edit, so it is only counted."""
    if pair.source == "override":
        summary["remapped_override_pairs"] += 1
        logger.warning(
            "overrides.yaml maps %s to %s, but ATT&CK revoked %s in favor of %s. The pair was "
            "remapped so it is not lost; update overrides.yaml to name %s directly.",
            pair.technique_id,
            pair.control_id,
            pair.technique_id,
            replacement_id,
            replacement_id,
        )
        return
    summary["remapped_ctid_pairs"] += 1


def _effective_pairs(ctid, overrides, revocations, summary):
    """Pairs surviving suppression, with revoked technique ids rewritten to the live
    technique that replaced them. Suppression keys are remapped as well: a tombstone
    written against a revoked id has to keep killing the pair once it moves, or
    remapping would silently resurrect a mapping the operator deliberately killed."""
    replacement = {r.revoked_id: r.replacement_id for r in revocations}
    suppressed = {
        (replacement.get(o.technique_id, o.technique_id), o.control_id) for o in overrides.pairs if o.suppressed
    }
    native, remapped = {}, {}
    for pair, version in _sourced_pairs(ctid, overrides):
        moved_to = replacement.get(pair.technique_id)
        technique_id = moved_to or pair.technique_id
        # Tombstones target the upstream mapping set, as overrides.yaml documents, so an
        # operator's own add: entry is never killed by their own suppress: entry.
        if pair.source != "override" and (technique_id, pair.control_id) in suppressed:
            continue
        key = (technique_id, pair.control_id, pair.source)
        if moved_to is None:
            native[key] = version
            continue
        _count_remap(pair, moved_to, summary)
        remapped.setdefault(key, f"{version} via {pair.technique_id}")
    # A native pair states the mapping directly while a remapped one only inherits it,
    # so the native provenance wins when both produce the same row.
    return {(*key, version) for key, version in {**remapped, **native}.items()}


def _validate_sources(sources):
    _require(sources.cci_path)
    _require(sources.attack_path)
    _require(sources.ctid_path)
    if not sources.benchmarks:
        raise FileNotFoundError(
            f"No STIG artifacts found: sources.benchmarks is empty. Place a SRG-STIG "
            f"Library Compilation, a sunset compilation, a product zip, or a loose XCCDF "
            f"benchmark .xml file in {config.SOURCES_DIR} before running the ETL. A loose "
            f"file is taken either because it is named *xccdf.xml or because its root "
            f"element is a Benchmark, so the name alone is not why it was ignored. See "
            f"docs/operations.md, section 'The lifecycle of sources/', for what each "
            f"of those looks like."
        )
    for benchmark in sources.benchmarks:
        _require(benchmark.path)


def _load_ccis(conn, cci_records, summary):
    for record in cci_records:
        conn.execute("INSERT OR IGNORE INTO ccis(cci_id, definition) VALUES (?, ?)", (record.cci_id, record.definition))
    summary["ccis"] = len(cci_records)


def _load_attack(conn, attack, summary):
    known_technique_ids = {tech.technique_id for tech in attack.techniques}
    # Insert base techniques before sub-techniques so the parent_id self-FK is
    # always satisfied; null a parent that isn't in the dataset (e.g. revoked).
    for tech in sorted(attack.techniques, key=lambda t: t.is_subtechnique):
        parent_id = tech.parent_id if tech.parent_id in known_technique_ids else None
        conn.execute(
            "INSERT OR IGNORE INTO techniques(technique_id, name, is_subtechnique, parent_id, tactics, "
            "attack_version, created) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                tech.technique_id,
                tech.name,
                int(tech.is_subtechnique),
                parent_id,
                ",".join(tech.tactics),
                attack.version,
                tech.created,
            ),
        )
    summary["techniques"] = len(attack.techniques)
    for revocation in attack.revocations:
        conn.execute(
            "INSERT OR IGNORE INTO revoked_technique(revoked_id, replacement_id, revoked_name, source_version) "
            "VALUES (?, ?, ?, ?)",
            (revocation.revoked_id, revocation.replacement_id, revocation.revoked_name, attack.version),
        )
    summary["revocations"] = len(attack.revocations)
    for actor in attack.actors:
        conn.execute(
            "INSERT OR IGNORE INTO actors(actor_id, name, aliases) VALUES (?, ?, ?)",
            (actor.actor_id, actor.name, ",".join(actor.aliases)),
        )


def _load_ctid_status(conn, ctid, revocations):
    """Mark each technique mapped, non_mappable or absent in CTID's own terms, before overrides.
    Ids ATT&CK revoked are followed to their replacement, as _effective_pairs does for pairs."""
    replacement = {r.revoked_id: r.replacement_id for r in revocations}
    mapped = {replacement.get(p.technique_id, p.technique_id) for p in ctid.pairs}
    reviewed = {replacement.get(t, t) for t in ctid.non_mappable} - mapped
    for status, ids in (("mapped", mapped), ("non_mappable", reviewed)):
        conn.executemany(
            "UPDATE techniques SET ctid_status = ? WHERE technique_id = ?", [(status, t) for t in sorted(ids)]
        )


def _attack_release_dates(path):
    """{version: release date} from attack_index.json, or {} when it is absent or unreadable.
    Optional like the catalog: without it the server cannot tell a newer technique from one the
    mapping never covered, and says so."""
    if not path or not Path(path).is_file():
        return {}
    try:
        return upstream.parse_attack_index(json.loads(Path(path).read_text())).release_dates
    except (OSError, ValueError, upstream.UpstreamError) as exc:
        logger.warning("Ignoring %s: %s. Answers will not date techniques against the mapping.", Path(path).name, exc)
        return {}


def _load_controls(conn, sources, cci_records, effective):
    """Populate controls from the 800-53r5 catalog (names, families, base<->enhancement
    links). Base controls precede their enhancements in the parser output, so the
    parent_control_id self-FK is always satisfied. The catalog is optional: without it,
    control rows fall back to id-only (name/family NULL). Returns whether the catalog was
    loaded (for the ingest_meta record)."""
    catalog_loaded = bool(sources.catalog_path and Path(sources.catalog_path).exists())
    if catalog_loaded:
        for cc in parse_control_catalog(sources.catalog_path):
            conn.execute(
                "INSERT OR IGNORE INTO controls(control_id, name, family, is_enhancement, parent_control_id) "
                "VALUES (?, ?, ?, ?, ?)",
                (cc.control_id, cc.name, cc.family, int(cc.is_enhancement), cc.parent_control_id),
            )
    elif sources.catalog_path:
        logger.warning(
            "Control catalog not found at %s; control name/family/parent will be "
            "NULL. Run stig-mcp-fetch to download it.",
            sources.catalog_path,
        )

    # FK-integrity fallback: any control referenced by a mapping but absent from the
    # catalog gets an id-only row (name/family NULL) so joins never dangle.
    control_ids = {cid for record in cci_records for cid in record.controls}
    control_ids |= {control for _, control, _, _ in effective}
    for control_id in control_ids:
        conn.execute(
            "INSERT OR IGNORE INTO controls(control_id, is_enhancement) VALUES (?, ?)",
            (control_id, int("(" in control_id)),
        )
    return catalog_loaded


def _load_cci_control(conn, cci_records):
    for record in cci_records:
        for control_id in record.controls:
            conn.execute(
                "INSERT OR IGNORE INTO cci_control(cci_id, control_id, source_version) VALUES (?, ?, ?)",
                (record.cci_id, control_id, "r5"),
            )


def _drop_orphan_pair(technique_id, control_id, source, stale_ctid_ids, summary):
    """An override orphan is a typo in a file the operator wrote, so name the pair. A
    CTID orphan means the published mapping set predates the ingested ATT&CK release,
    which is one fact about the whole file rather than hundreds of separate problems."""
    if source == "override":
        summary["orphan_override_pairs"] += 1
        logger.warning(
            "overrides.yaml maps %s to %s, but %s is not in the ATT&CK bundle, so the pair "
            "was dropped. Check the technique id for a typo, or for an id ATT&CK revoked.",
            technique_id,
            control_id,
            technique_id,
        )
        return
    summary["orphan_ctid_pairs"] += 1
    stale_ctid_ids.add(technique_id)


def _load_technique_control(conn, effective, technique_ids, attack_version, summary):
    stale_ctid_ids = set()
    for technique_id, control_id, source, source_version in sorted(effective):
        if technique_id not in technique_ids:
            _drop_orphan_pair(technique_id, control_id, source, stale_ctid_ids, summary)
            continue
        conn.execute(
            "INSERT OR IGNORE INTO technique_control(technique_id, control_id, source, source_version, suppressed) "
            "VALUES (?, ?, ?, ?, 0)",
            (technique_id, control_id, source, source_version),
        )
    if stale_ctid_ids:
        logger.warning(
            "Dropped %d CTID mapping(s) covering %d technique id(s) that ATT&CK %s does not "
            "define, so those techniques have no controls in this KB. The CTID set is "
            "published against an older ATT&CK release; the ids were: %s",
            summary["orphan_ctid_pairs"],
            len(stale_ctid_ids),
            attack_version,
            ", ".join(sorted(stale_ctid_ids)),
        )


def _load_actor_technique(conn, actors, technique_ids):
    # No orphan accounting here, unlike technique_control: parse_attack only appends a
    # technique_id to an actor when that same technique went into the technique list, so
    # the filter below cannot fire on parser output. Counting it would add a branch no
    # fixture can reach.
    for actor in actors:
        for technique_id in actor.technique_ids:
            if technique_id in technique_ids:
                conn.execute(
                    "INSERT OR IGNORE INTO actor_technique(actor_id, technique_id, source) VALUES (?, ?, 'attack')",
                    (actor.actor_id, technique_id),
                )


def _load_mappings(conn, attack, cci_records, effective, summary):
    technique_ids = {t.technique_id for t in attack.techniques}
    _load_cci_control(conn, cci_records)
    _load_technique_control(conn, effective, technique_ids, attack.version, summary)
    _load_actor_technique(conn, attack.actors, technique_ids)


def _release_label(parsed):
    """The token DISA uses everywhere: zip names, the revision history, cyber.mil.

    Composed from the document's own <version> and Release: N, never from a filename, which
    holds for the Y-dated STIGs too: U_Cisco_IOS_Router_Y24M01_STIG.zip carries
    <version>3</version> and Release: 8 inside, so Y24M01 is a filename convention
    while V3R8 is what the document calls itself."""
    match = re.search(r"Release:\s*(\d+)", parsed.release_info or "")
    if match and (parsed.version or "").strip().isdigit():
        return f"V{parsed.version.strip()}R{match.group(1)}"
    logger.warning(
        "Cannot compose a release label for %s (version=%r, release_info=%r); reporting release_info verbatim instead.",
        parsed.stig_id,
        parsed.version,
        parsed.release_info,
    )
    return parsed.release_info


def _major(version):
    try:
        return int(version)
    except (TypeError, ValueError):
        return 0


def _drop(key, parsed, discovered, reason, summary, counter):  # noqa: PLR0913
    """Report a dropped benchmark at the level its origin deserves.

    A file the operator placed by hand is named individually, because they chose to put
    it there and deserve to know it lost. A benchmark losing inside a bulk archive is one
    of many, so it is counted into a single aggregate line instead."""
    summary[counter] += 1
    if discovered.origin in ("product_zip", "loose"):
        logger.warning(
            "%s %s from %s was not ingested: %s.", key[0], parsed.version, discovered.source_artifact, reason
        )


def _id_key(stig_id):
    """A benchmark id folded for COMPARISON only, never for storage.

    DISA has spelled one product's id two ways across artifacts: the library ships
    `Solaris_11_X86_STIG` at major 3 and the Rev 4 sunset compilation ships
    `Solaris_11_x86_STIG` at major 2. They are one product, so lifecycle selection has to see
    one id at two majors; a literal comparison would make them unrelated products and keep the
    retired major in the knowledge base beside the current one.

    Comparison only, because the stored spelling is the surviving document's own and the
    `stig_rules` foreign key is written against it. Nothing is merged or renamed here.

    This folds the MAJOR-level contest in _select, and nothing else. `_group_by_published_key`
    still groups on the literal id, so two spellings at the SAME major never meet the release
    contest in `_contest`, and _select then sees two keys rather than one. Three shapes
    therefore still leave both spellings in `stigs`: two library rows (_select keeps every
    library row before consulting library_max at all); a library row at a lower major than a
    non-library one, where the major rule keeps both; and two non-library rows at one major,
    which the local_max branch keeps because each equals the maximum.

    Separately, and not one of those three because it leaves only ONE row: two spellings at the
    same major never meet `_contest`, so _select compares majors alone and the library row wins
    even when the non-library one carries a newer RELEASE. A same-spelling pair is arbitrated
    by release first, so the newer release wins.

    The second shape occurs in real corpora: DISA has shipped both spellings of BIND
    (`BIND_9-x_STIG`, `Bind_9-x_STIG`) in libraries over time as well as in product zips, so
    expect this class to recur rather than treating Solaris as a one-off. No DISA compilation
    examined carries two spellings of one id, so every pair this can reach is cross-artifact.
    """
    return stig_id.lower()


def _origin_rank(discovered):
    # 1 means library because this feeds a max-style comparison (see _contest's use in
    # _settle). resolver._origin_rank shares this name and returns the opposite, 0 for
    # library, because it feeds an ascending sort. Both are correct in place; copying
    # either one over the other silently inverts the rule.
    return 1 if discovered.origin == "library" else 0


def _contest(parsed, discovered):
    """Sort key deciding which of two files at the same (id, major) wins.

    Newer RELEASE first; then the current library beats everything else at the same release;
    then the later DOCUMENT wins; then the artifact name.

    The last two exist because DISA republishes an unchanged benchmark across successive
    quarterly archives, so two product zips routinely supply one key at one release. With only
    the first two components that is a tie, the incumbent survives, and the incumbent is
    whichever file classify walked first, so the selection would depend on walk order.

    status_date is the correctness component and is deliberately not the filename: the Y25M07
    convention is not universal. It is already ISO, so it sorts as a plain string with no date
    parsing and no locale assumption, and None floors to "" so an undated document loses to a
    dated one. DISA's STIG documents carry an ISO yyyy-mm-dd status date, so the lexical
    comparison is sound. The real case it decides is Citrix XenDesktop V1R3, republished with
    renumbered rule ids and a deprecated status; picking the older copy discards the lifecycle
    data the xccdf_status column exists to carry.

    source_artifact does no correctness work. It only breaks the remaining ties between
    artifacts, which are between identical republications, so its choice is arbitrary by
    construction and its whole value is that it is stable.

    THE ORDER IS TOTAL ACROSS ARTIFACTS, NOT ABSOLUTELY. Two documents reaching this contest
    from one artifact share a source_artifact, and a source_member too when an inner zip holds
    both, so they still compare equal and the incumbent still survives on walk order. Walk
    order would be wrong for two different benchmarks sharing one id (the MS SQL 2012 Database
    and Instance pair in one inner zip), so _resolve_group catches that case before this
    contest runs (see _find_collision). What is left for the walk order to decide here is a
    document from one artifact tying against another that _distinct_benchmarks did NOT judge
    to be a second benchmark, whether because their rule ids are identical, merely overlapping
    rather than disjoint, or one side holds no rules at all. There the walk order cannot be
    wrong the way a resurrected split id would be, because neither document claims to be a
    second benchmark in the first place."""
    return (_version_key(parsed), _origin_rank(discovered), parsed.status_date or "", discovered.source_artifact)


def _distinct_benchmarks(parsed, discovered, other_parsed, other_discovered):
    """Two documents at one key that cannot be releases of each other.

    All three conditions carry weight, and disjointness alone is measurably wrong, because DISA
    renumbers rule ids: HP_FlexFabric_Switch_NDM_STIG V1R2 and V1R4 share none of their rules,
    and Citrix_XenDesktop_License_Server_STIG V1R3 was renumbered with no release bump at all.
    Both are ordinary supersessions, and both arrive from DIFFERENT artifacts. Inside ONE
    artifact at ONE release neither document can be a later release of the other; the known
    disjoint pair there is the MS SQL 2012 Database and Instance split.

    An empty rule set is disjoint from everything, so it is excluded: a document with no rules
    is a parse or content problem, not a second benchmark."""
    if discovered.source_artifact != other_discovered.source_artifact:
        return False
    if _version_key(parsed) != _version_key(other_parsed):
        return False
    rule_ids = {rule.rule_id for rule in parsed.rules}
    other_rule_ids = {rule.rule_id for rule in other_parsed.rules}
    return bool(rule_ids) and bool(other_rule_ids) and rule_ids.isdisjoint(other_rule_ids)


def _corrected(parsed, discovered, corrections):
    """The document under its corrected identity, or None when the map cannot name it."""
    correction = id_corrections.correction_for(parsed.stig_id, discovered.source_document, corrections)
    if correction is None:
        return None
    # benchmark_id is deliberately untouched. stig_parser sets it from the document's own
    # Benchmark/@id, so DISA's published identity survives in the row even though the id this
    # knowledge base keys on is ours.
    return replace(parsed, stig_id=correction.stig_id, title=correction.title)


def _correct_pair(first, second, corrections):
    """Both halves of a detected collision under their corrected identities, or None when the
    map cannot name at least one of them. The caller then falls back to the ordinary contest
    rather than storing either document under the id the split found it claiming."""
    corrected = [_corrected(first[0], first[1], corrections), _corrected(second[0], second[1], corrections)]
    return None if any(document is None for document in corrected) else corrected


def _keys_available(corrected, newest_by_key):
    """Whether a corrected pair's own ids are free to occupy.

    Takes whatever `corrected` it is given, not only one built from a map that has been
    through id_corrections.load_corrections: a hand-built map can name the same stig_id twice
    for both halves, so the distinctness check stays live even though the shipped
    id_corrections.yaml can never produce it (id_corrections._unique already rejects that
    there, and both halves share a version by construction, having reached here through
    _distinct_benchmarks)."""
    keys = [(document.stig_id, document.version) for document in corrected]
    if len(set(keys)) != len(keys):
        return False
    return not any(key in newest_by_key for key in keys)


def _report_departure(winner_discovered, loser_key, loser_parsed, loser_discovered, summary):
    """Count every benchmark that loses a same-key contest, and say what beat it.

    A non-library loser to a library winner keeps its own counter, because the library is the
    artifact DISA maintains today, an operator's stale duplicate losing to it is news, and
    docs/operations.md and the quarterly refresh checklist both cite that number by name.

    Everything else is counted too: a library copy losing to a newer product zip release, and two
    non-library artifacts contesting one key. Uncounted, a benchmark could be replaced by a
    different document and leave no trace in the summary, and that happens hundreds of times
    per full build.

    same_key_departures is deliberately redundant with that split, and is an axis rather than a
    third bin: every departure here increments it as well as exactly one of the two counters.
    The split is the operator's view, answering what beat this benchmark. The total is the corpus
    harness's, and it needs its own number because superseded_by_library is also written by
    _select for the major-level contest, which supplies most of it, so a harness comparing the
    split's sum against a replay of THIS contest compares two different populations."""
    summary["same_key_departures"] += 1
    if winner_discovered.origin == "library" and loser_discovered.origin != "library":
        counter = "superseded_by_library"
        reason = "the current library already ships this benchmark"
    else:
        counter = "superseded_same_key"
        reason = f"{winner_discovered.source_artifact} supplied the same benchmark and won"
    _drop(loser_key, loser_parsed, loser_discovered, reason, summary, counter)


def _warn_uncorrectable(key, first, second, summary):
    """A detected same-artifact collision whose map entry cannot name at least one document."""
    summary["same_key_collision_unmapped"] += 1
    logger.warning(
        "%s is claimed by two different benchmarks in %s, sharing no rule ids: %s and %s. "
        "One of them will be discarded. Add an entry for %s to %s naming both documents.",
        key[0],
        first[1].source_artifact,
        first[1].source_document,
        second[1].source_document,
        key[0],
        id_corrections.CORRECTIONS_PATH.name,
    )


def _warn_occupied(key, first, second, corrected, summary):
    """A detected collision the map DOES name, but a corrected id is already held by an
    unrelated benchmark this build kept. Distinct wording from _warn_uncorrectable: telling the
    operator to add an entry that already exists does not say what they actually need to
    change, which is either the map or the id it collides with."""
    summary["same_key_collision_unmapped"] += 1
    occupied = " and ".join(f"{document.stig_id} {document.version}" for document in corrected)
    logger.warning(
        "%s in %s corrects to %s, but a different benchmark is already kept under one of "
        "those ids. Declining the split rather than overwriting it: one of %s and %s will be "
        "discarded instead.",
        key[0],
        id_corrections.CORRECTIONS_PATH.name,
        occupied,
        first[1].source_document,
        second[1].source_document,
    )


def _settle(key, parsed, discovered, newest_by_key, summary):
    """Insert this document at key, or run the same-key contest against whoever already holds
    it. Returns whether this document is the one now resident at key, so a caller that needs to
    know whether its own document survived (rather than merely was offered) can tell."""
    current = newest_by_key.get(key)
    if current is None:
        newest_by_key[key] = (parsed, discovered)
        return True
    if _contest(parsed, discovered) > _contest(current[0], current[1]):
        _report_departure(discovered, key, current[0], current[1], summary)
        newest_by_key[key] = (parsed, discovered)
        return True
    _report_departure(current[1], key, parsed, discovered, summary)
    return False


def _split_collision(key, first, second, newest_by_key, corrections, summary):  # noqa: PLR0913
    """Correct and store both halves of a same-artifact, same-release, disjoint-rule
    collision under their own ids.

    Returns the corrected pair when both were stored, in which case no contest is run and no
    departure is counted for THIS call, because neither loses to the other at this moment; a
    corrected id already held by an unrelated benchmark was already excluded by
    _keys_available. That is not a lifetime guarantee: a document arriving later for the same
    corrected id (see _route_split_arrival) can still displace one of these two through the
    ordinary _settle contest, which does count that as a departure when it happens. Returns
    None for everything else, including a detected collision the map cannot name and one the
    map names but whose corrected ids are already occupied: the caller then runs the ordinary
    same-key contest, and the operator gets a WARNING naming what went wrong. A curation gap
    must degrade to that contest, never abort a build.

    same_key_content_collision counts once per published id where such a pair was found, not
    once per pair: _find_collision only ever reports the first pair in a group, so two
    independent same-artifact pairs sharing one id (see the two-artifacts test) count 1 here,
    not 2. id_corrections_applied is NOT counted here; see _resolve_group and
    _stored_corrections, since whether a document is still resident at the end is not decided
    until the whole group has been processed."""
    summary["same_key_content_collision"] += 1
    corrected = _correct_pair(first, second, corrections)
    if corrected is None:
        _warn_uncorrectable(key, first, second, summary)
        return None
    if not _keys_available(corrected, newest_by_key):
        _warn_occupied(key, first, second, corrected, summary)
        return None
    for document, (_parsed, source) in zip(corrected, (first, second)):
        newest_by_key[(document.stig_id, document.version)] = (document, source)
    logger.info(
        "%s in %s is two benchmarks sharing one id; kept both as %s.",
        key[0],
        first[1].source_artifact,
        " and ".join(document.stig_id for document in corrected),
    )
    return corrected


def _route_split_arrival(parsed, discovered, corrections, summary):
    """A document self-reporting a published id this build already split elsewhere in the same
    run. It must never come to rest under that id, or it silently resurrects the id one half of
    the split gave up: see _resolve_group. Returns the corrected document and its key, or
    (None, None) once an uncorrectable one has been warned about, counted as an unmapped
    collision, and reported as a same-key departure so it still reconciles against stig_files
    like every other discard in this file. Correcting a document here does not yet count it
    into id_corrections_applied: whether it is actually stored is still decided by the _settle
    contest the caller runs next, so that counter is the caller's responsibility too (see
    _resolve_group and _stored_corrections)."""
    corrected = _corrected(parsed, discovered, corrections)
    if corrected is None:
        # same_key_collision_unmapped here means "a document claiming an already-split id could
        # not itself be corrected", a different event from the two _warn_* meanings above, which
        # both mean "a newly detected pair could not be resolved". All three share the counter.
        summary["same_key_collision_unmapped"] += 1
        logger.warning(
            "%s from %s self-reports %s, an id this build already split into separate "
            "benchmarks, but it does not match either document pattern in %s. Discarding it "
            "rather than storing it back under the split id.",
            discovered.source_document or discovered.path,
            discovered.source_artifact,
            parsed.stig_id,
            id_corrections.CORRECTIONS_PATH.name,
        )
        summary["same_key_departures"] += 1
        _drop(
            (parsed.stig_id, parsed.version),
            parsed,
            discovered,
            "its published id was already split into separate benchmarks by this build, and "
            "this document could not be corrected to either half's id",
            summary,
            "superseded_same_key",
        )
        return None, None
    return corrected, (corrected.stig_id, corrected.version)


def _find_collision(members):
    """The first same-artifact, same-release, disjoint-rule pair among everything sharing one
    published id, or None. A nested scan over pairs, not a single pass: no DISA compilation
    examined holds more than one such pair per id, so the first one found is resolved and
    anything left over is the caller's responsibility (see _resolve_group). The
    scan is pairwise rather than adjacent-only on purpose: the two halves of a real split are
    not guaranteed to be next to each other once a third document sharing the id sits between
    them in arrival order (see the interleaved-ordering test)."""
    for index, member in enumerate(members):
        parsed, discovered = member
        for other in members[index + 1 :]:
            other_parsed, other_discovered = other
            if _distinct_benchmarks(parsed, discovered, other_parsed, other_discovered):
                return member, other
    return None


def _settle_group(key, members, newest_by_key, summary):
    for parsed, discovered in members:
        _settle(key, parsed, discovered, newest_by_key, summary)


def _stored_corrections(corrected, newest_by_key):
    """How many of these corrected documents are still the ones actually resident under their
    id. A correction can be produced, even momentarily stored, and then lose a later contest to
    another corrected document claiming the same id (see the lone-half-after-the-pair
    ordering); counting it there would report more corrections applied than the database
    actually holds."""
    return sum(
        1
        for document in corrected
        if newest_by_key.get((document.stig_id, document.version), (None, None))[0] is document
    )


def _resolve_group(key, members, newest_by_key, corrections, summary):
    """Everything self-reporting one published id, in arrival order.

    Grouped and resolved together, rather than reduced pairwise as documents stream in, so that
    finding a same-artifact collision does not depend on what else shares the id or where in
    the walk it falls: a foreign document sharing the id cannot stand between the two true
    halves and cost one of them its only contest before they are ever compared to each other.
    That is all this grouping guarantees: _contest's own walk-order tiebreak for two documents
    it genuinely cannot tell apart still applies (see _contest), and _keys_available's
    occupancy check depends on what an EARLIER group already stored, so which of two published
    ids wins a genuine name collision against an unrelated benchmark is sensitive to which
    group this loop reaches first.

    A found pair is corrected and stored under its own ids; nothing here folds it into the
    ordinary release/origin contest below. Anything else sharing the key, including a document
    arriving after the pair, must be routed through _route_split_arrival once the id is known
    split, never settled under the published id directly."""
    pair = _find_collision(members)
    if pair is None:
        _settle_group(key, members, newest_by_key, summary)
        return
    first, second = pair
    corrected = _split_collision(key, first, second, newest_by_key, corrections, summary)
    if corrected is None:
        _settle_group(key, members, newest_by_key, summary)
        return
    remaining = [member for member in members if member is not first and member is not second]
    for parsed, discovered in remaining:
        redirected, redirected_key = _route_split_arrival(parsed, discovered, corrections, summary)
        if redirected is not None and _settle(redirected_key, redirected, discovered, newest_by_key, summary):
            corrected.append(redirected)
    summary["id_corrections_applied"] += _stored_corrections(corrected, newest_by_key)


_SKIP_COUNTER = {"srg": "skipped_srg", "draft": "skipped_draft", "neither": "skipped_unclassified"}


def _skip_non_stig(kind, parsed, discovered, summary):
    """Count a document the classifier rejected, and warn only when it is a mystery.

    SRG and draft rejections are routine and numerous, so they stay an aggregate count; a
    DEBUG line names every skip regardless of kind, for whoever is triaging a specific corpus
    build. A document that identifies as neither is rare and is the tripwire for DISA
    changing their titling convention, so it alone escalates to a WARNING naming it."""
    summary[_SKIP_COUNTER[kind]] += 1
    logger.debug("%s from %s classified as %s and skipped", parsed.stig_id, discovered.source_artifact, kind)
    if kind == "neither":
        logger.warning(
            "%s (%r) from %s identifies as neither a STIG nor an SRG, so it is not ingested. "
            "If DISA has changed how they title benchmarks, document_kind needs a new rule.",
            parsed.stig_id,
            parsed.title,
            discovered.source_artifact,
        )


def _group_by_published_key(benchmarks, summary):
    """Parse and classify every benchmark file, grouping the survivors by the (stig_id,
    version) each self-reports, in arrival order. Grouping first, rather than reducing
    key-by-key as documents stream in, is what lets _resolve_group find a same-artifact
    collision regardless of what else shares its id or in what order it arrives."""
    groups = {}
    for discovered in benchmarks:
        try:
            parsed = parse_stig(discovered.path)
        except Exception as exc:
            # One malformed benchmark among a whole library must not abort the build.
            logger.warning("Skipping unparseable STIG file %s: %s", discovered.path, exc, exc_info=True)
            continue
        kind = document_kind(parsed)
        if kind != "stig":
            _skip_non_stig(kind, parsed, discovered, summary)
            continue
        summary["stig_files"] += 1
        groups.setdefault((parsed.stig_id, parsed.version), []).append((parsed, discovered))
    return groups


def _newest_benchmarks(benchmarks, summary, corrections=None, library_keys=None):
    """Parse every benchmark file, keeping the newest RELEASE within each
    (benchmark id, major version). Distinct majors coexist: DISA pins some STIGs to a
    product release train (e.g. vSphere 8.0 V1R1 -> 8.0 U1/U2, V2Rx -> U3), so both
    majors must survive; _select decides between majors.

    A same-key, same-release tie is decided by origin: the current library always beats
    a sunset, product_zip or loose copy of the same release, so an operator's hand-placed
    duplicate can never silently outrank the library just because classify walked it
    first. A genuinely newer release still wins regardless of origin. When origin ties as
    well, which is the routine case for two product zips, _contest goes on to the document's
    own status_date and then its artifact name, so the winner does not depend on which
    artifact was walked first. Two documents arriving from the SAME artifact at the SAME
    release are handled before _contest ever runs on them, regardless of whether it could
    decide between them: when their rule id sets are disjoint they are not one benchmark at
    all, and _resolve_group keeps both under corrected ids instead of folding them into this
    contest.

    library_keys, when given, receives every key a library document offered, whether or not
    that document survived the contest. _select needs it: the contest can replace a library row
    with a newer non-library release of the same major, and afterwards nothing in newest_by_key
    says the library ever shipped that major."""
    corrections = id_corrections.load_corrections() if corrections is None else corrections
    newest_by_key = {}
    groups = _group_by_published_key(benchmarks, summary)
    if library_keys is not None:
        library_keys.update(key for key, members in groups.items() if any(d.origin == "library" for _p, d in members))
    for key, members in groups.items():
        _resolve_group(key, members, newest_by_key, corrections, summary)
    return newest_by_key


def _maxima(newest_by_key):
    """The highest major per folded id among library rows and among the rest, and the winning
    spelling of each, for _select's drop messages."""
    library_max, local_max = {}, {}
    # The winning SPELLING per folded id, so a drop message can name the benchmark that beat
    # this one. Without it "the current library already ships this benchmark" leaves an
    # operator nothing to search for, and folding is what makes the winner's spelling
    # potentially differ from the loser's.
    winner = {}
    for (stig_id, version), (_parsed, discovered) in newest_by_key.items():
        folded = _id_key(stig_id)
        target = library_max if discovered.origin == "library" else local_max
        # `not in winner` first, and it is load bearing rather than defensive: `_major` returns
        # int(version) from the XCCDF's own <version> text, so a document declaring a negative
        # major never beats the -1 sentinel. Comparing on the major alone would leave `winner`
        # unset while `target` is set, and the lookup in _select would raise KeyError, aborting
        # a whole build against docs/operations.md's promise that a malformed benchmark is
        # logged and skipped. A bare `>=` would handle a PAIR of negative majors but not a lone
        # one. This does not close every abort: a <Benchmark> with no id parses to stig_id
        # None, which document_kind still calls a STIG, and that fails here on the fold.
        winner_key = (discovered.origin == "library", folded)
        if winner_key not in winner or _major(version) > target.get(folded, -1):
            winner[winner_key] = stig_id
        target[folded] = max(target.get(folded, -1), _major(version))

    return library_max, local_max, winner


def _select(newest_by_key, summary, library_keys=frozenset()):
    """Which benchmarks survive when several artifacts supply the same id.

    Coexisting majors are legal only where the current library deliberately ships both.
    That is the vSphere case, justified by DISA's own Overview PDF and arbitrated by
    applicability.yaml. A retired product has no such statement and no live build to
    arbitrate for, so a second major there is pure double-answer, and without this the knowledge
    base would carry their rule_ids twice. A non-library row is dropped when the library ships
    its id at the same or a higher major; when the library does not ship the id at all, every
    non-library row below the highest non-library major is dropped. A non-library row in
    library_keys is kept regardless: it beat the library's own copy on release, at a major the
    library offered."""
    library_max, local_max, winner = _maxima(newest_by_key)
    kept = {}
    for key, (parsed, discovered) in newest_by_key.items():
        stig_id, version = key
        folded = _id_key(stig_id)
        # A non-library row at a key in library_keys beat the library's own copy on release at a
        # major the library ships, so it is kept before any major comparison: when it beat every
        # library copy of the id, library_max no longer holds the id at all.
        if discovered.origin == "library" or key in library_keys:
            kept[key] = (parsed, discovered)
        elif folded in library_max:
            if _major(version) > library_max[folded]:
                kept[key] = (parsed, discovered)
            else:
                _drop(
                    key,
                    parsed,
                    discovered,
                    f"the current library already ships this benchmark as "
                    f"{winner[(True, folded)]} major {library_max[folded]}",
                    summary,
                    "superseded_by_library",
                )
        elif _major(version) == local_max[folded]:
            kept[key] = (parsed, discovered)
        else:
            _drop(
                key,
                parsed,
                discovered,
                f"{winner[(False, folded)]} major {local_max[folded]} of the same benchmark is newer",
                summary,
                "superseded_by_newer_major",
            )
    return kept


def _insert_rules(conn, parsed, seen_rule_ids, summary):
    """Store this benchmark's rules, returning who already held the ones it could not take.

    Returns {(stig_id, version): [group_id, ...]}, the benchmarks that already held what this one
    could not take and the groups it lost to each. seen_rule_ids maps a rule_id to the
    (stig_id, version) that stored it, rather than being a plain set, because the count alone
    does not tell an operator where the guidance went. Without it, finding the holder means
    querying the built knowledge base.
    """
    holders = defaultdict(list)
    for rule in parsed.rules:
        if rule.rule_id in seen_rule_ids:
            # rule_id is the PK; a collision across benchmarks/versions would be silently
            # dropped by INSERT OR IGNORE. DEBUG rather than WARNING because this fires once
            # per RULE, over a hundred lines on a library build, which would bury the count.
            # _warn_rules_held_elsewhere reports the same thing once per benchmark, and only
            # this level still names the individual ids.
            held_by = seen_rule_ids[rule.rule_id]
            # group_id is the only column separating two occurrences inside ONE document, so it
            # is the only thing that identifies WHICH requirement was dropped. Without it this
            # line names an id that is still in the knowledge base, attached to the survivor.
            logger.debug(
                "Duplicate rule_id %s from group %s (in %s %s): kept the first occurrence, which %s %s stored",
                rule.rule_id,
                rule.group_id,
                parsed.stig_id,
                parsed.version,
                held_by[0],
                held_by[1],
            )
            summary["rule_id_collisions"] += 1
            # The GROUP, not just a count. For a duplicate inside one document it is the only
            # thing identifying which requirement was dropped, and stig-mcp-ingest logs at INFO
            # with no flag to lower it (main() parses no options), so a DEBUG line an operator
            # cannot reach is not a record of anything.
            holders[held_by].append(rule.group_id)
            continue
        seen_rule_ids[rule.rule_id] = (parsed.stig_id, parsed.version)
        if not is_known_level(rule.severity_level):
            summary["unknown_severity"] += 1
        conn.execute(
            "INSERT INTO stig_rules(rule_id, group_id, stig_id, stig_version, severity_cat, "
            "severity_level, title, discussion, fix_text, check_text) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                rule.rule_id,
                rule.group_id,
                parsed.stig_id,
                parsed.version,
                rule.severity_cat,
                rule.severity_level,
                rule.title,
                rule.discussion,
                rule.fix_text,
                rule.check_text,
            ),
        )
        summary["stig_rules"] += 1
        for cci_id in rule.ccis:
            conn.execute("INSERT OR IGNORE INTO rule_cci(rule_id, cci_id) VALUES (?, ?)", (rule.rule_id, cci_id))
    return holders


# How many holders one WARNING names before it summarizes the rest. A loser's ids are not
# necessarily held by one benchmark: Network_-_Infrastructure_Router_-_Cisco loses its 88 ids
# to four holders, 44/26/10/8. Three keeps the line readable while naming the ones carrying
# the bulk.
_NAMED_HOLDERS = 3


def _holder_phrase(parsed, holders):
    """Who holds this benchmark's lost ids: the within-document duplicate first, then largest share.

    A benchmark can hold its own id, because DISA ships duplicates INSIDE one document: SAN and
    MULTI-FUNCTION_DEVICE each do. Naming the loser as its own holder would read like a defect
    in the message, so that case says what it is instead, and it is named FIRST and never
    truncated: it is at most one entry, the tail sentence turns on it, and folding it into
    "N further benchmark(s)" would both call it a benchmark and lose the fact.
    """
    self_key = (parsed.stig_id, parsed.version)
    others = sorted(
        ((key, groups) for key, groups in holders.items() if key != self_key),
        key=lambda pair: -len(pair[1]),
    )
    named = [f"{stig_id} {version} ({len(groups)})" for (stig_id, version), groups in others[:_NAMED_HOLDERS]]
    remaining = len(others) - len(named)
    if remaining:
        named.append(f"{remaining} further benchmark(s)")
    if self_key in holders:
        groups = ", ".join(str(group) for group in holders[self_key])
        named.insert(0, f"a duplicate id within the document, dropping group(s) {groups}")
    return ", ".join(named)


# The sentences that follow the holder list. They are composed rather than chosen, because a
# benchmark can lose ids BOTH ways at once and only one of the two would then be true.
_ELSEWHERE = (
    "Insertion order is newest xccdf_status_date, then library origin, then stig_id, then the newer "
    "major, so for the ids held by ANOTHER benchmark what moved is attribution: that guidance is in "
    "the knowledge base under the holding benchmark and a query scoped to %s is short by them."
)
# A within-document duplicate is a different requirement, not a repeat: in both of DISA's real
# cases, SV-6802r1_rule in SAN and SV-7031r1_rule in MULTI-FUNCTION_DEVICE, the two occurrences
# differ in title, fix text and check text, so the dropped one is in no benchmark at all and
# this sentence must not say nothing is missing.
#
# Nor may it offer the cross-benchmark sentence's composite key as the fix: both occurrences
# share (stig_id, stig_version, rule_id), being one document, so only group_id separates them.
# One phrase for both shapes would send a reader to a fix that leaves this case where it is.
_WITHIN = (
    "The duplicate inside this document is a different requirement carrying an id already used, not "
    "a repeat of it, so the group named above is stored under no benchmark and its text is only in "
    "the source XML. No insertion order can change that, and neither would a "
    "(stig_id, stig_version, rule_id) key, since both occurrences share all three. Separating them "
    "needs group_id in the key, which is necessary and not sufficient: rule_cci.rule_id is a foreign "
    "key onto stig_rules(rule_id) and would have to move with it."
)


def _warn_rules_held_elsewhere(parsed, holders):
    skipped = sum(len(groups) for groups in holders.values())
    self_key = (parsed.stig_id, parsed.version)
    tail = []
    if set(holders) - {self_key}:
        tail.append(_ELSEWHERE % parsed.stig_id)
    if self_key in holders:
        tail.append(_WITHIN)
    logger.warning(
        "%s %s stores %d of the %d rules parsed from it: %d rule id(s) are already held by %s. %s",
        parsed.stig_id,
        parsed.version,
        len(parsed.rules) - skipped,
        len(parsed.rules),
        skipped,
        _holder_phrase(parsed, holders),
        " ".join(tail),
    )


def _insertion_order(newest_by_key):
    """Benchmarks in the order they claim a rule_id: newest status date, then library, then id.

    `stig_rules.rule_id` is a global PRIMARY KEY and `_insert_rules` keeps the first
    occurrence, so this order alone decides which benchmark a shared id is attributed to.
    Two benchmarks legitimately share ids where DISA renames a product and carries its rules
    across: `RH_OpenShift_Container_Platform_4-12_STIG` and
    `RH_OpenShift_Container_Platform_4-x_STIG` share most of their rule ids, and the shared
    rules are byte-identical in title, fix, check and severity. Nothing is lost either way;
    what moves is which benchmark answers completely.

    Left to `newest_by_key`'s dict order, the winner would be an accident of the directory
    walk, and the newer benchmark could be served only a fraction of its rules. Under this
    order the OLDER-DATED benchmark is the one left short, which is the trade this ordering
    makes rather than a defect. Not "the superseded one": these two are a RENAME carrying
    identical rules across, and docs/operations.md separates that from supersession because
    only one of the two shapes means the loser has a successor. Making both answer completely
    needs a composite key on `stig_rules`, which is a schema change.

    A benchmark stating no status date sorts last: preferring one that states its currency is
    the whole point, and `""` is smaller than any date under the descending sort.

    Two passes because the directions differ. `stig_id` ascending has no meaning of its own
    and sits UNDER date and origin, which descend. Python's sort is stable, so the least
    significant key is sorted first.

    `stig_id` alone is NOT a total order: `newest_by_key` is keyed `(stig_id, version)` and
    `_select` keeps every library row whatever its major, so two majors of one id coexist and
    tie (the vSphere 8-0 families). With equal dates such a pair would fall through to dict
    order, so the newer MAJOR breaks the tie, descending for the same reason the date does.
    `_major` returns 0 for anything it cannot read rather than raising, so an unreadable
    version sorts behind every real major and never aborts a build. Behind, not last: a
    document declaring a NEGATIVE major sorts behind the unreadable one, and two unreadable
    versions of one id tie with each other. Both are junk documents sitting behind every
    real major, and both are `_major`'s existing semantics, which `_select` already relies on.
    """
    ordered = sorted(newest_by_key.values(), key=lambda pair: (pair[0].stig_id, -_major(pair[0].version)))
    ordered.sort(key=lambda pair: (pair[0].status_date or "", _origin_rank(pair[1])), reverse=True)
    return ordered


def _insert_stigs(conn, newest_by_key, summary, now):
    seen_rule_ids = {}
    for parsed, discovered in _insertion_order(newest_by_key):
        conn.execute(
            "INSERT OR IGNORE INTO stigs(stig_id, version, title, benchmark_id, release_info, "
            "release_label, product_keywords, origin, source_artifact, source_member, "
            "xccdf_status, xccdf_status_date) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                parsed.stig_id,
                parsed.version,
                parsed.title,
                parsed.benchmark_id,
                parsed.release_info,
                _release_label(parsed),
                _keywords(parsed.title, parsed.stig_id),
                discovered.origin,
                discovered.source_artifact,
                discovered.source_member,
                parsed.status,
                parsed.status_date,
            ),
        )
        holders = _insert_rules(conn, parsed, seen_rule_ids, summary)
        if holders:
            _warn_rules_held_elsewhere(parsed, holders)
        conn.execute(
            "INSERT OR REPLACE INTO ingest_meta(source_name, source_version, artifact_url_or_file, "
            "ingested_at, schema_version) VALUES (?, ?, ?, ?, ?)",
            (
                f"stig:{parsed.stig_id}:{parsed.version}",
                parsed.version,
                discovered.source_artifact,
                now,
                SCHEMA_VERSION,
            ),
        )
    summary["stigs"] = len(newest_by_key)


def _library_artifact(sources):
    """The library compilation's filename to cite, preferring what classify() identified
    over what happened to yield rows.

    sources.library_artifact carries the classified name when main() set it. A hand-built
    IngestSources that leaves it unset (as most tests do) falls back to inferring it from
    benchmark origins. Preferring the classified name means a compilation that classified
    correctly but contributed zero benchmarks (a truncated download, or one holding only SRGs)
    is still cited rather than silently disappearing from the sources block."""
    if sources.library_artifact is not None:
        return sources.library_artifact
    return next((b.source_artifact for b in sources.benchmarks if b.origin == "library"), None)


def _source_versions(sources, attack, ctid, catalog_loaded):
    """The ingest_meta payload _populate writes: the per-source versions _write_source_meta
    already recorded, plus the extra rows naming the mapping's own ATT&CK currency."""
    versions = {
        "attack": attack.version,
        "ctid": ctid.version,
        "cci": cci_list_version(sources.cci_path) or "",
        "catalog": (catalog_version(sources.catalog_path) or "") if catalog_loaded else "",
    }
    extra = []
    if ctid.attack_version:
        extra.append(("ctid_attack_version", ctid.attack_version, sources.ctid_path))
        released = _attack_release_dates(sources.attack_index_path).get(ctid.attack_version)
        if released:
            extra.append(("ctid_attack_release", released, sources.attack_index_path))
    return versions, extra


def _write_extra_meta(conn, extra, now):
    """ingest_meta rows that describe a source rather than name one: the mapping's ATT&CK version
    and its release date."""
    for name, version, path in extra:
        conn.execute(
            "INSERT OR REPLACE INTO ingest_meta(source_name, source_version, artifact_url_or_file, "
            "ingested_at, schema_version) VALUES (?, ?, ?, ?, ?)",
            (name, version, Path(path).name, now, SCHEMA_VERSION),
        )


# A packaged license file's dist-info path is <name>.dist-info/licenses/<relative path>: at
# least this many leading parts before the relative path fragment begins.
_LICENSE_PATH_MIN_PARTS = 2


def _license_files_of(dist):
    """The license files one distribution ships, keyed by its path under dist-info/licenses."""
    texts = {}
    for file in dist.files or ():
        if (
            len(file.parts) > _LICENSE_PATH_MIN_PARTS
            and file.parts[0].endswith(".dist-info")
            and file.parts[1] == "licenses"
        ):
            texts["/".join(file.parts[2:])] = file.read_text(encoding="utf-8")
    return texts


def _license_texts():
    """Every license file this distribution ships, keyed by its path under dist-info/licenses.

    Read from the installed distribution because pyproject.toml's license-files decides which
    notices travel with the package, and the same set must travel inside every knowledge base:
    ATT&CK's terms require its notice "in any such copy", and a knowledge base is copied on its
    own, without the package around it."""
    found_any = False
    for dist in distributions(name="stig-mcp"):
        found_any = True
        # setuptools' editable build writes <pkg>.egg-info into the source root as a build
        # byproduct, and that root sits on sys.path under pytest (tests/ is a package) and under
        # `python -m`, so distributions(name=...) can yield that egg-info ahead of the venv's
        # real dist-info. Its files, read from SOURCES.txt, are bare source-relative paths like
        # "LICENSE" with no ".dist-info/licenses/" segment, so _license_files_of returns nothing
        # for it and the loop moves on to the next candidate instead of stopping here.
        texts = _license_files_of(dist)
        if texts:
            return texts
    if not found_any:
        raise RuntimeError(
            "stig-mcp is not installed, so its license files cannot be read into the knowledge "
            "base. Run `uv sync` in the checkout, or install the package, then re-run stig-mcp-ingest."
        )
    raise RuntimeError(
        "The installed stig-mcp distribution ships no license files, so the knowledge base "
        "would carry no notices. Check pyproject.toml license-files, then run "
        "`uv sync --reinstall-package stig-mcp`."
    )


def _write_notices(conn):
    conn.executemany("INSERT INTO notices(name, text) VALUES (?, ?)", sorted(_license_texts().items()))


def _input_files(sources):
    """Every file this build read, each once: the classified artifacts plus whichever
    supporting sources exist. Optional ones (catalog, overrides, attack index) are recorded
    only when present."""
    candidates = [
        *sources.artifact_paths,
        sources.cci_path,
        sources.attack_path,
        sources.ctid_path,
        sources.catalog_path,
        sources.overrides_path,
        sources.attack_index_path,
    ]
    return sorted({Path(p) for p in candidates if p is not None and Path(p).is_file()})


def _write_source_files(conn, sources):
    by_name = {}
    for path in _input_files(sources):
        if path.name in by_name:
            raise RuntimeError(
                f"Two inputs share the name {path.name}: {by_name[path.name]} and {path}. The knowledge "
                f"base records each input by file name, so rename or move one of them, then re-run "
                f"stig-mcp-ingest."
            )
        by_name[path.name] = path
    rows = []
    for name, path in sorted(by_name.items()):
        with path.open("rb") as handle:
            digest = hashlib.file_digest(handle, "sha256").hexdigest()
        rows.append((name, digest, path.stat().st_size))
    conn.executemany("INSERT INTO source_files(name, sha256, size) VALUES (?, ?, ?)", rows)


def _write_source_meta(conn, sources, versions, catalog_loaded, now):
    meta_sources = [("cci", sources.cci_path), ("attack", sources.attack_path), ("ctid", sources.ctid_path)]
    if catalog_loaded:
        meta_sources.append(("catalog", sources.catalog_path))
    library = _library_artifact(sources)
    if library is not None:
        meta_sources.append(("stig_library", library))
    for name, path in meta_sources:
        # A bare filename, one convention for every source recorded here: the full path
        # would leak the operator's home directory and username into a response an LLM
        # surfaces to a user, and it names nothing a reader can verify against DISA.
        conn.execute(
            "INSERT OR REPLACE INTO ingest_meta(source_name, source_version, artifact_url_or_file, "
            "ingested_at, schema_version) VALUES (?, ?, ?, ?, ?)",
            (name, versions.get(name, ""), Path(path).name, now, SCHEMA_VERSION),
        )


def _check_applicability(conn, entries, summary):
    """Report drift between the applicability rules and what this KB actually holds.

    Never raises on drift: a stale rule, a rule matching no benchmark, or a governed major
    with no threshold all warn and continue, because a stale rule degrades to unfiltered
    behavior, which is safe. A rule file that will not parse at all is a separate, hard
    failure by design (see applicability.load_entries): silently ignoring it would be
    indistinguishable from having no rules at all, so that failure happens earlier, in
    _populate, before any parsing, rather than here."""
    rows = [(r["stig_id"], r["version"]) for r in conn.execute("SELECT stig_id, version FROM stigs")]
    info, warnings, unmapped = applicability.check_against_kb(rows, entries)
    for line in info:
        logger.info("%s", line)
    for line in warnings:
        logger.warning("%s", line)
    summary["applicability_unmapped_rows"] = unmapped


def _check_distinctiveness_margin(conn, summary):
    """Report tokens sitting within one document of the resolver's distinctiveness gate.

    Split across two levels the way _check_applicability splits its own two lists. Losing
    warns: the token stops counting as identity-bearing, so a query naming it stops scoping
    confidently and the caller gets an EMPTY scope, which they cannot tell apart from
    "nothing applies". Silence is this tool's worse failure mode. Gaining informs: more queries
    scope confidently, which can be wrong (bare MS auto-scoping five benchmarks is one example)
    but is never silent.

    This warns on current builds, because some tokens already sit inside the gate. That is an
    accepted cost. Each token is printed with its df so the line is diffable between builds
    rather than decorative.
    """
    band = distinctiveness_margin(conn)
    summary["distinctiveness_margin_tokens"] = len(band.losing) + len(band.gaining)
    if band.losing:
        logger.warning(
            "distinctiveness margin: %d token(s) sit inside the distinctiveness gate by one document "
            "or less (gate df <= %.2f at n=%d): %s. The gate moves with every benchmark the corpus "
            "gains or loses, and a token's df moves by one with every benchmark that starts or stops "
            "holding it, so a token this close to the gate can lose distinctiveness on the corpus's "
            "very next benchmark, and a query naming one that does would then stop scoping "
            "confidently. Not every token listed here can cross: which ones do depends on where "
            "in the band the df sits, and resolver.distinctiveness_margin carries the exact "
            "conditions.",
            len(band.losing),
            band.gate,
            band.n,
            ", ".join(f"{token!r} df {count}" for token, count in band.losing),
        )
    if band.gaining:
        logger.info(
            "distinctiveness margin: %d token(s) sit outside the distinctiveness gate by one "
            "document or less: %s. The gate moves with every benchmark the corpus gains or "
            "loses, and a token's df moves by one with every benchmark that starts or stops "
            "holding it, so a token this close to the gate can gain distinctiveness on the "
            "corpus's very next benchmark: from retiring a benchmark that holds it, or from "
            "growth alone when the gap is at or under the ratio (%s). A query naming one that "
            "does could then start scoping confidently. Not every token listed here can cross: "
            "which ones do depends on where in the band the df sits, and "
            "resolver.distinctiveness_margin carries the exact conditions.",
            len(band.gaining),
            ", ".join(f"{token!r} df {count}" for token, count in band.gaining),
            _DISTINCTIVE_DF_RATIO,
        )


def _populate(conn, sources, summary, now):
    # Loaded first and outside any try/except: a rule file that will not parse must abort
    # the build before the expensive work runs, not after every benchmark has been parsed
    # and inserted. This is also what the runtime resolver calls on every resolve, so a
    # broken file would break serving too; failing the build now is strictly better than
    # shipping a valid KB behind a server that fails later.
    entries = applicability.load_entries()

    cci_records = parse_cci_list(sources.cci_path)
    _load_ccis(conn, cci_records, summary)

    attack = parse_attack(sources.attack_path)
    _load_attack(conn, attack, summary)

    ctid = load_ctid_mappings(sources.ctid_path)
    overrides = (
        load_overrides(sources.overrides_path) if sources.overrides_path else MappingSet(OVERRIDE_VERSION_DEFAULT, [])
    )
    effective = _effective_pairs(ctid, overrides, attack.revocations, summary)
    _load_ctid_status(conn, ctid, attack.revocations)

    catalog_loaded = _load_controls(conn, sources, cci_records, effective)
    _load_mappings(conn, attack, cci_records, effective, summary)

    library_keys = set()
    newest_by_key = _newest_benchmarks(sources.benchmarks, summary, library_keys=library_keys)
    if sources.benchmarks and not newest_by_key:
        raise RuntimeError(
            f"No STIG benchmark parsed successfully out of {len(sources.benchmarks)} "
            f"file(s) in benchmarks, every file failed to parse. See the per-file "
            f"warnings above; check the XCCDF sources rather than shipping an empty KB."
        )
    newest_by_key = _select(newest_by_key, summary, library_keys=library_keys)
    _insert_stigs(conn, newest_by_key, summary, now)
    _check_applicability(conn, entries, summary)
    _check_distinctiveness_margin(conn, summary)
    versions, extra = _source_versions(sources, attack, ctid, catalog_loaded)
    _write_source_meta(conn, sources, versions, catalog_loaded, now)
    _write_extra_meta(conn, extra, now)
    _write_notices(conn)
    _write_source_files(conn, sources)


def build_kb(sources, out_path):
    out_path = Path(out_path)
    tmp_path = out_path.with_suffix(out_path.suffix + ".building")
    _validate_sources(sources)

    conn = None
    now = datetime.now(timezone.utc).isoformat()
    summary = {
        "stig_files": 0,
        "stigs": 0,
        "stig_rules": 0,
        "rule_id_collisions": 0,
        "techniques": 0,
        "revocations": 0,
        "ccis": 0,
        "orphan_ctid_pairs": 0,
        "orphan_override_pairs": 0,
        "unknown_severity": 0,
        "remapped_ctid_pairs": 0,
        "remapped_override_pairs": 0,
        "applicability_unmapped_rows": 0,
        "distinctiveness_margin_tokens": 0,
        "superseded_by_library": 0,
        "superseded_same_key": 0,
        "same_key_departures": 0,
        "same_key_content_collision": 0,
        "same_key_collision_unmapped": 0,
        "id_corrections_applied": 0,
        "superseded_by_newer_major": 0,
        "skipped_srg": 0,
        "skipped_draft": 0,
        "skipped_unclassified": 0,
    }
    try:
        conn = create_db(tmp_path)
        _populate(conn, sources, summary, now)
        conn.commit()
        conn.close()
        tmp_path.replace(out_path)
    finally:
        # close() is idempotent, so the success path closing first is safe, and conn is
        # only unset if create_db itself failed. missing_ok is load-bearing for the same
        # reason as the close: on success replace() has already moved the staging file,
        # and only the failure paths leave one to remove.
        if conn is not None:
            conn.close()
        tmp_path.unlink(missing_ok=True)
    logger.info("Built KB: %s", summary)
    return summary


def _require_named_overrides():
    """Refuse when the operator NAMED an overrides file that is not there.

    load_overrides treats a missing file as an empty one, which is right for the default
    location: docs/operations.md documents overrides.yaml as optional, and an ingest that
    refused without one would break every existing checkout. It is wrong for a path the
    operator typed: silently ignoring a named file hides a typo or a wrong location.

    Here rather than in load_overrides so the message can name the variable, and so build_kb's
    library contract (a missing overrides path means no overrides) stays as documented.
    """
    # is_file, not exists: a directory of that name satisfies exists() and then reaches
    # load_overrides as an IsADirectoryError from inside build_kb, which is the unhelpful
    # failure this refusal exists to replace.
    if config.OVERRIDES_FROM_ENV and not config.OVERRIDES_PATH.is_file():
        raise FileNotFoundError(
            f"STIG_MCP_OVERRIDES names {config.OVERRIDES_PATH}, which is not a readable file. "
            f"Create it, correct the variable, or unset it to fall back to the default "
            f"location. An overrides file that is absent is ignored only at the default "
            f"location, where it is optional; a named one is not."
        )


def main(argv=None):
    # argv rather than sys.argv alone so a test can drive the CLI without patching the
    # interpreter's own state, which every other test in the process shares.
    argparse.ArgumentParser(description=__doc__ or "stig-mcp").parse_args(argv)
    logging.basicConfig(level=logging.INFO)
    _require_named_overrides()
    # build_kb never makes the knowledge base's parent, so without this an ingest into a data
    # directory nothing has created yet would fail on the write. In the documented order this
    # is a no-op, because fetch_public creates SOURCES_DIR and DATA_DIR is its parent; it
    # carries the operator who brings sources by hand, or who repoints STIG_MCP_DATA after
    # fetching. Hence exist_ok, which is the normal case rather than the edge one.
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    artifacts = inventory.classify(config.SOURCES_DIR)
    library_artifact = next((a.path.name for a in artifacts if a.kind == "library"), None)
    tmp_extract = Path(tempfile.mkdtemp(prefix="stig-lib-"))
    try:
        sources = IngestSources(
            benchmarks=inventory.collect(artifacts, tmp_extract),
            cci_path=config.SOURCES_DIR / "U_CCI_List.xml",
            attack_path=config.SOURCES_DIR / "enterprise-attack.json",
            ctid_path=config.SOURCES_DIR / "ctid_mappings.json",
            overrides_path=config.OVERRIDES_PATH,
            catalog_path=config.SOURCES_DIR / "nist_800_53_rev5_catalog.json",
            library_artifact=library_artifact,
            attack_index_path=config.SOURCES_DIR / "attack_index.json",
            artifact_paths=tuple(a.path for a in artifacts),
        )
        build_kb(sources, config.KB_PATH)
    finally:
        shutil.rmtree(tmp_extract, ignore_errors=True)


# Reachable as `python -m`, for the reason given at the end of library.py.
if __name__ == "__main__":
    main()
