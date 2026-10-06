"""Run the shipped ingest pipeline over a staged corpus and assert properties of the result.

Assertions are invariants rather than golden values on purpose. Nobody can hand-author
expected output for hundreds of benchmarks, and a golden file would rot at the next
quarterly release. What stays true across releases is that every artifact is accounted for,
every benchmark parses, and the selection rule leaves exactly one row per surviving key."""

import argparse
import logging
import re
import shutil
import tempfile
import zipfile
from collections import namedtuple
from contextlib import contextmanager
from pathlib import Path

from stig_mcp.ingest import id_corrections, inventory
from stig_mcp.ingest.orchestrator import (
    IngestSources,
    _contest,
    _corrected,
    _find_collision,
    _id_key,
    _release_label,
    build_kb,
)
from stig_mcp.ingest.stig_parser import document_kind, parse_stig
from stig_mcp.kb.db import open_db
from stig_mcp.kb.queries import stigs_for_resolver
from stig_mcp.resolver.normalize import glued_versions, normalize
from stig_mcp.resolver.resolver import _straddling_pairs, _version_runs, distinctiveness_margin, resolve
from tools import corpus_manifest

Finding = namedtuple("Finding", "phase severity message")

ERROR = "error"
WARNING = "warning"
INFO = "info"


class _RecordingHandler(logging.Handler):
    """A logging.Handler that appends every record it receives to a list.

    A subclass overriding emit() is the idiomatic form; assigning a bound method over
    Handler.emit works identically at runtime but reads as an attribute of the wrong type to
    static analysis, and that would fire every time this file is touched."""

    def __init__(self, records):
        super().__init__()
        self._records = records

    def emit(self, record):
        self._records.append(record)


@contextmanager
def _capture_logs(logger_name):
    """Every record logged to logger_name during the with-block.

    The pipeline reports a rejected artifact by logging it rather than by returning it, so
    reading those records is how the harness learns what was skipped and why.

    Forces logger_name's own level to INFO for the duration and restores whatever it was
    before, rather than trusting main()'s logging.basicConfig(level=logging.INFO): that call
    is a no-op once a handler is already on the root logger, which pytest's own logging
    plugin installs by default. Without this, the INFO records this handler exists to catch
    are never produced under pytest, and cost metrics counting from them read zero."""
    records = []
    handler = _RecordingHandler(records)
    logger = logging.getLogger(logger_name)
    previous_level = logger.level
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)
    try:
        yield records
    finally:
        logger.removeHandler(handler)
        logger.setLevel(previous_level)


def _unreadable_archive_finding(artifact):
    """None, or an error Finding when a classified artifact cannot even be opened as a zip.

    classify() decides an ARCHIVE's kind by filename alone (only an .xml is ever opened),
    so a truncated or corrupt download is still classified as an artifact: it is not "ignored"
    in the sense phase_accounting reports at info. It must be reported as a defect instead of
    silently vanishing once collect() gets to it and logs the failure on its own, deep inside
    a corpus-wide run.

    Deliberately broad, unlike inventory._from_product_zip's narrower (BadZipFile, EOFError):
    that function is production ingest, where failing loudly on an unexpected corruption shape
    is defensible. This is a diagnostic harness whose purpose is to survive bad input across a
    whole corpus run and report it; a rarer corruption shape, e.g. a malformed
    end-of-central-directory raising struct.error, or an OSError from the filesystem, must not
    crash the run over one bad file. Do not narrow this to match inventory.py: the two call
    sites have opposite failure tolerances on purpose."""
    if artifact.kind == "loose":
        return None
    try:
        with zipfile.ZipFile(artifact.path):
            pass
    except Exception as exc:
        return Finding("accounting", ERROR, f"{artifact.path.name} is not a readable archive: {exc}")
    return None


def _unreadable_xml_finding(path):
    """None, or an error Finding when an UNCLASSIFIED .xml could not be read at all.

    Only a name inventory.LOOSE_GLOB misses can get here, and that is the entire population at
    risk. A file called `..._Manual-xccdf.xml` is classified `loose` on its NAME without ever
    being opened, so it becomes an artifact and the parser reports its failure later; promoting
    it here would double-report it. Any OTHER .xml is opened by _kind_of to check its root
    element, and one that could not be read falls through unclassified, arriving here
    indistinguishable from a PDF. It is not "legitimately ignored". It is a candidate benchmark
    that may have been lost, and it earns the same error treatment as a truncated archive.

    The suffix test must be spelled the same way inventory._kind_of spells it, `endswith`
    rather than `Path.suffix`. `Path(".xml").suffix` is empty on every supported interpreter,
    so the two rules would disagree about exactly one population: the file _kind_of opened,
    failed to read, and this function then waved through at info. Do not reach for `..xml` as
    the example: its suffix differs between 3.13 and 3.14.

    The WARNING inventory logs for it cannot serve instead: _capture_logs wraps collect(),
    and this failure happens earlier, inside classify(). Only .xml is a candidate, so an
    unreadable PDF stays at info. This re-reads a file _kind_of already tried; the read is
    only ever attempted for a file that turned out not to be an artifact."""
    if not path.name.lower().endswith(inventory.LOOSE_SUFFIX):
        return None
    try:
        path.read_bytes()
    except OSError as exc:
        return Finding("accounting", ERROR, f"{path.name} is a candidate benchmark that could not be read: {exc}")
    return None


def phase_accounting(corpus_dir):
    """Phase 1: classify the corpus, and report anything that produced no artifact.

    A file that is neither an archive nor an XCCDF is legitimately ignored, so it is
    reported at info rather than error. The failure this phase exists to catch is an
    archive that classify accepted and that then yielded nothing without saying so, or a
    candidate benchmark that vanished because nothing could read it."""
    corpus_dir = Path(corpus_dir)
    artifacts = inventory.classify(corpus_dir)
    classified = {artifact.path.name for artifact in artifacts}
    findings = [finding for finding in (_unreadable_archive_finding(artifact) for artifact in artifacts) if finding]
    for path in sorted(corpus_dir.iterdir()):
        if not path.is_file() or path.name in classified:
            continue
        ignored = Finding("accounting", INFO, f"{path.name} matched no artifact kind and was ignored")
        findings.append(_unreadable_xml_finding(path) or ignored)
    return artifacts, findings


def collect_benchmarks(artifacts, staging_dir):
    """(benchmarks, log messages) for everything reachable from the artifacts.

    Separate from phase_accounting so the caller owns the staging directory's lifetime: a
    full corpus extracts a lot of XML and the caller has to be able to delete it. The log
    messages are returned rather than swallowed because the pipeline reports a rejected
    archive by logging it, so they are the only record of what was opened and skipped."""
    with _capture_logs("stig_mcp.ingest.inventory") as records:
        benchmarks = inventory.collect(artifacts, staging_dir)
    return benchmarks, [record.getMessage() for record in records]


def compose_build_dir(corpus_dir, compilations, work_dir):
    """A directory holding every product zip plus the given compilations, as symlinks.

    inventory.classify refuses more than one LIBRARY compilation, deliberately, because month
    names do not sort chronologically and a silent choice would serve stale guidance for a
    quarter. The published directory carries nine of them, so a corpus run pairs the product
    zips with one library at a time rather than staging all nine together. A build may also
    carry the sunset archive alongside that one library: classify only refuses a second
    LIBRARY, and a library plus the sunset archive is exactly the shape a real knowledge base
    is built from. compilations is therefore an iterable of zero or more paths, and it is the
    caller's job, via _compilations_in, to never put two libraries in it at once.

    Symlinks because a library compilation is roughly 1GB and nine copies of the product set
    would be pointless. Path.is_file() follows a symlink and so does zipfile.ZipFile, so
    classify sees exactly what it would see with real files, which keeps it under test rather
    than bypassed.

    work_dir must be empty or not yet exist: symlink_to raises FileExistsError on a name that
    is already there, so a caller reusing one work_dir across builds (e.g. one per compilation)
    must give each call its own fresh directory rather than the same one repeatedly."""
    work_dir = Path(work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)
    for source in sorted(Path(corpus_dir).iterdir()):
        if source.is_file():
            (work_dir / source.name).symlink_to(source.resolve())
    for raw_compilation in compilations:
        compilation = Path(raw_compilation)
        (work_dir / compilation.name).symlink_to(compilation.resolve())
    return work_dir


def phase_parse(benchmarks):
    """Phase 2: parse every discovered benchmark and check what the schema depends on.

    release_info feeds orchestrator._version_key, so a benchmark that parses with an empty
    one sorts as release 0 and silently loses the newest-release-wins contest, so it is
    checked here across the whole corpus rather than trusted."""
    parsed_pairs = []
    findings = []
    for discovered in benchmarks:
        try:
            parsed = parse_stig(discovered.path)
        except Exception as exc:  # deliberately broad: a corpus-wide sweep must not stop at one bad file
            findings.append(Finding("parse", ERROR, f"{discovered.source_artifact}: parse failed: {exc}"))
            continue
        if not (parsed.release_info or "").strip():
            findings.append(
                Finding("parse", ERROR, f"{parsed.stig_id} from {discovered.source_artifact} has empty release_info")
            )
        label = _release_label(parsed)
        if not label.startswith("V"):
            findings.append(
                Finding(
                    "parse",
                    WARNING,
                    f"{parsed.stig_id} from {discovered.source_artifact} has no V#R# label, got {label!r}",
                )
            )
        parsed_pairs.append((parsed, discovered))
    return parsed_pairs, findings


def open_kb(path):
    return open_db(path)


def build_corpus_kb(artifacts, inputs_dir, out_path, staging_dir, reverse=False):
    """Build one knowledge base from the corpus, using explicit paths throughout.

    Every input path is passed in rather than read from config, so this can never write to
    the operator's real knowledge base or read their real sources directory."""
    inputs_dir = Path(inputs_dir)
    ordered = list(reversed(artifacts)) if reverse else list(artifacts)
    library = next((a.path.name for a in ordered if a.kind == "library"), None)
    benchmarks, _ = collect_benchmarks(ordered, staging_dir)
    sources = IngestSources(
        benchmarks=benchmarks,
        cci_path=inputs_dir / "U_CCI_List.xml",
        attack_path=inputs_dir / "enterprise-attack.json",
        ctid_path=inputs_dir / "ctid_mappings.json",
        catalog_path=inputs_dir / "nist_800_53_rev5_catalog.json",
        library_artifact=library,
    )
    return build_kb(sources, out_path)


def composition(conn):
    """The identity of every stored benchmark, ordered so two builds compare directly."""
    return conn.execute(
        "SELECT stig_id, version, origin, source_artifact, release_label FROM stigs ORDER BY stig_id, version"
    ).fetchall()


def _duplicate_keys(conn):
    return conn.execute(
        "SELECT stig_id, version, COUNT(*) FROM stigs GROUP BY stig_id, version HAVING COUNT(*) > 1"
    ).fetchall()


def _published_groups(parsed_pairs):
    """Every STIG document under the (stig_id, version) it self-reports, in arrival order.

    Documents the classifier rejects are excluded, because _newest_benchmarks skips them before
    the contest and they can share a key with a STIG it does keep. phase_parse deliberately keeps
    them in parsed_pairs: its release_info and V#R# checks cover every discovered document, SRGs
    included, so the filter belongs here rather than there."""
    groups = {}
    for parsed, discovered in parsed_pairs:
        if document_kind(parsed) != "stig":
            continue
        groups.setdefault((parsed.stig_id, parsed.version), []).append((parsed, discovered))
    return groups


def _settle_replay(key, parsed, discovered, current_by_key):
    """Seat this document at key or contest it against whoever holds it, returning 1 if a
    benchmark departed. The comparison is _contest itself, so the prediction is this input's real
    behavior, but the arbitration around it is written out here rather than delegated to
    orchestrator._settle: see _same_key_departures."""
    current = current_by_key.get(key)
    if current is None:
        current_by_key[key] = (parsed, discovered)
        return 0
    if _contest(parsed, discovered) > _contest(current[0], current[1]):
        current_by_key[key] = (parsed, discovered)
    return 1


def _applicable_split(members, current_by_key, corrections):
    """The (member, corrected document) pairs of a content collision this group can be split on,
    or None when the ingest would decline the split and run the ordinary contest instead.

    All three declining conditions are the ingest's, reimplemented rather than called, and each
    is reachable: _correct_pair returns None when the map cannot name one or both halves, two halves
    correcting to one id would re-create the collision the split exists to resolve, and
    _keys_available refuses to overwrite a corrected id that an EARLIER group already stored.
    That last one is why current_by_key is threaded through every group instead of being built
    per group: occupancy is a property of the whole build's history, so a replay that judged each
    group in isolation would split where the ingest declined and report a false departure."""
    pair = _find_collision(members)
    if pair is None:
        return None
    corrected = [_corrected(parsed, discovered, corrections) for parsed, discovered in pair]
    if any(document is None for document in corrected):
        return None
    keys = [(document.stig_id, document.version) for document in corrected]
    if len(set(keys)) != len(keys) or any(key in current_by_key for key in keys):
        return None
    return list(zip(pair, corrected))


def _replay_group(key, members, current_by_key, corrections):
    """How many of one published id's documents departed the same-key contest, seating the
    survivors in current_by_key.

    A split pair costs no departure here: neither half loses to the other, and both are seated
    under their own corrected ids. That is not a lifetime guarantee, and does not need to be: a
    later document, in this group or in a later one whose published id IS a corrected id, can
    still displace one of them through the ordinary contest, which counts that as a departure
    when it happens. Everything else sharing the published id is a document arriving at
    an id this build has already split, so it never settles under that id. The map names it and
    it contests at its corrected key, or the map cannot name it and the ingest discards it
    through _drop into superseded_same_key, which makes it a departure like any other."""
    split = _applicable_split(members, current_by_key, corrections)
    if split is None:
        return sum(_settle_replay(key, parsed, discovered, current_by_key) for parsed, discovered in members)
    for (_parsed, discovered), document in split:
        current_by_key[(document.stig_id, document.version)] = (document, discovered)
    halves = [member for member, _document in split]
    # Identity, not equality, as the ingest does: ParsedStig and DiscoveredBenchmark are both
    # dataclasses, so a duplicate document arriving from the same artifact compares equal to a
    # half and an equality test would silently drop it instead of routing it to its own key.
    arrivals = [member for member in members if all(member is not half for half in halves)]
    departures = 0
    for parsed, discovered in arrivals:
        document = _corrected(parsed, discovered, corrections)
        if document is None:
            departures += 1
            continue
        departures += _settle_replay((document.stig_id, document.version), document, discovered, current_by_key)
    return departures


def _same_key_departures(parsed_pairs, corrections=None):
    """Replay the same-key arbitration orchestrator._newest_benchmarks runs, returning both how
    many benchmarks departed it and which artifact won each key, using the production _contest so
    the prediction is this input's real behavior rather than an approximation.

    Both halves check the ingest rather than substituting for it. The count checks the ingest's
    same_key_departures, because a harness that simply read that number back would be trusting
    the very thing it is here to verify. The winners exist because the count stays blind to the
    comparator: which document ends up holding a key does not change how many documents departed
    it, so a version of this function that returned only the count would pass unchanged if
    _contest were replaced by a coin toss.

    Same two passes as the ingest, group then decide, and for the same reason: which documents
    form a content collision must not depend on what else shares their published id or where in
    the walk it falls. Only _contest, _find_collision and _corrected are borrowed, because they
    are pure functions of the documents. The arbitration itself is written out here. Calling
    _resolve_group or _split_collision would be trusting the thing this exists to verify.

    Be exact about what this does and does not catch, because a check that cannot fail reads as
    coverage. It catches the ingest not applying the rules it declares: wrong operands, a later
    stage overriding the outcome, or any nondeterminism. It catches a split applied where the
    ingest declined one, and the reverse, because a group that splits costs strictly fewer
    departures than the same group contested whole, so one such disagreement always moves the
    total. Only ONE, though: the comparison is a single sum over every group, so two
    disagreements in opposite directions in different groups cancel, and nothing here catches
    that. Not even the winners: _arbitration_findings iterates stored rows and skips one the
    replay never predicted, and a group the two sides disagree about splitting at all leaves no
    key they both hold. It does NOT catch a deterministic change to _contest,
    _find_collision or _corrected themselves, because the ingest and this replay import the same
    functions and would move together. Those are covered by the ingest's own unit tests over
    each, and order dependence by phase_determinism. It is equally blind to a key _contest does
    not separate: two documents from one artifact at one release whose rule ids are identical or
    merely overlapping are not a content collision, so they go to the ordinary contest, where
    artifact, release and origin are equal by construction and only status_date can tell them
    apart. When that matches too, this replay resolves the tie exactly as the ingest does, by
    keeping whichever it walked first, so the two agree and the check passes over it in silence.
    A disjoint-rule pair is decided by content on both sides; the identical-status_date tie has
    no instrument here. See _contest."""
    corrections = id_corrections.load_corrections() if corrections is None else corrections
    current_by_key = {}
    total = 0
    for key, members in _published_groups(parsed_pairs).items():
        total += _replay_group(key, members, current_by_key, corrections)
    return total, {key: discovered.source_artifact for key, (_parsed, discovered) in current_by_key.items()}


def _folded_id_findings(conn):
    """Two spellings of one benchmark id that both survived into `stigs`.

    `orchestrator._id_key` exists to make case irrelevant to lifecycle selection, but it folds
    only the major-level contest in `_select`. Three shapes get past it, all named in that
    function's docstring, and every one of them puts a product in the knowledge base twice: two
    of the caller's five result slots, two entries in a version-coverage tier, and two
    unrelated-looking products where there is one.

    Nothing else in this harness can see it. The reconciliation above reads the ingest's own
    counters, so it stays balanced whatever the fold does; the `same_key_departures` replay
    covers `_newest_benchmarks` and never reaches `_select`; and the multi-major INFO below
    groups on the literal `stig_id`, so a case-only pair such as Solaris's produces no finding
    there.

    A WARNING rather than an ERROR. Eight true findings sit in the harness corpus, all of them a
    library shipping an OLDER major than a sunset or product-zip copy, which _select correctly
    keeps (e.g. `Solaris_11_X86_STIG` 1 against `Solaris_11_x86_STIG` 2, and `BIND_9-x_STIG`
    against the lowercase `Bind_9-x_STIG` 2). Eight permanent known-true errors would be the
    noise that hides the ninth. A current reference build reports nothing here, so a warning
    that starts firing on a build like it is the signal that matters.
    """
    findings = []
    # Folded with the ingest's own _id_key rather than SQL lower(), so there is ONE definition
    # of "differs only in case" instead of two that can disagree: SQLite's lower() is ASCII-only
    # and Python's is not, so `ÄÖÜ_STIG` folds in the ingest and would not fold here. Grouped in
    # Python for the same reason GROUP_CONCAT is avoided: it specifies no order within a group,
    # and this report is diffed against a recorded baseline.
    spellings = {}
    for row in conn.execute("SELECT DISTINCT stig_id FROM stigs ORDER BY stig_id"):
        spellings.setdefault(_id_key(row["stig_id"]), []).append(row["stig_id"])
    for names in spellings.values():
        if len(names) == 1:
            continue
        findings.append(
            Finding(
                "invariants",
                WARNING,
                f"{','.join(names)} differ only in case, so one product is stored twice; "
                f"orchestrator._select folded the major contest but something kept both",
            )
        )
    return findings


def _arbitration_findings(conn, summary, parsed_pairs):
    """Check the ingest's same-key accounting and arbitration against an independent replay."""
    findings = []
    counted = summary.get("same_key_departures", 0)
    total_departures, winners = _same_key_departures(parsed_pairs)
    if counted != total_departures:
        findings.append(
            Finding(
                "invariants",
                ERROR,
                f"the ingest counted {counted} of {total_departures} same-key departure(s); a departure "
                f"the ingest does not count is a benchmark replaced with no trace in the summary",
            )
        )
    stored = conn.execute("SELECT stig_id, version, source_artifact FROM stigs").fetchall()
    # Iterating stored, not winners, is what makes this safe: keys _select dropped are absent
    # from stigs and so never come up. The membership guard covers the opposite case, a stored
    # key the replay never saw, and skips it rather than reporting it, because the reconciliation
    # above already catches a row that no parsed pair accounts for.
    disagreed = [
        (stig_id, version, artifact, winners[(stig_id, version)])
        for stig_id, version, artifact in stored
        if (stig_id, version) in winners and winners[(stig_id, version)] != artifact
    ]
    if disagreed:
        findings.append(
            Finding(
                "invariants",
                ERROR,
                f"{len(disagreed)} key(s) stored a different artifact than replaying _contest predicts, "
                f"first {disagreed[0][0]} {disagreed[0][1]}: stored {disagreed[0][2]}, replay {disagreed[0][3]}",
            )
        )
    return findings


_DEFENSE_TABLES = (
    "mitigations",
    "technique_mitigation",
    "detection_strategies",
    "analytics",
    "analytic_log_sources",
    "data_components",
)


def defense_counts(conn):
    return {table: conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] for table in _DEFENSE_TABLES}  # noqa: S608


def _defense_findings(conn):
    findings = []
    for table, count in defense_counts(conn).items():
        if count == 0:
            findings.append(
                Finding("invariants", ERROR, f"{table} holds 0 rows; the ATT&CK defensive data did not load")
            )
        else:
            findings.append(Finding("invariants", INFO, f"{table} holds {count} rows"))
    return findings


def phase_invariants(conn, summary, parsed_pairs=()):
    """Phase 3: properties that must hold of any corpus build, at any size."""
    findings = []
    missing = conn.execute("SELECT COUNT(*) FROM stigs WHERE origin IS NULL OR source_artifact IS NULL").fetchone()[0]
    if missing:
        findings.append(Finding("invariants", ERROR, f"{missing} row(s) stored without provenance"))
    for stig_id, version, count in _duplicate_keys(conn):
        findings.append(Finding("invariants", ERROR, f"{stig_id} {version} stored {count} times"))
    if summary.get("rule_id_collisions"):
        findings.append(
            Finding("invariants", ERROR, f"{summary['rule_id_collisions']} rule_id collision(s) across the corpus")
        )
    # One counter, three events, and the message must fit all three or it sends the operator to
    # fix the wrong thing: a detected collision id_corrections.yaml cannot name
    # (_warn_uncorrectable), one it DOES name whose corrected id is already held by another
    # benchmark (_warn_occupied), and a later document arriving at an already-split id that it
    # cannot name (_route_split_arrival). The middle one is why this cannot simply say the map
    # does not name the document: there the map is right and telling the operator to add an entry
    # that already exists says nothing about what to change. Every one of the three ends with a
    # benchmark discarded and no trace of it in the composition, so this line is the operator's
    # only record of the event in the report.
    if summary.get("same_key_collision_unmapped"):
        findings.append(
            Finding(
                "invariants",
                ERROR,
                f"{summary['same_key_collision_unmapped']} same-key re-keying failure(s), each "
                f"costing at least one benchmark that the composition keeps no trace of: "
                f"id_corrections.yaml does not name the document, or it does and a corrected id is "
                f"already held by a different benchmark. The ingest logs a WARNING naming the "
                f"documents and saying which of the two it was",
            )
        )
    if summary.get("id_corrections_applied"):
        findings.append(
            Finding(
                "invariants",
                INFO,
                f"{summary['id_corrections_applied']} document(s) are stored under an id_corrections "
                f"identity rather than the one DISA stamped on them",
            )
        )
    stored = conn.execute("SELECT COUNT(*) FROM stigs").fetchone()[0]
    # The bins, not the axis: same_key_departures is a parallel total of the same events, so
    # adding it here would double-count every same-key departure out of the reconciliation.
    dropped = (
        summary.get("superseded_by_library", 0)
        + summary.get("superseded_same_key", 0)
        + summary.get("superseded_by_newer_major", 0)
    )
    if summary.get("stig_files", 0) - dropped != stored:
        findings.append(
            Finding(
                "invariants",
                ERROR,
                f"counts do not reconcile: parsed {summary.get('stig_files')} minus dropped {dropped} "
                f"is not stored {stored}",
            )
        )
    findings += _arbitration_findings(conn, summary, parsed_pairs)
    findings += _folded_id_findings(conn)
    for row in conn.execute(
        "SELECT stig_id, COUNT(*) FROM stigs GROUP BY stig_id HAVING COUNT(*) > 1 ORDER BY stig_id"
    ).fetchall():
        findings.append(
            Finding("invariants", INFO, f"{row[0]} carries {row[1]} majors, each must be individually justified")
        )
    unclassified = summary.get("skipped_unclassified", 0)
    if unclassified:
        findings.append(
            Finding(
                "invariants",
                WARNING,
                f"{unclassified} document(s) identify as neither STIG nor SRG; if DISA has changed "
                f"how they title benchmarks, stig_parser.document_kind needs a new rule",
            )
        )
    findings.extend(_defense_findings(conn))
    return findings


def phase_determinism(artifacts, inputs_dir, work_dir):
    """Build twice with the artifact order reversed and require identical composition.

    This is the direct demonstration of the same-key arbitration, which must make the winner
    of a tie independent of classify's filename ordering, so reversing the list is the
    maximal perturbation and the composition must not move."""
    work_dir = Path(work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)
    findings = []
    forward_path, reverse_path = work_dir / "forward.sqlite", work_dir / "reverse.sqlite"
    build_corpus_kb(artifacts, inputs_dir, forward_path, work_dir / "stage-forward")
    build_corpus_kb(artifacts, inputs_dir, reverse_path, work_dir / "stage-reverse", reverse=True)
    forward_conn, reverse_conn = open_kb(forward_path), open_kb(reverse_path)
    forward, reverse = composition(forward_conn), composition(reverse_conn)
    forward_conn.close()
    reverse_conn.close()
    if forward != reverse:
        only_forward = [tuple(row) for row in forward if tuple(row) not in {tuple(r) for r in reverse}]
        findings.append(
            Finding(
                "determinism",
                ERROR,
                f"composition depends on artifact order: {len(only_forward)} row(s) differ, "
                f"first difference {only_forward[:1]}",
            )
        )
    return findings


# A sentinel expectation: this query must report its version as one the build does not
# hold. DISA has never published a SQL Server 2019 STIG (the line runs 2012, 2014, 2016,
# then 2022), so this holds in every build.
UNCOVERED_VERSION = object()

# Queries the resolver's precision and the vSphere applicability rules must keep answering.
# The expected value is a substring of the winning stig_id, not an exact row, because the
# release that wins moves every quarter while the product must not.
PINNED_QUERIES = (
    ("Microsoft SQL Server 2019", UNCOVERED_VERSION),
    ("RedHat Linux Server 9", "RHEL_9"),
    ("Windows 11", "Windows_11"),
    ("Windows Server 2019", "Windows_Server_2019"),
    ("ESXi 8.0 U3", "VMW_vSphere_8-0_ESXi"),
)


_PADDED_VERSION_RE = re.compile(r"^0\d")


def _padded_version_findings(stigs):
    """A zero-padded MAJOR on the DOCUMENT side, which makes the coverage classifier deny a
    version this knowledge base holds.

    `resolver._version_matched` unpads what the CALLER wrote and never what DISA wrote, and that
    asymmetry is deliberate: canonicalizing the document side would make `4` and `04` one version,
    and Canonical writes 22.04, so a caller saying 'Ubuntu 4' would be auto-scoped to Ubuntu 22.04
    confidently. A wrong answer in the selection path is worse than a wrong sentence, so the
    relation stays one-way, and the cost is paid here. A padded major DISA writes is invisible to
    it, and a caller naming that version bare is told the version is not held.

    Ubuntu's `04` is the only padded token in the library today, and it is a MINOR, which is safe:
    a query naming 22.04 yields the major 22, so the padded token is never on the query side of the
    comparison. The trigger is therefore a padded token the title does not write as a minor, and
    this reports it rather than waiting for an operator to notice a false denial.

    Read against BOTH channels `resolver._build_corpus` unions into the set the classifier compares
    against: `normalize`'s version tokens alone miss `v08`, a spelling DISA already uses for v11,
    v9 and v8.

    ERROR, so `main` exits non-zero and the corpus run stops. That is deliberate but it does mean a
    legitimate benchmark can stop the run: one whose title omits the version entirely while its
    folded stig_id carries a padded token has nothing to prove the token is a minor, and it is
    reported. The classifier would compare against that token either way, so the report is true; it
    is the operator's call whether the answer is to fix the classifier or to narrow this check.
    """
    reported = {}
    for stig in stigs:
        toks = normalize(f"{stig['title']} {stig['product_keywords']}")
        products, versions = toks.product, toks.version
        # Both channels _build_corpus unions into the classifier's `versions`, not just normalize's.
        # `normalize` keeps a v-prefixed version as a PRODUCT token, so a title writing `v08` emits
        # no version token at all while glued_versions puts `08` straight into what the classifier
        # compares against. DISA writes that spelling: v11, v9 and v8 are all in the real library.
        versions = versions | glued_versions(products)
        runs = _version_runs(stig["title"])
        # Safe means minor SOMEWHERE and major NOWHERE. Subtracting the majors matters because the
        # sets are flat across every run in the title: 'Acmeware 08 ... Photon OS 4.08' writes 08 as
        # a major of one run and a minor of another, and excusing it on the second reading would
        # excuse exactly the case this exists to catch.
        safe = {part for run in runs for part in run.split(".")[1:]} - {run.split(".")[0] for run in runs}
        padded = tuple(sorted(v for v in versions if _PADDED_VERSION_RE.match(v) and v not in safe))
        if padded:
            # Keyed on the benchmark rather than appended per row: stigs_for_resolver returns one row
            # per (stig_id, version), so an id with two majors would otherwise be reported twice.
            reported[(stig["stig_id"], padded)] = Finding(
                "resolver",
                ERROR,
                f"{stig['stig_id']} carries the zero-padded version token(s) {list(padded)}, which its "
                f"title does not write as a minor. resolver._version_matched unpads the caller's "
                f"spelling only, so a caller naming that version without the zero is now told "
                f"this knowledge base does not hold it. Give _version_coverage its own "
                f"padding-tolerant comparison, which is safe there because it feeds no selection.",
            )
    return [reported[key] for key in sorted(reported)]


def _straddling_pair_findings(stigs):
    """Report the (word before, word after) pairs `_straddling_pairs` protects from splitting,
    one Finding per pair.

    One Finding per pair, not one Finding naming the whole set, so the INFO count itself moves
    when the set changes: a single combined Finding leaves the report's error/warning/info
    triplet unchanged when a third pair is added, and only alters one line of text buried inside
    several hundred, which is easy to miss. Counted per pair, adding or losing one moves the
    triplet a reviewer already watches.

    The set is DATA derived from DISA's titles, not a curated list: a future benchmark titled
    with a separator inside its own product name adds a pair with no code change and no review,
    and that pair then changes how every caller description splits. These INFO lines are the
    only place that change becomes visible, at the next corpus build.
    """
    pairs = _straddling_pairs(stigs)
    return [
        Finding(
            "resolver",
            INFO,
            f"straddling pair protected from splitting: {before}/{after}",
        )
        for before, after in sorted(pairs)
    ]


def phase_resolver(conn, pins=PINNED_QUERIES):
    """Phase 4: the pinned precision queries, against whatever the corpus holds.

    A product absent from the corpus cannot be resolved, and that is not a regression, so
    the miss is reported at info. Only resolving to the wrong product is an error.

    An UNCOVERED_VERSION pin is checked differently and cannot be skipped: it asserts the
    resolver SAYS the version is not held. A substring pin would pass whichever held version
    won, e.g. 'Microsoft SQL Server 2019' landing on the 2012, 2014 or 2016 benchmark
    depending on the build.

    The padded-version check runs on every benchmark rather than on a query, because the
    condition it watches for is a property of DISA's titles and no pinned query would name it."""
    stigs = stigs_for_resolver(conn)
    findings = _padded_version_findings(stigs) + _straddling_pair_findings(stigs)
    held = {row[0] for row in conn.execute("SELECT stig_id FROM stigs").fetchall()}
    for query, expected in pins:
        if expected is UNCOVERED_VERSION:
            hits = resolve(conn, query)
            if not hits:
                # Nothing in this corpus resembles the product, so it holds no versions to
                # judge. Same reasoning as the substring skip below, reached differently
                # because the sentinel carries no stig_id to look for in `held`.
                findings.append(Finding("resolver", INFO, f"{query!r} skipped: corpus holds no candidate for it"))
                continue
            # Any fragment reporting it is enough: every pinned query here is single-fragment,
            # so this reads the one verdict, but a pin gaining a second product must not start
            # failing because the uncovered one stopped being first.
            coverage = hits[0]["version_coverage"]
            if not any(verdict["verdict"] == "uncovered" for verdict in coverage):
                findings.append(
                    Finding(
                        "resolver",
                        ERROR,
                        f"{query!r} resolved to {hits[0]['stig_id']}; expected it to report the version as uncovered",
                    )
                )
            continue
        if not any(expected in stig_id for stig_id in held):
            findings.append(Finding("resolver", INFO, f"{query!r} skipped: corpus holds no {expected}"))
            continue
        hits = resolve(conn, query)
        top = hits[0]["stig_id"] if hits else "no match"
        if expected not in top:
            findings.append(Finding("resolver", ERROR, f"{query!r} resolved to {top}, expected {expected}"))
        elif not hits[0]["high_confidence"]:
            findings.append(Finding("resolver", WARNING, f"{query!r} resolved to {top} but not high confidence"))
    return findings


def phase_margin(conn):
    """Phase 4b: tokens within one document of the resolver's distinctiveness gate.

    One Finding per token, not one naming the whole band, for the reason
    _straddling_pair_findings gives above: a combined Finding leaves the report's
    error/warning/info triplet unchanged when the band changes, and alters one clause inside
    one line among several hundred. The triplet is what a reviewer watches, and the
    straddling-pair report is per item for the same reason.

    Reported per pairing as well as per token because nine pairings are nine different DISA
    corpora with nine different values of n, so this is the only view showing whether a token
    has been drifting toward the gate across releases or has sat beside it for years. A single
    build shows one corpus.
    """
    band = distinctiveness_margin(conn)
    return [
        Finding(
            "resolver",
            INFO,
            f"distinctiveness margin at n={band.n}, gate {band.gate:.2f}: {direction} {token!r} df {count}",
        )
        for direction, tokens in (("losing", band.losing), ("gaining", band.gaining))
        for token, count in tokens
    ]


def write_report(findings, summaries, path):
    """Write the report. summaries is (label, summary) pairs, one per build, in build order.

    Findings accumulate across every build, so each build's ingest counters are rendered under
    their own heading rather than merged into one summary: a single summary would pair one
    build's counters with findings from all of them, and a per-build composition claim could
    not be checked against the build it is about."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    counts = {severity: sum(1 for f in findings if f.severity == severity) for severity in (ERROR, WARNING, INFO)}
    lines = [
        "# STIG corpus conformance report",
        "",
        f"{counts[ERROR]} error, {counts[WARNING]} warning, {counts[INFO]} info",
        "",
        "## Ingest summary",
        "",
    ]
    for label, summary in summaries:
        lines += [f"### {label}", "", "```", repr(summary), "```", ""]
    lines += [
        "## Findings",
        "",
    ]
    if not findings:
        lines.append("None.")
    for finding in findings:
        lines.append(f"- **{finding.severity}** [{finding.phase}] {finding.message}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _tier_divergence_findings(directory):
    """An info Finding for each staged compilation corpus_manifest.tier_of tiers COMPILATION
    but that matches neither of inventory's two globs, so _compilations_in would give it no
    build at all rather than folding it into one.

    Scoped to --compilations, not --corpus: a COMPILATION-tiered name landing in --corpus
    that matches neither inventory.LIBRARY_GLOB nor SUNSET_GLOB is symlinked into every
    build as a product_zip, so only a divergent name staged as a compilation goes missing
    this way. Reads corpus_manifest.tier_of and inventory._kind_of
    rather than re-testing the globs here, so there is one definition of each side instead of
    two that can drift apart unnoticed. Does not change inventory._kind_of's globs to close
    the gap: they gate what reaches the knowledge base, which is not this check's job to move.

    tier_of raises ValueError on a CUI_ name; that population is refused everywhere else in
    this project and never reaches a staged corpus, so it is skipped here rather than reported."""
    if directory is None:
        return []
    findings = []
    for path in sorted(p for p in Path(directory).iterdir() if p.is_file()):
        try:
            tier = corpus_manifest.tier_of(path.name)
        except ValueError:
            continue
        if tier != corpus_manifest.COMPILATION:
            continue
        if inventory._kind_of(path) in ("library", "sunset"):
            continue
        findings.append(
            Finding(
                "accounting",
                INFO,
                f"[manifest] {path.name} is tiered COMPILATION by corpus_manifest but matches "
                f"neither inventory.LIBRARY_GLOB nor SUNSET_GLOB, so _compilations_in would "
                f"give it no build at all",
            )
        )
    return findings


def _label_for(compilations):
    """The name(s) a build's findings are labeled with, or "no compilation" for none."""
    return ", ".join(path.name for path in compilations) or "no compilation"


def _compilations_in(directory):
    """Every (library, sunset...) build to run, or [()] when nothing is staged.

    One build per LIBRARY, because inventory.classify refuses more than one at a time and
    month names do not sort chronologically. The sunset archive is not itself a library, so
    classify accepts it alongside one, and it is paired into every library's build here rather
    than given a build of its own: a library plus the sunset archive is exactly the shape a
    real knowledge base is built from, and a solo build for the sunset archive would never
    exercise the library-vs-sunset arbitration _select exists for at corpus scale.

    [()] rather than [] so the caller runs exactly once over the products alone, which is the
    right behavior for a corpus with no compilation staged. A sunset archive staged with no
    library to pair it against still gets its own build, since there is nothing to pair it
    with; that never happens on the real corpus, which always carries libraries."""
    if directory is None:
        return [()]
    staged = sorted(path for path in Path(directory).iterdir() if path.is_file())
    # One _kind_of call per path, not two: it opens a loose .xml, so a Benchmark staged in
    # compilations/ would otherwise be read and parsed twice.
    kinds = [(path, inventory._kind_of(path)) for path in staged]
    libraries = [path for path, kind in kinds if kind == "library"]
    sunsets = tuple(path for path, kind in kinds if kind == "sunset")
    if not libraries:
        return [sunsets] if sunsets else [()]
    return [(library, *sunsets) for library in libraries]


def run_once(corpus_dir, inputs_dir, work, compilations, skip_determinism):
    """Every phase for one pairing of the product corpus with its compilations.

    Findings are labeled with the compilations' names because a nine-build run produces
    nine sets of them and an unlabeled report would be unreadable."""
    label = _label_for(compilations)
    build_dir = compose_build_dir(corpus_dir, compilations, work / "build")
    artifacts, findings = phase_accounting(build_dir)
    try:
        benchmarks, collect_log = collect_benchmarks(artifacts, work / "stage")
    except Exception as exc:  # a truncated compilation must not abort a corpus-wide sweep
        findings.append(Finding("accounting", ERROR, f"could not collect benchmarks: {exc}"))
        return [finding._replace(message=f"[{label}] {finding.message}") for finding in findings], {}
    parsed_pairs, parse_findings = phase_parse(benchmarks)
    findings += parse_findings
    opened_for_nothing = [line for line in collect_log if "contains no XCCDF benchmark" in line]
    summary = build_corpus_kb(artifacts, inputs_dir, work / "kb.sqlite", work / "stage-build")
    findings.append(
        Finding(
            "cost",
            INFO,
            f"{len(opened_for_nothing)} archive(s) were opened and held no benchmark; the classifier "
            f"rejected {summary.get('skipped_srg', 0)} SRG, {summary.get('skipped_draft', 0)} draft and "
            f"{summary.get('skipped_unclassified', 0)} unclassified document(s)",
        )
    )
    conn = open_kb(work / "kb.sqlite")
    findings += phase_invariants(conn, summary, parsed_pairs)
    findings += phase_resolver(conn)
    findings += phase_margin(conn)
    conn.close()
    if not skip_determinism:
        findings += phase_determinism(artifacts, inputs_dir, work / "determinism")
    return [finding._replace(message=f"[{label}] {finding.message}") for finding in findings], summary


def main():
    parser = argparse.ArgumentParser(description="Run the ingest pipeline over a staged corpus.")
    parser.add_argument("--corpus", required=True, help="directory holding the staged product archives")
    parser.add_argument("--inputs", required=True, help="directory holding U_CCI_List.xml and the JSON sources")
    parser.add_argument(
        "--compilations",
        default=None,
        help="directory of staged compilations. One build is run per library compilation, "
        "each paired with the sunset archive if one is staged, because inventory.classify "
        "refuses more than one library compilation at a time.",
    )
    parser.add_argument("--report", required=True)
    parser.add_argument("--skip-determinism", action="store_true", help="skip the second build")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)
    findings = _tier_divergence_findings(args.compilations)
    summaries = []
    for index, compilations in enumerate(_compilations_in(args.compilations)):
        work = Path(tempfile.mkdtemp(prefix=f"stig-corpus-{index}-"))
        label = _label_for(compilations)
        try:
            run_findings, summary = run_once(args.corpus, args.inputs, work, compilations, args.skip_determinism)
            findings += run_findings
            summaries.append((label, summary))
        except Exception as exc:  # one build failing hours in must not discard every other build's findings
            findings.append(Finding("accounting", ERROR, f"[{label}] build failed: {exc}"))
            summaries.append((label, {}))
        finally:
            shutil.rmtree(work, ignore_errors=True)
    written = write_report(findings, summaries, args.report)
    errors = sum(1 for finding in findings if finding.severity == ERROR)
    print(f"Wrote {written} with {errors} error(s)")
    raise SystemExit(1 if errors else 0)


if __name__ == "__main__":
    main()
