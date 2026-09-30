"""Classify everything in the sources directory, and extract benchmarks from it.

The invariant this module exists to hold: every artifact classify() returns either
contributes benchmarks or produces a log line naming it and saying why.

Nothing inside an XCCDF distinguishes a current benchmark from a retired one: current and
retired benchmarks alike carry <status>accepted</status>, and their dates overlap, so neither
status nor date can classify them. Origin is therefore a property of the container, knowable
only here, at the moment of extraction, and it is recorded because it cannot be recovered
afterwards.
"""

import fnmatch
import logging
import zipfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from stig_mcp.ingest.library import (
    COMPILATION_GLOB,
    UNREADABLE_ZIP,
    CuiContentError,
    _is_benchmark,
    iter_stig_members,
    pick_xccdf,
    refuse_cui,
    refuse_cui_names,
)

logger = logging.getLogger(__name__)

# library.COMPILATION_GLOB is the single definition; find_compilation_zip and classify()
# must never disagree about what counts as a compilation.
LIBRARY_GLOB = COMPILATION_GLOB
SUNSET_GLOB = "*sunset_compilation*.zip"
LOOSE_GLOB = "*xccdf.xml"
LOOSE_SUFFIX = ".xml"


@dataclass(frozen=True)
class Artifact:
    kind: str
    path: Path


def _loose_benchmark(path):
    """True when a loose .xml on disk is an XCCDF Benchmark, read to find out.

    _is_benchmark catches parse failures on bytes it was handed, never the read itself, so
    the read is guarded here: an unreadable file in sources/ must not abort a build before
    it starts, and the operator needs to be told which file it was.
    """
    try:
        data = path.read_bytes()
    except OSError as exc:
        logger.warning("Cannot read %s, so it is not ingested: %s", path, exc)
        return False
    return _is_benchmark(path.name, data)


def _kind_of(path):
    """The artifact kind of one file, or None when it is not one the ingest reads.

    Cheapest test first, the same shape as library.pick_xccdf and for the same reason.

    Archives are judged by NAME, which is all their names have to tell us. So is an .xml
    NAMED like a benchmark, and keeping that rule is load bearing: a file DISA called
    `..._Manual-xccdf.xml` is loose whether or not its bytes parse, so a corrupt one still
    reaches the parser and the failure is reported against it. Judging loose files by
    content ALONE would drop that file here in silence, trading one invisible omission for
    another. The ORDER of the two rules is only about cost: a corrupt named file fails the
    content test and the name rule catches it either way, so nothing but a wasted read turns
    on which runs first.

    Only an .xml the glob cannot reach is opened and judged by its ROOT ELEMENT, because
    DISA does not reliably name a benchmark after what it is: the glob alone would silently
    drop files such as `EDB_Postgres_Advanced_Server_STIG.xml` and DISA's doubled `.xml.xml`
    Samsung names. Parsing rather than loosening the pattern is what keeps a SCAP data-stream
    out: it embeds XCCDF content, so only the root element separates the two.

    The read_bytes() this falls through to carries no size cap. In a stock sources/ directory
    it reaches U_CCI_List.xml (about 3 MB), which cci_parser reads in full anyway, and any name
    LOOSE_GLOB misses that stig-mcp-extract leaves behind. A cap would guard against a cost
    nothing pays today; revisit it if large non-benchmark .xml files get staged here.
    """
    low = path.name.lower()
    if fnmatch.fnmatch(low, LIBRARY_GLOB):
        return "library"
    if fnmatch.fnmatch(low, SUNSET_GLOB):
        return "sunset"
    if low.endswith(".zip"):
        return "product_zip"
    if fnmatch.fnmatch(low, LOOSE_GLOB):
        return "loose"
    if low.endswith(LOOSE_SUFFIX) and _loose_benchmark(path):
        return "loose"
    return None


class TwoLibrariesError(RuntimeError):
    """Two SRG-STIG Library compilations in one sources directory.

    A RuntimeError subclass so every existing caller that catches RuntimeError keeps working;
    the point is that source_status can catch THIS and let any other one through, rather than
    reporting benchmarks present on the strength of a failure it never looked at.
    """


def classify(sources_dir):
    """Every ingestible artifact in sources_dir, labeled by kind.

    Two library compilations is a hard failure rather than a guess. Month names do not sort
    chronologically (January_2027 sorts before July_2026), so a sorted pick can silently build
    from a stale quarter. Which one the operator wants is genuinely unknowable, and a wrong
    guess is invisible for a quarter."""
    sources_dir = Path(sources_dir)
    if not sources_dir.is_dir():
        return []
    artifacts = []
    for path in sorted(sources_dir.iterdir()):
        if not path.is_file():
            continue
        refuse_cui(path.name, sources_dir)
        kind = _kind_of(path)
        if kind is not None:
            artifacts.append(Artifact(kind=kind, path=path))
    libraries = [a.path.name for a in artifacts if a.kind == "library"]
    if len(libraries) > 1:
        listed = "\n    ".join(sorted(libraries))
        raise TwoLibrariesError(
            f"{len(libraries)} SRG-STIG Library compilations in\n  {sources_dir}:\n    {listed}\n"
            f"Delete the one you are not building from, then re-run stig-mcp-ingest."
        )
    return artifacts


_SOURCE_FILES = {
    "ATT&CK": "enterprise-attack.json",
    "CTID": "ctid_mappings.json",
    "800-53r5 catalog": "nist_800_53_rev5_catalog.json",
    "DISA CCI list": "U_CCI_List.xml",
}


def _benchmark_members(archive):
    """The XCCDF benchmark members of one open product zip.

    A one-line wrapper on purpose. It is the single place saying what pick_xccdf must be called
    with, so _from_product_zip and _holds_benchmark can never drift about what a product zip
    holds. They differ in what they do with the answer, never in how they arrive at it.
    """
    return pick_xccdf(archive.namelist(), archive.read)


def _holds_benchmark(artifact):
    """Whether this artifact can yield a benchmark, without extracting anything.

    Only a product zip is opened, and the asymmetry is a cost decision rather than an oversight.
    A loose file was already judged a benchmark by _kind_of, by name or by root element. A
    compilation is trusted on its name because opening one means library.iter_stig_members
    reading every inner zip's bytes in full, which is the whole archive, and this runs while a
    server is answering a tool call.

    So a compilation is reported present without being read, and what happens next depends on
    which way it is broken. A VALID one holding no benchmark draws a warning naming it from
    _from_compilation when the ingest runs, which is the compensating control. A CORRUPT one has
    none: _from_compilation opens it with no try, so the ingest stops with a traceback instead
    of a report. That is a known limitation.

    Never raises, which is the whole contract on the readiness path: whatever escapes reaches an
    operator as a traceback in place of the report readiness.payload exists to render, and it
    escapes exactly when sources/ is in a state worth reporting.

    Silent at INFO and above: collect's census INFO exists to say why staged
    content was SKIPPED and nothing is skipped here, while readiness.payload reaches this on
    every tool call made against an unusable knowledge base, so one line per archive would put
    hundreds on stderr each time. Not silent at DEBUG, where library._is_benchmark logs once per
    .xml member it cannot parse.
    """
    if artifact.kind != "product_zip":
        return True
    try:
        with zipfile.ZipFile(artifact.path) as archive:
            return bool(_benchmark_members(archive))
    except Exception:
        # Deliberately broad, the same call library._is_benchmark makes and for the same reason:
        # every failure here means one thing, that it cannot be told whether this archive holds a
        # benchmark, and the answer to that is False. An enumeration does not converge; at least
        # these reach this handler: BadZipFile, zlib.error and EOFError from
        # library.UNREADABLE_ZIP; PermissionError and FileNotFoundError for a zip whose
        # mode bits changed or that was deleted between classify() and this open;
        # NotImplementedError for a compression method no Python supports; RuntimeError for an
        # encrypted member; and UnicodeDecodeError for a member name whose bytes are not UTF-8.
        # KeyboardInterrupt and SystemExit are not Exception subclasses, so an operator can
        # still interrupt a slow sweep.
        return False


def source_status(sources_dir):
    """Which source classes are present, for a readiness report.

    Benchmarks are answered by opening what classify found rather than by a filename test:
    _kind_of's last rule calls any .zip a product zip, so an existence test would report
    benchmarks staged for a directory holding only U_CCI_List.zip.

    It still does NOT agree with the ingest in every case. _holds_benchmark
    opens only product zips: a compilation is trusted on its name, so an empty or corrupt one is
    reported present here and yields nothing there, and so is a file LOOSE_GLOB matched, which
    _kind_of accepts on its name without reading it. The other four classes are fixed filenames
    that fetch writes and the operator can also place by hand.

    Opening every archive is the worst case, reached only when NOTHING holds a benchmark,
    because any() stops at the first artifact that does. The path is cold besides:
    tools._answerable calls readiness.payload only once kb.acquire() has returned no
    connection, so nothing reaches here while the server can answer from the knowledge base.
    """
    sources_dir = Path(sources_dir)
    status = {name: (sources_dir / filename).is_file() for name, filename in _SOURCE_FILES.items()}
    try:
        artifacts = classify(sources_dir)
    except (TwoLibrariesError, CuiContentError):
        # Benchmarks are certainly present, or a refused CUI file is; the ingest will refuse for
        # either reason and say so itself. Scoped to these two classes deliberately: any other
        # RuntimeError out of classify is a failure this function has not looked at, and
        # reporting benchmarks present on the strength of it would be a guess.
        status["STIG benchmarks"] = True
    else:
        status["STIG benchmarks"] = any(_holds_benchmark(artifact) for artifact in artifacts)
    return status


@dataclass(frozen=True)
class DiscoveredBenchmark:
    """An XCCDF benchmark found in an artifact, before anyone has decided what it is.

    This is deliberately not "a STIG". SRGs, drafts and checklists all reach here; whether a
    document is ingested is decided by stig_parser.document_kind once orchestrator has parsed
    it. Filtering earlier would mean filtering on a filename, which misses STIGs that DISA
    ships in misnamed archives.

    source_member and source_document are not the same thing and the difference is load
    bearing. Inside a compilation, source_member is the inner ZIP name, which two documents
    shipped in one product zip share; source_document is the path within that zip, which they
    do not. Only the second can tell apart the pair that ingest.id_corrections exists to fix."""

    path: Path
    origin: str
    source_artifact: str
    source_member: str | None
    source_document: str | None = None


def _census(names):
    counts = Counter(Path(n).suffix.lower() for n in names if not n.endswith("/"))
    return ", ".join(f"{count} {suffix or 'no extension'}" for suffix, count in counts.most_common(8))


def _write_member(archive, member, dest_dir, index):
    # basename only, so a malicious "../.." member cannot escape dest_dir. The index
    # prefix keeps two artifacts that ship the same basename from clobbering each other.
    out = dest_dir / f"{index}_{Path(member).name}"
    out.write_bytes(archive.read(member))
    return out


def _from_compilation(artifact, dest_dir, counter):
    """Benchmarks inside a zip-of-zips, keeping the inner zip name as the member.

    The walk itself, including the corrupt-inner-zip and corrupt-member handling,
    lives in library.iter_stig_members. This function only decides the destination
    naming and stamps origin onto what comes out."""
    found = []
    with zipfile.ZipFile(artifact.path) as outer:
        for inner_name, member, data in iter_stig_members(outer, artifact.path.name):
            counter[0] += 1
            out = dest_dir / f"{counter[0]}_{Path(member).name}"
            out.write_bytes(data)
            found.append(
                DiscoveredBenchmark(
                    path=out,
                    origin=artifact.kind,
                    source_artifact=artifact.path.name,
                    source_member=inner_name,
                    source_document=member,
                )
            )
    if not found:
        logger.warning(
            "%s is a %s compilation but yielded no benchmarks: every inner zip lacked an "
            "XCCDF benchmark, or was unreadable.",
            artifact.path.name,
            artifact.kind,
        )
    return found


def _from_product_zip(artifact, dest_dir, counter):
    """Benchmarks inside a single product zip, opened one level only.

    Only a compilation is a zip-of-zips. The Intune policy package carries a 298-member
    inner zip of unrelated PowerShell content, and recursing would scan all of it."""
    try:
        archive = zipfile.ZipFile(artifact.path)
    except (zipfile.BadZipFile, EOFError) as exc:
        logger.warning("Skipping unreadable zip %s: %s", artifact.path.name, exc)
        return []
    found = []
    with archive:
        refuse_cui_names(archive.namelist(), artifact.path.name)
        try:
            members = _benchmark_members(archive)
            if not members:
                logger.info(
                    "%s contains no XCCDF benchmark (%s). Only Manual STIG content is ingested; "
                    "SCAP benchmarks and GPO or Intune policy packages are not.",
                    artifact.path.name,
                    _census(archive.namelist()),
                )
                return []
            for member in members:
                counter[0] += 1
                found.append(
                    DiscoveredBenchmark(
                        path=_write_member(archive, member, dest_dir, counter[0]),
                        origin=artifact.kind,
                        source_artifact=artifact.path.name,
                        source_member=member,
                        source_document=member,
                    )
                )
        except UNREADABLE_ZIP as exc:
            # A corrupt member must not abort the whole run, matching the guarantee
            # library.iter_stig_members makes for a corrupt member inside a compilation.
            # Members already written before the failure stay in found.
            logger.warning("Skipping unreadable member in %s: %s", artifact.path.name, exc)
    return found


def collect(artifacts, dest_dir):
    """Every benchmark reachable from these artifacts, each stamped with its origin.

    Every archive is opened; nothing is judged by name. Non-STIG documents come out of here
    and are dropped downstream."""
    dest_dir = Path(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)
    counter = [0]
    found = []
    for artifact in artifacts:
        if artifact.kind == "loose":
            found.append(
                DiscoveredBenchmark(
                    path=artifact.path,
                    origin="loose",
                    source_artifact=artifact.path.name,
                    source_member=None,
                    source_document=artifact.path.name,
                )
            )
        elif artifact.kind in ("library", "sunset"):
            found += _from_compilation(artifact, dest_dir, counter)
        else:
            found += _from_product_zip(artifact, dest_dir, counter)
    logger.info("Discovered %d benchmark file(s) from %d artifact(s)", len(found), len(artifacts))
    return found
