"""Extract STIG XCCDF benchmarks from a DISA SRG-STIG Library Compilation.

The compilation is a zip-of-zips: the outer archive holds one inner `.zip` per
STIG/SRG/checklist, and each STIG zip contains a Manual `*-xccdf.xml`. Every inner zip is
opened, because DISA does not reliably name an archive after what is inside it; what each
document is gets decided by stig_parser.document_kind once it is parsed. Used both by the
`stig-mcp-extract` helper and auto-detected by `stig-mcp-ingest`.

Extracting into sources/ records every file with origin `loose`, which loses the
record of which archive it came from. `main()` refuses to do this to a sunset
compilation, whose benchmarks depend on that record to be skipped correctly.
"""

import argparse
import fnmatch
import hashlib
import io
import logging
import zipfile
import zlib
from collections import Counter
from pathlib import Path

from defusedxml import ElementTree

from stig_mcp.ingest import config
from stig_mcp.ingest.stig_parser import document_kind, parse_stig_bytes

logger = logging.getLogger(__name__)

# The compilation filename embeds the release month, e.g. U_SRG-STIG_Library_July_2026.zip.
# Lowercase because it is matched against the lowercased filename, never the raw one; this
# is the single definition inventory.LIBRARY_GLOB reuses, so the two entry points agree on
# what counts as a compilation.
COMPILATION_GLOB = "*stig_library*.zip"


_BENCHMARK_TAG = "Benchmark"


# What a zip raises when it, or a member of it, cannot be read. Defined here rather than in
# inventory because inventory imports this module and this one can only reach inventory through
# a local import, so this is the only side both catch sites can share.
UNREADABLE_ZIP = (zipfile.BadZipFile, zlib.error, EOFError)


class CuiContentError(RuntimeError):
    """A source file or archive member whose name marks it Controlled Unclassified Information.

    Refused by name, matching catalog.tier_of: CUI content requires a DOD PKI certificate, and
    a knowledge base built from it could not be shared. stig-mcp-fetch already refuses it; this
    closes the path where an operator places it by hand."""


def refuse_cui(name, where):
    # Every component, split by hand on both separators: a CUI_ directory marks all beneath it,
    # and PureWindowsPath reads "\\srv\..." as a UNC anchor whose .name is empty.
    if any(part.lower().startswith("cui_") for part in name.replace("\\", "/").split("/")):
        raise CuiContentError(
            f"Refusing to ingest {name} from {where}: CUI content requires a DOD PKI certificate "
            f"(CAC) and is out of scope for stig-mcp, and a knowledge base built from it could not "
            f"be shared. Remove it from {where}, then re-run the command."
        )


def refuse_cui_names(names, where):
    for name in names:
        refuse_cui(name, where)


def _is_benchmark(name, data):
    """True when these bytes are an XCCDF Benchmark document.

    Parsed rather than pattern-matched: a SCAP data-stream embeds XCCDF content, so any
    byte-window search would eventually admit one. defusedxml refuses DTDs and entities,
    and anything it will not parse is simply not a benchmark."""
    try:
        return ElementTree.fromstring(data).tag.rsplit("}", 1)[-1] == _BENCHMARK_TAG
    except Exception:
        # Deliberately broad. Every failure mode here means the same thing, that these
        # bytes are not a benchmark, and an unparseable member must never abort a
        # build: a Group Policy package alone carries 159 XML files that are not benchmarks.
        # debug rather than warning: most rejections here are routine (overview PDFs
        # renamed .xml, GPO backups), so this is for someone actively investigating a
        # missing benchmark, not for the default build log.
        logger.debug("%s does not parse as an XCCDF Benchmark; not treating it as one", name)
        return False


def pick_xccdf(names, read):
    """Benchmark members of one STIG zip, cheapest test first.

    The suffix fast path covers almost every benchmark. The root-element fallback exists for
    the files it misses, such as EDB_Postgres_Advanced_Server_STIG.xml in U_EPAS_V2R1_STIG.zip,
    and excludes SCAP data-streams and Group Policy backups by construction."""
    manual = [n for n in names if n.lower().endswith("xccdf.xml") and "manual" in n.lower()]
    if manual:
        return manual
    xccdf = [n for n in names if n.lower().endswith("xccdf.xml")]
    if xccdf:
        return xccdf
    return [n for n in names if n.lower().endswith(".xml") and _is_benchmark(n, read(n))]


def find_compilation_zip(sources_dir):
    """Return the SRG-STIG Library Compilation zip in sources_dir, or None.

    Matched case-insensitively against the lowercased filename, the same rule
    inventory.classify uses for its "library" kind, so this helper and stig-mcp-ingest
    never disagree about what counts as a compilation. Two matches is a hard failure
    rather than a guess, for the same reason classify refuses it: month names do not
    sort chronologically, so a silent pick could extract from a stale quarter's zip."""
    sources_dir = Path(sources_dir)
    if not sources_dir.is_dir():
        return None
    candidates = (p for p in sources_dir.iterdir() if p.is_file())
    matches = sorted(p for p in candidates if fnmatch.fnmatch(p.name.lower(), COMPILATION_GLOB))
    if len(matches) > 1:
        listed = "\n    ".join(m.name for m in matches)
        raise RuntimeError(
            f"{len(matches)} SRG-STIG Library compilations in\n  {sources_dir}:\n    {listed}\n"
            f"Delete the one you are not extracting from, then re-run stig-mcp-extract."
        )
    return matches[0] if matches else None


def iter_stig_members(outer, where):
    """Yield (inner_zip_name, member_name, data) for every benchmark member inside
    an already-open zip-of-zips archive, which `where` names in messages.

    Every inner zip is opened, because a name cannot answer what a document is: DISA ships
    real STIG benchmarks inside U_zOS_RACF_Y26M07_Products.zip. What each document
    actually is gets decided by stig_parser.document_kind after it is parsed. An inner zip
    or member that fails to read is logged once, naming the inner zip, and skipped rather
    than raised: a corrupt inner zip or a corrupt member must not abort the whole run.

    A name with a CUI_ path component is the exception, raised rather than skipped: every
    outer name is checked before anything is yielded, and every name in an inner zip before
    any of that zip's members are.

    Shared by extract_stig_xccdfs and stig_mcp.ingest.inventory, which both walk
    the same zip-of-zips shape and differ only in what they do with what comes out.
    """
    refuse_cui_names(outer.namelist(), where)
    for name in outer.namelist():
        if not name.lower().endswith(".zip"):
            continue
        try:
            inner = zipfile.ZipFile(io.BytesIO(outer.read(name)))
            refuse_cui_names(inner.namelist(), f"{name} in {where}")
            for member in pick_xccdf(inner.namelist(), inner.read):
                yield name, member, inner.read(member)
        except UNREADABLE_ZIP as exc:
            logger.warning("Skipping unreadable STIG zip %s: %s", name, exc)


def _destination(dest_dir, member, data, taken):
    """Where `member` should be written, or None when its bytes are already on disk.

    Basename only, so a malicious "../.." member cannot escape dest_dir. That flattening makes
    collisions possible, and DISA ships them, normally byte-identical. So a repeat is usually a
    duplicate rather than a second document, and only a repeat whose bytes DIFFER earns a name
    of its own.

    That name takes an index PREFIX (`2_`, then `3_`), matching inventory._write_member, so the
    rescued file still ends `xccdf.xml` and is classified by the NAME rule without being read.
    An index between stem and suffix (`..._Manual-xccdf.2.xml`) would miss the glob
    `*xccdf.xml` and reach inventory._kind_of's root-element fallback instead.

    `taken` maps each filename already chosen to its digest and is threaded through one extract
    run, so a file left by a previous run is still overwritten.
    """
    name = Path(member).name
    digest = hashlib.sha256(data).hexdigest()
    candidate = name
    index = 1
    while candidate in taken:
        if taken[candidate] == digest:
            return None
        index += 1
        candidate = f"{index}_{name}"
    taken[candidate] = digest
    return dest_dir / candidate


def extract_stig_xccdfs(compilation_zip, dest_dir):
    """Extract each Manual XCCDF from the compilation zip-of-zips into dest_dir.
    An inner zip without a Manual XCCDF inside (checklists, other bundles) simply
    contributes nothing; an unreadable inner zip is logged and skipped. Returns the
    list of written paths."""
    compilation_zip = Path(compilation_zip)
    dest_dir = Path(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)
    written = []
    skipped = Counter()
    taken = {}
    duplicates = 0
    with zipfile.ZipFile(compilation_zip) as outer:
        for _inner_name, member, data in iter_stig_members(outer, compilation_zip.name):
            try:
                kind = document_kind(parse_stig_bytes(data))
            except Exception:
                # A member that will not parse is treated as not a STIG. Extract is a
                # convenience CLI, so it declines rather than aborting; stig-mcp-ingest reads
                # the same archive directly and reports parse failures per file.
                logger.debug("%s does not parse, so it is not extracted", member)
                skipped["unparseable"] += 1
                continue
            if kind != "stig":
                skipped[kind] += 1
                continue
            out = _destination(dest_dir, member, data, taken)
            if out is None:
                logger.debug("%s repeats a document already extracted byte for byte", member)
                duplicates += 1
                continue
            if out.name != Path(member).name:
                logger.warning(
                    "%s shares a basename with a DIFFERENT document already extracted, so it is "
                    "written as %s instead. Both are visible to ingest; if they turn out to be "
                    "one benchmark, the loser of the same-key contest is dropped.",
                    member,
                    out.name,
                )
            elif out.exists():
                logger.debug("%s already extracted; %s overwrites it", out, member)
            out.write_bytes(data)
            written.append(out)
    logger.info(
        "Extracted %d STIG XCCDF(s) from %s; skipped %d non-STIG document(s) %s and %d duplicate(s)",
        len(written),
        compilation_zip.name,
        sum(skipped.values()),
        dict(skipped),
        duplicates,
    )
    return written


def main():
    """CLI `stig-mcp-extract [<compilation.zip>]`: extract STIG XCCDFs into the
    configured sources directory. With no argument, uses a compilation zip already
    there. Extracted files are recorded with origin `loose` and lose the record of
    which archive they came from, so a sunset compilation is refused rather than
    flattened."""
    from stig_mcp.ingest import inventory  # noqa: PLC0415 (local to avoid a cycle: inventory imports library)

    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser(description=__doc__ or "stig-mcp")
    parser.add_argument("compilation", nargs="?", help="path to a U_SRG-STIG_Library_*.zip")
    arg = parser.parse_args().compilation
    if arg:
        zip_path = Path(arg)
        if not zip_path.exists():
            raise SystemExit(f"{zip_path} does not exist. Pass the path to an existing U_SRG-STIG_Library_*.zip.")
    else:
        zip_path = find_compilation_zip(config.SOURCES_DIR)
        if zip_path is None:
            raise SystemExit(
                f"No SRG-STIG Library Compilation zip found. Pass the path to "
                f"U_SRG-STIG_Library_*.zip, or place it in {config.SOURCES_DIR} first."
            )
    try:
        refuse_cui(zip_path.name, zip_path.parent)
    except CuiContentError as exc:
        raise SystemExit(str(exc)) from exc
    if fnmatch.fnmatch(zip_path.name.lower(), inventory.SUNSET_GLOB):
        raise SystemExit(
            f"{zip_path.name} is a sunset compilation. Extracting it here would flatten it "
            f"into loose XCCDFs and lose the record that its benchmarks came from a sunset "
            f"archive, which is what keeps superseded majors out of the knowledge base. "
            f"Leave it in {config.SOURCES_DIR} and run stig-mcp-ingest, which reads it directly."
        )
    written = extract_stig_xccdfs(zip_path, config.SOURCES_DIR)
    print(f"Extracted {len(written)} STIG XCCDF file(s) into {config.SOURCES_DIR}")


# Reachable as `python -m`, not only as a console script. A registry install may put the
# package in an environment whose scripts are not on the user's PATH, and readiness emits
# `sys.executable -m ...` so the command it names always runs.
if __name__ == "__main__":
    main()
