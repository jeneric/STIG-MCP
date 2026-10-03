"""What a built knowledge base must pass before it is packaged for release."""

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from stig_mcp.ingest import catalog, fetch
from stig_mcp.kb.db import open_db
from stig_mcp.server import readiness, tools
from stig_mcp.server.app import KnowledgeBase
from tools.kb_package import source_file

_EXPECTED_FILES = frozenset(
    {fetch.MANIFEST_NAME, fetch.ATTACK_INDEX_NAME, fetch._CCI_MEMBER, *fetch._TARGET_FILENAMES.values()}
)


class VerifyError(RuntimeError):
    """The build must not be released. The message names every failure found."""


@dataclass(frozen=True)
class Golden:
    label: str
    check: Callable


def unrecorded_files(sources_dir):
    """Files the ingest would read that no fetch recorded: hand-placed, or left by a run that
    kept withdrawn files. A release carries only what DISA and the public sources publish now."""
    recorded = set(fetch.read_manifest(sources_dir)["entries"]) | _EXPECTED_FILES
    return sorted(p.name for p in Path(sources_dir).iterdir() if p.is_file() and p.name not in recorded)


def _key(name):
    match, scheme, release = catalog.release_of(name)
    if match is None:
        return None, None
    return (name[: match.start()].casefold(), scheme, release[0] if scheme == "VR" else None), release


def _label(scheme, release):
    return f"V{release[0]}R{release[1]}" if scheme == "VR" else f"Y{release[0]:02d}M{release[1]:02d}"


def _stored(conn):
    held = {}
    for row in conn.execute("SELECT origin, source_artifact, source_member FROM stigs"):
        name = source_file(row)
        if not name:
            continue
        key, release = _key(name)
        if key is not None:
            held.setdefault(key, []).append(release)
    return held


def tripwire(conn, index_names):
    """Each benchmark on the index against what the knowledge base stores for the same product,
    scheme and major. Only stale fails the build: other_major and unmatched are notes, because
    the library-wins rule keeps an older major on the index on purpose, and DISA keeps listing
    renamed products under their old names, which no stored benchmark came from."""
    held = _stored(conn)
    result = {"stale": [], "other_major": [], "unmatched": []}
    for name in sorted(index_names):
        key, release = _key(name) if catalog.tier_of(name) == catalog.BENCHMARK else (None, None)
        if key is None:
            continue
        if key in held and max(held[key]) < release:
            result["stale"].append(f"{name} (knowledge base holds {_label(key[1], max(held[key]))})")
        elif key not in held:
            other = any(stored[:2] == key[:2] for stored in held)
            result["other_major" if other else "unmatched"].append(name)
    return result


def _windows_11(kb):
    result = tools.defenses_for_technique(kb, "T1078", system_description="Windows 11")
    systems = {row["stig_id"] for row in result.get("resolved_systems", [])}
    if "Microsoft_Windows_11_STIG" not in systems:
        return f"resolved {sorted(systems)}, not Microsoft_Windows_11_STIG"
    if not result["protect"]["findings"]:
        return "no STIG findings under any control"
    details = tools.finding_details(kb, list(result["protect"]["findings"])[:1])
    return None if details["findings"][0]["fix_text"] else "finding_details returned no fix text"


def _apt29(kb):
    return None if tools.techniques_for_actor(kb, "APT29").get("techniques") else "no techniques"


def _rhel_9(kb):
    candidates = tools.resolve_system(kb, "RHEL 9").get("candidates") or [{}]
    top = candidates[0].get("stig_id")
    return None if top == "RHEL_9_STIG" else f"top candidate is {top}"


def _t1078_defenses(kb):
    result = tools.defenses_for_technique(kb, "T1078")
    if not result["protect"]["mitigations"]:
        return "no ATT&CK mitigation on T1078"
    if not result["detect"]:
        return "no detection strategy on T1078"
    return None


def _det0103(kb):
    """DET0103 is a real 19.x strategy; the check that its analytics carry log sources is what
    catches a bundle whose detection objects parsed but came through hollow."""
    details = tools.defense_details(kb, ["DET0103"])
    analytics = details["detection_strategies"][0]["analytics"] if details["detection_strategies"] else []
    if not any(a["log_sources"] for a in analytics):
        return "DET0103 has no analytic with a log source"
    return None


# Each drives a different server tool end to end against the built knowledge base.
GOLDEN = (
    Golden("T1078 on Windows 11", _windows_11),
    Golden("APT29's techniques", _apt29),
    Golden("RHEL 9", _rhel_9),
    Golden("T1078 defenses", _t1078_defenses),
    Golden("DET0103 details", _det0103),
)


def _run_check(golden, kb):
    """A tool's refusal (an unknown technique or actor) is a failed check, not a crash."""
    try:
        return golden.check(kb)
    except tools.CallerError as exc:
        return str(exc)


def golden_failures(kb_path, golden=GOLDEN):
    kb = KnowledgeBase(kb_path)
    try:
        return [f"{g.label}: {reason}" for g in golden if (reason := _run_check(g, kb)) is not None]
    finally:
        kb.release()


def verify(kb_path, sources_dir, golden=GOLDEN):
    reason = readiness.check(kb_path)
    if reason != readiness.READY:
        raise VerifyError(f"The knowledge base at {kb_path} is not ready ({reason}); run stig-mcp-ingest first.")
    manifest = fetch.read_manifest(sources_dir)["entries"]
    if not manifest:
        raise VerifyError(
            f"{sources_dir} has no fetch manifest, so the tripwire has no index to compare against. "
            f"Run stig-mcp-fetch --refresh --drop-withdrawn, then stig-mcp-ingest."
        )
    failures = [f"not recorded by stig-mcp-fetch: {name}" for name in unrecorded_files(sources_dir)]
    failures += golden_failures(kb_path, golden)
    conn = open_db(kb_path)
    try:
        wire = tripwire(conn, manifest)
    finally:
        conn.close()
    failures += [f"stale: {line}" for line in wire["stale"]]
    if failures:
        raise VerifyError("The build must not be released:\n  " + "\n  ".join(failures))
    return {"tripwire": wire}
