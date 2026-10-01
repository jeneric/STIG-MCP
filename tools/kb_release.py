"""Decide whether to draft a knowledge-base release, and build its assets and notes.

The kb-release workflow calls this; so does an operator whose network can reach DISA when the
runners cannot. It never talks to GitHub: the workflow passes the authenticated listing in, and
uploads what this writes out."""

import argparse
import datetime
import importlib.metadata
import json
import sys
from pathlib import Path

from stig_mcp.ingest import config, fetch
from stig_mcp.kb import releases
from stig_mcp.kb.db import SCHEMA_VERSION
from tools import kb_package, kb_verify

_CHANGED = 10


class ReleaseToolError(RuntimeError):
    """A run that must stop. The message says what to change."""


def _today():
    return datetime.datetime.now(datetime.UTC).date().isoformat()


def newest(listing):
    return releases.choose(releases.parse_listing(listing), SCHEMA_VERSION).compatible


def _reasons(listing, check_exit, event, previous, version):
    if check_exit == fetch.EXIT_COULD_NOT_CHECK:
        raise ReleaseToolError(
            "stig-mcp-fetch --check could not reach a source (exit 3), so this run cannot tell whether "
            "upstream changed. Its log names the source; rerun once it is reachable."
        )
    if check_exit not in (0, _CHANGED):
        raise ReleaseToolError(f"stig-mcp-fetch --check exited {check_exit}; expected 0, 3 or 10. See its log.")
    reasons = ["upstream sources changed since the cached fetch"] if check_exit == _CHANGED else []
    if newest(listing) is None:
        reasons.append(f"no published release for schema {SCHEMA_VERSION}")
    elif (previous or {}).get("built_with") != version:
        built = (previous or {}).get("built_with")
        reasons.append(f"newest release was built with stig-mcp {built}, main is {version}")
    if event == "workflow_dispatch":
        reasons.append("manual run")
    return reasons


def _kb_drafts(listing):
    # type(...) is int, not isinstance: bool subclasses int, and a listing's "id" must be a
    # real release id, never True/False.
    return [
        entry["id"]
        for entry in listing
        if isinstance(entry, dict)
        and entry.get("draft")
        and type(entry.get("id")) is int
        and entry["id"] > 0
        and isinstance(entry.get("tag_name"), str)
        and releases.TAG_RE.fullmatch(entry["tag_name"])
    ]


# Six inputs, each one the workflow supplies separately; a bundle object would only rename them.
def decide(listing, check_exit, event, previous, today, version):  # noqa: PLR0913
    reasons = _reasons(listing, check_exit, event, previous, version)
    tag = f"kb-{today}"
    if reasons and any(isinstance(e, dict) and not e.get("draft") and e.get("tag_name") == tag for e in listing):
        raise ReleaseToolError(
            f"Release {tag} is already published and published releases are never replaced. "
            f"Rerun after 00:00 UTC, when the tag is a new date."
        )
    return {
        "build": bool(reasons),
        "reasons": reasons,
        "tag": tag,
        "delete_drafts": _kb_drafts(listing) if reasons else [],
    }


def unchanged(doc, previous):
    keys = ("built_with", "upstream", "benchmarks", "sources")
    return previous is not None and all(doc.get(k) == previous.get(k) for k in keys)


def _by_id(benchmarks):
    grouped = {}
    for row in benchmarks or []:
        grouped.setdefault(row["stig_id"], []).append(row["release"])
    return {stig_id: ", ".join(sorted(labels)) for stig_id, labels in grouped.items()}


def _diff_lines(doc, previous, previous_tag):
    if previous is None:
        return [f"First release for schema {SCHEMA_VERSION}: {len(doc['benchmarks'])} benchmark(s)."]
    now, before = _by_id(doc["benchmarks"]), _by_id(previous.get("benchmarks"))
    added = [f"{i} {now[i]}" for i in sorted(now.keys() - before.keys())]
    dropped = [f"{i} {before[i]}" for i in sorted(before.keys() - now.keys())]
    changed = [f"{i} {before[i]} -> {now[i]}" for i in sorted(now.keys() & before.keys()) if now[i] != before[i]]
    lines = [f"Since {previous_tag}:"]
    for label, items in (("Added", added), ("Changed", changed), ("Dropped", dropped)):
        lines += ["", f"### {label} ({len(items)})", *(f"- {item}" for item in items or ["none"])]
    return lines


def notes(doc, previous, previous_tag, tag):
    lines = [f"# Knowledge base {tag}", "", f"Schema {SCHEMA_VERSION}, built with stig-mcp {doc['built_with']}.", ""]
    lines += ["## Benchmarks", *_diff_lines(doc, previous, previous_tag), ""]
    lines += ["## Upstream", *(f"- {k}: {v}" for k, v in sorted(doc["upstream"].items())), ""]
    lines += [
        "## Freshness tripwire",
        "Passed: every benchmark on DISA's index is held at its newest release within the same major.",
    ]
    lines += ["", "## SHA-256", f"- xz: {doc['sha256']['xz']}", f"- sqlite: {doc['sha256']['sqlite']}", ""]
    return "\n".join(lines)


def tripwire_summary(wire):
    """The tripwire's notes for the maintainer: index names it could not match to a stored
    benchmark by name. Neither fails the build, and neither tells a user what changed."""
    lines = ["## Freshness tripwire notes", ""]
    for heading, names in (
        ("Newer major on the index, library major kept", wire["other_major"]),
        ("On the index under a name no stored benchmark came from (usually an older name)", wire["unmatched"]),
    ):
        lines += [f"### {heading} ({len(names)})", *([f"- `{name}`" for name in names] or ["- none"]), ""]
    return "\n".join(lines)


def _read_json(path):
    return None if path is None else json.loads(Path(path).read_text(encoding="utf-8"))


# One keyword per input the workflow varies, so a test names only what it changes.
def build(  # noqa: PLR0913
    tag,
    out_dir,
    previous_path=None,
    event="schedule",
    *,
    previous_tag=None,
    kb_path=None,
    sources_dir=None,
    version=None,
    step_summary=None,
):
    kb_path = Path(kb_path or config.KB_PATH)
    version = version or importlib.metadata.version("stig-mcp")
    sources_dir = Path(sources_dir or config.SOURCES_DIR)
    verified = kb_verify.verify(kb_path, sources_dir, golden=kb_verify.GOLDEN)
    out_dir = Path(out_dir)
    assets = kb_package.package(kb_path, out_dir, tag, version, sources_dir)
    doc = _read_json(out_dir / releases.RELEASE_JSON_NAME)
    previous = _read_json(previous_path)
    changed = event == "workflow_dispatch" or not unchanged(doc, previous)
    (out_dir / kb_package.NOTES_NAME).write_text(notes(doc, previous, previous_tag, tag), encoding="utf-8")
    if step_summary is not None:
        with open(step_summary, "a", encoding="utf-8") as out:
            out.write(tripwire_summary(verified["tripwire"]))
    listed = "".join(f"{path}\n" for path in assets) if changed else ""
    (out_dir / kb_package.ASSETS_LIST_NAME).write_text(listed, encoding="utf-8")
    return {"changed": changed, "assets": assets if changed else []}


def _write_outputs(path, values):
    if path is None:
        return
    with open(path, "a", encoding="utf-8") as out:
        for key, value in values.items():
            out.write(f"{key}={value}\n")


def _parser():
    parser = argparse.ArgumentParser(description="Draft kb-* releases: decide, then build.")
    sub = parser.add_subparsers(dest="command", required=True)
    newest_cmd = sub.add_parser("newest")
    newest_cmd.add_argument("--listing", required=True)
    decide_cmd = sub.add_parser("decide")
    decide_cmd.add_argument("--listing", required=True)
    decide_cmd.add_argument("--check-exit", type=int, required=True)
    decide_cmd.add_argument("--event", required=True)
    decide_cmd.add_argument("--previous")
    decide_cmd.add_argument("--github-output")
    build_cmd = sub.add_parser("build")
    build_cmd.add_argument("--tag", required=True)
    build_cmd.add_argument("--out", required=True)
    build_cmd.add_argument("--previous")
    build_cmd.add_argument("--previous-tag")
    build_cmd.add_argument("--event", default="schedule")
    build_cmd.add_argument("--github-output")
    build_cmd.add_argument("--step-summary")
    return parser


def _validated_previous(path, listing):
    doc = _read_json(path)
    release = newest(listing)
    if doc is None or release is None:
        return None
    return releases.parse_release_json(doc, release)


def _run(args):
    if args.command == "newest":
        found = newest(_read_json(args.listing))
        if found is not None:
            print(found.tag)
        return
    if args.command == "decide":
        listing = _read_json(args.listing)
        previous = _validated_previous(args.previous, listing)
        version = importlib.metadata.version("stig-mcp")
        decision = decide(listing, args.check_exit, args.event, previous, _today(), version)
        print(json.dumps(decision, indent=2))
        _write_outputs(
            args.github_output,
            {
                "build": str(decision["build"]).lower(),
                "tag": decision["tag"],
                "delete_drafts": " ".join(map(str, decision["delete_drafts"])),
            },
        )
        return
    result = build(
        args.tag, args.out, args.previous, args.event, previous_tag=args.previous_tag, step_summary=args.step_summary
    )
    _write_outputs(args.github_output, {"changed": str(result["changed"]).lower()})


def main(argv=None):
    args = _parser().parse_args(argv)
    try:
        _run(args)
    except (ReleaseToolError, kb_verify.VerifyError, kb_package.PackageError, releases.ReleaseError) as exc:
        print(exc, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
