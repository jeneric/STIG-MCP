"""Build a tiered manifest of DISA's public STIG archives from a recorded one and the catalog.

This module downloads no archives. The manifest it produces is the durable artifact: what
DISA publishes changes continuously, so a recorded manifest is what makes a corpus run
reproducible and resumable against one revision of it. DISA closed the directory listing
that once named every file, and the cyber.mil catalog names only current ones, so a new
manifest is a recorded base plus whatever the catalog adds."""

import argparse
import json
import time
from pathlib import Path
from urllib.parse import urljoin

from stig_mcp import tls

# One definition, in the shipped package, because the fetch needs it too. Re-exported here
# for this module's callers.
from stig_mcp.ingest.catalog import (  # noqa: F401
    ADVERSARIAL,
    BENCHMARK,
    COMPILATION,
    JUNK,
    ZIP_BASE,
    fetch_catalog,
    head_length,
    parse_catalog,
    tier_of,
)

USER_AGENT = "stig-mcp-corpus-tool (+https://github.com/jeneric/STIG-MCP)"


def measure(entries, base, open_url, sleep=time.sleep, delay=1.0):
    """The live length of every catalog entry the base has already staged, by HEAD request.

    Only a staged entry has a recorded size to compare, so nothing else is requested. Each
    request pays the same politeness delay the stager does."""
    staged = {entry["name"] for entry in base["entries"] if entry["size"] is not None}
    lengths = {}
    for entry in entries:
        if entry.name not in staged:
            continue
        sleep(delay)
        lengths[entry.name] = head_length(entry, open_url, user_agent=USER_AGENT)
    return lengths


def _tiered(entry):
    """A manifest entry for a catalog name, None for a non-archive, ValueError for CUI_."""
    tier = tier_of(entry.name)
    if tier is None:
        return None
    return {"name": entry.name, "href": entry.href, "tier": tier, "sha256": None, "size": None}


def merge(base, entries, lengths):
    """The base manifest plus every catalog name it lacks, as (manifest, report).

    Every base entry is kept, listed or not, because the corpus replays history the catalog
    no longer carries. A staged entry whose live length differs from its recorded size is a
    same-name reissue, so its checksum is cleared and the stager downloads it again. A
    reissue of exactly the same size is not detected."""
    merged = {entry["name"]: dict(entry) for entry in base["entries"]}
    report = {"kept": len(merged), "added": [], "restaged": []}
    for name, length in lengths.items():
        entry = merged.get(name)
        if entry is not None and entry["size"] is not None and entry["size"] != length:
            entry["sha256"] = entry["size"] = None
            report["restaged"].append(name)
    cui_skipped = 0
    for entry in entries:
        if entry.name in merged:
            continue
        try:
            added = _tiered(entry)
        except ValueError:
            cui_skipped += 1
            continue
        if added is not None:
            merged[entry.name] = added
            report["added"].append(entry.name)
    report["added"].sort()
    report["restaged"].sort()
    manifest = {
        "source_url": base["source_url"],
        "entries": [merged[name] for name in sorted(merged)],
        "cui_skipped": cui_skipped,
    }
    return manifest, report


def write_manifest(manifest, path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    return path


def entry_url(manifest, entry):
    """The absolute URL for a manifest entry, joining its href to the listing URL."""
    return urljoin(manifest["source_url"], entry["href"])


def _parse_args():
    parser = argparse.ArgumentParser(
        description="Write a tiered corpus manifest: a recorded base manifest plus the live cyber.mil catalog."
    )
    parser.add_argument("--base", required=True, help="a manifest recorded earlier; it is never modified")
    parser.add_argument("--out", required=True, help="path to write the merged manifest JSON to")
    parser.add_argument("--delay", type=float, default=1.0, help="seconds to wait before each HEAD request")
    args = parser.parse_args()
    if Path(args.out).resolve() == Path(args.base).resolve():
        parser.error(
            f"--out {args.out} is the base manifest. The base is a dated record and is never "
            f"overwritten; pass a new path to --out."
        )
    base = json.loads(Path(args.base).read_text(encoding="utf-8"))
    if base.get("source_url") != ZIP_BASE:
        parser.error(
            f"{args.base} was recorded from {base.get('source_url')!r}, but catalog entries are "
            f"joined onto {ZIP_BASE}. Pass a base manifest recorded from {ZIP_BASE}."
        )
    return args, base


def main():
    args, base = _parse_args()
    entries = parse_catalog(fetch_catalog(user_agent=USER_AGENT))
    lengths = measure(entries, base, tls.opener(), delay=args.delay)
    manifest, report = merge(base, entries, lengths)
    written = write_manifest(manifest, args.out)
    counts = {}
    for entry in manifest["entries"]:
        counts[entry["tier"]] = counts.get(entry["tier"], 0) + 1
    print(
        f"Wrote {written} with {len(manifest['entries'])} entries: {counts}; kept {report['kept']}, "
        f"added {len(report['added'])}, re-staged {len(report['restaged'])}; "
        f"{manifest['cui_skipped']} CUI entr(y/ies) skipped (requires a DOD PKI certificate)"
    )
    for name in report["restaged"]:
        print(f"re-staged (size changed, corpus_fetch downloads it again): {name}")


if __name__ == "__main__":
    main()
