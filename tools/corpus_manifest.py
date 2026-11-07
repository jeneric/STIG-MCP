"""Build a tiered manifest of DISA's public STIG archive directory.

This module downloads no archives. The manifest it produces is the durable artifact: the
published directory changes continuously, so a recorded manifest is what makes a corpus
run reproducible and resumable against one revision of it."""

import argparse
import json
import time
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urljoin

# One definition, in the shipped package, because the fetch needs it too. Re-exported here
# for this module's callers.
from stig_mcp.ingest.catalog import (  # noqa: F401
    ADVERSARIAL,
    BENCHMARK,
    COMPILATION,
    JUNK,
    fetch_listing,
    head_length,
    tier_of,
)

USER_AGENT = "stig-mcp-corpus-tool (+https://github.com/jeneric/STIG-MCP)"


class _HrefCollector(HTMLParser):
    """Every anchor href on a page, in document order."""

    def __init__(self):
        super().__init__()
        self.hrefs = []

    def handle_starttag(self, tag, attrs):
        if tag != "a":
            return
        for name, value in attrs:
            if name == "href" and value:
                self.hrefs.append(value)


def parse_listing(html):
    """(decoded name, raw href) for every file link on an Apache autoindex page.

    Apache emits column-sort links and an absolute parent link, neither of which is a file.
    The href is kept percent-encoded because that is what goes back on the wire, while the
    decoded name is what the tier rules and the operator read. The published directory
    really does contain a filename with spaces, so the two genuinely differ."""
    collector = _HrefCollector()
    collector.feed(html)
    entries = []
    for href in collector.hrefs:
        if href.startswith(("?", "/", "#")) or href in ("../", "./"):
            continue
        name = unquote(href)
        if name.endswith("/"):
            continue
        entries.append((name, href))
    return entries


def build_manifest(source_url, entries):
    """A tiered manifest from parsed listing entries, recording no size or checksum yet.

    Sizes and dates are deliberately not read from the autoindex columns: that HTML is a
    presentation detail and parsing it is fragile. The stager records the real size and
    checksum from the response instead, which is the value worth trusting.

    tier_of() stays fail-closed and raises on a CUI_ entry, since anything it accepts could
    be staged; catching that raise here rather than letting it propagate is what stops one
    CUI_ entry, which main() fetches over HTTP and an operator cannot "remove from the
    listing input", from aborting the manifest for every other entry in the directory."""
    manifested = []
    cui_skipped = 0
    for name, href in entries:
        try:
            tier = tier_of(name)
        except ValueError:
            cui_skipped += 1
            continue
        if tier is None:
            continue
        manifested.append({"name": name, "href": href, "tier": tier, "sha256": None, "size": None})
    return {"source_url": source_url, "entries": manifested, "cui_skipped": cui_skipped}


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


def main():
    parser = argparse.ArgumentParser(description="Write a tiered manifest of a DISA STIG archive listing.")
    parser.add_argument("--url", default="https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/")
    parser.add_argument("--out", required=True, help="path to write the manifest JSON to")
    args = parser.parse_args()
    manifest = build_manifest(args.url, parse_listing(fetch_listing(args.url, user_agent=USER_AGENT)))
    written = write_manifest(manifest, args.out)
    counts = {}
    for entry in manifest["entries"]:
        counts[entry["tier"]] = counts.get(entry["tier"], 0) + 1
    print(
        f"Wrote {written} with {len(manifest['entries'])} entries: {counts}; "
        f"{manifest.get('cui_skipped', 0)} CUI entr(y/ies) skipped (requires a DOD PKI certificate)"
    )


if __name__ == "__main__":
    main()
