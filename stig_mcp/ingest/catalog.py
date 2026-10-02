"""What DISA publishes right now, read from its directory index.

Imports no database module and nothing that downloads archives. The only project imports,
require_web_url and require_bare_name from fetch, are the shared URL and name guards, not a
download path. Selection is decided here and downloading happens elsewhere, so this half is
testable against a saved page with no network and no database, and build_kb stays offline.
"""

import re
import urllib.parse
import urllib.request
from typing import NamedTuple

from stig_mcp import tls
from stig_mcp.ingest.fetch import require_bare_name, require_web_url

INDEX_URL = "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/"
USER_AGENT = "stig-mcp"
_TIMEOUT = 60

# An Apache autoindex row: link, then the upload date, then a human size like 665k or 1.1M.
_ROW = re.compile(
    r'<A HREF="([^"]+)">[^<]*</A>\s+(\d{2}-\w{3}-\d{4})\s+\d{2}:\d{2}\s+([0-9.]+[KMGkmg]?)',
    re.IGNORECASE,
)
_UNITS = {"K": 1024, "M": 1024**2, "G": 1024**3}


class Entry(NamedTuple):
    name: str
    href: str
    date: str
    size_bytes: int


def _bytes_of(size):
    unit = size[-1].upper()
    if unit in _UNITS:
        return int(float(size[:-1]) * _UNITS[unit])
    return int(float(size))


def parse_index(text):
    """Every file row on the index page. A page with no rows is empty, not an error; the
    caller decides whether empty is a failure, because for the compilation tier it is.

    Refuses the WHOLE page when a row names anything but a plain filename, the way tier_of
    refuses CUI_ content, so that every Entry this module hands out carries a name safe to
    join onto a directory. Every consumer does exactly that join (fetch.fetch_disa writes
    there, fetch.prune unlinks there, tools/corpus_fetch stages there), so an HREF of
    ../escape.zip would put a download outside the sources directory and, once a manifest
    recorded it, authorize a delete outside it too.

    Fail closed rather than dropping the offending row alone: an Apache autoindex publishes
    bare filenames, and its directory rows carry "-" in the size column so they never match
    _ROW at all, which makes a path-bearing row evidence that the page is not the one this
    tool means to read rather than one entry to skip.

    Guarding the unquoted NAME also covers the URL each href is joined to, and no separate
    href guard is needed: unquoting can only introduce separators, never remove them, so an
    href of %2e%2e%2fescape.zip or a whole https://elsewhere/x.zip unquotes to a name carrying
    a separator and is refused here, before urljoin resolves it to another path or host.
    require_web_url checks only the scheme and would pass both.
    """
    entries = [
        Entry(name=urllib.parse.unquote(href), href=href, date=date, size_bytes=_bytes_of(size))
        for href, date, size in _ROW.findall(text)
    ]
    for entry in entries:
        require_bare_name(entry.name)
    return entries


BENCHMARK = "benchmark"
ADVERSARIAL = "adversarial"
COMPILATION = "compilation"

# Not a U_ release (an installer, a document, a checksum list), or a U_ zip that is not STIG
# content at all: the STIG Viewer desktop application below. Kept visible rather than dropped
# (None) so a manifest built from this tier still records everything the directory held,
# including corpus_manifest's output and corpus_fetch's --tier choices.
JUNK = "junk"

# Name markers for content that cannot yield a manual XCCDF benchmark. SCAP ships a
# data-stream whose root element is not Benchmark, the automation variants ship playbooks
# and cookbooks, and an SRG is a requirements guide rather than a product benchmark.
_ADVERSARIAL_MARKERS = ("_scap_", "_ansible", "_chef", "_powershell_dsc", "_srg", "_policy_package", "_gpo")

# DISA names both compilations with the hyphenated pair "SRG-STIG", which contains "_srg"
# and does NOT contain "_stig". Without this check the two richest sources in the corpus
# are discarded as requirements guides, and the sunset archive is the only place several
# retired products exist at all.
_COMPILATION_MARKERS = ("srg-stig", "compilation")


def tier_of(name):
    """Which corpus tier a published filename belongs to, or None to ignore it entirely.

    Refuses CUI_ outright rather than tiering it. The Library Compilation README requires a
    DOD PKI certificate for that content, so it must never be fetched, and the public
    directory currently publishes none. Encoding the refusal here means no later caller can
    reach it by accident."""
    low = name.lower()
    if low.startswith("cui_"):
        raise ValueError(
            f"Refusing to manifest {name!r}: CUI content requires a DOD PKI certificate (CAC) "
            f"and is permanently out of scope for this tool. Remove it from the listing input."
        )
    if not low.endswith(".zip"):
        return None
    if not low.startswith("u_"):
        return JUNK
    if low.startswith("u_stigviewer-"):
        # The STIG Viewer desktop application (an Electron app), not a STIG. Its lowered name
        # contains "_stig" only by coincidence of spelling, so the final "_stig" test below
        # would misclassify it. Match DISA's "U_STIGViewer-" prefix rather than a loose
        # "stigviewer" substring that could catch a real product name.
        return JUNK
    # Its own tier, and checked before the marker and "_stig" tests because a compilation
    # name satisfies neither: "U_SRG-STIG_Library_July_2026.zip" contains "_srg" but its
    # only "stig" is preceded by a hyphen. The published directory carries nine historical
    # library compilations, and inventory.classify refuses more than one at a time, so they
    # can never be staged alongside each other.
    if any(marker in low for marker in _COMPILATION_MARKERS):
        return COMPILATION
    if any(marker in low for marker in _ADVERSARIAL_MARKERS):
        return ADVERSARIAL
    return BENCHMARK if "_stig" in low else ADVERSARIAL


# Public: fetch.prune must tell the quarterly library from the Rev 4 sunset archive, since
# both are COMPILATION tier and neither supersedes the other. Reaching into another
# module's private name is the coupling these boundaries exist to prevent.
SUNSET_RE = re.compile(r"sunset_compilation", re.IGNORECASE)
_LIBRARY_MONTH = re.compile(r"_Library_([A-Za-z]+)_(\d{4})\.zip$", re.IGNORECASE)
_LIBRARY_NUMERIC = re.compile(r"_Library_(\d{4})_(\d{2})", re.IGNORECASE)
_MONTHS = {
    m: i
    for i, m in enumerate(
        "january february march april may june july august september october november december".split(),
        start=1,
    )
}


def library_order(name):
    """(year, month) for a library compilation, or (0, 0) if the name says nothing.

    NEVER sort these names as strings. DISA writes the month as a word, so a lexical sort
    puts April before July and January_2027 before July_2026, and inventory.classify
    records that the resulting wrong build is invisible for a quarter.
    """
    month = _LIBRARY_MONTH.search(name)
    if month:
        return (int(month.group(2)), _MONTHS.get(month.group(1).lower(), 0))
    numeric = _LIBRARY_NUMERIC.search(name)
    if numeric:
        return (int(numeric.group(1)), int(numeric.group(2)))
    return (0, 0)


def newest_library(entries):
    """The current SRG-STIG Library Compilation, by release rather than by filename order."""
    candidates = [e for e in entries if tier_of(e.name) == COMPILATION and not SUNSET_RE.search(e.name)]
    if not candidates:
        raise ValueError(
            f"Found no SRG-STIG Library compilation in the index at {INDEX_URL}. Either DISA "
            f"changed how the directory listing is published, or the page did not load. "
            f"Download the compilation by hand and place it in the sources directory."
        )
    winner = max(candidates, key=lambda e: library_order(e.name))
    if library_order(winner.name) == (0, 0):
        # (0, 0) is the lowest tuple library_order can produce, so a (0, 0) winner means
        # every candidate scored (0, 0); no filter is needed to list them.
        unreadable = sorted(e.name for e in candidates)
        raise ValueError(
            f"Could not read a release date from any SRG-STIG Library compilation name: "
            f"{unreadable}. Either DISA changed the library filename format (expected "
            f"'..._Library_<Month>_<YYYY>.zip' or the legacy '..._Library_<YYYY>_<MM>...'), "
            f"or the page did not load. Download the correct compilation by hand and place "
            f"it in the sources directory."
        )
    return winner


# Public, for the same reason as SUNSET_RE: release_of below reads this, and fetch._product_key
# reads it through release_of to take a product prefix and a version scheme out of a filename.
VERSION_RE = re.compile(r"_(?:V(\d+)R(\d+)|Y(\d{2})M(\d{2}))_STIG\.zip$", re.IGNORECASE)


def release_of(name):
    """(match, scheme, release) for a benchmark filename, or (None, None, None) if the
    version does not parse. Returning the match here, rather than only the release, means the
    caller finds where the version starts (for the product prefix) without searching the name
    a second time, so the two searches can never disagree with each other.

    Public because fetch.prune must decide whether an arriving release is NEWER than the one on
    disk before deleting anything, and this is the one place a release ordinal is read out of a
    filename. A second copy of that rule would be the one wired to unlink().

    scheme is "VR" or "YM", and the two are not comparable. A Y/M name's two-digit year is a
    publication label rather than a proxy for how new the content inside is:
    U_IBM_HMC_Y23M04_STIG.zip holds benchmark members dated both 2023 and 2015.

    Comparing (major, minor) against (year, month) as one tuple space would pick the Y/M
    release whenever its year outnumbers the other's major, which is almost always, and that is
    exactly backwards. newest_per_product keeps scheme in the product key instead, so a release
    is only ever compared against another release in the same scheme.
    """
    match = VERSION_RE.search(name)
    if not match:
        return None, None, None
    major, minor, year, month = match.groups()
    if major is not None:
        return match, "VR", (int(major), int(minor))
    return match, "YM", (int(year), int(month))


def newest_per_product(entries):
    """The loose STIGs worth downloading: the newest release of each product in each version
    scheme, plus every filename whose version does not parse.

    This is a bandwidth rule and nothing more: the ingest still does the real selection, on
    parsed stig_id and version rather than on filenames, and it keeps products DISA
    deliberately publishes at two majors at once (see docs/operations.md). A mistake here
    therefore costs bytes, not answers, with one exception: dropping a product entirely is a
    silent coverage loss, which is why every filename the version pattern cannot read is kept
    as-is rather than skipped.

    A product publishing under both V/R and Y/M at once keeps its newest release in each
    scheme rather than one scheme's release being picked over the other's: see release_of for
    why the two schemes are not comparable.
    """
    benchmarks = [e for e in entries if tier_of(e.name) == BENCHMARK]
    newest = {}
    unversioned = []
    for entry in benchmarks:
        match, scheme, release = release_of(entry.name)
        if match is None:
            unversioned.append(entry)
            continue
        key = (entry.name[: match.start()], scheme)
        incumbent = newest.get(key)
        if incumbent is None or release > incumbent[0]:
            newest[key] = (release, entry)
    return sorted([entry for _, entry in newest.values()] + unversioned, key=lambda e: e.name)


def sunset(entries):
    """The Rev 4 sunset archive, or None if DISA has withdrawn it."""
    return next((e for e in entries if SUNSET_RE.search(e.name)), None)


def fetch_listing(url=INDEX_URL, opener=None, user_agent=USER_AGENT):
    """The index page as text. The only network call in this module."""
    require_web_url(url)
    request = urllib.request.Request(url, headers={"User-Agent": user_agent})  # noqa: S310  scheme confined by require_web_url above
    open_url = opener or tls.opener()
    with open_url(request, timeout=_TIMEOUT) as response:
        return response.read().decode("utf-8", errors="replace")
