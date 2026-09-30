import argparse
import functools
import hashlib
import http.client
import json
import os
import shutil
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
import zlib
from http import HTTPStatus
from pathlib import Path, PurePosixPath, PureWindowsPath

from stig_mcp.ingest import config, control_catalog, upstream

_ALLOWED_SCHEMES = frozenset({"http", "https"})

MANIFEST_NAME = ".stig-mcp-manifest.json"

# What each public source records in the manifest's "public" section. Any other key, a record
# that is not a dict, or a field that is neither a string nor None is dropped on read.
PUBLIC_FIELDS = {
    "attack": ("version", "url", "sha256", "release_date"),
    "ctid": ("attack_version", "url", "sha256", "attack_release_date"),
    "catalog": ("version", "url", "sha256", "git_blob_sha"),
}


def _usable_public(section):
    if not isinstance(section, dict):
        return {}
    usable = {}
    for source, fields in PUBLIC_FIELDS.items():
        record = section.get(source)
        if isinstance(record, dict) and all(isinstance(record.get(f), str | None) for f in fields):
            usable[source] = {f: record.get(f) for f in fields}
    return usable


# The bootstrap selection advertises about 0.95 GiB (powers of 1024), and the ingest adds
# roughly 100 MB of transient extraction and a knowledge base of about 64 MB that grows with
# fuller loose coverage. Those two ingest figures are approximate. 2 GiB leaves headroom
# without demanding a partition.
REQUIRED_FREE_BYTES = 2 * 1024**3

_CCI_NAME = "U_CCI_List.zip"
# Kept even by --drop-withdrawn: the ingest cannot run without it, and _product_key cannot key it.
NEVER_DROPPED = frozenset({_CCI_NAME})
# What DISA ships inside _CCI_NAME and what the ingest reads: inventory._SOURCE_FILES and
# orchestrator both name this file, and neither knows the archive exists.
_CCI_MEMBER = "U_CCI_List.xml"
_DOWNLOAD_TIMEOUT = 120
_DIGEST_CHUNK = 1024 * 1024

# A single reset connection can kill a refresh several minutes in, with no cache saved to resume
# from, so transient failures are retried. RETRY_ATTEMPTS is the total number of tries, so three
# attempts are given up before the fourth is treated as final; RETRY_BACKOFF is the pause in
# seconds before tries 2, 3 and 4.
RETRY_ATTEMPTS = 4
RETRY_BACKOFF = (5, 15, 45)

# DISA's own 5xx and its rate-limit code: a retry is worth attempting because the failure is
# the server's, not the request's. Every other 4xx is a client-side problem a retry cannot fix.
_TRANSIENT_HTTP_CODES = frozenset({429, 500, 502, 503, 504})

# ATT&CK and CTID have no fixed URL: take_public resolves the newest release of each through
# upstream. Only the catalog, which has no release index, has a fixed address.
SOURCE_URLS = {
    "catalog": "https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog-min.json",
}

_TARGET_FILENAMES = {
    "attack": "enterprise-attack.json",
    "ctid": "ctid_mappings.json",
    "catalog": "nist_800_53_rev5_catalog.json",
}

ATTACK_INDEX_NAME = "attack_index.json"


def manual_sources():
    # Interpolate SOURCES_DIR rather than a literal, so this names the same directory
    # stig-mcp-ingest reports, including when STIG_MCP_DATA is set.
    return [
        f"DISA STIG Library Compilation (quarterly zip) -> extract *xccdf.xml into {config.SOURCES_DIR}",
        f"DISA CCI List (U_CCI_List.xml) -> place in {config.SOURCES_DIR}",
        f"Loose product STIG zips (optional, broadens coverage) -> place in {config.SOURCES_DIR}",
    ]


def require_web_url(url):
    """Reject any non-web scheme before a download request is built. A file:/ftp:/data:
    URL would make urllib open a local or unexpected resource instead of the intended
    HTTPS source; callers must pass an http/https URL."""
    scheme = urllib.parse.urlsplit(url).scheme.lower()
    if scheme not in _ALLOWED_SCHEMES:
        raise ValueError(
            f"Refusing to fetch {url!r}: only http/https sources are allowed, not "
            f"scheme {scheme!r}. Change the source URL to an https:// address."
        )


def _is_bare_name(name):
    """Whether name is a plain filename, so that joining it onto a directory cannot leave it.

    Checked against BOTH path flavors rather than the running platform's alone. `..\\x.zip`
    is one ordinary filename to POSIX and a parent-directory step to Windows, and this project
    supports both (config._user_dir carries a live Windows branch), so a POSIX-only check
    would pass a name that escapes on the other platform. The Windows flavor also refuses a
    drive-relative `C:x.zip` and a UNC path, neither of which a POSIX check can see.

    The POSIX clause is currently redundant, because the Windows flavor treats "/" as a
    separator too, and it is kept deliberately: reducing this to the POSIX flavor alone reads
    like the obvious simplification and silently reopens `..\\x.zip`. Naming both flavors
    states the rule instead of resting it on one parser's incidental generosity.

    A name check rather than the resolved-containment check tools/corpus_fetch._target_for
    uses: this one is a pure function of the string, needing neither the destination to exist
    nor the running platform to share the separator rules of the platform that will join it.
    Containment is the right shape there because that guard sits at the join itself.

    The three pure-dot names are rejected by name rather than left to pathlib, because
    PurePath("..").name differs across CPython versions ("" on some, ".." on 3.14, which the
    comparison below would accept). None lands bytes anywhere on its own, since each joins to
    a directory, but the rule must not rest on a version-dependent accident.
    """
    if name in {"", ".", ".."}:
        return False
    return PurePosixPath(name).name == name and PureWindowsPath(name).name == name


def require_bare_name(name):
    """Reject a source name that is not a plain filename, before anything joins it to a path.

    Every user of these names builds `directory / name`: fetch_disa writes there, prune
    unlinks there, and tools/corpus_fetch stages there. A name carrying a directory
    separator, a drive letter or a `..` step therefore reaches outside the sources directory
    for both the write and the delete.

    The message names the index only: catalog.parse_index is the sole caller that raises it,
    and read_manifest applies the same rule through _is_bare_name by dropping the key instead.
    """
    if not _is_bare_name(name):
        raise ValueError(
            f"Refusing the index entry {name!r}: it must be a plain filename, not a path. It "
            f"is joined onto the sources directory, so a name carrying a directory separator, "
            f"a drive letter or a '..' step would write or delete outside it. DISA's directory "
            f"listing publishes plain filenames, so a row of this shape means the page read "
            f"was not that listing: check the URL fetched and read the index again."
        )


def fetch_public(dest_dir, opener=None):
    return take_public(dest_dir, ("attack", "ctid", "catalog"), opener=opener)


def take_public(dest_dir, names, opener=None):
    """Download the named public sources at their newest upstream release and record each one.

    Taken one at a time in a fixed order, so a failure names the source it stopped on before
    the error propagates; the caller still stops, so a half-finished fetch prunes nothing."""
    dest_dir = Path(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)
    open_url = opener or urllib.request.urlopen
    takers = {"attack": _take_attack, "ctid": _take_ctid, "catalog": _take_catalog}
    written = []
    for name in ("attack", "ctid", "catalog"):
        if name not in names:
            continue
        try:
            written.append(takers[name](dest_dir, open_url, opener))
        except Exception:
            print(
                f"{_PUBLIC_LABELS[name]} download failed: any previous {_TARGET_FILENAMES[name]} was kept and "
                f"nothing was pruned. Re-run the same stig-mcp-fetch command once the error that follows is fixed."
            )
            raise
    return written


def _download_replacing(open_url, url, target, parse=None):
    """_download into a sibling .part file, then swap it in, so a failed refresh keeps the file
    the operator already had instead of deleting it. parse, when given, reads the .part first
    and its result is returned: a body it rejects never replaces a good local copy."""
    partial = target.with_name(target.name + ".part")
    _download(open_url, url, partial, upstream.USER_AGENT)
    try:
        parsed = parse(partial) if parse else None
    except Exception:
        partial.unlink(missing_ok=True)
        raise
    os.replace(partial, target)
    return parsed


def _parse_attack_index_file(path):
    return upstream.parse_attack_index(json.loads(path.read_text()))


def _take_attack(dest_dir, open_url, _opener):
    index_path = dest_dir / ATTACK_INDEX_NAME
    index = _download_replacing(open_url, upstream.ATTACK_INDEX_URL, index_path, _parse_attack_index_file)
    target = dest_dir / _TARGET_FILENAMES["attack"]
    _download_replacing(open_url, index.latest.url, target)
    latest = index.latest
    record = {
        "version": latest.version,
        "url": latest.url,
        "sha256": _digest(target),
        "release_date": latest.release_date,
    }
    write_public(dest_dir, "attack", record)
    return target


def _take_ctid(dest_dir, open_url, opener):
    release = upstream.ctid_latest(opener)
    target = dest_dir / _TARGET_FILENAMES["ctid"]
    try:
        _download_replacing(open_url, release.url, target)
    except urllib.error.HTTPError as exc:
        if exc.code != HTTPStatus.NOT_FOUND:
            raise
        raise RuntimeError(
            f"CTID's newest mapping folder is {release.folder}, but {release.url} does not exist. CTID may "
            f"have changed its layout. Place ctid_mappings.json by hand (docs/operations.md, 'Placing the "
            f"sources by hand') until stig-mcp is updated."
        ) from exc
    released = _release_date(dest_dir, release.attack_version, opener)
    record = {
        "attack_version": release.attack_version,
        "url": release.url,
        "sha256": _digest(target),
        "attack_release_date": released,
    }
    write_public(dest_dir, "ctid", record)
    return target


def _release_date(dest_dir, attack_version, opener):
    """The release date of attack_version, from the attack_index.json a fetch saved when there is
    one, else from upstream; None when neither can say."""
    index_path = dest_dir / ATTACK_INDEX_NAME
    try:
        if index_path.is_file():
            index = _parse_attack_index_file(index_path)
        else:
            index = upstream.attack_latest(opener)
    except (OSError, ValueError, upstream.UpstreamError):
        return None
    return index.release_dates.get(attack_version)


def _take_catalog(dest_dir, open_url, _opener):
    target = dest_dir / _TARGET_FILENAMES["catalog"]
    version = _download_replacing(open_url, SOURCE_URLS["catalog"], target, control_catalog.catalog_version)
    record = {
        "version": version,
        "url": SOURCE_URLS["catalog"],
        "sha256": _digest(target),
        "git_blob_sha": upstream.git_blob_sha(target),
    }
    write_public(dest_dir, "catalog", record)
    return target


def selection(entries):
    """Everything worth downloading from one index read: the current library compilation, the
    sunset archive, the CCI list, and the newest loose STIG of each product."""
    # A module-level import here breaks `python -m stig_mcp.ingest.fetch` and the
    # stig-mcp-fetch console script outright, because they import this module first.
    from stig_mcp.ingest import catalog  # noqa: PLC0415 (local to avoid a cycle: catalog imports fetch)

    chosen = [catalog.newest_library(entries)]
    archive = catalog.sunset(entries)
    if archive is not None:
        chosen.append(archive)
    # Exact name, never a substring: the index publishes both U_CCI_List.zip and a differently
    # sized CCI_List.zip, and only the full name separates them.
    cci = next((e for e in entries if e.name == _CCI_NAME), None)
    if cci is not None:
        chosen.append(cci)
    chosen.extend(catalog.newest_per_product(entries))
    return chosen


def preflight(dest_dir, entries, disk_usage=None):
    """Refuse before the first byte rather than at 90% of a gigabyte.

    entries is what a run will ACTUALLY fetch, not the whole selection: refusing a run that
    would transfer nothing is indefensible, so fetch_disa passes the entries left after the
    skip and does not call this at all when none are left.

    The floor covers the ingest's transient extraction and the knowledge base, which any run
    that downloads anything is headed for. Doubling the selection's own size is headroom for
    a larger corpus: the full bootstrap advertises about 0.95 GiB, so the floor still wins
    max() today. Keep both.
    """
    usage = (disk_usage or shutil.disk_usage)(dest_dir)
    wanted = max(REQUIRED_FREE_BYTES, sum(e.size_bytes for e in entries) * 2)
    if usage.free < wanted:
        raise RuntimeError(
            f"Not enough free space at {dest_dir}: {usage.free / 1024**3:.1f} GiB free, "
            f"{wanted / 1024**3:.1f} GiB needed for the downloads, the ingest's temporary "
            f"extraction and the knowledge base. Free up space or point STIG_MCP_DATA at a "
            f"larger volume."
        )


def write_manifest(dest_dir, entries, *, vouched_for=None):
    """What the fetch took and what the index said about it, for --check and --refresh to diff.

    vouched_for names the entries whose file on disk the caller has just established: skipped
    because the recorded length still matched, or downloaded cleanly. Every OTHER entry
    records on_disk_bytes and sha256 as None no matter what sits at that path. A run must
    never credit itself with a file it did not fetch: manual_sources tells operators to drop
    zips into this very directory, so an entry a failed run never reached can easily have a
    stale or hand-placed archive there, and recording its length would satisfy the skip
    forever and stop the real file from ever arriving. A previous record is not carried over
    for the same reason. None means the caller vouches for every entry it passed.

    Costs a full SHA-256 read of every vouched file, roughly a gigabyte for a whole bootstrap,
    every time it is called and whether or not anything was downloaded. fetch_disa pays it on
    the failure path too, so an interrupted bootstrap hashes what it already has before the
    error surfaces. Call it once at the end of a run, never inside a per-entry loop.

    The write itself is not atomic, so a failure caused by a full volume can truncate the
    previous manifest while trying to replace it, costing a re-download. The whole body,
    every digest included, is built BEFORE the write, so the far longer hashing window cannot
    leave a half-written file: only the write itself is exposed.

    size_bytes and on_disk_bytes answer different questions and routinely disagree:
    size_bytes is what the index advertised, which is a rounded human-readable column, while
    on_disk_bytes is the length of the file actually stored. See _already_downloaded.

    The public section belongs to fetch_public and is carried over unchanged.
    """
    path = Path(dest_dir) / MANIFEST_NAME
    previous_public = read_manifest(dest_dir)["public"]
    body = {
        "entries": {
            e.name: _record(Path(dest_dir) / e.name, e, vouched_for is None or e.name in vouched_for) for e in entries
        }
    }
    if previous_public:
        body["public"] = previous_public
    path.write_text(json.dumps(body, indent=2, sort_keys=True))
    return path


def write_public(dest_dir, source, record):
    """Record one public source's download in the manifest, leaving every other record as it was."""
    manifest = read_manifest(dest_dir)
    body = {"entries": manifest["entries"], "public": {**manifest["public"], source: record}}
    path = Path(dest_dir) / MANIFEST_NAME
    path.write_text(json.dumps(body, indent=2, sort_keys=True))
    return path


def _record(path, entry, vouched):
    return {
        "date": entry.date,
        "size_bytes": entry.size_bytes,
        "on_disk_bytes": _length(path) if vouched else None,
        "sha256": _digest(path) if vouched else None,
    }


def read_manifest(dest_dir):
    """The manifest of a previous run, or an empty one when there was no usable previous run.

    Always returns a dict with an "entries" dict of dicts, so every caller can index it and
    then index what it finds. Valid JSON of the wrong shape (a bare {}, a list) is as useless
    to them as no manifest at all, and returning it unchecked would fail them with a KeyError
    or an AttributeError instead.

    A row that is not a record is dropped on its own rather than costing the whole manifest.
    Each row stands alone: one unreadable row is one archive re-fetched, while discarding the
    file for it would re-fetch every selected artifact and roughly a gigabyte with them.

    A key that is not a plain filename is dropped the same way, and this is the guard that
    stands between a manifest and prune's unlink: prune iterates these keys and joins each one
    onto dest_dir, so a key like ../victim.zip would delete outside the sources directory.
    Validating index entries alone would not close that, because this file is JSON read off
    disk, written by an earlier run or edited by hand, not an index the current run parsed.
    Dropped rather than raised, unlike an index entry (catalog.parse_index): the manifest is
    local state any run rewrites, so dropping costs one re-fetch, while raising would leave
    every command dead until the operator deleted the file by hand.
    """
    path = Path(dest_dir) / MANIFEST_NAME
    if not path.is_file():
        return {"entries": {}, "public": {}}
    try:
        body = json.loads(path.read_text())
    except (OSError, ValueError):
        return {"entries": {}, "public": {}}
    if not isinstance(body, dict) or not isinstance(body.get("entries"), dict):
        return {"entries": {}, "public": {}}
    usable = {
        name: record for name, record in body["entries"].items() if isinstance(record, dict) and _is_bare_name(name)
    }
    return {**body, "entries": usable, "public": _usable_public(body.get("public"))}


def _length(path):
    return path.stat().st_size if path.is_file() else None


def _digest(path):
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(_DIGEST_CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _already_downloaded(target, recorded):
    """True when the file this manifest entry recorded is still on disk at that length.

    Compares against on_disk_bytes and NEVER against the index's size_bytes. The index's size
    column is a rounded display value that matches almost no real file's length, so comparing
    against it would re-download the whole selection on every run.

    A file present at some other length is a truncated or superseded download and must be
    taken again, and so is a file recorded while it was absent (on_disk_bytes is None).
    """
    stored = recorded.get("on_disk_bytes")
    return stored is not None and target.is_file() and target.stat().st_size == stored


def _refuse_cui_url(url):
    """Refuse a resolved URL carrying CUI content regardless of the entry's name. CUI needs
    a DOD PKI certificate and must never reach a shipped knowledge base."""
    if "cui_" in url.lower():
        raise RuntimeError(
            f"Refusing to fetch {url!r}: it resolves to CUI content, which requires a DOD "
            f"PKI certificate (CAC) and must not be ingested."
        )


def is_transient(exc):
    """Whether exc is a network failure a bounded retry can plausibly heal.

    HTTPError is checked before URLError because HTTPError subclasses it. A URLError is
    transient only when its reason is an OSError that is not an ssl.SSLError: that covers a
    reset, a refused or aborted connection, an unreachable network and a DNS failure, while
    leaving a certificate problem, which a retry cannot heal, to propagate at once. TimeoutError,
    ConnectionError and http.client.HTTPException are also checked directly, for the shape each
    one takes when raised outside a URLError, such as an IncompleteRead while copyfileobj reads
    a response body.
    """
    if isinstance(exc, urllib.error.HTTPError):
        return exc.code in _TRANSIENT_HTTP_CODES
    if isinstance(exc, urllib.error.URLError):
        return isinstance(exc.reason, OSError) and not isinstance(exc.reason, ssl.SSLError)
    return isinstance(exc, TimeoutError | ConnectionError | http.client.HTTPException)


def _with_retry(call, what, pause):
    """Call call() up to RETRY_ATTEMPTS times total, retrying only a transient failure
    (is_transient) and pausing RETRY_BACKOFF seconds between tries. Returns call()'s result on
    success. The last attempt's exception propagates unchanged, so a caller sees exactly what an
    unretried call would have raised; a non-transient failure propagates immediately, on the
    first attempt, without pausing at all.
    """
    for attempt in range(1, RETRY_ATTEMPTS + 1):
        try:
            return call()
        except Exception as exc:
            if attempt == RETRY_ATTEMPTS or not is_transient(exc):
                raise
            wait = RETRY_BACKOFF[attempt - 1]
            reason = str(exc)[:120]
            print(
                f"Retrying {what} after {reason} (attempt {attempt + 1} of {RETRY_ATTEMPTS}, waiting {wait} s).",
                file=sys.stderr,
            )
            pause(wait)


def _download(open_url, url, target, user_agent):
    """Fetch one archive, leaving nothing behind if it fails partway.

    A partial file must not survive the failure. write_manifest would record its short length,
    and _already_downloaded would then read that length back as a complete download and skip
    the file forever, which is the very trap the manifest exists to avoid. BaseException
    rather than Exception so a Ctrl-C during a gigabyte of downloading is cleaned up too.
    """
    require_web_url(url)
    # S310: require_web_url on the line above confines url to http/https before the request is
    # constructed, and fetch_disa applies the same guard to every entry before reaching here.
    request = urllib.request.Request(url, headers={"User-Agent": user_agent})  # noqa: S310
    try:
        with open_url(request, timeout=_DOWNLOAD_TIMEOUT) as response, target.open("wb") as handle:
            shutil.copyfileobj(response, handle)
    except BaseException:
        target.unlink(missing_ok=True)
        raise


def extract_cci(dest_dir):
    """Put U_CCI_List.xml beside the archive a fetch took, or nothing when there is no archive.

    DISA publishes the CCI list only as a zip and the ingest reads the XML inside it
    (inventory._SOURCE_FILES, and the cci_path orchestrator builds). Without this the two
    documented commands do not compose at all: the fetch completes and the ingest then stops
    on a missing artifact. The ingest's contract is untouched by it. That side still reads a
    plain XML file out of the sources directory and still never imports this module, so an
    operator who places one by hand and never runs a fetch is unaffected.

    Keyed on the ARCHIVE being on disk, never on the CCI being among a run's entries, so one
    call covers every state that ends with the archive there: a fresh download, a download
    skipped because the manifest still matches, and a --refresh whose entries do not name the
    CCI at all. Keyed on the entries, the last two would leave no XML behind.

    Overwrites whatever XML is already there. The archive is the file the manifest vouches
    for, so it is the authority on the member's contents, and an XML from an older release
    surviving a fetch that took a newer archive is the worse failure of the two because
    nothing would ever report it.

    Reads exactly one member, by exact key, into a destination built from module constants
    alone. No name out of the archive reaches the path written to and extractall is never
    called, so a member called ../U_CCI_List.xml or /etc/passwd is not dangerous but simply
    absent: it is not the key asked for, and the read raises instead.

    Every failure of the READ becomes a RuntimeError. _fetch_disa_or_advise catches
    RuntimeError, OSError and ValueError in order to print the manual fallback, and
    zipfile.BadZipFile subclasses none of the three, so an unconverted one would reach the
    operator as a traceback carrying no remedy. The write is deliberately outside that
    conversion: an OSError from it is already one of the three, and wrapping it would put a
    message about reading the archive on a failure to write the XML.
    """
    archive_path = Path(dest_dir) / _CCI_NAME
    if not archive_path.is_file():
        return None
    try:
        with zipfile.ZipFile(archive_path) as archive:
            data = archive.read(_CCI_MEMBER)
    except (zipfile.BadZipFile, KeyError, OSError, EOFError, zlib.error) as exc:
        raise RuntimeError(
            f"Cannot read {_CCI_MEMBER} out of {archive_path}: {exc}. Delete that archive and "
            f"run stig-mcp-fetch again to take it afresh, or download {_CCI_NAME} from "
            f"cyber.mil and place {_CCI_MEMBER} from it in {dest_dir} by hand."
        ) from exc
    target = Path(dest_dir) / _CCI_MEMBER
    target.write_bytes(data)
    return target


def fetch_disa(dest_dir, opener=None, delay=0.25, sleep=None, entries=None):
    """Download the selected DISA artifacts into dest_dir and write the manifest.

    Roughly a gigabyte from one government host, so requests are spaced by delay seconds;
    entries already on disk at their recorded length are skipped and make no request at all.
    Pass entries to fetch a subset, otherwise the index is read once and selection decides.

    Returns every selected file now on disk, skipped and freshly fetched alike, followed by
    the CCI XML when extract_cci produced one. That last path is NOT an index entry and never
    reaches the manifest; it is returned so main() prints it and the operator sees the file
    the ingest will read. The manifest is written even when a download fails, so that a retry
    re-fetches only what did not arrive. It describes exactly the entries this call was
    given, so a caller fetching a subset must merge into the existing manifest rather than
    let this call replace it.

    The extraction runs only after every download has succeeded. An interrupted run has no
    complete source set for the ingest to read anyway, and _fetch_disa_or_advise has already
    named U_CCI_List.xml among the artifacts to place by hand; the next run that completes
    extracts it.

    The index read and each download retry a transient failure through sleep, which also
    receives the inter-download delay.
    """
    from stig_mcp.ingest import catalog  # noqa: PLC0415 (local to avoid a cycle, as in selection)

    dest_dir = Path(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)
    pause = sleep or time.sleep
    if entries is None:
        read = functools.partial(catalog.fetch_listing, opener=opener)
        entries = selection(catalog.parse_index(_with_retry(read, "the DISA index", pause)))
    recorded = read_manifest(dest_dir)["entries"]
    written = []
    pending = []
    vouched_for = set()
    for entry in entries:
        url = urllib.parse.urljoin(catalog.INDEX_URL, entry.href)
        _refuse_cui_url(url)
        require_web_url(url)
        target = dest_dir / entry.name
        written.append(target)
        if _already_downloaded(target, recorded.get(entry.name, {})):
            vouched_for.add(entry.name)
        else:
            pending.append((entry, url, target))
    if pending:
        # Only what this run will actually transfer, and not at all when it will transfer
        # nothing: a fully cached selection must not be refused for lack of room it does not
        # need. Before the first request, so nothing is half-fetched when the volume is full.
        preflight(dest_dir, [entry for entry, _, _ in pending])
    open_url = opener or urllib.request.urlopen
    try:
        for index, (entry, url, target) in enumerate(pending):
            if index:
                # Between requests, not between entries: a skip touched no host, so pausing
                # for it would delay the first real download for nothing.
                pause(delay)
            call = functools.partial(_download, open_url, url, target, catalog.USER_AGENT)
            _with_retry(call, entry.name, pause)
            vouched_for.add(entry.name)
    finally:
        # vouched_for holds only what this run established: entries whose recorded length
        # still matched, and entries it downloaded cleanly. Anything still pending when a
        # download raised is recorded as absent, whatever is sitting at its path.
        write_manifest(dest_dir, entries, vouched_for=vouched_for)
    extracted = extract_cci(dest_dir)
    if extracted is not None:
        written.append(extracted)
    return written


def diff(entries, manifest):
    """What changed on the DISA index since the manifest was written, by name set alone.

    Compares the names entries carries against the names manifest["entries"] carries, and
    never compares dates: DISA bulk re-uploads move most of the index's dates at once, so date
    equality proves nothing about content. DISA encodes the release in the filename, so a
    genuine change always arrives under a new name. size_bytes is a corroborating check for a
    name that survives; the date is only carried for a caller that wants to print it.

    manifest["entries"] is read back exactly as write_manifest wrote it, so its size_bytes is
    what the index advertised when the manifest was written, never on_disk_bytes.
    """
    known = manifest.get("entries", {})
    current = {e.name: e for e in entries}
    return {
        "new": sorted(name for name in current if name not in known),
        "resized": sorted(
            name
            for name, entry in current.items()
            if name in known and known[name].get("size_bytes") != entry.size_bytes
        ),
        "withdrawn": sorted(name for name in known if name not in current),
    }


def _prune_key(name):
    """What another file must match to supersede this one, or None when nothing can.

    A loose benchmark is superseded only by a release of the same product in the same version
    scheme, which is _product_key's rule and not a second copy of it. A compilation is
    superseded only by a compilation of its own kind: the quarterly library and the Rev 4
    sunset archive are both COMPILATION tier and neither replaces the other, so pairing any
    compilation with any other would delete a sunset archive the moment DISA publishes a Rev 5
    one. The two key shapes cannot collide, because a version scheme is only ever "VR" or "YM".

    None for a name carrying no version pattern, and callers must NOT treat that as a key:
    catalog.newest_per_product deliberately keeps every unversioned benchmark, and matching
    None against None would make each of them supersede all the others.

    Anything COMPILATION tier that is not a sunset archive keys as the library, which is the
    DELETING branch (see _supersedes). What makes that safe is selection: it takes exactly one
    compilation of each kind, newest_library's winner and sunset's match, so a third
    COMPILATION-tier name never enters a manifest and never reaches here. newest_library does
    NOT refuse such a name on its own; it raises only when it can read a release from none of
    the candidates.
    """
    from stig_mcp.ingest import catalog  # noqa: PLC0415 (local to avoid a cycle, as in selection)

    if catalog.tier_of(name) == catalog.COMPILATION:
        return "compilation", "sunset" if catalog.SUNSET_RE.search(name) else "library"
    return _product_key(name)


def _supersedes(arriving, name):
    """True when a verified arrival replaces the local file `name`, which is what authorizes
    deleting it. Both names share a _prune_key, so the comparison stays inside one product and
    one version scheme.

    A loose benchmark is replaced only by a LATER release. An index that regresses, DISA pulling
    a release or one bad read of the page, must not cost the newer local copy: the rule prune
    rests on is that a superseded file is strictly worse than the one replacing it, and an older
    arrival is not better at all.

    A LIBRARY compilation is replaced by whichever one the index carries, older or newer. That
    asymmetry is forced rather than an oversight: inventory.classify raises on two artifacts of
    kind "library", so exactly one may exist, and keeping a newer local one would mean deleting
    the copy this very run downloaded and recorded. The index is the authority on which quarter
    that is.

    A SUNSET archive is never replaced at all. classify tolerates two of those and ingests both
    through _from_compilation, so nothing forces a choice, and the sunset archive is the only
    place several retired products exist. Deleting one is therefore a coverage loss buying
    nothing. It cannot be a newest-wins rule either: catalog.library_order reads (0, 0) from
    every sunset name, so there is no ordinal to compare without inventing one.
    """
    from stig_mcp.ingest import catalog  # noqa: PLC0415 (local to avoid a cycle, as in selection)

    if catalog.tier_of(name) == catalog.COMPILATION:
        return catalog.SUNSET_RE.search(name) is None
    return catalog.release_of(arriving)[2] > catalog.release_of(name)[2]


def _dispose(path, name, replacement, drop_withdrawn):
    """Which of prune's three lists `name` belongs to, unlinking the file first when it does.

    replacement is arrived.get(_prune_key(name)), already looked up by the caller.
    """
    if replacement is not None and _supersedes(replacement, name):
        path.unlink()
        return "deleted"
    if drop_withdrawn and name not in NEVER_DROPPED:
        path.unlink()
        return "dropped"
    return "retained"


def prune(dest_dir, entries, manifest, *, drop_withdrawn=False):
    """Remove what a newer release supersedes; keep what DISA withdrew.

    A superseded file is strictly worse than the release replacing it and the ingest would
    discard it anyway. A WITHDRAWN file is the opposite: it is coverage that cannot be
    re-fetched once deleted, and the server already labels what it yields (_provenance_notes
    tells a caller the answer came from a local artifact that is not in the current library
    compilation). So a file is deleted only when a replacement for it arrived and _supersedes
    it, never merely because the index stopped carrying its name. Loose releases and
    compilations answer that question differently, and _supersedes says why.

    Only names the manifest carries are ever considered, which is the whole bound on what this
    can unlink. manual_sources() tells operators to place loose zips in this same directory, so
    a file no run recorded is an expected state and stays untouched.

    entries must hold at most one name per _prune_key, which selection guarantees: two names
    sharing a key would leave only the last of them able to supersede anything.

    manifest is the one read BEFORE the fetch, which is the only record of what a previous run
    put on disk; entries is what the index carries now. Call this only after a fetch that
    completed, because deciding what is superseded from a half-completed one is how a good file
    gets deleted for a replacement that never arrived.

    An arrival authorizes a deletion only if it is on disk at the length the manifest in
    dest_dir records for it, which is the manifest fetch_disa has just written by then. Never
    the index's size_bytes: that column is a rounded display value that matches almost nothing
    (_already_downloaded), so verifying against it would verify nothing and never prune the
    library compilation, and inventory.classify refuses two of those at once. The check is
    independent of the caller's ordering rather than a guard against anything _run_refresh can
    produce: after a fetch_disa that returned, every entry verifies.

    drop_withdrawn additionally deletes what the index no longer carries at all, unless the
    name is in NEVER_DROPPED, for a CI build that must ship only what DISA currently publishes.
    """
    dest_dir = Path(dest_dir)
    stored = read_manifest(dest_dir)["entries"]
    current = {e.name for e in entries}
    arrived = {
        _prune_key(e.name): e.name for e in entries if _already_downloaded(dest_dir / e.name, stored.get(e.name, {}))
    }
    arrived.pop(None, None)  # the ONE place an unversioned name is stopped from superseding another
    buckets = {"deleted": [], "retained": [], "dropped": []}
    for name in manifest.get("entries", {}):
        path = dest_dir / name
        if name in current or not path.is_file():
            continue
        replacement = arrived.get(_prune_key(name))
        buckets[_dispose(path, name, replacement, drop_withdrawn)].append(name)
    return {key: sorted(names) for key, names in buckets.items()}


def main():
    parser = argparse.ArgumentParser(description="Fetch the sources the ingest needs.")
    action = parser.add_mutually_exclusive_group()
    action.add_argument(
        "--check",
        action="store_true",
        help="report what DISA's index, ATT&CK, the CTID mapping and the NIST catalog have that the "
        "last fetch does not, download nothing; exits 10 if updates are available, 3 if nothing is "
        "to take but a source printed as unknown could not be checked, else 0",
    )
    action.add_argument(
        "--refresh",
        action="store_true",
        help="download what --check reports, ATT&CK, the CTID mapping and the NIST catalog first and "
        "then DISA, and delete the DISA files it supersedes, keeping products DISA has withdrawn",
    )
    parser.add_argument("--delay", type=float, default=0.25, help="seconds between DISA downloads")
    parser.add_argument(
        "--drop-withdrawn",
        action="store_true",
        help="with --refresh, also delete recorded DISA files the index no longer carries (kept by "
        "default); for building a release from current publications only",
    )
    args = parser.parse_args()
    if args.drop_withdrawn and not args.refresh:
        parser.error("--drop-withdrawn only applies with --refresh: run stig-mcp-fetch --refresh --drop-withdrawn")
    if args.check:
        raise SystemExit(_run_check(config.SOURCES_DIR))
    if args.refresh:
        _run_refresh(config.SOURCES_DIR, args.delay, drop_withdrawn=args.drop_withdrawn)
        return
    written = fetch_public(config.SOURCES_DIR)
    for path in written:
        print(f"Wrote {path}")
    written = _fetch_disa_or_advise(config.SOURCES_DIR, delay=args.delay)
    for path in written:
        print(f"Wrote {path}")
    print("Now build the knowledge base with stig-mcp-ingest.")


def _fetch_disa_or_advise(dest_dir, **kwargs):
    """fetch_disa, naming the manual fallback when it does not complete.

    Both commands that download need this, so it lives in one place: whatever the automatic
    fetch would have taken is still worth naming, and manual_sources() is that list. Printed
    only on the failure path, since a clean run leaves nothing to do by hand. The exception is
    re-raised, so a caller still refuses to act on a half-completed fetch.
    """
    try:
        return fetch_disa(dest_dir, **kwargs)
    except (RuntimeError, OSError, ValueError):
        print("Automatic DISA fetch failed. Fetch these sources by hand instead:")
        for reminder in manual_sources():
            print(f"  - {reminder}")
        raise


def _product_key(name):
    """(product prefix, version scheme) for a versioned STIG filename, or None if the name
    does not carry a version this way at all.

    Mirrors catalog.newest_per_product's own key rather than matching on product text alone: a
    V/R release and a Y/M release of the same product are not comparable (see
    catalog.release_of's docstring), so a product publishing under both at once (real products
    on the live index do) must never have a V/R withdrawal read as superseded by an unrelated
    Y/M release just because their names share a prefix.

    Reads the scheme off catalog.release_of rather than off the match groups here, so the key
    and the release ordinal _supersedes compares can never disagree about which scheme a name
    is in.
    """
    from stig_mcp.ingest import catalog  # noqa: PLC0415 (local to avoid a cycle, as in selection)

    match, scheme, _release = catalog.release_of(name)
    if match is None:
        return None
    return name[: match.start()], scheme


def _withdrawn_line(name, new_names):
    """The text to print for one withdrawn name: qualified with what replaced it when the
    withdrawal is really just a version bump (the common case a quarterly check hits), bare
    when DISA genuinely dropped the name from the index.

    Display only. The "withdrawn" list names every entry selection does not keep, whatever
    this prints; nothing downstream reads it, and prune deletes on supersession rather than
    on withdrawal.
    """
    key = _product_key(name)
    if key is None:
        return name
    replacement = next((other for other in new_names if _product_key(other) == key), None)
    return name if replacement is None else f"{name} (superseded by {replacement})"


_PUBLIC_LABELS = {"attack": "ATT&CK", "ctid": "CTID mapping", "catalog": "NIST catalog"}


def _catalog_line(label, entry, have):
    if entry["upstream_changed"]:
        return f"  {label}: changed upstream (have {have})"
    if entry["action"] == "refresh":
        return f"  {label}: matches upstream, but no version is recorded; --refresh will record it"
    return f"  {label}: current (have {have})"


def _public_line(name, entry):
    label = _PUBLIC_LABELS[name]
    if entry.get("status") == "unknown":
        return f"  {label}: unknown ({entry['reason']})"
    have = entry.get("downloaded") or "none recorded"
    if name == "catalog":
        return _catalog_line(label, entry, have)
    if entry["action"] == "refresh":
        return f"  {label}: {entry['upstream']} available (have {have})"
    return f"  {label}: current ({have})"


# argparse already exits 2 on a usage error, so "could not check" takes 3.
EXIT_COULD_NOT_CHECK = 3


def _run_check(dest_dir, opener=None):
    """Exit 0 when there is nothing new to download, 10 when there is, and EXIT_COULD_NOT_CHECK
    when nothing is to take but a source could not be reached.

    A pure withdrawal exits 0 too: nothing came in for stig-mcp-fetch to take, even though
    the sources have changed. Only a new or resized entry, something the next fetch would
    actually transfer, exits 10.

    opener mirrors fetch_disa's own injection point, so a test reads the index from a fake
    opener the same way every other test in this module reaches the DISA index: without
    patching urllib.request.urlopen or anything else global. main() calls this with no
    opener, so a real run reads the live index.

    ATT&CK, CTID and the catalog are checked too. A source that cannot be reached, DISA
    included, prints unknown with the whole reason and is named in the closing line. It does
    not mask 10: a script still refreshes what could be checked.
    """
    from stig_mcp.ingest import currency  # noqa: PLC0415 (currency imports fetch)

    report = currency.currency_report(dest_dir, opener=opener)
    disa = report["disa"]
    if disa.get("status") == "unknown":
        print(f"  DISA: unknown ({disa['reason']})")
        disa = {"new": [], "resized": [], "withdrawn": []}
    for label in ("new", "resized"):
        for name in disa[label]:
            print(f"  {label}: {name}")
    for name in disa["withdrawn"]:
        print(f"  withdrawn: {_withdrawn_line(name, disa['new'])}")
    for name in ("attack", "ctid", "catalog"):
        print(_public_line(name, report[name]))
    to_take = any(entry.get("action") == "refresh" for entry in report.values())
    print(_closing_line(report, to_take, disa["withdrawn"]))
    if to_take:
        return 10
    unchecked = any(entry.get("status") == "unknown" for entry in report.values())
    return EXIT_COULD_NOT_CHECK if unchecked else 0


def _closing_line(report, to_take, withdrawn):
    """What the check found, never calling a source current that it could not reach."""
    labels = {"disa": "DISA", **_PUBLIC_LABELS}
    unchecked = [label for name, label in labels.items() if report[name].get("status") == "unknown"]
    if to_take:
        line = "Run stig-mcp-fetch --refresh, then stig-mcp-ingest."
    elif withdrawn:
        line = "Nothing new to download; DISA has withdrawn the name(s) listed above."
    elif unchecked:
        line = "Nothing new to download from the sources that could be checked."
    else:
        line = "All sources are current."
    if unchecked:
        line += f" Could not check: {', '.join(unchecked)} (reason above)."
    return line


def _refresh_public(dest_dir, report, opener):
    """Take each public source the report marks for refresh. Runs before the DISA fetch, whose
    write_manifest carries the public records forward."""
    for name, entry in report.items():
        if entry.get("status") == "unknown":
            print(f"  {_PUBLIC_LABELS[name]}: not refreshed ({entry['reason']})")
    stale = [name for name, entry in report.items() if entry.get("action") == "refresh"]
    take_public(dest_dir, stale, opener=opener)
    return stale


def _run_refresh(dest_dir, delay, opener=None, drop_withdrawn=False):
    """Take what the index has that the last fetch does not, then delete what it supersedes.

    ATT&CK, CTID and the catalog are refreshed first when newer upstream. A source whose CHECK
    fails is named and skipped; a source whose DOWNLOAD fails stops the whole refresh before
    anything is pruned, leaving the previous file in place.

    The manifest is read BEFORE the fetch, because fetch_disa replaces it with one describing
    only what the index carries now, and prune needs the older record to know what a previous
    run left on disk.

    No manifest is written after prune. fetch_disa builds the manifest from the entries it was
    given, so a name prune deletes is one the index no longer carries and is already absent
    from it; and on a fetch_disa that returned, every entry is on disk and vouched for, so a
    second write would re-hash roughly a gigabyte to produce the same file. write_manifest is
    meant to be called once at the end of a run, and this is that call, made by fetch_disa. A
    caller that ever fetches a SUBSET here must revisit this: the manifest would then describe
    the subset alone.

    opener mirrors _run_check's own injection point, so a test drives the whole command
    without patching anything global. main() calls this with no opener. The index read retries
    a transient failure through time.sleep, as fetch_disa's own index read does through sleep.
    """
    from stig_mcp.ingest import catalog, currency  # noqa: PLC0415 (both import fetch, so a cycle at module level)

    taken = _refresh_public(dest_dir, currency.public_report(dest_dir, opener=opener), opener)
    read = functools.partial(catalog.fetch_listing, opener=opener)
    entries = selection(catalog.parse_index(_with_retry(read, "the DISA index", time.sleep)))
    manifest = read_manifest(dest_dir)
    changes = diff(entries, manifest)
    # Nothing is pruned when this raises: a half-completed fetch cannot say what is superseded.
    _fetch_disa_or_advise(dest_dir, opener=opener, delay=delay, entries=entries)
    result = prune(dest_dir, entries, manifest, drop_withdrawn=drop_withdrawn)
    print(f"fetched {len(changes['new']) + len(changes['resized'])} changed artifact(s)")
    print(f"deleted {len(result['deleted'])} superseded file(s)")
    if result["retained"]:
        print(f"{len(result['retained'])} product(s) no longer published; local copies retained")
    if result["dropped"]:
        print(f"dropped {len(result['dropped'])} withdrawn file(s): {', '.join(result['dropped'])}")
    if taken:
        print(f"updated public source(s): {', '.join(_PUBLIC_LABELS[n] for n in taken)}")
    if changes["new"] or changes["resized"] or result["deleted"] or result["dropped"] or taken:
        print("Sources changed. Now run stig-mcp-ingest.")
    else:
        # The commonest run of all, on an index that has not moved since the last one. Sending
        # the operator to rebuild the knowledge base for that would cost an hour for nothing,
        # and a retained withdrawal is not a change to the files the ingest reads.
        print("Sources were already current; nothing to rebuild.")


# Reachable as `python -m`, for the reason given at the end of library.py.
if __name__ == "__main__":
    main()
