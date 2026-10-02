"""This project's knowledge-base releases on GitHub: the listing, the choice among them, and the
only network access the MCP server performs.

Every name that reaches a URL or a path is matched in full against a pattern first, and every
asset URL must be exactly this repository's download URL for that tag and name, so a listing
cannot point an install anywhere else."""

import hashlib
import http.client
import json
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

from stig_mcp import tls

REPOSITORY = "jeneric/STIG-MCP"
LISTING_URL = f"https://api.github.com/repos/{REPOSITORY}/releases?per_page=100"
TAG_URL = f"https://api.github.com/repos/{REPOSITORY}/releases/tags/{{tag}}"
DOWNLOAD_PREFIX = f"https://github.com/{REPOSITORY}/releases/download/"
SUMS_NAME = "SHA256SUMS"
RELEASE_JSON_NAME = "release.json"

# re.ASCII throughout: a bare \d also matches other scripts' digits, which int() converts.
TAG_RE = re.compile(r"kb-(\d{4}-\d{2}-\d{2})", re.ASCII)
KB_ASSET_RE = re.compile(r"stig_kb-schema(\d{1,4})-(\d{4}-\d{2}-\d{2})\.sqlite\.xz", re.ASCII)
_ASSET_NAME_RE = re.compile(r"SHA256SUMS|release\.json|stig_kb-schema\d{1,4}-\d{4}-\d{2}-\d{2}\.sqlite\.xz", re.ASCII)
_HEX64_RE = re.compile(r"[0-9a-f]{64}", re.ASCII)
_SUMS_LINE_RE = re.compile(r"([0-9a-f]{64}) [ *](\S+)", re.ASCII)
_BUILT_WITH_RE = re.compile(r"[0-9A-Za-z.+!-]{1,40}", re.ASCII)
_UPSTREAM_KEY_LIMIT = 40
_UPSTREAM_VALUE_LIMIT = 100


class ReleaseError(RuntimeError):
    """A release could not be listed, fetched or trusted. The message is written for the caller.
    status carries the HTTP status code when the failure was an HTTP response, else None."""

    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


@dataclass(frozen=True)
class Release:
    tag: str
    date: str
    schema: str
    kb_asset: str
    assets: dict

    @property
    def sqlite_name(self):
        return self.kb_asset.removesuffix(".xz")

    def url(self, name):
        if name not in self.assets:
            raise ReleaseError(
                f"Release {self.tag} has no {name} asset, so it cannot be verified. Choose another "
                f"release, or report it at https://github.com/{REPOSITORY}/issues."
            )
        return self.assets[name]


@dataclass(frozen=True)
class Choice:
    compatible: Release | None
    newer_schema: Release | None


def parse_listing(doc):
    """Published knowledge-base releases. Package releases (v*), drafts, prereleases and releases
    without exactly one knowledge-base asset dated like their tag are skipped. An asset URL that
    is not this repository's download URL for that tag and name refuses the whole listing."""
    if not isinstance(doc, list):
        raise ReleaseError(
            f"{LISTING_URL} did not return a list of releases; GitHub may have changed its API. "
            f"Build the knowledge base locally with stig-mcp-fetch and stig-mcp-ingest."
        )
    return [release for release in map(_release, doc) if release is not None]


def _release(entry):
    if not isinstance(entry, dict) or entry.get("draft") or entry.get("prerelease"):
        return None
    tag = entry.get("tag_name")
    match = TAG_RE.fullmatch(tag) if isinstance(tag, str) else None
    if match is None:
        return None
    assets = _assets(tag, entry.get("assets"))
    dated = [name for name in assets if (m := KB_ASSET_RE.fullmatch(name)) and m.group(2) == match.group(1)]
    if len(dated) != 1:
        return None
    schema = KB_ASSET_RE.fullmatch(dated[0]).group(1)
    return Release(tag=tag, date=match.group(1), schema=schema, kb_asset=dated[0], assets=assets)


def _assets(tag, listed):
    assets = {}
    for asset in listed if isinstance(listed, list) else []:
        name = asset.get("name") if isinstance(asset, dict) else None
        if not isinstance(name, str) or not _ASSET_NAME_RE.fullmatch(name):
            continue
        url = asset.get("browser_download_url")
        if url != f"{DOWNLOAD_PREFIX}{tag}/{name}":
            raise ReleaseError(
                f"Release {tag} lists {name} at {str(url)[:120]!r}, not at {DOWNLOAD_PREFIX}{tag}/{name}. "
                f"stig-mcp downloads only from {REPOSITORY}'s releases, so nothing was installed."
            )
        assets[name] = url
    return assets


def choose(found, schema, tag=None):
    """The newest release for this schema, and the newest one needing a higher schema. With a
    tag, only that release is considered: a pin or a rollback."""
    current = int(schema)
    pool = [release for release in found if tag is None or release.tag == tag]

    def newest(candidates):
        return max(candidates, key=lambda release: release.date, default=None)

    return Choice(
        compatible=newest([r for r in pool if int(r.schema) == current]),
        newer_schema=newest([r for r in pool if int(r.schema) > current]),
    )


def parse_sums(text):
    sums = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        match = _SUMS_LINE_RE.fullmatch(line.strip())
        if match is None:
            raise ReleaseError(
                f"SHA256SUMS holds a line that is not '<sha256>  <file>': {line[:120]!r}. The release "
                f"cannot be verified, so nothing was installed."
            )
        sums[match.group(2)] = match.group(1)
    return sums


def parse_release_json(doc, release):
    """The contract fields of a release's release.json, validated; other fields are dropped."""
    if not _well_formed(doc, release):
        raise ReleaseError(
            f"{release.tag}'s release.json lacks the schema, built_with, sha256 and upstream fields "
            f"this stig-mcp reads, or its schema disagrees with {release.kb_asset}."
        )
    upstream = {
        key: value
        for key, value in doc["upstream"].items()
        if isinstance(key, str)
        and len(key) <= _UPSTREAM_KEY_LIMIT
        and isinstance(value, (str, int))
        and len(str(value)) <= _UPSTREAM_VALUE_LIMIT
    }
    sha = doc["sha256"]
    return {
        "schema": doc["schema"],
        "built_with": doc["built_with"],
        "sha256": {"xz": sha["xz"], "sqlite": sha["sqlite"]},
        "upstream": upstream,
    }


def _well_formed(doc, release):
    if not isinstance(doc, dict) or doc.get("schema") != release.schema:
        return False
    built_with, sha = doc.get("built_with"), doc.get("sha256")
    if not isinstance(built_with, str) or not _BUILT_WITH_RE.fullmatch(built_with):
        return False
    if not isinstance(sha, dict) or not isinstance(doc.get("upstream"), dict):
        return False
    return all(isinstance(sha.get(k), str) and _HEX64_RE.fullmatch(sha[k]) for k in ("xz", "sqlite"))


# github.com/<owner>/<repo>/releases/download/... answers 302 to release-assets.githubusercontent.com;
# objects.githubusercontent.com is GitHub's earlier asset host.
ASSET_REDIRECT_HOSTS = frozenset({"release-assets.githubusercontent.com", "objects.githubusercontent.com"})
USER_AGENT = "stig-mcp"
GITHUB_ACCEPT = "application/vnd.github+json"
TIMEOUT = 30
SMALL_CAP = 4 * 1024 * 1024
KB_DOWNLOAD_CAP = 64 * 1024 * 1024
CHUNK = 1024 * 1024
_QUOTE_LIMIT = 120
_HTTP_NOT_FOUND = 404
_API_PATH = f"/repos/{REPOSITORY}/releases"
_DOWNLOAD_PATH = f"/{REPOSITORY}/releases/download/"
# 10 digits is generous through the year 2286; a longer or non-ASCII-digit value is never a real
# reset time (GitHub sends whole seconds), so it is treated as unknown rather than passed to gmtime.
_RESET_RE = re.compile(r"[0-9]{1,10}", re.ASCII)
OFFLINE = (
    "To install without network access, download the release's .sqlite.xz and SHA256SUMS on another "
    "machine and run stig-mcp-install-kb --file PATH --sha256 HEX, or build locally with "
    "stig-mcp-fetch and stig-mcp-ingest."
)


def _quoted(text):
    text = str(text)
    return text if len(text) <= _QUOTE_LIMIT else text[: _QUOTE_LIMIT - 3] + "..."


def require_allowed(url):
    parts = urllib.parse.urlsplit(url) if isinstance(url, str) else None
    # Unquoted: a percent-encoded %2e%2e or %5c is still a ".." or "\" step once the server decodes it.
    path = urllib.parse.unquote(parts.path) if parts is not None else ""
    allowed = (
        parts is not None
        and parts.scheme == "https"
        and parts.username is None
        and parts.port is None
        and ".." not in path.split("/")
        and "\\" not in path
        and (
            (parts.hostname == "api.github.com" and (path == _API_PATH or path.startswith(_API_PATH + "/")))
            or (parts.hostname == "github.com" and path.startswith(_DOWNLOAD_PATH))
            or parts.hostname in ASSET_REDIRECT_HOSTS
        )
    )
    if not allowed:
        raise ReleaseError(
            f"Refusing {_quoted(url)!r}: stig-mcp contacts only {REPOSITORY}'s GitHub releases, so "
            f"nothing was requested there."
        )


class _AllowlistRedirects(urllib.request.HTTPRedirectHandler):
    # Signature fixed by the base class being overridden, not by choice.
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: PLR0913
        try:
            require_allowed(newurl)
        except ReleaseError:
            if fp is not None:
                fp.close()
            raise
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def default_opener():
    return tls.opener(_AllowlistRedirects)


def _reset_time(reset):
    """The rate-limit reset header as a UTC date and time, or None when it is absent, too long,
    not all ASCII digits, or too large for this platform's gmtime to accept."""
    if not _RESET_RE.fullmatch(reset or ""):
        return None
    try:
        return time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(int(reset)))
    except (ValueError, OverflowError, OSError):
        return None


def explain(exc, url):
    """What went wrong reaching url, for the caller, always ending with the offline route."""
    host = urllib.parse.urlsplit(url).hostname
    if isinstance(exc, urllib.error.HTTPError):
        headers = exc.headers or {}
        if exc.code in (403, 429) and headers.get("X-RateLimit-Remaining") == "0":
            when = _reset_time(headers.get("X-RateLimit-Reset"))
            resets = f"it resets at {when}" if when else "it resets within the hour"
            return (
                f"GitHub's limit of 60 unauthenticated requests per hour from this address is used up; "
                f"{resets}. {OFFLINE}"
            )
        return f"{_quoted(url)} answered HTTP {exc.code}. {OFFLINE}"
    reason = exc.reason if isinstance(exc, urllib.error.URLError) else exc
    if isinstance(reason, ssl.SSLError):
        return (
            f"The TLS connection to {host} failed ({_quoted(reason)}); an inspecting proxy is likely. Set "
            f"HTTPS_PROXY, or add your organization's CA certificate to Python's trust store. {OFFLINE}"
        )
    if isinstance(reason, TimeoutError):
        return f"The connection to {host} timed out. {OFFLINE}"
    return f"Could not reach {host}: {_quoted(reason)}. {OFFLINE}"


def _open(url, opener, accept=None):
    require_allowed(url)
    headers = {"User-Agent": USER_AGENT, **({"Accept": accept} if accept else {})}
    request = urllib.request.Request(url, headers=headers)  # noqa: S310 (require_allowed checked scheme and host)
    try:
        response = (opener or default_opener())(request, timeout=TIMEOUT)
    except (OSError, http.client.HTTPException) as exc:
        message = explain(exc, url)
        if isinstance(exc, urllib.error.HTTPError):
            exc.close()
        raise ReleaseError(message, status=getattr(exc, "code", None)) from exc
    landed = response.geturl()
    try:
        require_allowed(landed)
    except ReleaseError:
        response.close()
        # Unlike require_allowed's own message: the request was made, so it did land somewhere,
        # just not somewhere this project's allowlist covers.
        raise ReleaseError(
            f"The response for {_quoted(url)!r} landed at {_quoted(landed)!r}, outside stig-mcp's "
            f"release allowlist, and was discarded."
        ) from None
    return response


def _cap_text(cap):
    if cap < 1024 * 1024:
        return f"{cap} bytes"
    return f"{cap / (1024 * 1024):.1f} MB"


def _stream(url, opener, cap, sink, accept=None):
    with _open(url, opener, accept) as response:
        total = 0
        while True:
            try:
                chunk = response.read(CHUNK)
            except (OSError, http.client.HTTPException) as exc:
                raise ReleaseError(explain(exc, url), status=getattr(exc, "code", None)) from exc
            if not chunk:
                return
            total += len(chunk)
            if total > cap:
                raise ReleaseError(
                    f"{_quoted(url)} sent more than the {_cap_text(cap)} cap for this file, so the "
                    f"download was stopped."
                )
            sink(chunk)


def fetch_text(url, opener=None):
    parts = []
    _stream(url, opener, SMALL_CAP, parts.append)
    return b"".join(parts).decode("utf-8", errors="replace")


def fetch_json(url, opener=None, accept=None):
    parts = []
    _stream(url, opener, SMALL_CAP, parts.append, accept)
    try:
        return json.loads(b"".join(parts))
    except ValueError as exc:
        raise ReleaseError(f"{_quoted(url)} did not return JSON ({_quoted(exc)}). {OFFLINE}") from exc


def download_to(url, dest, opener=None, cap=KB_DOWNLOAD_CAP):
    """Stream the asset at url into dest, returning its SHA-256 hex digest. On any failure,
    including a cap violation or a local write error, dest is left as a partial file for the
    caller's staging directory to remove; nothing here deletes it."""
    digest = hashlib.sha256()
    with open(dest, "wb") as out:

        def sink(chunk):
            try:
                digest.update(chunk)
                out.write(chunk)
            except OSError as exc:
                raise ReleaseError(
                    f"Could not write {dest}: {exc}. Free space or fix permissions in the data "
                    f"directory, then try again."
                ) from exc

        _stream(url, opener, cap, sink)
    return digest.hexdigest()


def list_releases(opener=None, tag=None):
    if tag is None:
        return parse_listing(fetch_json(LISTING_URL, opener, GITHUB_ACCEPT))
    if not isinstance(tag, str) or not TAG_RE.fullmatch(tag):
        raise ReleaseError(
            f"{_quoted(tag)!r} is not a knowledge-base release tag. Pass one of the form kb-YYYY-MM-DD, "
            f"as check_sources reports it, or omit it for the newest release."
        )
    try:
        doc = fetch_json(TAG_URL.format(tag=tag), opener, GITHUB_ACCEPT)
    except ReleaseError as exc:
        if exc.status == _HTTP_NOT_FOUND:
            raise ReleaseError(
                f"No published release {tag}. Omit the release to install the newest one, or check "
                f"the tag against check_sources."
            ) from exc
        raise
    # Compared before parsing: parse_listing drops a draft, which would hide the mismatch.
    answered = doc.get("tag_name") if isinstance(doc, dict) else None
    if answered is not None and answered != tag:
        raise ReleaseError(
            f"GitHub's release lookup for {tag} answered with {_quoted(answered)!r} instead; refusing "
            f"the mismatch, so nothing was installed."
        )
    return parse_listing([doc])


def metadata(release, opener=None):
    return parse_release_json(fetch_json(release.url(RELEASE_JSON_NAME), opener), release)


def checksums(release, opener=None):
    return parse_sums(fetch_text(release.url(SUMS_NAME), opener))
