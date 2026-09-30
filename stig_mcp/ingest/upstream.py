"""What the public sources have published, for --check and --refresh.

Every network function takes an injected opener, the same seam fetch_disa and _run_check use,
so a test serves canned responses without patching anything global. Everything read here is
remote input that chooses URLs, so each value is validated before anything acts on it."""

import hashlib
import json
import logging
import re
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

USER_AGENT = "stig-mcp"
TIMEOUT = 10
GITHUB_ACCEPT = "application/vnd.github+json"

ATTACK_INDEX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json"
ATTACK_URL_PREFIX = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
CTID_LISTING_URL = (
    "https://api.github.com/repos/center-for-threat-informed-defense/mappings-explorer/contents/mappings/nist_800_53"
)
CTID_FILE_URL = (
    "https://raw.githubusercontent.com/center-for-threat-informed-defense/mappings-explorer/main/mappings/"
    "nist_800_53/{folder}/nist_800_53-rev5/enterprise/nist_800_53-rev5_{folder}-enterprise.json"
)
CATALOG_LISTING_URL = "https://api.github.com/repos/usnistgov/oscal-content/contents/nist.gov/SP800-53/rev5/json"
CATALOG_FILE_NAME = "NIST_SP-800-53_rev5_catalog-min.json"

# re.ASCII: a bare \d also matches other scripts' digits, which int() converts, so "\u0669\u0669.\u0660"
# would rank as version 99.0 and a remote name could outrank every real release.
_VERSION_RE = re.compile(r"\d+\.\d+", re.ASCII)
_DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}", re.ASCII)
_CTID_FOLDER_RE = re.compile(r"attack-(\d+\.\d+)", re.ASCII)
_BLOB_SHA_RE = re.compile(r"[0-9a-f]{40}")


class UpstreamError(RuntimeError):
    """A public source answered with something this module will not act on."""


@dataclass(frozen=True)
class AttackRelease:
    version: str
    url: str
    release_date: str | None


@dataclass(frozen=True)
class AttackIndex:
    latest: AttackRelease
    release_dates: dict


def version_key(version):
    if not isinstance(version, str) or not _VERSION_RE.fullmatch(version):
        raise UpstreamError(f"{version!r} is not a MAJOR.MINOR version; refusing to compare or record it.")
    major, minor = version.split(".")
    return int(major), int(minor)


def require_url_under(url, prefix):
    parts = urllib.parse.urlsplit(url) if isinstance(url, str) else None
    # Unquoted: a percent-encoded segment such as %2e%2e is still a ".." step once decoded,
    # and unquoting only ever introduces separators, never removes them.
    path = urllib.parse.unquote(parts.path) if parts is not None else ""
    if parts is None or parts.scheme != "https" or not url.startswith(prefix) or ".." in path.split("/"):
        raise UpstreamError(
            f"Refusing {url!r}: expected an https URL under {prefix}. The upstream index named a "
            f"location outside the repository it describes, so nothing was downloaded."
        )


def date_part(value):
    if isinstance(value, str) and _DATE_RE.fullmatch(value[:10]):
        return value[:10]
    return None


def parse_attack_index(doc):
    """Enterprise releases from index.json's parsed body, ordered numerically, never by position."""
    collections = doc.get("collections") if isinstance(doc, dict) else None
    enterprise = next(
        (c for c in collections or [] if isinstance(c, dict) and c.get("name") == "Enterprise ATT&CK"), None
    )
    if enterprise is None:
        raise UpstreamError(f"{ATTACK_INDEX_URL} lists no 'Enterprise ATT&CK' collection; MITRE may have renamed it.")
    releases = [
        AttackRelease(entry["version"], entry.get("url"), date_part(entry.get("modified")))
        for entry in enterprise.get("versions") or []
        if isinstance(entry, dict) and isinstance(entry.get("version"), str) and _VERSION_RE.fullmatch(entry["version"])
    ]
    if not releases:
        raise UpstreamError(f"{ATTACK_INDEX_URL} lists no Enterprise version in MAJOR.MINOR form.")
    latest = max(releases, key=lambda release: version_key(release.version))
    require_url_under(latest.url, ATTACK_URL_PREFIX)
    return AttackIndex(latest, {release.version: release.release_date for release in releases})


def get_json(url, opener=None, accept=None):
    headers = {"User-Agent": USER_AGENT}
    if accept:
        headers["Accept"] = accept
    # S310: every caller passes one of this module's https constants.
    request = urllib.request.Request(url, headers=headers)  # noqa: S310
    open_url = opener or urllib.request.urlopen
    with open_url(request, timeout=TIMEOUT) as response:
        body = response.read()
    try:
        return json.loads(body)
    except ValueError as exc:
        raise UpstreamError(f"{url} did not return JSON ({exc}).") from exc


def attack_latest(opener=None):
    return parse_attack_index(get_json(ATTACK_INDEX_URL, opener))


@dataclass(frozen=True)
class CtidRelease:
    attack_version: str
    folder: str
    url: str


def parse_ctid_listing(listing):
    """The highest attack-X.Y folder in CTID's nist_800_53 directory. A folder name is used in a
    URL, so only an exact attack-MAJOR.MINOR match is ever kept."""
    versions = []
    for entry in listing if isinstance(listing, list) else []:
        name = entry.get("name") if isinstance(entry, dict) else None
        match = _CTID_FOLDER_RE.fullmatch(name) if isinstance(name, str) else None
        if match and entry.get("type") == "dir":
            versions.append(match.group(1))
        elif entry and isinstance(entry, dict) and entry.get("type") == "dir":
            logger.info("Ignoring CTID folder %r: not of the form attack-MAJOR.MINOR.", name)
    if not versions:
        raise UpstreamError(f"{CTID_LISTING_URL} lists no attack-MAJOR.MINOR folder; CTID may have changed its layout.")
    best = max(versions, key=version_key)
    folder = f"attack-{best}"
    return CtidRelease(best, folder, CTID_FILE_URL.format(folder=folder))


def ctid_latest(opener=None):
    return parse_ctid_listing(get_json(CTID_LISTING_URL, opener, accept=GITHUB_ACCEPT))


def parse_catalog_listing(listing):
    entries = listing if isinstance(listing, list) else []
    entry = next(
        (e for e in entries if isinstance(e, dict) and e.get("name") == CATALOG_FILE_NAME and e.get("type") == "file"),
        None,
    )
    if entry is None:
        raise UpstreamError(f"{CATALOG_LISTING_URL} no longer lists {CATALOG_FILE_NAME}; NIST may have moved it.")
    sha = entry.get("sha")
    if not isinstance(sha, str) or not _BLOB_SHA_RE.fullmatch(sha):
        raise UpstreamError(f"{CATALOG_LISTING_URL} gave {sha!r} for {CATALOG_FILE_NAME}, which is not a git blob sha.")
    return sha


def catalog_state(opener=None):
    return parse_catalog_listing(get_json(CATALOG_LISTING_URL, opener, accept=GITHUB_ACCEPT))


def git_blob_sha(path):
    """The sha GitHub's contents API reports for a file, computed locally, so the catalog can be
    compared without downloading it."""
    data = Path(path).read_bytes()
    return hashlib.sha1(b"blob %d\0" % len(data) + data, usedforsecurity=False).hexdigest()
