"""Install a knowledge base from this project's releases or from a local file.

The order is fixed and every step can refuse: verify the file's SHA-256, decompress under a cap,
check the result is an intact knowledge base for this server's schema, and only then close the
server's connection and replace the file. A refusal at any step leaves the installed knowledge
base exactly as it was, and the staging directory is removed either way."""

import argparse
import contextlib
import hashlib
import json
import lzma
import os
import re
import shutil
import sqlite3
import sys
import tempfile
import urllib.parse
from datetime import UTC, datetime
from pathlib import Path

from stig_mcp.ingest import config
from stig_mcp.kb import releases
from stig_mcp.kb.db import SCHEMA_VERSION

XZ_MAGIC = b"\xfd7zXZ\x00"
SQLITE_MAGIC = b"SQLite format 3\x00"
DECOMPRESSED_CAP = 512 * 1024 * 1024
CHUNK = 1024 * 1024
REQUIRED_TABLES = ("ingest_meta", "notices", "source_files")
_HEX64_RE = re.compile(r"[0-9a-f]{64}", re.ASCII)


class InstallError(RuntimeError):
    """The install was refused; the message says why and what to do. Nothing was replaced."""


class UnverifiedSource(InstallError):
    """A local file was refused before the caller proved it knows the file's content. str() is
    the operator's detail; summary is the one text an MCP caller gets for every such refusal,
    since any difference between them tells a prompt-injected caller whether a path exists, is
    readable, or hashes to a guess."""

    def __init__(self, detail, name, expected):
        super().__init__(detail)
        self.summary = (
            f"Cannot install {name} with SHA-256 {expected}: the file is missing, unreadable, not a "
            f".sqlite.xz or .sqlite knowledge base, or its SHA-256 differs. Check the path, and check "
            f"the value against the release's SHA256SUMS."
        )


def file_sha256(path):
    with open(path, "rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def record_path(kb_path):
    kb_path = Path(kb_path)
    return kb_path.with_name(kb_path.stem + ".release.json")


def read_record(kb_path):
    try:
        record = json.loads(record_path(kb_path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return record if isinstance(record, dict) else None


def _write_record(kb_path, record):
    target = record_path(kb_path)
    temporary = target.with_name(target.name + ".tmp")
    temporary.write_text(json.dumps(record, indent=2), encoding="utf-8")
    os.replace(temporary, target)


@contextlib.contextmanager
def _staging(kb_path):
    """A scratch directory beside the knowledge base, so the final os.replace never crosses a
    filesystem and is atomic."""
    parent = Path(kb_path).parent
    try:
        parent.mkdir(parents=True, exist_ok=True)
        scratch = tempfile.TemporaryDirectory(dir=parent, prefix=".stig-mcp-install-")
    except OSError as exc:
        raise InstallError(
            f"Could not create a staging directory under {parent} ({exc}). Free space or fix "
            f"permissions in the data directory, then try again."
        ) from exc
    with scratch as directory:
        yield Path(directory)


def _kind(path, label=None):
    with open(path, "rb") as handle:
        head = handle.read(len(SQLITE_MAGIC))
    if head.startswith(XZ_MAGIC):
        return "xz"
    if head == SQLITE_MAGIC:
        return "sqlite"
    raise InstallError(
        f"{label or Path(path).name} is neither an xz-compressed knowledge base (.sqlite.xz) nor a SQLite "
        f"database (.sqlite). Pass the .sqlite.xz asset from a kb-* release."
    )


def _decompress(src, dest, cap=None, label=None):
    cap = DECOMPRESSED_CAP if cap is None else cap
    name = label or Path(src).name
    decompressor = lzma.LZMADecompressor(format=lzma.FORMAT_XZ)
    written = 0
    try:
        with open(src, "rb") as fin, open(dest, "wb") as fout:
            while not decompressor.eof:
                chunk = fin.read(CHUNK) if decompressor.needs_input else b""
                if decompressor.needs_input and not chunk:
                    raise InstallError(f"{name} ends before its xz stream does; re-download it.")
                data = decompressor.decompress(chunk, max_length=CHUNK)
                written += len(data)
                if written > cap:
                    raise InstallError(
                        f"{name} decompresses to more than {cap // CHUNK} MB, the cap for a "
                        f"knowledge base, so it was refused and nothing was replaced."
                    )
                fout.write(data)
            if decompressor.unused_data or fin.read(1):
                raise InstallError(f"{name} holds data after its xz stream ends; re-download it.")
    except lzma.LZMAError as exc:
        raise InstallError(f"{name} is not a valid xz file ({exc}); re-download it.") from exc
    except OSError as exc:
        raise InstallError(
            f"Could not decompress {name} to {dest} ({exc}). Free space or fix permissions "
            f"in the data directory, then try again."
        ) from exc


def _check_candidate(path):
    """The candidate's schema version, once it is proven an intact knowledge base."""
    try:
        # Quoted: in a file: URI, # ends the path, ? starts the query and % escapes a byte.
        conn = sqlite3.connect(f"file:{urllib.parse.quote(str(path))}?mode=ro", uri=True)
    except sqlite3.Error as exc:
        raise InstallError(
            f"Could not open the staged knowledge base at {path} ({exc}); nothing was replaced. Fix "
            f"permissions in the data directory, then try again."
        ) from exc
    try:
        integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        missing = [name for name in REQUIRED_TABLES if name not in tables]
        row = None if missing else conn.execute("SELECT schema_version FROM ingest_meta LIMIT 1").fetchone()
    except sqlite3.DatabaseError as exc:
        raise InstallError(f"The download is not an intact SQLite database ({exc}); nothing was replaced.") from exc
    finally:
        conn.close()
    if integrity != "ok":
        raise InstallError(f"The download is not an intact SQLite database (integrity_check: {integrity[:120]}).")
    if missing:
        raise InstallError(
            f"The download lacks the {', '.join(missing)} table(s), so it is not a stig-mcp knowledge base."
        )
    return row[0] if row else None


def _replace(candidate, kb_path, before_replace):
    if before_replace is not None:
        before_replace()
    try:
        os.replace(candidate, kb_path)
    except OSError as exc:
        raise InstallError(
            f"Could not replace {kb_path} ({exc}). On Windows a running stig-mcp server holds it open: "
            f"install through that server's install_knowledge_base tool, or stop the server first."
        ) from exc


def _old_sha256(kb_path):
    """The installed file's SHA-256, or None when there is none or it cannot be read: readiness
    already sends the operator here to replace an unreadable knowledge base."""
    try:
        return file_sha256(kb_path) if kb_path.is_file() else None
    except OSError:
        return None


def _install_candidate(candidate, kb_path, before_replace, record):
    """Check, replace and record; returns what was replaced."""
    schema = _check_candidate(candidate)
    if schema is None:
        raise InstallError(
            "The download records no schema version in its ingest_meta table, so it cannot be "
            "verified as a stig-mcp knowledge base."
        )
    if schema != SCHEMA_VERSION:
        raise InstallError(
            f"The download is a schema {schema} knowledge base; this stig-mcp reads schema {SCHEMA_VERSION}. "
            f"Install a release built for schema {SCHEMA_VERSION}, or upgrade stig-mcp."
        )
    kb_path = Path(kb_path)
    old_sha = _old_sha256(kb_path)
    previous = read_record(kb_path) or {}
    old_release = previous.get("release") if old_sha is not None and previous.get("sha256") == old_sha else None
    _replace(candidate, kb_path, before_replace)
    try:
        _write_record(kb_path, {**record, "installed_at": datetime.now(UTC).isoformat(timespec="seconds")})
    except OSError as exc:
        raise InstallError(
            f"The knowledge base was installed, but its release record at {record_path(kb_path)} could not be "
            f"written ({exc}); check_sources will treat this install as a local build until it is."
        ) from exc
    return {"sha256": old_sha, "release": old_release}


def _expected_sha(sha256):
    expected = sha256.strip().lower() if isinstance(sha256, str) else ""
    if not _HEX64_RE.fullmatch(expected):
        raise InstallError(
            "sha256 must be the 64 hexadecimal characters listed for this file in the release's SHA256SUMS."
        )
    return expected


def _stage_source(path, staging):
    """Copy path into staging, so every later step reads the one copy whose hash is checked
    rather than a file that can change between the check and the install."""
    copy = staging / "source" / "verified"
    try:
        source = open(path, "rb")
    except OSError as exc:
        raise InstallError(
            f"Cannot read {path} ({exc.strerror or exc}): fix its permissions or pass another file."
        ) from exc
    try:
        with source:
            copy.parent.mkdir()
            with open(copy, "wb") as out:
                shutil.copyfileobj(source, out)
    except OSError as exc:
        raise InstallError(
            f"Could not copy {path.name} to {copy} ({exc}). Free space or fix permissions "
            f"in the data directory, then try again."
        ) from exc
    return copy


@contextlib.contextmanager
def _unverified_until_matched(given, expected):
    """Turn every refusal raised inside into UnverifiedSource, including the OSError that
    Path.is_file raises on Python 3.11 to 3.13 and expanduser's RuntimeError for an unknown
    account, which would otherwise reach an MCP caller as a distinguishable generic error."""
    name = Path(given).name
    try:
        yield
    except InstallError as exc:
        raise UnverifiedSource(str(exc), name, expected) from exc
    except (OSError, RuntimeError, ValueError) as exc:
        raise UnverifiedSource(f"Cannot read {given} ({exc}).", name, expected) from exc


def install_file(path, sha256, kb_path, before_replace=None):
    """Install from a local .sqlite.xz or .sqlite; never touches the network."""
    expected = _expected_sha(sha256)
    with _staging(kb_path) as staging:
        with _unverified_until_matched(path, expected):
            path = Path(path).expanduser()
            if not path.is_file():
                raise InstallError(
                    f"{path} does not exist or is not a file. Pass the path of the downloaded .sqlite.xz."
                )
            copy = _stage_source(path, staging)
            actual = file_sha256(copy)
            if actual != expected:
                raise InstallError(
                    f"{path.name} has SHA-256 {actual}, not {expected}. Re-download it, or check the value "
                    f"passed as sha256 against the release's SHA256SUMS."
                )
            kind = _kind(copy, path.name)
        candidate, sha = copy, {"xz": None, "sqlite": actual}
        if kind == "xz":
            candidate = staging / "candidate.sqlite"
            _decompress(copy, candidate, label=path.name)
            sha = {"xz": actual, "sqlite": file_sha256(candidate)}
        record = {"release": None, "sha256": sha["sqlite"], "file": path.name}
        replaced = _install_candidate(candidate, kb_path, before_replace, record)
    return {
        "installed": {"release": None, "file": path.name, "sha256": sha},
        "schema": SCHEMA_VERSION,
        "replaced": replaced,
    }


def newer_schema_payload(release, opener=None):
    """What to tell a caller about a release this stig-mcp cannot read."""
    try:
        upgrade_to = f"stig-mcp {releases.metadata(release, opener)['built_with']} or later"
    except releases.ReleaseError:
        upgrade_to = f"a stig-mcp release that reads schema {release.schema}"
    return {"schema": release.schema, "release": release.tag, "upgrade_to": upgrade_to}


def no_release_message(choice, tag=None, opener=None, newer=None):
    """newer, when given, is a payload the caller already fetched via newer_schema_payload for
    this same choice.newer_schema: reuse it rather than fetching that release's release.json
    a second time."""
    if choice.newer_schema is not None:
        newer = newer if newer is not None else newer_schema_payload(choice.newer_schema, opener)
        return (
            f"Release {newer['release']} holds a schema {newer['schema']} knowledge base; this stig-mcp reads "
            f"schema {SCHEMA_VERSION}. Upgrade to {newer['upgrade_to']}, or build locally with stig-mcp-fetch "
            f"and stig-mcp-ingest."
        )
    if tag is not None:
        return (
            f"No published release {tag} holds a schema {SCHEMA_VERSION} knowledge base. Omit the release "
            f"to install the newest one."
        )
    return (
        f"No published knowledge-base release for schema {SCHEMA_VERSION} yet. Build one locally with "
        f"stig-mcp-fetch and then stig-mcp-ingest."
    )


def _download_verified(target, staging, opener):
    """(candidate path, sha256 block, release.json) for a release, verified against SHA256SUMS."""
    sums = releases.checksums(target, opener)
    meta = releases.metadata(target, opener)
    expected_xz, expected_sqlite = sums.get(target.kb_asset), sums.get(target.sqlite_name)
    if expected_xz is None or expected_sqlite is None:
        raise InstallError(
            f"Release {target.tag}'s SHA256SUMS does not list {target.kb_asset} and {target.sqlite_name}."
        )
    if meta["sha256"] != {"xz": expected_xz, "sqlite": expected_sqlite}:
        raise InstallError(
            f"Release {target.tag}'s release.json and SHA256SUMS disagree on its SHA-256 values; "
            f"the release is inconsistent, so nothing was replaced."
        )
    xz = staging / target.kb_asset
    actual_xz = releases.download_to(target.url(target.kb_asset), xz, opener)
    if actual_xz != expected_xz:
        raise InstallError(
            f"{target.kb_asset} downloaded with SHA-256 {actual_xz}, but SHA256SUMS lists {expected_xz}. "
            f"Nothing was replaced; try again, and report it if it repeats."
        )
    candidate = staging / "candidate.sqlite"
    _decompress(xz, candidate)
    actual_sqlite = file_sha256(candidate)
    if actual_sqlite != expected_sqlite:
        raise InstallError(
            f"{target.kb_asset} decompressed to SHA-256 {actual_sqlite}, but SHA256SUMS lists {expected_sqlite} "
            f"for {target.sqlite_name}. Nothing was replaced; re-download it, and report it if it repeats."
        )
    return candidate, {"xz": actual_xz, "sqlite": actual_sqlite}, meta


def install_release(kb_path, release=None, opener=None, before_replace=None):
    """Install the newest release for this schema, or exactly `release` for a pin or a rollback."""
    choice = releases.choose(releases.list_releases(opener, tag=release), SCHEMA_VERSION, tag=release)
    target = choice.compatible
    if target is None:
        raise InstallError(no_release_message(choice, release, opener))
    with _staging(kb_path) as staging:
        candidate, sha, meta = _download_verified(target, staging, opener)
        record = {
            "release": target.tag,
            "sha256": sha["sqlite"],
            "xz_sha256": sha["xz"],
            **{k: meta[k] for k in ("schema", "built_with", "upstream")},
        }
        replaced = _install_candidate(candidate, kb_path, before_replace, record)
    result = {
        "installed": {"release": target.tag, "file": target.kb_asset, "sha256": sha},
        "schema": SCHEMA_VERSION,
        "built_with": meta["built_with"],
        "upstream": meta["upstream"],
        "replaced": replaced,
    }
    if choice.newer_schema is not None:
        result["newer_schema_available"] = newer_schema_payload(choice.newer_schema, opener)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="stig-mcp-install-kb",
        description=(
            "Install a prebuilt knowledge base. With no arguments, download the newest release for this "
            "stig-mcp from GitHub. On an air-gapped host, copy a release's .sqlite.xz across and pass "
            "--file with the --sha256 SHA256SUMS lists for it."
        ),
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--release", metavar="TAG", help="install this kb-YYYY-MM-DD release (pin or roll back)")
    source.add_argument("--file", metavar="PATH", type=Path, help="install this local .sqlite.xz or .sqlite")
    parser.add_argument("--sha256", metavar="HEX", help="the SHA-256 SHA256SUMS lists for --file")
    args = parser.parse_args(argv)
    if (args.file is None) != (args.sha256 is None):
        parser.error("--file and --sha256 go together: pass the file and the SHA-256 its release lists for it.")
    try:
        if args.file is not None:
            result = install_file(args.file, args.sha256, config.KB_PATH)
        else:
            result = install_release(config.KB_PATH, release=args.release)
    except (InstallError, releases.ReleaseError) as exc:
        print(f"stig-mcp-install-kb: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
