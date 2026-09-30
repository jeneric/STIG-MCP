"""The assets of one kb-* release, written from a built knowledge base.

stig_mcp.kb.install and stig_mcp.kb.releases consume every file written here, so the tests feed
these files to them instead of restating the format."""

import json
import lzma
from pathlib import Path, PurePosixPath

from stig_mcp.ingest import fetch
from stig_mcp.kb import freshness, install, queries, releases
from stig_mcp.kb.db import SCHEMA_VERSION, open_db

LATEST_NAME = "LATEST"
# Written by kb_release.build into the same directory once package returns.
NOTES_NAME = "notes.md"
ASSETS_LIST_NAME = "assets.txt"
_CHUNK = 1024 * 1024
_COMPILATION_ORIGINS = ("library", "sunset")
_RESERVED = frozenset({releases.SUMS_NAME, releases.RELEASE_JSON_NAME, LATEST_NAME, NOTES_NAME, ASSETS_LIST_NAME})


class PackageError(RuntimeError):
    """The knowledge base or the arguments cannot make a release. The message says what to change."""


def kb_asset_name(schema, date):
    return f"stig_kb-schema{schema}-{date}.sqlite.xz"


def compress(src, dest):
    """One xz stream and nothing after it: the installer refuses stream padding and a second
    stream, both of which xz(1) can produce."""
    compressor = lzma.LZMACompressor(format=lzma.FORMAT_XZ, preset=6)
    with open(src, "rb") as fin, open(dest, "wb") as fout:
        while chunk := fin.read(_CHUNK):
            fout.write(compressor.compress(chunk))
        fout.write(compressor.flush())


def source_file(row):
    """The DISA zip a benchmark came out of: the inner zip for a compilation member, the loose
    zip otherwise. The same file name the index lists, so the tripwire can compare the two.

    A compilation member's source_member is the archive member's full path (namelist, via
    library.iter_stig_members), not a bare name: DISA nests every inner zip of a library
    compilation under a folder, e.g. "U_SRG-STIG_Library_April_2025/U_MS_Windows_11_V2R8_STIG.zip".
    PurePosixPath, not Path: a zip's namelist is always forward-slash separated, regardless of
    the platform this runs on."""
    column = row["source_member"] if row["origin"] in _COMPILATION_ORIGINS else row["source_artifact"]
    return PurePosixPath(column).name if column else None


def _upstream(conn):
    found = {}
    for name, row in queries.source_versions(conn).items():
        field = freshness._COMPARED.get(name, ("version",))[0]
        if row.get(field):
            found[name] = row[field]
    found["loose_stigs"] = conn.execute("SELECT count(*) FROM stigs WHERE origin = 'product_zip'").fetchone()[0]
    return found


def _benchmarks(conn):
    rows = conn.execute(
        "SELECT stig_id, version, release_label, origin, source_artifact, source_member FROM stigs "
        "ORDER BY stig_id, version"
    ).fetchall()
    return [
        {"stig_id": r["stig_id"], "version": r["version"], "release": r["release_label"], "file": source_file(r)}
        for r in rows
    ]


def _sources(sources_dir):
    """The content digest of every input the fetch recorded. A DISA re-post under the same file
    name, or a public source replaced at the same version, changes only this."""
    manifest = fetch.read_manifest(sources_dir)
    return {
        section: {name: record.get("sha256") for name, record in manifest[section].items()}
        for section in ("entries", "public")
    }


def release_doc(conn, sha, built_with, sources_dir):
    return {
        "schema": SCHEMA_VERSION,
        "built_with": built_with,
        "sha256": {"xz": sha["xz"], "sqlite": sha["sqlite"]},
        "upstream": _upstream(conn),
        "benchmarks": _benchmarks(conn),
        "sources": _sources(sources_dir),
    }


def _write_notices(conn, out_dir, reserved):
    written = {}
    for name, text in conn.execute("SELECT name, text FROM notices ORDER BY name"):
        flat = Path(name).name
        if flat in ("", ".", "..") or flat in written or flat in reserved:
            raise PackageError(
                f"Notice {name!r} cannot be a release asset: its file name {flat!r} is empty or already "
                f"used by {written.get(flat, 'another asset')}. Rename it in pyproject.toml license-files."
            )
        (out_dir / flat).write_text(text, encoding="utf-8")
        written[flat] = name
    return [out_dir / flat for flat in written]


def package(kb_path, out_dir, tag, built_with, sources_dir):
    """The asset paths in upload order. Also writes LATEST for the kb-latest branch."""
    match = releases.TAG_RE.fullmatch(tag)
    if match is None:
        raise PackageError(f"Tag {tag!r} is not kb-YYYY-MM-DD; pass the tag kb_release decide printed.")
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    xz = out_dir / kb_asset_name(SCHEMA_VERSION, match.group(1))
    compress(kb_path, xz)
    sha = {"xz": install.file_sha256(xz), "sqlite": install.file_sha256(kb_path)}
    sums = out_dir / releases.SUMS_NAME
    sums.write_text(f"{sha['xz']}  {xz.name}\n{sha['sqlite']}  {xz.name.removesuffix('.xz')}\n", encoding="utf-8")
    conn = open_db(kb_path)
    try:
        doc = release_doc(conn, sha, built_with, sources_dir)
        notices = _write_notices(conn, out_dir, _RESERVED | {xz.name})
    finally:
        conn.close()
    meta = out_dir / releases.RELEASE_JSON_NAME
    meta.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out_dir / LATEST_NAME).write_text(f"{tag}\nschema {SCHEMA_VERSION}\nsha256 {sha['sqlite']}\n", encoding="utf-8")
    return [xz, sums, meta, *notices]
