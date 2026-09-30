import hashlib
import json
import lzma
import shutil
import sqlite3

import pytest

from stig_mcp.ingest import catalog, fetch
from stig_mcp.kb import freshness, install, queries, releases
from stig_mcp.kb.db import SCHEMA_VERSION
from tests.conftest import open_db_for_test
from tests.kb.fake_github import FakeGitHub
from tools import kb_package

TAG = "kb-2026-09-28"


@pytest.fixture
def built(tmp_path, kb_path):
    copy = tmp_path / "build" / "stig_kb.sqlite"
    copy.parent.mkdir()
    shutil.copyfile(kb_path, copy)
    return copy


def _package(built, tmp_path):
    out = tmp_path / "release"
    return out, kb_package.package(built, out, TAG, "0.1.0", tmp_path)


def test_source_file__a_folder_prefixed_library_member__returns_the_bare_name():
    # DISA nests every inner zip of a library compilation under a folder (library.py's
    # iter_stig_members yields the namelist entry unchanged), so source_member is a path,
    # not a bare name: U_SRG-STIG_Library_April_2025.zip alone nests 196 of them this way.
    row = {
        "origin": "library",
        "source_artifact": "U_SRG-STIG_Library_April_2025.zip",
        "source_member": "U_SRG-STIG_Library_April_2025/U_MS_Windows_11_V2R8_STIG.zip",
    }
    assert kb_package.source_file(row) == "U_MS_Windows_11_V2R8_STIG.zip"


def test_source_file__a_library_row_with_no_member_name__is_none():
    row = {"origin": "library", "source_artifact": "U_SRG-STIG_Library_April_2025.zip", "source_member": None}
    assert kb_package.source_file(row) is None


def test_package__a_built_knowledge_base__installs_offline_through_the_real_installer(built, tmp_path):
    out, assets = _package(built, tmp_path)
    xz = out / kb_package.kb_asset_name(SCHEMA_VERSION, "2026-09-28")
    sums = releases.parse_sums((out / releases.SUMS_NAME).read_text())
    target = tmp_path / "installed" / "stig_kb.sqlite"
    target.parent.mkdir()
    result = install.install_file(xz, sums[xz.name], target)
    assert result["installed"]["sha256"] == {"xz": sums[xz.name], "sqlite": sums[xz.name.removesuffix(".xz")]}
    assert target.read_bytes() == built.read_bytes()


def test_package__served_as_a_release__installs_online_and_then_reads_as_current(built, tmp_path):
    out, assets = _package(built, tmp_path)
    github = FakeGitHub()
    github.publish_directory(TAG, out, [path.name for path in assets])
    target = tmp_path / "installed" / "stig_kb.sqlite"
    target.parent.mkdir()
    install.install_release(target, opener=github)
    conn = open_db_for_test(target)
    report = freshness.report(target, install.file_sha256(target), queries.source_versions(conn), opener=github)
    assert report["action"] == "none"


def test_release_doc__upstream__compares_equal_to_the_knowledge_base_it_describes(built):
    # The like-for-like promise: a local build of the same sources must read neither newer nor
    # older than the release. Restating the keys here would drift with them; freshness decides.
    conn = open_db_for_test(built)
    doc = kb_package.release_doc(conn, {"xz": "a" * 64, "sqlite": "b" * 64}, "0.1.0", built.parent)
    meta = queries.source_versions(conn)
    # Measured on the kb_path fixture: attack 15.1 and stig_library U_SRG-STIG_Library_July_2026.zip
    # are the compared sources it records, one per field kind.
    assert {"attack", "stig_library"} <= doc["upstream"].keys()
    assert doc["upstream"]["stig_library"] == "U_SRG-STIG_Library_July_2026.zip"
    assert freshness._upstream_diff(meta, doc["upstream"]) == ([], [])


def test_release_doc__every_field__survives_the_installer_parser(built, tmp_path):
    out, _assets = _package(built, tmp_path)
    doc = json.loads((out / releases.RELEASE_JSON_NAME).read_text())
    release = releases.Release(
        tag=TAG,
        date="2026-09-28",
        schema=SCHEMA_VERSION,
        kb_asset=kb_package.kb_asset_name(SCHEMA_VERSION, "2026-09-28"),
        assets={},
    )
    parsed = releases.parse_release_json(doc, release)
    assert parsed["upstream"] == doc["upstream"], "a value the parser drops would never be compared"
    assert doc["benchmarks"], "the notes diff reads this list"
    assert len((out / releases.RELEASE_JSON_NAME).read_bytes()) < releases.SMALL_CAP


def test_release_doc__sources__records_the_digest_of_every_fetched_input(built, tmp_path):
    sources = tmp_path / "sources"
    sources.mkdir()
    (sources / "U_Foo_V1R1_STIG.zip").write_bytes(b"z")
    fetch.write_manifest(sources, [catalog.Entry(name="U_Foo_V1R1_STIG.zip", href="x", date="d", size_bytes=1)])
    fetch.write_public(sources, "attack", {"version": "19.2", "url": "u", "sha256": "d" * 64, "release_date": None})
    out = tmp_path / "release"
    kb_package.package(built, out, TAG, "0.1.0", sources)
    doc = json.loads((out / releases.RELEASE_JSON_NAME).read_text())
    assert doc["sources"] == {
        "entries": {"U_Foo_V1R1_STIG.zip": hashlib.sha256(b"z").hexdigest()},
        "public": {"attack": "d" * 64},
    }
    release = releases.Release(
        tag=TAG,
        date="2026-09-28",
        schema=SCHEMA_VERSION,
        kb_asset=kb_package.kb_asset_name(SCHEMA_VERSION, "2026-09-28"),
        assets={},
    )
    assert releases.parse_release_json(doc, release)["built_with"] == "0.1.0"


def test_compress__output__is_one_xz_stream_with_nothing_after_it(built, tmp_path):
    dest = tmp_path / "kb.sqlite.xz"
    kb_package.compress(built, dest)
    decompressor = lzma.LZMADecompressor(format=lzma.FORMAT_XZ)
    assert decompressor.decompress(dest.read_bytes()) == built.read_bytes()
    assert decompressor.eof and decompressor.unused_data == b""


def test_package__notices__are_written_flat_from_the_knowledge_base(built, tmp_path):
    out, assets = _package(built, tmp_path)
    conn = sqlite3.connect(built)
    try:
        notices = dict(conn.execute("SELECT name, text FROM notices"))
    finally:
        conn.close()
    assert "licenses/apache-2.0.txt" in notices
    assert (out / "apache-2.0.txt").read_text() == notices["licenses/apache-2.0.txt"]
    assert {path.name for path in assets} >= {"LICENSE", "NOTICE", "apache-2.0.txt"}


def test_package__latest__names_the_tag_schema_and_sqlite_hash(built, tmp_path):
    out, assets = _package(built, tmp_path)
    sums = releases.parse_sums((out / releases.SUMS_NAME).read_text())
    sqlite_name = kb_package.kb_asset_name(SCHEMA_VERSION, "2026-09-28").removesuffix(".xz")
    assert (out / "LATEST").read_text() == f"{TAG}\nschema {SCHEMA_VERSION}\nsha256 {sums[sqlite_name]}\n"
    assert out / "LATEST" not in assets


def test_package__a_tag_that_is_not_kb_date__is_refused_before_writing(built, tmp_path):
    with pytest.raises(kb_package.PackageError, match="kb-YYYY-MM-DD"):
        kb_package.package(built, tmp_path / "release", "v0.1.0", "0.1.0", tmp_path)
    assert not (tmp_path / "release").exists()
