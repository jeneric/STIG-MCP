import hashlib
import json
import lzma
import os
import shutil
import sqlite3
from contextlib import closing
from datetime import datetime, timedelta

import pytest

from stig_mcp.kb import install, releases
from stig_mcp.kb.db import SCHEMA_VERSION
from stig_mcp.kb.install import InstallError
from tests.kb.fake_github import FakeGitHub, refuse_network


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _variant(tmp_path, kb_path, sql, name="variant.sqlite"):
    """A copy of the fixture knowledge base with one statement applied."""
    copy = tmp_path / name
    shutil.copyfile(kb_path, copy)
    with closing(sqlite3.connect(copy)) as conn:
        conn.executescript(sql)
    return copy


def _xz(tmp_path, data, name="kb.sqlite.xz"):
    path = tmp_path / name
    path.write_bytes(lzma.compress(data))
    return path


def test_install_file__xz_into_a_data_directory_that_does_not_exist__creates_it_and_installs(tmp_path, kb_path):
    data = kb_path.read_bytes()
    source = _xz(tmp_path, data)
    target = tmp_path / "fresh" / "data" / "stig_kb.sqlite"
    result = install.install_file(source, _sha(source.read_bytes()), target)
    assert target.read_bytes() == data
    assert result["installed"] == {
        "release": None,
        "file": source.name,
        "sha256": {"xz": _sha(source.read_bytes()), "sqlite": _sha(data)},
    }
    assert result["schema"] == SCHEMA_VERSION
    assert result["replaced"] == {"sha256": None, "release": None}


def test_install_file__uncompressed_sqlite__installs_it(tmp_path, kb_path):
    target = tmp_path / "data" / "stig_kb.sqlite"
    result = install.install_file(kb_path, _sha(kb_path.read_bytes()), target)
    assert target.read_bytes() == kb_path.read_bytes()
    assert result["installed"]["sha256"] == {"xz": None, "sqlite": _sha(kb_path.read_bytes())}


def test_install_file__sha256_in_upper_case__is_accepted(tmp_path, kb_path):
    target = tmp_path / "data" / "stig_kb.sqlite"
    install.install_file(kb_path, _sha(kb_path.read_bytes()).upper(), target)
    assert target.is_file()


def test_install_file__over_an_existing_kb__reports_what_it_replaced_and_writes_the_record(tmp_path, kb_path):
    target = tmp_path / "data" / "stig_kb.sqlite"
    target.parent.mkdir(parents=True)
    old = _variant(tmp_path, kb_path, "UPDATE ingest_meta SET ingested_at = 'old'")
    shutil.copyfile(old, target)
    result = install.install_file(kb_path, _sha(kb_path.read_bytes()), target)
    assert result["replaced"] == {"sha256": _sha(old.read_bytes()), "release": None}
    record = json.loads(install.record_path(target).read_text())
    assert record["sha256"] == _sha(kb_path.read_bytes())
    assert record["release"] is None
    assert install.read_record(target) == record
    installed_at = datetime.fromisoformat(record["installed_at"])
    assert installed_at.utcoffset() == timedelta(0)


def test_install_file__sha256_not_hex__refuses_naming_the_expected_form(tmp_path, kb_path):
    with pytest.raises(InstallError, match="64 hexadecimal"):
        install.install_file(kb_path, "abc", tmp_path / "data" / "stig_kb.sqlite")


def test_install_file__file_missing__refuses_naming_it(tmp_path):
    with pytest.raises(InstallError, match="nothing.sqlite.xz"):
        install.install_file(tmp_path / "nothing.sqlite.xz", "0" * 64, tmp_path / "data" / "stig_kb.sqlite")


def test_install_file__neither_xz_nor_sqlite__refuses(tmp_path):
    source = tmp_path / "notes.txt"
    source.write_bytes(b"hello")
    with pytest.raises(InstallError, match="neither"):
        install.install_file(source, _sha(b"hello"), tmp_path / "data" / "stig_kb.sqlite")


def test_install_file__candidate_lacks_the_notices_table__refuses(tmp_path, kb_path):
    bad = _variant(tmp_path, kb_path, "DROP TABLE notices")
    with pytest.raises(InstallError, match="notices"):
        install.install_file(bad, _sha(bad.read_bytes()), tmp_path / "data" / "stig_kb.sqlite")


def test_install_file__closes_the_server_connection_before_replacing(tmp_path, kb_path, monkeypatch):
    order = []
    real_replace = install.os.replace

    def replacing(src, dst):
        order.append("replace")
        return real_replace(src, dst)

    monkeypatch.setattr(install.os, "replace", replacing)
    install.install_file(
        kb_path,
        _sha(kb_path.read_bytes()),
        tmp_path / "data" / "stig_kb.sqlite",
        before_replace=lambda: order.append("close"),
    )
    assert order[:2] == ["close", "replace"]


def test_install_file__replace_refused_by_the_os__explains_the_open_file(tmp_path, kb_path, monkeypatch):
    def refused(src, dst):
        raise PermissionError(13, "Access is denied")

    monkeypatch.setattr(install.os, "replace", refused)
    target = tmp_path / "data" / "stig_kb.sqlite"
    target.parent.mkdir(parents=True)
    old = _variant(tmp_path, kb_path, "UPDATE ingest_meta SET ingested_at = 'old'")
    shutil.copyfile(old, target)
    with pytest.raises(InstallError, match="install_knowledge_base"):
        install.install_file(kb_path, _sha(kb_path.read_bytes()), target)
    assert target.read_bytes() == old.read_bytes()
    assert list(target.parent.glob(".stig-mcp-install-*")) == []


def test_decompress__xz_stream_truncated_mid_stream__refuses_naming_it(tmp_path):
    source = tmp_path / "kb.sqlite.xz"
    source.write_bytes(lzma.compress(b"hello world" * 1000)[:-5])
    with pytest.raises(InstallError, match="ends before its xz stream"):
        install._decompress(source, tmp_path / "candidate.sqlite")


def test_decompress__xz_magic_but_corrupt_body__refuses_naming_it(tmp_path):
    source = tmp_path / "kb.sqlite.xz"
    source.write_bytes(install.XZ_MAGIC + b"\x00" * 64)
    with pytest.raises(InstallError, match="not a valid xz file"):
        install._decompress(source, tmp_path / "candidate.sqlite")


def test_decompress__trailing_garbage_after_the_xz_stream__refuses_naming_it(tmp_path):
    source = tmp_path / "kb.sqlite.xz"
    source.write_bytes(lzma.compress(b"hello world" * 1000) + b"GARBAGE")
    with pytest.raises(InstallError, match="holds data after its xz stream"):
        install._decompress(source, tmp_path / "candidate.sqlite")


def test_decompress__second_concatenated_xz_stream__refuses_naming_it(tmp_path):
    source = tmp_path / "kb.sqlite.xz"
    first = lzma.compress(b"hello world" * 1000)
    second = lzma.compress(b"a second, independent xz stream" * 100)
    source.write_bytes(first + second)
    with pytest.raises(InstallError, match="holds data after its xz stream"):
        install._decompress(source, tmp_path / "candidate.sqlite")


def test_install_file__ingest_meta_has_no_row__refuses_naming_no_schema_version(tmp_path, kb_path):
    bad = _variant(tmp_path, kb_path, "DELETE FROM ingest_meta")
    with pytest.raises(InstallError, match="no schema version"):
        install.install_file(bad, _sha(bad.read_bytes()), tmp_path / "data" / "stig_kb.sqlite")


def test_install_file__write_record_fails_after_a_successful_replace__still_reports_the_kb_installed(
    tmp_path, kb_path, monkeypatch
):
    target = tmp_path / "data" / "stig_kb.sqlite"
    target.parent.mkdir(parents=True)

    def failing(kb_path, record):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(install, "_write_record", failing)
    with pytest.raises(InstallError, match="was installed"):
        install.install_file(kb_path, _sha(kb_path.read_bytes()), target)
    assert target.read_bytes() == kb_path.read_bytes()


def test_install_file__existing_record_does_not_match_the_installed_file__does_not_trust_its_release(tmp_path, kb_path):
    target = tmp_path / "data" / "stig_kb.sqlite"
    target.parent.mkdir(parents=True)
    old = _variant(tmp_path, kb_path, "UPDATE ingest_meta SET ingested_at = 'old'")
    shutil.copyfile(old, target)
    install.record_path(target).write_text(
        json.dumps({"release": "kb-2026-01-01", "sha256": _sha(b"not the installed file")})
    )
    result = install.install_file(kb_path, _sha(kb_path.read_bytes()), target)
    assert result["replaced"]["release"] is None


def test_install_file__existing_record_matches_the_installed_file__trusts_its_release(tmp_path, kb_path):
    target = tmp_path / "data" / "stig_kb.sqlite"
    target.parent.mkdir(parents=True)
    old = _variant(tmp_path, kb_path, "UPDATE ingest_meta SET ingested_at = 'old'")
    shutil.copyfile(old, target)
    install.record_path(target).write_text(json.dumps({"release": "kb-2026-01-01", "sha256": _sha(old.read_bytes())}))
    result = install.install_file(kb_path, _sha(kb_path.read_bytes()), target)
    assert result["replaced"]["release"] == "kb-2026-01-01"


def _schema(tmp_path, kb_path, schema):
    sql = f"UPDATE ingest_meta SET schema_version = '{schema}'"  # noqa: S608 (schema is this test's own literal)
    return _variant(tmp_path, kb_path, sql, f"schema{schema}.sqlite")


def test_install_release__newest_compatible__installs_it_and_reports_the_release(tmp_path, kb_path):
    github = FakeGitHub()
    github.publish("kb-2026-10-04", kb_path.read_bytes(), built_with="0.2.0", upstream={"attack": "19.2"})
    target = tmp_path / "data" / "stig_kb.sqlite"
    result = install.install_release(target, opener=github)
    assert target.read_bytes() == kb_path.read_bytes()
    assert result["installed"]["release"] == "kb-2026-10-04"
    assert result["installed"]["sha256"]["sqlite"] == _sha(kb_path.read_bytes())
    assert result["upstream"] == {"attack": "19.2"}
    assert result["built_with"] == "0.2.0"
    assert "newer_schema_available" not in result
    assert install.read_record(target)["release"] == "kb-2026-10-04"


def test_install_release__pinned_to_an_older_tag__rolls_back_to_it(tmp_path, kb_path):
    older = _variant(tmp_path, kb_path, "UPDATE ingest_meta SET ingested_at = 'older'", "older.sqlite").read_bytes()
    github = FakeGitHub()
    github.publish("kb-2026-10-04", older)
    github.publish("kb-2026-10-11", kb_path.read_bytes())
    target = tmp_path / "data" / "stig_kb.sqlite"
    install.install_release(target, opener=github)
    result = install.install_release(target, release="kb-2026-10-04", opener=github)
    assert target.read_bytes() == older
    assert result["replaced"] == {"sha256": _sha(kb_path.read_bytes()), "release": "kb-2026-10-11"}


def test_install_release__a_higher_schema_release_also_exists__reports_it(tmp_path, kb_path):
    github = FakeGitHub()
    github.publish("kb-2026-10-04", kb_path.read_bytes())
    github.publish("kb-2026-10-11", _schema(tmp_path, kb_path, "7").read_bytes(), schema="7", built_with="0.3.0")
    result = install.install_release(tmp_path / "data" / "stig_kb.sqlite", opener=github)
    assert result["installed"]["release"] == "kb-2026-10-04"
    assert result["newer_schema_available"] == {
        "schema": "7",
        "release": "kb-2026-10-11",
        "upgrade_to": "stig-mcp 0.3.0 or later",
    }


def test_install_release__only_a_higher_schema_release__refuses_naming_the_upgrade(tmp_path, kb_path):
    github = FakeGitHub()
    github.publish("kb-2026-10-11", _schema(tmp_path, kb_path, "7").read_bytes(), schema="7", built_with="0.3.0")
    with pytest.raises(InstallError, match=r"stig-mcp 0\.3\.0 or later"):
        install.install_release(tmp_path / "data" / "stig_kb.sqlite", opener=github)


def test_install_release__no_release_at_all__says_to_build_locally(tmp_path):
    with pytest.raises(InstallError, match="stig-mcp-fetch"):
        install.install_release(tmp_path / "data" / "stig_kb.sqlite", opener=FakeGitHub())


def test_install_release__pinned_tag_holds_another_schema__refuses_naming_it(tmp_path, kb_path):
    github = FakeGitHub()
    github.publish("kb-2026-10-11", _schema(tmp_path, kb_path, "7").read_bytes(), schema="7")
    with pytest.raises(InstallError, match=r"kb-2026-10-11"):
        install.install_release(tmp_path / "data" / "stig_kb.sqlite", release="kb-2026-10-11", opener=github)


def test_install_release__pinned_tag_holds_an_older_schema__refuses_naming_it(tmp_path, kb_path):
    github = FakeGitHub()
    github.publish("kb-2026-09-01", _schema(tmp_path, kb_path, "5").read_bytes(), schema="5")
    with pytest.raises(InstallError, match=r"No published release kb-2026-09-01"):
        install.install_release(tmp_path / "data" / "stig_kb.sqlite", release="kb-2026-09-01", opener=github)


def test_install_release__newer_schemas_release_json_is_unreachable__falls_back_to_naming_the_schema(tmp_path, kb_path):
    github = FakeGitHub()
    github.publish("kb-2026-10-11", _schema(tmp_path, kb_path, "7").read_bytes(), schema="7")
    [release] = releases.list_releases(github)
    del github.bodies[release.url(releases.RELEASE_JSON_NAME)]
    with pytest.raises(InstallError, match="a stig-mcp release that reads schema 7"):
        install.install_release(tmp_path / "data" / "stig_kb.sqlite", opener=github)


def test_install_release__sha256sums_omits_both_entries__refuses_naming_the_asset(tmp_path, kb_path):
    github = FakeGitHub()
    github.publish("kb-2026-10-04", kb_path.read_bytes())
    [release] = releases.list_releases(github)
    github.bodies[release.url(releases.SUMS_NAME)] = b"\n"
    with pytest.raises(InstallError, match="does not list"):
        install.install_release(tmp_path / "data" / "stig_kb.sqlite", opener=github)


def test_main__file_and_sha256__installs_and_exits_zero(tmp_path, kb_path, monkeypatch, capsys):
    monkeypatch.setattr(install.config, "KB_PATH", tmp_path / "data" / "stig_kb.sqlite")
    monkeypatch.setattr(releases, "default_opener", lambda: refuse_network)
    code = install.main(["--file", str(kb_path), "--sha256", _sha(kb_path.read_bytes())])
    assert code == 0
    assert json.loads(capsys.readouterr().out)["installed"]["file"] == kb_path.name


def test_main__refused__prints_the_reason_and_exits_one(tmp_path, kb_path, monkeypatch, capsys):
    monkeypatch.setattr(install.config, "KB_PATH", tmp_path / "data" / "stig_kb.sqlite")
    code = install.main(["--file", str(kb_path), "--sha256", "0" * 64])
    assert code == 1
    assert "Re-download" in capsys.readouterr().err


def test_main__release_from_the_network__uses_the_allowlisted_opener(tmp_path, kb_path, monkeypatch, capsys):
    github = FakeGitHub()
    github.publish("kb-2026-10-04", kb_path.read_bytes())
    monkeypatch.setattr(install.config, "KB_PATH", tmp_path / "data" / "stig_kb.sqlite")
    monkeypatch.setattr(releases, "default_opener", lambda: github)
    assert install.main([]) == 0
    assert json.loads(capsys.readouterr().out)["installed"]["release"] == "kb-2026-10-04"


def test_main__file_without_sha256__is_a_usage_error(tmp_path, kb_path, monkeypatch):
    monkeypatch.setattr(install.config, "KB_PATH", tmp_path / "data" / "stig_kb.sqlite")
    with pytest.raises(SystemExit) as exc:
        install.main(["--file", str(kb_path)])
    assert exc.value.code == 2


def test_main__release_and_file_together__is_a_usage_error():
    with pytest.raises(SystemExit) as exc:
        install.main(["--release", "kb-2026-10-04", "--file", "x", "--sha256", "0" * 64])
    assert exc.value.code == 2


def test_install_file__staging_directory_cannot_be_created__refuses_naming_the_path(tmp_path, kb_path):
    blocker = tmp_path / "afile"
    blocker.write_bytes(b"not a directory")
    target = blocker / "data" / "stig_kb.sqlite"
    with pytest.raises(InstallError, match="staging directory"):
        install.install_file(kb_path, _sha(kb_path.read_bytes()), target)


def test_main__staging_directory_cannot_be_created__exits_one(tmp_path, kb_path, monkeypatch):
    blocker = tmp_path / "afile"
    blocker.write_bytes(b"not a directory")
    monkeypatch.setattr(install.config, "KB_PATH", blocker / "data" / "stig_kb.sqlite")
    code = install.main(["--file", str(kb_path), "--sha256", _sha(kb_path.read_bytes())])
    assert code == 1


def test_decompress__dest_cannot_be_opened_for_writing__refuses_naming_the_path(tmp_path):
    source = tmp_path / "kb.sqlite.xz"
    source.write_bytes(lzma.compress(b"hello world" * 1000))
    dest = tmp_path / "adir"
    dest.mkdir()
    with pytest.raises(InstallError, match="Could not decompress"):
        install._decompress(source, dest)


def test_install_file__sqlite_copy_fails__refuses_naming_the_path(tmp_path, kb_path, monkeypatch):
    def failing(src, dst):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(install.shutil, "copyfileobj", failing)
    with pytest.raises(InstallError, match="Could not copy"):
        install.install_file(kb_path, _sha(kb_path.read_bytes()), tmp_path / "data" / "stig_kb.sqlite")


_AS_ROOT = getattr(os, "geteuid", lambda: 1)() == 0


@pytest.mark.skipif(_AS_ROOT, reason="root reads a file whatever its mode")
def test_install_file__source_unreadable__refuses_naming_it_and_the_fix(tmp_path, kb_path):
    source = tmp_path / "kb.sqlite"
    shutil.copyfile(kb_path, source)
    source.chmod(0o200)
    with pytest.raises(InstallError, match=r"Cannot read .*kb\.sqlite .*fix its permissions or pass another file"):
        install.install_file(source, _sha(kb_path.read_bytes()), tmp_path / "data" / "stig_kb.sqlite")


@pytest.mark.skipif(_AS_ROOT, reason="root reads a file whatever its mode")
def test_install_file__installed_kb_unreadable__replaces_it_with_its_sha256_unknown(tmp_path, kb_path):
    target = tmp_path / "data" / "stig_kb.sqlite"
    target.parent.mkdir(parents=True)
    old = _variant(tmp_path, kb_path, "UPDATE ingest_meta SET ingested_at = 'old'")
    shutil.copyfile(old, target)
    install.record_path(target).write_text(json.dumps({"release": "kb-2026-01-01", "sha256": _sha(old.read_bytes())}))
    target.chmod(0o200)
    result = install.install_file(kb_path, _sha(kb_path.read_bytes()), target)
    assert result["replaced"] == {"sha256": None, "release": None}
    assert target.read_bytes() == kb_path.read_bytes()


@pytest.mark.skipif(_AS_ROOT, reason="root reads a file whatever its mode")
def test_main__file_unreadable__prints_the_reason_and_exits_one(tmp_path, kb_path, monkeypatch, capsys):
    monkeypatch.setattr(install.config, "KB_PATH", tmp_path / "data" / "stig_kb.sqlite")
    source = tmp_path / "kb.sqlite"
    shutil.copyfile(kb_path, source)
    source.chmod(0o200)
    code = install.main(["--file", str(source), "--sha256", _sha(kb_path.read_bytes())])
    assert code == 1
    err = capsys.readouterr().err
    assert "Cannot read" in err
    assert "Traceback" not in err


def test_install_file__path_under_the_home_directory_as_a_tilde__expands_it(tmp_path, kb_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    source = _xz(tmp_path, kb_path.read_bytes())
    target = tmp_path / "data" / "stig_kb.sqlite"
    install.install_file(f"~/{source.name}", _sha(source.read_bytes()), target)
    assert target.read_bytes() == kb_path.read_bytes()


def test_read_record__record_is_a_json_list__is_none(tmp_path):
    target = tmp_path / "stig_kb.sqlite"
    install.record_path(target).write_text("[1, 2]", encoding="utf-8")
    assert install.read_record(target) is None


def test_install_file__staging_directory__is_created_beside_the_knowledge_base(tmp_path, kb_path, monkeypatch):
    target = tmp_path / "data" / "stig_kb.sqlite"
    real = install.tempfile.TemporaryDirectory
    parents = []

    def spying(*args, **kwargs):
        parents.append(kwargs.get("dir"))
        return real(*args, **kwargs)

    monkeypatch.setattr(install.tempfile, "TemporaryDirectory", spying)
    install.install_file(kb_path, _sha(kb_path.read_bytes()), target)
    assert parents == [target.parent]


def test_install_file__staged_copy_directory_cannot_be_created__refuses_naming_the_path(tmp_path, kb_path, monkeypatch):
    real_mkdir = install.Path.mkdir

    def failing(self, *args, **kwargs):
        if self.name == "source":
            raise OSError(28, "No space left on device")
        return real_mkdir(self, *args, **kwargs)

    monkeypatch.setattr(install.Path, "mkdir", failing)
    with pytest.raises(InstallError, match="Could not copy"):
        install.install_file(kb_path, _sha(kb_path.read_bytes()), tmp_path / "data" / "stig_kb.sqlite")


def test_install_file__candidate_cannot_be_opened__refuses_instead_of_raising_sqlite3s_error(
    tmp_path, kb_path, monkeypatch
):
    def unopenable(*args, **kwargs):
        raise sqlite3.OperationalError("unable to open database file")

    monkeypatch.setattr(install.sqlite3, "connect", unopenable)
    with pytest.raises(InstallError, match="unable to open database file"):
        install.install_file(kb_path, _sha(kb_path.read_bytes()), tmp_path / "data" / "stig_kb.sqlite")
