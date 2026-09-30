import sqlite3
import subprocess
import sys
import tomllib
from contextlib import closing
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

import pytest

from stig_mcp.ingest import config
from stig_mcp.kb.db import create_db
from stig_mcp.server import readiness

REPO_ROOT = Path(__file__).parent.parent.parent


def _console_scripts():
    """The real [project.scripts] table, read from pyproject.toml rather than hardcoded.

    A hardcoded list of the two names drifts the same way readiness._SCRIPTS itself could:
    both would go stale together and neither test would notice.
    """
    with (REPO_ROOT / "pyproject.toml").open("rb") as f:
        return tomllib.load(f)["project"]["scripts"]


def test_check__no_file__is_no_knowledge_base(tmp_path):
    assert readiness.check(tmp_path / "absent.sqlite") == "no_knowledge_base"


def test_check__corrupt_file__is_unreadable(tmp_path):
    kb = tmp_path / "kb.sqlite"
    kb.write_bytes(b"not a database, just bytes")
    assert readiness.check(kb) == "unreadable"


def test_check__wrong_schema_version__is_schema_outdated(tmp_path):
    # INSERT, not UPDATE. create_db leaves ingest_meta EMPTY, so an UPDATE hits zero rows
    # and this would pass through the empty-table path instead, unable to tell a real
    # version mismatch from a table that was never populated.
    kb = tmp_path / "kb.sqlite"
    conn = create_db(kb)
    conn.execute("INSERT INTO ingest_meta (schema_version) VALUES ('0')")
    conn.commit()
    conn.close()
    assert readiness.check(kb) == "schema_outdated"


def test_check__an_empty_ingest_meta__is_also_schema_outdated(tmp_path):
    # The other cause of the same verdict, pinned separately so neither test can stand in
    # for the other. A knowledge base whose ingest_meta never got a row is incomplete.
    kb = tmp_path / "kb.sqlite"
    create_db(kb).close()
    assert readiness.check(kb) == "schema_outdated"


def test_check__a_built_knowledge_base__is_ready(kb_path):
    assert readiness.check(kb_path) == "ready"


def test_identity__a_rebuilt_file__differs_from_the_original(tmp_path):
    # This is what lets the server notice a rebuild without a restart. mtime_ns plus size
    # is the same shape resolver._file_identity already uses for the alias cache.
    kb = tmp_path / "kb.sqlite"
    kb.write_bytes(b"one")
    first = readiness.identity(kb)
    kb.write_bytes(b"two different bytes")
    assert readiness.identity(kb) != first


def test_payload__every_named_command__actually_runs(tmp_path, monkeypatch):
    # A payload naming a command that does not exist is worse than no payload, because the
    # agent will follow it. Under a uvx install the console scripts are not on PATH, so the
    # runnable form must go through sys.executable.
    #
    # SOURCES_DIR is monkeypatched because readiness.payload reads it unconditionally: without
    # this the test scans the real sources directory of whoever runs it, which is a
    # machine-dependent read this suite must not make. Same reasoning as tests/server/test_app.py.
    monkeypatch.setattr(config, "SOURCES_DIR", tmp_path)
    body = readiness.payload(tmp_path / "absent.sqlite", "no_knowledge_base")
    assert body["status"] == "not_ready"
    assert body["reason"] == "no_knowledge_base"
    for step in body["next"]:
        # S603: argv is sys.executable plus the module names readiness._MODULES defines
        # in-repo, not external or user input.
        result = subprocess.run(  # noqa: S603
            [*step["run"].split(), "--help"], capture_output=True, text=True, check=False
        )
        assert result.returncode == 0, f"{step['run']}: {result.stderr}"
        assert step["run"].startswith(sys.executable)
        # The PAIRING, not just membership: `x in _console_scripts()` passes with the two
        # values in readiness._SCRIPTS swapped, because both names are in the table either way.
        # The console script and the `-m` module have to name the same entry point.
        script = step["as_installed"].split()[-1]
        assert _console_scripts()[script].split(":")[0] == step["run"].split(" -m ")[1]


def test_payload__a_stale_schema__tells_the_caller_to_rebuild(kb_path, tmp_path, monkeypatch):
    monkeypatch.setattr(config, "SOURCES_DIR", tmp_path)  # as above: never read the real corpus
    body = readiness.payload(kb_path, "schema_outdated")
    assert "rebuild" in " ".join(step["why"] for step in body["next"]).lower()


def test_payload__the_ready_reason__is_refused_rather_than_rendered(kb_path, tmp_path, monkeypatch):
    # payload builds a body whose status is always "not_ready", so READY produces the
    # self-contradictory {"status": "not_ready", "reason": "ready"}. check never hands it
    # over, and refusing it keeps a caller that stops branching on READY from serving that
    # body to an agent as a real answer.
    monkeypatch.setattr(config, "SOURCES_DIR", tmp_path)
    # Not match="ready": that word is in "readiness", "not_ready" and "unreadable", so the
    # pattern would hold with the reason deleted from the message entirely.
    with pytest.raises(ValueError, match=r"reason 'ready'"):
        readiness.payload(kb_path, readiness.READY)


def test_payload__a_reason_check_never_returns__is_refused(kb_path, tmp_path, monkeypatch):
    monkeypatch.setattr(config, "SOURCES_DIR", tmp_path)
    # Not match="no_knowledge_base": the message always lists the valid reasons, so that
    # pattern is satisfied by the enumeration and never by the rejected reason.
    with pytest.raises(ValueError, match=r"reason 'corrupted'"):
        readiness.payload(kb_path, "corrupted")


def test_check__a_valid_sqlite_file_with_no_ingest_meta__is_unreadable(tmp_path):
    # The DatabaseError branch, which the corrupt-file test never reaches: that one fails
    # earlier, inside open_db's own sqlite_master probe, and returns from the branch above.
    # This file opens cleanly and only the ingest_meta read fails, which is the shape a
    # knowledge base built by something other than this ingest would have.
    kb = tmp_path / "not_a_kb.sqlite"
    with closing(sqlite3.connect(kb)) as conn:
        conn.execute("CREATE TABLE unrelated(a TEXT)")
        conn.commit()
    assert readiness.check(kb) == "unreadable"


@pytest.mark.parametrize("reason", ["no_knowledge_base", "schema_outdated", "unreadable"])
def test_payload__every_reason__names_the_install_tool_first(tmp_path, monkeypatch, reason):
    monkeypatch.setattr(config, "SOURCES_DIR", tmp_path)
    monkeypatch.setattr(readiness, "_launch_mode", lambda: "installed")
    first = readiness.payload(tmp_path / "absent.sqlite", reason)["next"][0]
    assert first["tool"] == "install_knowledge_base"
    assert first["as_installed"] == "stig-mcp-install-kb"


def test_payload__no_knowledge_base__keeps_fetch_and_ingest_as_the_fallback(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "SOURCES_DIR", tmp_path)
    monkeypatch.setattr(readiness, "_launch_mode", lambda: "installed")
    steps = readiness.payload(tmp_path / "absent.sqlite", "no_knowledge_base")["next"]
    assert [step["as_installed"] for step in steps] == ["stig-mcp-install-kb", "stig-mcp-fetch", "stig-mcp-ingest"]


def test_payload__schema_outdated__offers_install_then_rebuild(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "SOURCES_DIR", tmp_path)
    monkeypatch.setattr(readiness, "_launch_mode", lambda: "installed")
    steps = readiness.payload(tmp_path / "absent.sqlite", "schema_outdated")["next"]
    assert [step["as_installed"] for step in steps] == ["stig-mcp-install-kb", "stig-mcp-ingest"]


def _package_in(prefix):
    package_dir = prefix / "lib" / "python3.13" / "site-packages" / "stig_mcp"
    package_dir.mkdir(parents=True)
    return package_dir


def test_launch_mode__package_beside_its_pyproject__is_checkout(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "stig-mcp"\n')
    (tmp_path / "stig_mcp").mkdir()
    assert readiness._launch_mode(tmp_path / ".venv", tmp_path / "stig_mcp") == "checkout"


def test_launch_mode__environment_inside_a_tagged_cache__is_uvx(tmp_path):
    # The layout uvx produced on a real run: ~/.cache/uv/archive-v0/<id>, with the tag at ~/.cache/uv.
    cache = tmp_path / "cache" / "uv"
    cache.mkdir(parents=True)
    (cache / "CACHEDIR.TAG").write_text("Signature: 8a477f597d28d172789f06886806bc55\n")
    prefix = cache / "archive-v0" / "w7Sh9G-JXJ2ykMMp"
    assert readiness._launch_mode(prefix, _package_in(prefix)) == "uvx"


def test_launch_mode__environment_outside_any_cache__is_installed(tmp_path):
    prefix = tmp_path / "tools" / "stig-mcp"
    assert readiness._launch_mode(prefix, _package_in(prefix)) == "installed"


@pytest.mark.parametrize(
    ("mode", "expected"),
    [
        ("checkout", "uv run stig-mcp-install-kb"),
        ("uvx", f"uvx --from stig-mcp=={version('stig-mcp')} stig-mcp-install-kb"),
        ("installed", "stig-mcp-install-kb"),
    ],
)
def test_payload__each_launch_mode__names_the_command_a_person_can_run(tmp_path, monkeypatch, mode, expected):
    monkeypatch.setattr(config, "SOURCES_DIR", tmp_path)
    monkeypatch.setattr(readiness, "_launch_mode", lambda: mode)
    first = readiness.payload(tmp_path / "absent.sqlite", "no_knowledge_base")["next"][0]
    assert first["as_installed"] == expected


def test_launch_mode__tag_in_the_environment_itself__is_installed(tmp_path):
    # uv tags every venv it creates at the venv's own root, so a uv tool install carries one.
    prefix = tmp_path / "tools" / "stig-mcp"
    package_dir = _package_in(prefix)
    (prefix / "CACHEDIR.TAG").write_text("Signature: 8a477f597d28d172789f06886806bc55\n")
    assert readiness._launch_mode(prefix, package_dir) == "installed"


def test_launch_mode__checkout_package_in_a_cached_environment__is_checkout(tmp_path):
    # `uv run --isolated` in a checkout: the environment is in the cache, the code is not.
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "stig-mcp"\n')
    (tmp_path / "stig_mcp").mkdir()
    cache = tmp_path / "cache"
    cache.mkdir()
    (cache / "CACHEDIR.TAG").write_text("Signature: 8a477f597d28d172789f06886806bc55\n")
    assert readiness._launch_mode(cache / "archive-v0" / "id", tmp_path / "stig_mcp") == "checkout"


def test_launch_mode__no_arguments__reads_this_checkout():
    assert readiness._launch_mode() == "checkout"


def test_payload__uvx_without_distribution_metadata__falls_back_to_the_script(tmp_path, monkeypatch):
    def missing(name):
        raise PackageNotFoundError(name)

    monkeypatch.setattr(config, "SOURCES_DIR", tmp_path)
    monkeypatch.setattr(readiness, "_launch_mode", lambda: "uvx")
    monkeypatch.setattr(readiness, "version", missing)
    first = readiness.payload(tmp_path / "absent.sqlite", "no_knowledge_base")["next"][0]
    assert first["as_installed"] == "stig-mcp-install-kb"


def test_launch_mode__no_arguments_under_uvx__reads_the_running_environment(tmp_path, monkeypatch):
    cache = tmp_path / "cache" / "uv"
    cache.mkdir(parents=True)
    (cache / "CACHEDIR.TAG").write_text("Signature: 8a477f597d28d172789f06886806bc55\n")
    prefix = cache / "archive-v0" / "w7Sh9G-JXJ2ykMMp"
    monkeypatch.setattr(readiness, "_PACKAGE_DIR", _package_in(prefix))
    monkeypatch.setattr(sys, "prefix", str(prefix))
    assert readiness._launch_mode() == "uvx"
