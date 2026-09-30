import sqlite3
from contextlib import closing

import pytest

from stig_mcp.kb.db import SCHEMA_VERSION, create_db, open_db, table_names

EXPECTED_TABLES = {
    "techniques",
    "controls",
    "ccis",
    "stigs",
    "stig_rules",
    "actors",
    "technique_control",
    "cci_control",
    "rule_cci",
    "actor_technique",
    "ingest_meta",
    "revoked_technique",
    "source_files",
    "notices",
}


def test_create_db__fresh_path__creates_all_tables(tmp_path):
    with closing(create_db(tmp_path / "kb.sqlite")) as conn:
        assert EXPECTED_TABLES.issubset(table_names(conn))


def test_schema_version__is_defined__nonempty_string():
    assert isinstance(SCHEMA_VERSION, str) and SCHEMA_VERSION


def test_open_db__missing_file__raises_FileNotFoundError(tmp_path):
    with pytest.raises(FileNotFoundError):
        open_db(tmp_path / "nope.sqlite")


def test_open_db__file_is_not_a_database__raises_with_rebuild_guidance(tmp_path):
    # sqlite3.connect() never touches the file, so without an explicit probe this
    # surfaces as a raw DatabaseError at the first tool call instead of at startup.
    bad = tmp_path / "kb.sqlite"
    bad.write_bytes(b"not a database, just bytes")
    with pytest.raises(RuntimeError) as excinfo:
        open_db(bad)
    message = str(excinfo.value)
    assert "stig-mcp-ingest" in message
    assert str(bad) in message


def test_open_db__valid_kb__still_opens(kb_path):
    with closing(open_db(kb_path)) as conn:
        assert conn.execute("SELECT 1").fetchone()[0] == 1


def test_create_db__fresh_path__revoked_technique_requires_a_live_replacement(tmp_path):
    # The foreign key states the invariant the parser already enforces: a stored
    # revocation always points at a technique that exists.
    with closing(create_db(tmp_path / "kb.sqlite")) as conn, pytest.raises(sqlite3.IntegrityError):
        conn.execute("INSERT INTO revoked_technique(revoked_id, replacement_id) VALUES ('T1', 'T-nonexistent')")


def test_create_db__stigs_table__carries_the_provenance_columns(tmp_path):
    assert SCHEMA_VERSION == "6"
    conn = create_db(tmp_path / "kb.sqlite")
    columns = {r[1] for r in conn.execute("PRAGMA table_info(stigs)")}
    assert {
        "origin",
        "source_artifact",
        "source_member",
        "release_label",
        "xccdf_status",
        "xccdf_status_date",
    } <= columns
    conn.close()


def test_create_db__techniques_table__carries_created_and_ctid_status(tmp_path):
    with closing(create_db(tmp_path / "kb.sqlite")) as conn:
        columns = {r[1] for r in conn.execute("PRAGMA table_info(techniques)")}
        assert {"created", "ctid_status"} <= columns
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("INSERT INTO techniques(technique_id, name, ctid_status) VALUES ('T1', 'x', 'maybe')")


def test_create_db__source_files_table__rejects_a_digest_that_is_not_64_characters(tmp_path):
    with closing(create_db(tmp_path / "kb.sqlite")) as conn:
        conn.execute("INSERT INTO source_files(name, sha256, size) VALUES ('a.zip', ?, 1)", ("0" * 64,))
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("INSERT INTO source_files(name, sha256, size) VALUES ('b.zip', 'abc', 1)")


def test_create_db__notices_table__requires_text(tmp_path):
    with closing(create_db(tmp_path / "kb.sqlite")) as conn, pytest.raises(sqlite3.IntegrityError):
        conn.execute("INSERT INTO notices(name, text) VALUES ('LICENSE', NULL)")
