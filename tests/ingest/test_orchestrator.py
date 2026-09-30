import hashlib
import io
import json
import logging
import tempfile
import tomllib
import zipfile
from contextlib import closing
from pathlib import Path

import pytest

from stig_mcp import applicability
from stig_mcp.ingest import config, id_corrections
from stig_mcp.ingest import orchestrator as orchestrator_module
from stig_mcp.ingest.inventory import Artifact, DiscoveredBenchmark, collect
from stig_mcp.ingest.orchestrator import (
    IngestSources,
    _check_distinctiveness_margin,
    _release_label,
    build_kb,
    discover_stig_paths,
)
from stig_mcp.ingest.orchestrator import _select as select_benchmarks
from stig_mcp.ingest.stig_parser import ParsedStig, parse_stig
from stig_mcp.kb import queries
from stig_mcp.kb.db import create_db
from tests.conftest import (
    MSSQL_DATABASE_DOCUMENT,
    MSSQL_INSTANCE_DOCUMENT,
    _filler_benchmarks,
    _sources,
    discovered,
    mssql_pair,
    open_db_for_test,
)

FIX = Path(__file__).parent.parent / "fixtures"


def test_build_kb__full_fixture_sources__populates_all_tables(tmp_path):
    out = tmp_path / "kb.sqlite"
    summary = build_kb(_sources(), out)
    assert out.exists()
    assert summary["stigs"] == 1
    assert summary["stig_rules"] == 2
    assert summary["rule_id_collisions"] == 0  # global rule_id uniqueness held
    conn = open_db_for_test(out)
    techniques = {r["technique_id"] for r in conn.execute("SELECT technique_id FROM techniques")}
    assert "T1078" in techniques
    meta = conn.execute("SELECT schema_version FROM ingest_meta LIMIT 1").fetchone()
    assert meta["schema_version"] == "6"
    stig_meta = conn.execute("SELECT * FROM ingest_meta WHERE source_name LIKE 'stig:%'").fetchall()
    assert len(stig_meta) == 1
    assert stig_meta[0]["source_name"].startswith("stig:")


def test_build_kb__subtechnique_before_parent_and_dangling_parent__no_fk_error_and_parent_nulled(tmp_path):
    # attack_unordered.json lists sub-techniques (T1078.001, orphan T2000.001)
    # BEFORE the base T1078, and includes a sub-technique whose parent is absent.
    out = tmp_path / "kb.sqlite"
    build_kb(_sources(attack_path=FIX / "attack_unordered.json"), out)  # must not raise IntegrityError
    conn = open_db_for_test(out)
    parents = {
        r["technique_id"]: r["parent_id"] for r in conn.execute("SELECT technique_id, parent_id FROM techniques")
    }
    assert parents["T1078.001"] == "T1078"  # parent present -> linked
    assert parents["T2000.001"] is None  # parent absent from dataset -> nulled, no dangling FK


def test_discover_stig_paths__case_insensitive_extension__finds_both(tmp_path):
    (tmp_path / "a_STIG_Manual-xccdf.xml").write_text("<x/>")
    (tmp_path / "b_STIG_Manual-xccdf.XML").write_text("<x/>")  # DISA ships some as .XML
    (tmp_path / "readme.txt").write_text("nope")
    result = discover_stig_paths(tmp_path)
    assert [p.name for p in result] == sorted(["a_STIG_Manual-xccdf.xml", "b_STIG_Manual-xccdf.XML"])


def test_build_kb__same_benchmark_different_majors__keeps_both(tmp_path):
    # RHEL_9_STIG shipped as major 1 and major 2 (like vSphere V1 + V2, which are
    # pinned to different product release trains). BOTH must be kept, each carrying
    # its own rules under its own stig_version.
    out = tmp_path / "kb.sqlite"
    summary = build_kb(
        _sources(benchmarks=[discovered(FIX / "rhel9_xccdf.xml"), discovered(FIX / "rhel9_v2_xccdf.xml")]), out
    )
    assert summary["stig_files"] == 2
    assert summary["stigs"] == 2  # both majors kept as distinct (stig_id, version) rows
    conn = open_db_for_test(out)
    versions = {r["version"] for r in conn.execute("SELECT version FROM stigs WHERE stig_id='RHEL_9_STIG'")}
    assert versions == {"1", "2"}
    by_rule = {
        r["rule_id"]: r["stig_version"]
        for r in conn.execute("SELECT rule_id, stig_version FROM stig_rules WHERE stig_id='RHEL_9_STIG'")
    }
    assert by_rule.get("SV-100001r1_rule") == "1"  # v1 rule, labeled v1
    assert by_rule.get("SV-200001r1_rule") == "2"  # v2 rule, labeled v2


def test_build_kb__same_benchmark_same_major_two_releases__keeps_newest_release(tmp_path):
    # Two releases within major 1 (R1 and R2) collapse to one row, newest release wins;
    # rules are NOT unioned across releases of the same major.
    out = tmp_path / "kb.sqlite"
    summary = build_kb(
        _sources(benchmarks=[discovered(FIX / "rhel9_xccdf.xml"), discovered(FIX / "rhel9_v1r2_xccdf.xml")]), out
    )
    assert summary["stig_files"] == 2
    assert summary["stigs"] == 1  # one (RHEL_9_STIG, "1") row
    conn = open_db_for_test(out)
    row = conn.execute("SELECT version, release_info FROM stigs WHERE stig_id='RHEL_9_STIG'").fetchone()
    assert row["version"] == "1"
    assert "Release: 2" in row["release_info"]
    rule_ids = {r["rule_id"] for r in conn.execute("SELECT rule_id FROM stig_rules WHERE stig_id='RHEL_9_STIG'")}
    assert "SV-100009r1_rule" in rule_ids  # R2 rule kept
    assert "SV-100001r1_rule" not in rule_ids  # R1 rules not unioned in


def test_findings_for_control__benchmark_with_two_majors__returns_both_versions_labeled(tmp_path):
    out = tmp_path / "kb.sqlite"
    build_kb(_sources(benchmarks=[discovered(FIX / "rhel9_xccdf.xml"), discovered(FIX / "rhel9_v2_xccdf.xml")]), out)
    conn = open_db_for_test(out)
    # Both versions' rules map to AC-2(1) via CCI-000015; both must surface, labeled.
    findings = queries.findings_for_control(conn, "AC-2(1)", [("RHEL_9_STIG", "1"), ("RHEL_9_STIG", "2")])
    assert {f["stig_version"] for f in findings} == {"1", "2"}
    assert all(f["stig_id"] == "RHEL_9_STIG" for f in findings)
    # exactly one finding per version (no cartesian duplication from the join)
    assert len(findings) == 2
    assert len({f["rule_id"] for f in findings}) == 2


def test_build_kb__all_stig_files_malformed__raises_rather_than_empty_kb(tmp_path):
    sources = _sources(benchmarks=[discovered(FIX / "broken-xccdf.xml")])
    with pytest.raises(RuntimeError, match="parsed successfully"):
        build_kb(sources, tmp_path / "kb.sqlite")


def test_build_kb__malformed_stig_file__skips_and_still_builds(tmp_path, caplog):
    out = tmp_path / "kb.sqlite"
    sources = _sources(benchmarks=[discovered(FIX / "broken-xccdf.xml"), discovered(FIX / "rhel9_xccdf.xml")])
    with caplog.at_level(logging.WARNING):
        summary = build_kb(sources, out)
    assert summary["stigs"] == 1
    conn = open_db_for_test(out)
    ids = {r["stig_id"] for r in conn.execute("SELECT stig_id FROM stigs")}
    assert "RHEL_9_STIG" in ids
    assert any("broken-xccdf.xml" in rec.message for rec in caplog.records)


def test_build_kb__with_catalog__populates_control_name_family_parent(tmp_path):
    out = tmp_path / "kb.sqlite"
    build_kb(_sources(catalog_path=FIX / "oscal_catalog.json"), out)
    conn = open_db_for_test(out)
    ac2 = conn.execute(
        "SELECT name, family, is_enhancement, parent_control_id FROM controls WHERE control_id='AC-2'"
    ).fetchone()
    assert ac2["name"] == "Account Management" and ac2["family"] == "Access Control"
    assert ac2["is_enhancement"] == 0 and ac2["parent_control_id"] is None
    ac2_1 = conn.execute("SELECT is_enhancement, parent_control_id FROM controls WHERE control_id='AC-2(1)'").fetchone()
    assert ac2_1["is_enhancement"] == 1 and ac2_1["parent_control_id"] == "AC-2"


def test_build_kb__without_catalog__control_name_family_null(tmp_path):
    # No catalog -> id-only control rows, and the build still succeeds.
    out = tmp_path / "kb.sqlite"
    build_kb(_sources(catalog_path=None), out)
    conn = open_db_for_test(out)
    ac2 = conn.execute("SELECT name, family FROM controls WHERE control_id='AC-2'").fetchone()
    assert ac2["name"] is None and ac2["family"] is None


def test_build_kb__catalog_path_set_but_missing__warns_and_falls_back(tmp_path, caplog):
    out = tmp_path / "kb.sqlite"
    with caplog.at_level(logging.WARNING):
        build_kb(_sources(catalog_path=tmp_path / "nope.json"), out)  # must not raise
    conn = open_db_for_test(out)
    assert conn.execute("SELECT name FROM controls WHERE control_id='AC-2'").fetchone()["name"] is None
    assert any("catalog not found" in rec.message.lower() for rec in caplog.records)


def test_build_kb__missing_required_source__raises_with_named_artifact(tmp_path):
    sources = _sources(cci_path=tmp_path / "absent_cci.xml")
    with pytest.raises(FileNotFoundError, match="absent_cci.xml"):
        build_kb(sources, tmp_path / "kb.sqlite")


def test_build_kb__missing_required_source__error_names_the_real_sources_dir_and_the_operations_guide(tmp_path):
    # The section the message cites, 'Build the knowledge base', is in docs/operations.md;
    # README.md has no such heading.
    sources = _sources(cci_path=tmp_path / "absent_cci.xml")
    with pytest.raises(FileNotFoundError) as excinfo:
        build_kb(sources, tmp_path / "kb.sqlite")
    message = str(excinfo.value)
    assert str(config.SOURCES_DIR) in message  # not a hand-written "data/sources/"
    assert "docs/operations.md" in message
    assert "README.md" not in message


def test_build_kb__empty_stig_paths__raises_with_sources_dir_and_pattern(tmp_path):
    sources = _sources(benchmarks=[])
    with pytest.raises(FileNotFoundError, match=r"\*xccdf\.xml"):
        build_kb(sources, tmp_path / "kb.sqlite")


def test_build_kb__ctid_and_override_rows__carry_their_own_source_version(tmp_path):
    # The fixture ATT&CK bundle is 15.1 while the CTID fixture targets 16.1, so
    # stamping every row with the ATT&CK version would be provably wrong provenance.
    out = tmp_path / "kb.sqlite"
    build_kb(_sources(ctid_path=FIX / "ctid_mappings.json"), out)
    conn = open_db_for_test(out)
    versions = {
        (r["source"], r["source_version"]) for r in conn.execute("SELECT source, source_version FROM technique_control")
    }
    assert ("ctid", "attack-16.1/rev5@04/16/2025") in versions
    assert ("override", "local") in versions
    assert not any(version == "15.1" for _, version in versions)


def test_build_kb__ctid_source__ingest_meta_records_the_mapping_version(tmp_path):
    out = tmp_path / "kb.sqlite"
    build_kb(_sources(ctid_path=FIX / "ctid_mappings.json"), out)
    conn = open_db_for_test(out)
    row = conn.execute("SELECT source_version FROM ingest_meta WHERE source_name='ctid'").fetchone()
    assert row["source_version"] == "attack-16.1/rev5@04/16/2025"


def test_build_kb__override_names_an_unknown_technique__warns_with_the_pair(tmp_path, caplog):
    # An override orphan is a typo in a file the operator controls, so the warning has
    # to name the exact pair. Aggregating it would leave them nothing to grep for.
    overrides = tmp_path / "overrides.yaml"
    overrides.write_text("add:\n  - technique: T9999\n    control: AC-6\n")
    out = tmp_path / "kb.sqlite"
    with caplog.at_level(logging.WARNING):
        summary = build_kb(_sources(overrides_path=overrides), out)
    assert summary["orphan_override_pairs"] == 1
    # caplog's handler formats each record, so rec.message is already interpolated and
    # rec.message % rec.args would raise TypeError. getMessage() is safe either way.
    message = " ".join(rec.getMessage() for rec in caplog.records)
    assert "T9999" in message and "AC-6" in message and "overrides.yaml" in message


def test_build_kb__ctid_maps_a_technique_absent_from_attack__warns_once_about_staleness(tmp_path, caplog):
    # Real data drops 174 pairs across 16 technique ids, every one revoked upstream, so
    # this must be one aggregate staleness warning rather than one line per pair.
    ctid = tmp_path / "ctid.csv"
    ctid.write_text("technique_id,control_id\nT1078,AC-2\nT9999,AC-2\nT9999,AC-3\nT8888,AC-3\n")
    out = tmp_path / "kb.sqlite"
    with caplog.at_level(logging.WARNING):
        summary = build_kb(_sources(ctid_path=ctid), out)
    assert summary["orphan_ctid_pairs"] == 3  # two ids, three pairs
    stale = [rec for rec in caplog.records if "CTID" in rec.getMessage()]
    assert len(stale) == 1  # aggregated, not one per pair
    text = stale[0].getMessage()
    assert "T8888" in text and "T9999" in text
    assert "Dropped 3 CTID mapping(s)" in text  # pins the pair count, not just a bare "3"
    assert "15.1" in text  # the ATT&CK version they are stale against


def test_build_kb__no_orphans__logs_no_staleness_warning(tmp_path, caplog):
    out = tmp_path / "kb.sqlite"
    with caplog.at_level(logging.WARNING):
        summary = build_kb(_sources(), out)
    assert summary["orphan_ctid_pairs"] == 0
    assert summary["orphan_override_pairs"] == 0
    assert not any("CTID" in rec.getMessage() for rec in caplog.records)


def test_build_kb__mid_build_failure__leaves_no_temp_and_does_not_touch_the_existing_kb(tmp_path, monkeypatch):
    # Three things make the swap atomic, and all three need pinning: the error reaches
    # the caller, no staging file survives, and an already-built KB is untouched.
    out = tmp_path / "kb.sqlite"
    build_kb(_sources(), out)
    before = out.read_bytes()

    def boom(*args, **kwargs):
        raise RuntimeError("ETL exploded")

    monkeypatch.setattr("stig_mcp.ingest.orchestrator._insert_stigs", boom)
    with pytest.raises(RuntimeError, match="ETL exploded"):
        build_kb(_sources(), out)

    assert list(tmp_path.glob("*.building")) == []
    assert out.read_bytes() == before


def test_build_kb__create_db_fails__propagates_original_error_and_leaves_no_temp(tmp_path, monkeypatch):
    # A create_db failure must not leave a *.building file on disk, and with create_db inside
    # the try block, conn may be unbound when the finally block's close() runs, which must
    # not become a NameError masking the real failure. Pin both: the original error surfaces,
    # and no staging file survives.
    def boom(path, *args, **kwargs):
        # sqlite3.connect() creates the file before executescript() runs, so a real
        # create_db failure really does leave a staging file behind; the fake must
        # mirror that ordering for the "no temp survives" assertion to mean anything.
        Path(path).touch()
        raise RuntimeError("db creation exploded")

    monkeypatch.setattr("stig_mcp.ingest.orchestrator.create_db", boom)
    with pytest.raises(RuntimeError, match="db creation exploded"):
        build_kb(_sources(), tmp_path / "kb.sqlite")

    assert list(tmp_path.glob("*.building")) == []


def test_build_kb__all_stig_files_malformed__leaves_no_temp(tmp_path):
    # The all-files-failed guard raises from inside the build, the same path as any
    # other mid-build error, so it must clean up the same way.
    with pytest.raises(RuntimeError, match="parsed successfully"):
        build_kb(_sources(benchmarks=[discovered(FIX / "broken-xccdf.xml")]), tmp_path / "kb.sqlite")
    assert list(tmp_path.glob("*.building")) == []


def test_build_kb__revoked_techniques__are_recorded_with_their_replacements(tmp_path):
    out = tmp_path / "kb.sqlite"
    summary = build_kb(_sources(), out)
    assert summary["revocations"] == 3  # T8001, T8002 and T8003 all resolve to T9000
    conn = open_db_for_test(out)
    rows = {
        r["revoked_id"]: (r["replacement_id"], r["revoked_name"])
        for r in conn.execute("SELECT revoked_id, replacement_id, revoked_name FROM revoked_technique")
    }
    assert rows["T8001"] == ("T9000", "Old One Hop")
    assert rows["T8002"][0] == "T9000"  # chain followed to the live technique
    assert "T8004" not in rows  # cycle dropped
    assert "T8006" not in rows  # replacement is not a live technique


def test_build_kb__revoked_technique_rows__carry_the_attack_version(tmp_path):
    # The revocation is a fact from the ATT&CK bundle, so it is stamped with the
    # bundle's version, matching how every other source records provenance.
    out = tmp_path / "kb.sqlite"
    build_kb(_sources(), out)
    conn = open_db_for_test(out)
    versions = {r["source_version"] for r in conn.execute("SELECT source_version FROM revoked_technique")}
    assert versions == {"15.1"}


def test_build_kb__rule_with_unrecognized_severity__counts_it_in_the_summary(tmp_path):
    odd = tmp_path / "odd-xccdf.xml"
    odd.write_text(
        '<Benchmark id="ODD_STIG"><title>Odd</title><version>1</version>'
        '<Group id="V-1"><Rule id="SV-9001r1_rule" severity="critical">'
        "<title>Odd rule</title><description>d</description><fixtext>f</fixtext>"
        "<check><check-content>c</check-content></check>"
        "</Rule></Group></Benchmark>"
    )
    summary = build_kb(
        _sources(benchmarks=[discovered(FIX / "rhel9_xccdf.xml"), discovered(odd)]), tmp_path / "kb.sqlite"
    )
    assert summary["unknown_severity"] == 1
    assert summary["stig_rules"] == 3  # the odd rule is ingested, not dropped


def test_build_kb__ctid_pair_on_a_revoked_technique__lands_on_the_replacement(tmp_path):
    out = tmp_path / "kb.sqlite"
    summary = build_kb(_sources(), out)
    conn = open_db_for_test(out)
    pairs = {
        (r["technique_id"], r["control_id"]): r["source_version"]
        for r in conn.execute("SELECT technique_id, control_id, source_version FROM technique_control")
    }
    assert ("T9000", "AC-3") not in pairs  # suppressed via the remapped tombstone
    assert ("T9000", "AC-7") in pairs  # the CTID pair moved here from T8001
    assert ("T9000", "AC-5") in pairs  # the override pair moved here from T8001
    assert summary["remapped_ctid_pairs"] == 1  # AC-7 survived; the two AC-3 pairs were suppressed first
    assert not any(technique.startswith("T8") for technique, _ in pairs)


def test_build_kb__remapped_pair__records_the_hop_in_its_source_version(tmp_path):
    out = tmp_path / "kb.sqlite"
    build_kb(_sources(), out)
    conn = open_db_for_test(out)
    row = conn.execute(
        "SELECT source_version FROM technique_control WHERE technique_id='T9000' AND control_id='AC-5'"
    ).fetchone()
    assert row["source_version"].endswith(" via T8001")


def test_build_kb__native_pair_and_remapped_pair_collide__native_wins(tmp_path):
    # T9000,AC-4 is stated directly by the mapping set while a remapped pair would only
    # inherit it, so the row must record the native provenance with no "via" hop.
    ctid = tmp_path / "ctid.csv"
    ctid.write_text("technique_id,control_id\nT9000,AC-4\nT8001,AC-4\n")
    out = tmp_path / "kb.sqlite"
    build_kb(_sources(ctid_path=ctid), out)
    conn = open_db_for_test(out)
    rows = conn.execute(
        "SELECT source_version FROM technique_control WHERE technique_id='T9000' AND control_id='AC-4'"
    ).fetchall()
    assert len(rows) == 1
    assert "via" not in rows[0]["source_version"]


def test_build_kb__suppression_written_against_a_revoked_id__still_kills_the_pair(tmp_path):
    # Without remapping the suppression key, the tombstone stops matching the moment the
    # pair moves, and a mapping the operator deliberately killed comes back silently.
    out = tmp_path / "kb.sqlite"
    build_kb(_sources(), out)
    conn = open_db_for_test(out)
    found = conn.execute("SELECT 1 FROM technique_control WHERE technique_id='T9000' AND control_id='AC-3'").fetchone()
    assert found is None


def test_build_kb__override_names_a_revoked_technique__remaps_it_and_says_to_fix_the_file(tmp_path, caplog):
    out = tmp_path / "kb.sqlite"
    with caplog.at_level(logging.WARNING):
        summary = build_kb(_sources(), out)
    assert summary["remapped_override_pairs"] == 1
    message = " ".join(rec.getMessage() for rec in caplog.records)
    assert "T8001" in message and "T9000" in message and "overrides.yaml" in message


def test_build_kb__no_revoked_ids_in_the_mappings__counts_no_remaps(tmp_path):
    ctid = tmp_path / "ctid.csv"
    ctid.write_text("technique_id,control_id\nT1078,AC-2\n")
    overrides = tmp_path / "overrides.yaml"
    overrides.write_text("add: []\nsuppress: []\n")
    summary = build_kb(_sources(ctid_path=ctid, overrides_path=overrides), tmp_path / "kb.sqlite")
    assert summary["remapped_ctid_pairs"] == 0
    assert summary["remapped_override_pairs"] == 0


def test_build_kb__overrides_add_and_suppress_the_same_pair__the_add_survives(tmp_path):
    # overrides.yaml documents suppress: as removing CTID pairs (tombstones), so an
    # operator's own add: entry must survive their own suppress: entry on the same pair.
    overrides = tmp_path / "overrides.yaml"
    overrides.write_text(
        "add:\n  - technique: T1078\n    control: AC-9\nsuppress:\n  - technique: T1078\n    control: AC-9\n"
    )
    out = tmp_path / "kb.sqlite"
    build_kb(_sources(overrides_path=overrides), out)
    conn = open_db_for_test(out)
    found = conn.execute("SELECT 1 FROM technique_control WHERE technique_id='T1078' AND control_id='AC-9'").fetchone()
    assert found is not None


def test_build_kb__remapped_tombstone__does_not_kill_the_operators_own_add(tmp_path):
    # A tombstone against a retired id remaps onto the replacement, but it must still only
    # kill the CTID pair there, not an override add: entry the operator wrote on purpose.
    ctid = tmp_path / "ctid.csv"
    ctid.write_text("technique_id,control_id\nT8001,AC-9\n")
    overrides = tmp_path / "overrides.yaml"
    overrides.write_text(
        "add:\n  - technique: T9000\n    control: AC-9\nsuppress:\n  - technique: T8001\n    control: AC-9\n"
    )
    out = tmp_path / "kb.sqlite"
    build_kb(_sources(ctid_path=ctid, overrides_path=overrides), out)
    conn = open_db_for_test(out)
    sources = {
        r["source"]
        for r in conn.execute("SELECT source FROM technique_control WHERE technique_id='T9000' AND control_id='AC-9'")
    }
    assert sources == {"override"}  # the remapped CTID pair was killed; the operator's add survives


def test_build_kb__two_revoked_ids_remap_onto_the_same_pair__collapses_deterministically(tmp_path):
    # Two retired ids remapping onto the same live pair must collapse to one row, and
    # which retired id's hop is recorded must not depend on file or set iteration order.
    ctid = tmp_path / "ctid.csv"
    ctid.write_text("technique_id,control_id\nT8002,AC-9\nT8001,AC-9\n")
    out = tmp_path / "kb.sqlite"
    build_kb(_sources(ctid_path=ctid), out)
    conn = open_db_for_test(out)
    rows = conn.execute(
        "SELECT source_version FROM technique_control WHERE technique_id='T9000' AND control_id='AC-9'"
    ).fetchall()
    assert len(rows) == 1
    assert rows[0]["source_version"].endswith(" via T8001")  # T8001 sorts before T8002


def test_build_kb__rule_governs_a_major_it_does_not_map__warns_and_counts_it(tmp_path, monkeypatch, caplog):
    # RHEL_9_STIG lands at majors 1 and 2 here; the rule maps only major 1, so major 2 is
    # governed but never scoped by build. That is the signal that the rule is stale.
    rules = tmp_path / "rules.yaml"
    rules.write_text(
        "TEST_RHEL:\n"
        "  id_pattern: '^RHEL_9_STIG$'\n"
        "  build_pattern: '\\b(?:u(?P<n>\\d+)[a-z]?|ga)\\b'\n"
        "  source: 'test fixture'\n"
        "  verified_against: 'test fixture'\n"
        "  thresholds:\n"
        "    - min: 0\n"
        '      version: "1"\n'
    )
    monkeypatch.setattr(applicability, "RULES_PATH", rules)
    out = tmp_path / "kb.sqlite"
    with caplog.at_level(logging.WARNING):
        summary = build_kb(
            _sources(benchmarks=[discovered(FIX / "rhel9_xccdf.xml"), discovered(FIX / "rhel9_v2_xccdf.xml")]), out
        )
    assert summary["applicability_unmapped_rows"] == 1
    assert any("major '2'" in rec.message and "no threshold maps" in rec.message for rec in caplog.records)


def test_build_kb__rule_matches_no_benchmark__warns_that_the_pattern_is_stale(tmp_path, monkeypatch, caplog):
    rules = tmp_path / "rules.yaml"
    rules.write_text(
        "TEST_NOTHING:\n"
        "  id_pattern: '^NO_SUCH_BENCHMARK'\n"
        "  build_pattern: '\\b(?:u(?P<n>\\d+)[a-z]?|ga)\\b'\n"
        "  source: 'test fixture'\n"
        "  verified_against: 'test fixture'\n"
        "  thresholds:\n"
        "    - min: 0\n"
        "      version: null\n"
    )
    monkeypatch.setattr(applicability, "RULES_PATH", rules)
    out = tmp_path / "kb.sqlite"
    with caplog.at_level(logging.WARNING):
        summary = build_kb(_sources(benchmarks=[discovered(FIX / "rhel9_xccdf.xml")]), out)
    assert summary["applicability_unmapped_rows"] == 0
    assert any("governs no benchmark" in rec.message for rec in caplog.records)


def test_build_kb__shipped_rule_against_the_fixture_kb__does_not_block_the_build(tmp_path):
    # The shipped vSphere rule governs nothing in a RHEL fixture KB. That warns, and the
    # build must still succeed: a stale rule degrades to unfiltered behavior, which is safe.
    out = tmp_path / "kb.sqlite"
    summary = build_kb(_sources(benchmarks=[discovered(FIX / "rhel9_xccdf.xml")]), out)
    assert summary["stigs"] == 1
    assert summary["applicability_unmapped_rows"] == 0


def test_build_kb__malformed_applicability_rule_file__aborts_naming_the_file(tmp_path, monkeypatch):
    # Unlike a stale rule, a rule file that will not parse at all is a hard failure by
    # design: silently ignoring it would be indistinguishable from having no rules at all.
    # It must also fail before any of the expensive parsing runs, not after.
    rules = tmp_path / "rules.yaml"
    rules.write_text(
        "BROKEN:\n"
        "  id_pattern: '['\n"
        "  build_pattern: '\\b(?:u(?P<n>\\d+)[a-z]?|ga)\\b'\n"
        "  thresholds:\n"
        "    - min: 0\n"
        '      version: "1"\n'
    )
    monkeypatch.setattr(applicability, "RULES_PATH", rules)

    def _unexpected_parse(*args, **kwargs):
        raise AssertionError("parse_cci_list ran before the applicability rule file was validated")

    monkeypatch.setattr(orchestrator_module, "parse_cci_list", _unexpected_parse)

    out = tmp_path / "kb.sqlite"
    with pytest.raises(ValueError) as excinfo:
        build_kb(_sources(), out)
    message = str(excinfo.value)
    assert "BROKEN" in message
    assert "invalid id_pattern" in message
    assert str(rules) in message


def test_build_kb__a_library_compilation_was_used__records_it_in_ingest_meta(tmp_path, minimal_sources):
    sources = minimal_sources
    sources.benchmarks[0] = discovered(
        sources.benchmarks[0].path, origin="library", source_artifact="U_SRG-STIG_Library_July_2026.zip"
    )
    build_kb(sources, tmp_path / "kb.sqlite")
    conn = open_db_for_test(tmp_path / "kb.sqlite")
    row = conn.execute("SELECT artifact_url_or_file FROM ingest_meta WHERE source_name='stig_library'").fetchone()
    assert row["artifact_url_or_file"] == "U_SRG-STIG_Library_July_2026.zip"


def test_build_kb__cci_attack_and_ctid_sources__record_bare_filenames_not_absolute_paths(tmp_path, minimal_sources):
    # cci_path/attack_path/ctid_path are absolute Paths (minimal_sources builds them from
    # FIX, an absolute fixtures directory). Storing str(path) in ingest_meta would leak the
    # operator's home directory and username into a response an LLM surfaces to a user.
    # stig_library uses a bare filename (inventory.py stamps origin from artifact.path.name);
    # every source_name here must follow that same convention.
    build_kb(minimal_sources, tmp_path / "kb.sqlite")
    conn = open_db_for_test(tmp_path / "kb.sqlite")
    rows = {
        r["source_name"]: r["artifact_url_or_file"]
        for r in conn.execute(
            "SELECT source_name, artifact_url_or_file FROM ingest_meta WHERE source_name IN ('cci', 'attack', 'ctid')"
        ).fetchall()
    }
    assert rows == {
        "cci": minimal_sources.cci_path.name,
        "attack": minimal_sources.attack_path.name,
        "ctid": minimal_sources.ctid_path.name,
    }
    assert not any(str(minimal_sources.cci_path.parent) in value for value in rows.values())


def test_build_kb__library_artifact_yielded_no_benchmarks__still_records_it(tmp_path, minimal_sources):
    # A truncated or partial library compilation classifies correctly but contributes
    # zero rows to sources.benchmarks. Deriving the stig_library meta row solely from
    # benchmark origins would make that compilation invisible: no meta row, no
    # sources.stig_library key, and a currency note falsely claiming no library was used.
    sources = minimal_sources
    sources.benchmarks = [discovered(b.path, origin="loose", source_artifact=b.path.name) for b in sources.benchmarks]
    sources.library_artifact = "U_SRG-STIG_Library_July_2026.zip"
    build_kb(sources, tmp_path / "kb.sqlite")
    conn = open_db_for_test(tmp_path / "kb.sqlite")
    row = conn.execute("SELECT artifact_url_or_file FROM ingest_meta WHERE source_name='stig_library'").fetchone()
    assert row is not None
    assert row["artifact_url_or_file"] == "U_SRG-STIG_Library_July_2026.zip"


def test_build_kb__no_library_compilation__writes_no_stig_library_row(tmp_path, minimal_sources):
    # Absence from the library is only a fact when a library was present. Without this
    # row the tools decline to claim a benchmark is not current rather than asserting it.
    sources = minimal_sources
    sources.benchmarks = [discovered(b.path, origin="loose", source_artifact=b.path.name) for b in sources.benchmarks]
    build_kb(sources, tmp_path / "kb.sqlite")
    conn = open_db_for_test(tmp_path / "kb.sqlite")
    assert conn.execute("SELECT 1 FROM ingest_meta WHERE source_name='stig_library'").fetchone() is None


def test_release_label__version_and_release_present__composes_the_disa_token(tmp_path):
    parsed = ParsedStig(
        stig_id="Windows_Server_2019_STIG",
        title="t",
        benchmark_id="b",
        version="3",
        release_info="Release: 9 Benchmark Date: 01 Jul 2026",
    )
    assert _release_label(parsed) == "V3R9"


def test_release_label__unparseable_release__falls_back_to_release_info_and_warns(caplog):
    parsed = ParsedStig(stig_id="Odd_STIG", title="t", benchmark_id="b", version="1", release_info="undated draft")
    with caplog.at_level("WARNING"):
        assert _release_label(parsed) == "undated draft"
    assert "Odd_STIG" in caplog.text


def _entry(stig_id, version, origin, release=1, artifact="a.zip"):
    parsed = ParsedStig(
        stig_id=stig_id,
        title=stig_id,
        benchmark_id=stig_id,
        version=version,
        release_info=f"Release: {release} Benchmark Date: 01 Jul 2026",
    )
    discovered = DiscoveredBenchmark(
        path=Path(tempfile.gettempdir()) / f"{stig_id}.xml", origin=origin, source_artifact=artifact, source_member=None
    )
    return (stig_id, version), (parsed, discovered)


def _select(entries, library_keys=frozenset()):
    summary = {"superseded_by_library": 0, "superseded_by_newer_major": 0}
    kept = select_benchmarks(dict(entries), summary, library_keys=library_keys)
    return sorted(kept), summary


def test_select__library_ships_the_id_at_a_higher_major__drops_the_archive_copy():
    # 89 of the sunset archive's 110 benchmarks are in this shape on real data.
    kept, summary = _select([_entry("SLES_15_STIG", "2", "library"), _entry("SLES_15_STIG", "1", "sunset")])
    assert kept == [("SLES_15_STIG", "2")]
    assert summary["superseded_by_library"] == 1


def test_select__the_two_ids_differ_only_in_case__are_one_benchmark():
    # A real case: the July 2026 library ships Solaris_11_X86_STIG at major 3 and the Rev 4
    # sunset compilation ships Solaris_11_x86_STIG at major 2. Compared literally they are
    # unrelated products, so the retired major survives beside the current one and every
    # id-keyed structure, including a tier note listing both, treats them as two.
    kept, summary = _select(
        [_entry("Solaris_11_X86_STIG", "3", "library"), _entry("Solaris_11_x86_STIG", "2", "sunset")]
    )
    assert kept == [("Solaris_11_X86_STIG", "3")]
    assert summary["superseded_by_library"] == 1


def test_id_key__two_genuinely_different_ids__do_not_fold_together():
    # The fold's other half, and the one _select's own tests cannot see: an over-folding
    # `_id_key` only ever DROPS more. Returning a constant, an initial, or the id with its
    # separators stripped would each discard real benchmarks silently.
    assert orchestrator_module._id_key("Solaris_11_X86_STIG") == orchestrator_module._id_key("Solaris_11_x86_STIG")
    for other in ("Solaris_11_SPARC_STIG", "Solaris_10_X86_STIG", "SolarWinds_X86_STIG", "S"):
        assert orchestrator_module._id_key("Solaris_11_X86_STIG") != orchestrator_module._id_key(other)
    # Case is the ONLY thing it folds: separators and length are identity-bearing.
    assert orchestrator_module._id_key("A_B_STIG") != orchestrator_module._id_key("AB_STIG")


def test_select__a_cased_id_absent_from_the_library__still_falls_to_the_local_major_branch():
    # The branch a partial fold breaks with a KeyError rather than a wrong answer: with no
    # library row at all, local_max is what both spellings have to agree on.
    kept, summary = _select(
        [_entry("Vectrix_Relay_STIG", "2", "sunset"), _entry("VECTRIX_RELAY_STIG", "1", "product_zip")]
    )
    assert kept == [("Vectrix_Relay_STIG", "2")]
    assert summary["superseded_by_newer_major"] == 1


def test_select__a_dropped_row__is_told_which_benchmark_beat_it(caplog):
    # After case folding the winner can be spelled differently from the loser, so "the current
    # library already ships this benchmark" would leave an operator nothing to search for.
    # product_zip origin because _drop names only hand-placed files individually; bulk-archive
    # losers stay aggregated.
    with caplog.at_level(logging.WARNING):
        _select([_entry("Solaris_11_X86_STIG", "3", "library"), _entry("Solaris_11_x86_STIG", "2", "product_zip")])
    assert any("Solaris_11_X86_STIG major 3" in record.message for record in caplog.records)


def test_select__a_benchmark_declaring_a_negative_major__does_not_abort_the_build():
    # _major returns int() of the XCCDF's own <version> text, so a document declaring a
    # negative major never beats the -1 sentinel. Tracking the winner on the major alone would
    # leave it unset while the max was set, and the drop path would raise KeyError out of
    # _select, aborting after every file had been parsed. docs/operations.md promises no abort.
    kept, _summary = _select([_entry("NEG_STIG", "-1", "sunset"), _entry("neg_stig", "-2", "product_zip")])
    assert kept == [("NEG_STIG", "-1")]
    # A lone row below the sentinel is the case that separates this guard from a bare `>=`,
    # which handles the pair above and still raises here. The row is then dropped against a
    # major nothing supplied, which the -1 sentinel has always done and which no DISA document
    # can reach; the abort is what mattered.
    assert _select([_entry("ONLY_STIG", "-5", "product_zip")])[0] == []


@pytest.mark.parametrize("max_first", [True, False])
def test_select__two_library_spellings__names_the_higher_major_as_the_winner(caplog, max_first):
    # Pins WHICH spelling the message names, not merely that one appears. BOTH orders, because
    # one order alone is passed by a winner that simply records the last row it saw: with the
    # max-major row listed second, "record everything" and "record the maximum" agree.
    library = [_entry("Alpha_STIG", "1", "library"), _entry("ALPHA_STIG", "5", "library")]
    if max_first:
        library.reverse()
    with caplog.at_level(logging.WARNING):
        _select([*library, _entry("alpha_stig", "2", "product_zip")])
    assert any("ALPHA_STIG major 5" in record.message for record in caplog.records)


def test_select__the_surviving_row__keeps_its_own_spelling_rather_than_the_folded_one():
    # _id_key folds for COMPARISON only. The stored spelling is the surviving document's own,
    # because stig_rules' foreign key is written against it.
    kept, _summary = _select(
        [_entry("Solaris_11_X86_STIG", "3", "library"), _entry("Solaris_11_x86_STIG", "2", "sunset")]
    )
    assert kept[0][0] == "Solaris_11_X86_STIG"


def test_newest_benchmarks__library_and_product_zip_share_a_release__library_wins_regardless_of_order(caplog):
    # U_CAN_Ubuntu_22-04_LTS_V2R9_STIG.zip duplicates what the library already ships, and
    # it sorts ahead of a library zip named e.g. U_SRG-STIG_Library_July_2026.zip, so
    # classify would walk it first. Library must still win: same-key, same-release
    # arbitration lives in _newest_benchmarks, not in file-processing order.
    summary = _skip_summary()
    benchmarks = [
        discovered(FIX / "rhel9_xccdf.xml", origin="product_zip", source_artifact="U_CAN_Ubuntu.zip"),
        discovered(FIX / "rhel9_xccdf.xml", origin="library"),
    ]
    with caplog.at_level("WARNING"):
        newest = orchestrator_module._newest_benchmarks(benchmarks, summary)
    assert {key: d.origin for key, (_, d) in newest.items()} == {("RHEL_9_STIG", "1"): "library"}
    assert summary["superseded_by_library"] == 1
    # A file the operator placed by hand is named, not folded into an aggregate count.
    assert "U_CAN_Ubuntu.zip" in caplog.text


def test_newest_benchmarks__library_processed_first__product_zip_at_the_same_release_still_loses(caplog):
    # Same contest as above with the artifacts in the opposite order, so the library is
    # the incumbent and the product_zip is the later challenger that must still lose.
    # Together the two tests prove the outcome does not depend on which one classify
    # walks first, only on origin.
    summary = _skip_summary()
    benchmarks = [
        discovered(FIX / "rhel9_xccdf.xml", origin="library"),
        discovered(FIX / "rhel9_xccdf.xml", origin="product_zip", source_artifact="U_CAN_Ubuntu.zip"),
    ]
    with caplog.at_level("WARNING"):
        newest = orchestrator_module._newest_benchmarks(benchmarks, summary)
    assert {key: d.origin for key, (_, d) in newest.items()} == {("RHEL_9_STIG", "1"): "library"}
    # superseded_by_library keeps its exact meaning: docs/operations.md and the quarterly
    # refresh checklist both cite it, and it answers a question superseded_same_key does not.
    assert summary["superseded_by_library"] == 1
    assert summary["superseded_same_key"] == 0
    assert "U_CAN_Ubuntu.zip" in caplog.text


def test_newest_benchmarks__product_zip_newer_release_beats_library__wins_and_is_counted_once():
    # A genuinely newer release must win on its own merits regardless of origin: an
    # origin-first comparison would break this, keeping the stale library copy instead.
    # The library copy's departure is the commonest corpus shape there is, and since the
    # winner is not library-origin, superseded_same_key is what records it.
    summary = _skip_summary()
    benchmarks = [
        discovered(FIX / "rhel9_xccdf.xml", origin="library"),  # V1R1
        discovered(FIX / "rhel9_v1r2_xccdf.xml", origin="product_zip", source_artifact="U_RHEL_9_V1R2.zip"),  # V1R2
    ]
    newest = orchestrator_module._newest_benchmarks(benchmarks, summary)
    parsed, disc = newest[("RHEL_9_STIG", "1")]
    assert disc.origin == "product_zip"
    assert "Release: 2" in parsed.release_info
    assert summary["superseded_same_key"] == 1
    assert summary["superseded_by_library"] == 0
    assert summary["superseded_by_newer_major"] == 0


def test_newest_benchmarks__every_departure__is_counted_by_exactly_one_counter():
    # The property the corpus harness reconciles against: parsed minus dropped equals stored.
    # A departure counted twice breaks it as surely as one counted zero times.
    summary = _skip_summary()
    benchmarks = [
        discovered(FIX / "citrix_v1r3_2020_xccdf.xml", origin="product_zip", source_artifact="U_A.zip"),
        discovered(FIX / "citrix_v1r3_2025_xccdf.xml", origin="product_zip", source_artifact="U_B.zip"),
        discovered(FIX / "rhel9_xccdf.xml", origin="library"),
        discovered(FIX / "rhel9_xccdf.xml", origin="sunset", source_artifact="U_Sunset.zip"),
    ]
    kept = orchestrator_module._newest_benchmarks(benchmarks, summary)
    departures = summary["superseded_by_library"] + summary["superseded_same_key"]
    assert len(benchmarks) - departures == len(kept)
    # One departure took each branch, so this also pins the axis against the bins: the corpus
    # harness compares same_key_departures against its own replay of this contest, and it
    # cannot use the bins' sum because _select writes superseded_by_library too.
    assert summary["superseded_by_library"] == 1
    assert summary["superseded_same_key"] == 1
    assert summary["same_key_departures"] == departures


def test_newest_benchmarks__an_uncorrectable_redirect__reconciles_like_every_other_departure():
    # tools/corpus_conformance.py asserts stig_files - (superseded_by_library +
    # superseded_same_key + superseded_by_newer_major) == stored, and raises if it does not. A
    # discard that skips _drop breaks that invariant as surely as a departure counted twice
    # does. Reachability is nil today, but it goes live the moment a loose copy's path matches
    # no correction fragment, which is exactly the case id_corrections.yaml exists to serve.
    summary = _skip_summary()
    foreign = discovered(
        FIX / "mssql2012_instance_xccdf.xml",
        origin="library",
        source_artifact="U_Zebra.zip",
        source_document="U_Foreign_Copy/x-xccdf.xml",
    )
    benchmarks = [foreign, *mssql_pair()]

    kept = orchestrator_module._newest_benchmarks(benchmarks, summary)

    dropped = summary["superseded_by_library"] + summary["superseded_same_key"] + summary["superseded_by_newer_major"]
    assert summary["stig_files"] - dropped == len(kept)
    assert summary["same_key_departures"] == dropped


def test_newest_benchmarks__the_major_level_contest_also_drops_benchmarks__the_axis_ignores_it():
    # Why same_key_departures exists at all. _select drops a benchmark the library covers at a
    # higher major into superseded_by_library, the same counter this contest writes, and on a
    # real build that is most of it. Only a number this contest alone increments can tell the
    # harness how many benchmarks departed HERE.
    summary = _skip_summary()
    benchmarks = [
        discovered(FIX / "rhel9_xccdf.xml", origin="library"),
        discovered(FIX / "rhel9_xccdf.xml", origin="sunset", source_artifact="U_Sunset.zip"),
    ]
    orchestrator_module._newest_benchmarks(benchmarks, summary)
    assert summary["same_key_departures"] == 1
    assert summary["superseded_by_library"] == 1
    select_benchmarks(dict([_entry("SLES_15_STIG", "2", "library"), _entry("SLES_15_STIG", "1", "sunset")]), summary)
    assert summary["superseded_by_library"] == 2
    assert summary["same_key_departures"] == 1


def test_contest__two_non_library_copies_at_the_same_release__the_later_status_date_wins():
    # The real case: DISA republished Citrix XenDesktop V1R3 in 2025 with renumbered rule ids,
    # an extra rule and a deprecated status. Picking the 2020 copy discards the lifecycle data
    # that the xccdf_status column exists to carry.
    old = orchestrator_module._contest(
        parse_stig(FIX / "citrix_v1r3_2020_xccdf.xml"),
        discovered(FIX / "citrix_v1r3_2020_xccdf.xml", origin="product_zip", source_artifact="U_Citrix_Y20M04.zip"),
    )
    new = orchestrator_module._contest(
        parse_stig(FIX / "citrix_v1r3_2025_xccdf.xml"),
        discovered(FIX / "citrix_v1r3_2025_xccdf.xml", origin="product_zip", source_artifact="U_Citrix_Y25M07.zip"),
    )
    assert new > old


def test_newest_benchmarks__same_key_same_release_differing_dates__the_later_wins_in_either_order():
    # The determinism property itself: both orderings must select the same document.
    old = discovered(FIX / "citrix_v1r3_2020_xccdf.xml", origin="product_zip", source_artifact="U_Citrix_Y20M04.zip")
    new = discovered(FIX / "citrix_v1r3_2025_xccdf.xml", origin="product_zip", source_artifact="U_Citrix_Y25M07.zip")
    forward = orchestrator_module._newest_benchmarks([old, new], _skip_summary())
    reversed_ = orchestrator_module._newest_benchmarks([new, old], _skip_summary())
    key = ("Citrix_XenDesktop_License_Server_STIG", "1")
    assert forward[key][1].source_artifact == "U_Citrix_Y25M07.zip"
    assert reversed_[key][1].source_artifact == "U_Citrix_Y25M07.zip"
    # Not just provenance: the winner must carry the 2025 content.
    assert forward[key][0].status == "deprecated"
    assert len(forward[key][0].rules) == 2


def test_newest_benchmarks__two_identical_copies_from_different_artifacts__pick_the_same_one_either_way():
    # The 129 corpus keys whose copies are byte-identical. Content does not decide, so
    # source_artifact must, or the winner depends on walk order and the build is not reproducible.
    first = discovered(FIX / "citrix_v1r3_2025_xccdf.xml", origin="product_zip", source_artifact="U_AAA.zip")
    second = discovered(FIX / "citrix_v1r3_2025_xccdf.xml", origin="product_zip", source_artifact="U_ZZZ.zip")
    key = ("Citrix_XenDesktop_License_Server_STIG", "1")
    forward = orchestrator_module._newest_benchmarks([first, second], _skip_summary())
    reversed_ = orchestrator_module._newest_benchmarks([second, first], _skip_summary())
    assert forward[key][1].source_artifact == reversed_[key][1].source_artifact


def test_newest_benchmarks__two_documents_from_one_artifact_tie__the_incumbent_survives():
    # The residual _contest documents, pinned rather than only described. Both documents carry
    # one source_artifact, so every component of the tuple is equal and the strict > leaves
    # whichever was walked first standing. Reversing the list therefore selects the other one,
    # which is the point: this is the one contest whose winner is still walk order.
    #
    # It is also the only observable difference between > and >= here, so without this test that
    # comparison can be flipped and the whole suite still passes. The real case is the MS SQL
    # 2012 pair in U_SRG-STIG_Library_2020_01.zip: a 28-rule and a 153-rule benchmark both
    # self-reporting MS_SQL_Server_2012_Database_Instance_STIG at V1R18, from one inner zip.
    two_rules = discovered(FIX / "citrix_v1r3_2025_xccdf.xml", origin="library", source_artifact="U_Lib.zip")
    one_rule = discovered(FIX / "citrix_v1r3_2025_twin_xccdf.xml", origin="library", source_artifact="U_Lib.zip")
    key = ("Citrix_XenDesktop_License_Server_STIG", "1")
    assert orchestrator_module._contest(parse_stig(two_rules.path), two_rules) == orchestrator_module._contest(
        parse_stig(one_rule.path), one_rule
    )
    forward = orchestrator_module._newest_benchmarks([two_rules, one_rule], _skip_summary())
    reversed_ = orchestrator_module._newest_benchmarks([one_rule, two_rules], _skip_summary())
    assert len(forward[key][0].rules) == 2
    assert len(reversed_[key][0].rules) == 1


def test_contest__status_date_is_missing__loses_to_a_dated_document_at_the_same_release():
    # None floors to "", which sorts before any ISO date. No contested group in the corpus
    # lacks a status_date, so this is a guard against a build crashing on the first that does.
    undated = orchestrator_module._contest(
        parse_stig(FIX / "rhel9_xccdf.xml"),
        discovered(FIX / "rhel9_xccdf.xml", origin="product_zip", source_artifact="U_AAA.zip"),
    )
    dated = orchestrator_module._contest(
        ParsedStig(
            stig_id="RHEL_9_STIG",
            title="Red Hat Enterprise Linux 9 Security Technical Implementation Guide",
            benchmark_id="RHEL_9_STIG",
            version="1",
            release_info="Release: 1",
            status_date="2024-07-24",
        ),
        discovered(FIX / "rhel9_xccdf.xml", origin="product_zip", source_artifact="U_AAA.zip"),
    )
    assert undated[2] == ""
    assert undated < dated


def _skip_summary():
    return {
        "stig_files": 0,
        "superseded_by_library": 0,
        "superseded_same_key": 0,
        "same_key_departures": 0,
        "superseded_by_newer_major": 0,
        "skipped_srg": 0,
        "skipped_draft": 0,
        "skipped_unclassified": 0,
        "same_key_content_collision": 0,
        "same_key_collision_unmapped": 0,
        "id_corrections_applied": 0,
    }


def test_newest_benchmarks__two_disjoint_documents_from_one_artifact__keeps_both_under_corrected_ids():
    summary = _skip_summary()

    newest = orchestrator_module._newest_benchmarks(mssql_pair(), summary)

    assert set(newest) == {
        ("MS_SQL_Server_2012_Database_STIG", "1"),
        ("MS_SQL_Server_2012_Instance_STIG", "1"),
    }
    # Neither document lost, so nothing may be counted as a departure.
    assert summary["same_key_departures"] == 0
    assert summary["superseded_same_key"] == 0
    assert summary["same_key_content_collision"] == 1
    assert summary["id_corrections_applied"] == 2


def test_newest_benchmarks__a_split_pair__keeps_each_documents_own_rules():
    # Without the split, one of these rule sets is destroyed.
    summary = _skip_summary()

    newest = orchestrator_module._newest_benchmarks(mssql_pair(), summary)

    database, _ = newest[("MS_SQL_Server_2012_Database_STIG", "1")]
    instance, _ = newest[("MS_SQL_Server_2012_Instance_STIG", "1")]
    assert {rule.rule_id for rule in database.rules} == {"SV-40911r1_rule"}
    assert {rule.rule_id for rule in instance.rules} == {"SV-40905r1_rule", "SV-40906r1_rule"}


def test_newest_benchmarks__a_split_pair__keeps_DISAs_published_id_as_the_benchmark_id():
    # stig_id is ours, benchmark_id is DISA's. A caller quoting an id back to DISA needs the
    # published one to still be in the row.
    summary = _skip_summary()

    newest = orchestrator_module._newest_benchmarks(mssql_pair(), summary)

    database, _ = newest[("MS_SQL_Server_2012_Database_STIG", "1")]
    assert database.benchmark_id == "MS_SQL_Server_2012_Database_Instance_STIG"
    assert database.title == "Microsoft SQL Server 2012 Database Security Technical Implementation Guide"


def test_newest_benchmarks__a_split_pair_walked_in_the_other_order__gives_the_same_result():
    # The split exists to remove order dependence, so it must not have any of its own.
    summary = _skip_summary()

    newest = orchestrator_module._newest_benchmarks(list(reversed(mssql_pair())), summary)

    assert set(newest) == {
        ("MS_SQL_Server_2012_Database_STIG", "1"),
        ("MS_SQL_Server_2012_Instance_STIG", "1"),
    }


def test_newest_benchmarks__disjoint_documents_from_DIFFERENT_artifacts__are_not_split(caplog):
    # Citrix XenDesktop V1R3 was republished in 2025 with every rule id renumbered and no
    # release bump, so the 2020 and 2025 copies are same key, same release and disjoint. They
    # are an ordinary supersession, and splitting them would invent a benchmark. This is the
    # measured false positive that the same-artifact condition exists to exclude.
    summary = _skip_summary()
    benchmarks = [
        discovered(FIX / "citrix_v1r3_2020_xccdf.xml", origin="product_zip", source_artifact="U_Citrix_Y20M04.zip"),
        discovered(FIX / "citrix_v1r3_2025_xccdf.xml", origin="product_zip", source_artifact="U_Citrix_Y25M07.zip"),
    ]

    with caplog.at_level("WARNING"):
        newest = orchestrator_module._newest_benchmarks(benchmarks, summary)

    assert set(newest) == {("Citrix_XenDesktop_License_Server_STIG", "1")}
    assert summary["same_key_content_collision"] == 0
    assert summary["same_key_departures"] == 1
    # The departure itself still warns, since these are product_zip origin; what must stay silent
    # is a collision WARNING. Proving the ingest never announced one is part of what "not split"
    # means for the Citrix false positive this test guards against.
    assert not any("claimed by two different benchmarks" in rec.getMessage() for rec in caplog.records)


def test_newest_benchmarks__two_documents_from_one_artifact_at_different_releases__are_not_split():
    # Within one artifact, two releases of one benchmark are a supersession, not a collision.
    # SharePoint 2013 V1R4 and V1R8 ship together in the 2020 library sharing 27 of 39 rules,
    # and a wider gap could renumber all of them, so release equality is checked rather than
    # inferred from the rule sets.
    summary = _skip_summary()
    benchmarks = [
        discovered(FIX / "rhel9_xccdf.xml", origin="library", source_artifact="U_Lib.zip"),  # V1R1
        discovered(FIX / "rhel9_v1r2_xccdf.xml", origin="library", source_artifact="U_Lib.zip"),  # V1R2
    ]

    newest = orchestrator_module._newest_benchmarks(benchmarks, summary)

    assert set(newest) == {("RHEL_9_STIG", "1")}
    assert summary["same_key_content_collision"] == 0


def test_newest_benchmarks__two_identical_documents_from_one_artifact__are_not_split():
    # Riverbed SteelHead ALG V1R1 and zOS_RACF_STIG V6R43 each ship twice inside the 2020
    # library with identical rule sets. Discarding one loses nothing and must stay a departure.
    summary = _skip_summary()
    benchmarks = [
        discovered(FIX / "rhel9_xccdf.xml", origin="library", source_artifact="U_Lib.zip", source_document="a/x.xml"),
        discovered(FIX / "rhel9_xccdf.xml", origin="library", source_artifact="U_Lib.zip", source_document="b/x.xml"),
    ]

    newest = orchestrator_module._newest_benchmarks(benchmarks, summary)

    assert set(newest) == {("RHEL_9_STIG", "1")}
    assert summary["same_key_content_collision"] == 0
    assert summary["same_key_departures"] == 1


def test_newest_benchmarks__partially_overlapping_documents_from_one_artifact__are_not_split():
    # isdisjoint, not !=: sharing SOME rule ids is still one benchmark superseding itself, and
    # only a rule set sharing NONE of the other's ids is a second benchmark. citrix_v1r3_2025
    # and its twin share SV-213200r960759_rule at the same release, which is the case that
    # tells isdisjoint and a bare inequality apart; the two tests above cannot, because one
    # short-circuits on the release check and the other compares a document against itself.
    summary = _skip_summary()
    benchmarks = [
        discovered(FIX / "citrix_v1r3_2025_xccdf.xml", origin="library", source_artifact="U_Lib.zip"),
        discovered(FIX / "citrix_v1r3_2025_twin_xccdf.xml", origin="library", source_artifact="U_Lib.zip"),
    ]

    newest = orchestrator_module._newest_benchmarks(benchmarks, summary)

    assert set(newest) == {("Citrix_XenDesktop_License_Server_STIG", "1")}
    assert summary["same_key_content_collision"] == 0


def test_newest_benchmarks__two_zero_rule_documents_from_one_artifact__are_not_split():
    # parse_stig drops a rule missing @severity, so a document can classify as a STIG with zero
    # rules. Two such documents sharing one id, one artifact and one release would otherwise
    # satisfy a bare isdisjoint check (an empty set is disjoint from everything), tripping a
    # spurious collision, a spurious WARNING, and a same_key_collision_unmapped bump the corpus
    # harness escalates to an ERROR.
    summary = _skip_summary()
    zero_rule_fixture = FIX / "zero_rule_xccdf.xml"
    benchmarks = [
        discovered(zero_rule_fixture, origin="library", source_artifact="U_Lib.zip", source_document="a/x.xml"),
        discovered(zero_rule_fixture, origin="library", source_artifact="U_Lib.zip", source_document="b/x.xml"),
    ]

    newest = orchestrator_module._newest_benchmarks(benchmarks, summary)

    assert set(newest) == {("Empty_Rules_STIG", "1")}
    assert summary["same_key_content_collision"] == 0
    assert summary["same_key_collision_unmapped"] == 0


def test_newest_benchmarks__a_collision_the_map_does_not_name__warns_and_runs_the_ordinary_contest(caplog):
    summary = _skip_summary()
    benchmarks = [
        discovered(
            FIX / "mssql2012_database_xccdf.xml",
            origin="library",
            source_artifact="U_Lib.zip",
            source_document="U_Unmapped_Database/x-xccdf.xml",
        ),
        discovered(
            FIX / "mssql2012_instance_xccdf.xml",
            origin="library",
            source_artifact="U_Lib.zip",
            source_document="U_Unmapped_Instance/y-xccdf.xml",
        ),
    ]

    with caplog.at_level("WARNING"):
        newest = orchestrator_module._newest_benchmarks(benchmarks, summary)

    assert set(newest) == {("MS_SQL_Server_2012_Database_Instance_STIG", "1")}
    assert summary["same_key_content_collision"] == 1
    assert summary["same_key_collision_unmapped"] == 1
    assert summary["id_corrections_applied"] == 0
    assert summary["same_key_departures"] == 1
    # The operator must be able to see WHICH documents collided, or they cannot write the entry.
    assert "U_Unmapped_Database/x-xccdf.xml" in caplog.text
    assert "U_Unmapped_Instance/y-xccdf.xml" in caplog.text


def test_newest_benchmarks__a_correction_colliding_with_a_benchmark_already_kept__declines_to_split(caplog):
    # Re-keying onto an id another benchmark already won would discard that benchmark, which is
    # the exact failure the split exists to stop.
    summary = _skip_summary()
    corrections = {
        "MS_SQL_Server_2012_Database_Instance_STIG": id_corrections.Entry(
            published_id="MS_SQL_Server_2012_Database_Instance_STIG",
            documents=(
                id_corrections.Correction(match="_Database_", stig_id="RHEL_9_STIG", title="Collides"),
                id_corrections.Correction(match="_Instance_", stig_id="MS_SQL_Server_2012_Instance_STIG", title="Fine"),
            ),
            source="test",
            verified_against="test",
        )
    }
    benchmarks = [discovered(FIX / "rhel9_xccdf.xml", origin="library", source_artifact="U_Lib.zip")] + mssql_pair(
        artifact="U_Lib.zip"
    )

    with caplog.at_level("WARNING"):
        newest = orchestrator_module._newest_benchmarks(benchmarks, summary, corrections)

    assert ("RHEL_9_STIG", "1") in newest
    real_rhel9 = newest[("RHEL_9_STIG", "1")][0]
    assert real_rhel9.stig_id == "RHEL_9_STIG"
    # _corrected sets exactly the stig_id the assertion above checks, so an impostor renamed
    # to RHEL_9_STIG would satisfy it too. Rule ids the correction cannot fake: the real RHEL9
    # fixture's rules are entirely different from the rigged MS SQL Database document's.
    assert {rule.rule_id for rule in real_rhel9.rules} == {"SV-100001r1_rule", "SV-100002r1_rule"}
    assert summary["same_key_collision_unmapped"] == 1


def test_newest_benchmarks__a_hand_built_map_corrects_both_documents_to_the_same_id__declines_to_split():
    # _keys_available accepts whatever mapping the caller passes, not only one that has been
    # through id_corrections.load_corrections and its _unique check, so a hand-built map naming
    # the same stig_id for both halves must decline rather than let one overwrite the other.
    summary = _skip_summary()
    corrections = {
        "MS_SQL_Server_2012_Database_Instance_STIG": id_corrections.Entry(
            published_id="MS_SQL_Server_2012_Database_Instance_STIG",
            documents=(
                id_corrections.Correction(match="_Database_", stig_id="MS_SQL_Server_2012_Merged_STIG", title="One"),
                id_corrections.Correction(match="_Instance_", stig_id="MS_SQL_Server_2012_Merged_STIG", title="Two"),
            ),
            source="test",
            verified_against="test",
        )
    }

    newest = orchestrator_module._newest_benchmarks(mssql_pair(), summary, corrections)

    assert set(newest) == {("MS_SQL_Server_2012_Database_Instance_STIG", "1")}
    assert summary["same_key_collision_unmapped"] == 1


def test_newest_benchmarks__a_lone_half_arrives_after_the_pair__redirects_instead_of_resurrecting_the_id():
    # The pair splits normally; the late arrival self-reports the published id the split
    # already resolved, and must be routed to its own corrected key rather than resurrecting
    # the published one.
    summary = _skip_summary()
    late_instance = discovered(
        FIX / "mssql2012_instance_xccdf.xml",
        origin="library",
        source_artifact="U_Second_Lib.zip",
        source_document=MSSQL_INSTANCE_DOCUMENT,
    )
    benchmarks = [*mssql_pair(), late_instance]

    newest = orchestrator_module._newest_benchmarks(benchmarks, summary)

    assert set(newest) == {
        ("MS_SQL_Server_2012_Database_STIG", "1"),
        ("MS_SQL_Server_2012_Instance_STIG", "1"),
    }
    # The late arrival is a legitimate correction that contests normally against the instance
    # the split already stored: a departure, not an unmapped collision. id_corrections_applied
    # counts documents actually resident at the end, not corrections attempted, so it stays 2
    # (one database, one instance) regardless of which of the two instance documents won.
    assert summary["id_corrections_applied"] == 2
    assert summary["same_key_collision_unmapped"] == 0
    assert summary["same_key_departures"] == 1


def test_newest_benchmarks__the_pair_arrives_twice_from_two_artifacts__the_second_redirects_without_a_bogus_warning(
    caplog,
):
    # Two independent same-artifact pairs claiming one published id. The first splits; the
    # second's two documents are each routed to their own corrected key and contest there
    # normally. No warning may claim id_corrections.yaml needs an entry that already exists.
    summary = _skip_summary()
    benchmarks = mssql_pair(artifact="U_Lib_A.zip") + mssql_pair(artifact="U_Lib_B.zip")

    with caplog.at_level("WARNING"):
        newest = orchestrator_module._newest_benchmarks(benchmarks, summary)

    assert set(newest) == {
        ("MS_SQL_Server_2012_Database_STIG", "1"),
        ("MS_SQL_Server_2012_Instance_STIG", "1"),
    }
    assert summary["same_key_collision_unmapped"] == 0
    # 2, not 4: id_corrections_applied counts documents actually resident at the end, and
    # exactly one of each pair's two candidates wins its corrected key.
    assert summary["id_corrections_applied"] == 2
    assert not any("Add an entry for" in rec.getMessage() for rec in caplog.records)


def test_newest_benchmarks__a_foreign_document_precedes_the_pair__the_pair_still_splits(caplog):
    # An unrelated document claiming the published id must not be able to cost one true half
    # its only contest before the two halves are ever compared to each other, regardless of
    # where in the walk it falls.
    #
    # U_Zebra.zip is load bearing, not decorative: it must sort ABOVE
    # U_SRG-STIG_Library_2020_01.zip (the pair's artifact), so _contest's final tiebreak
    # (source_artifact, since version_key, origin and status_date all tie) makes the foreign
    # document WIN its interim contest against the database half under a streaming, one-key-
    # at-a-time design. With an artifact sorting below instead, the database half would win
    # that interim contest on its own, and a streaming design would produce the correct split
    # too: the test would then no longer be pinning the two-pass architecture, only the
    # warning. With U_Zebra.zip a single-pass implementation fails the set(newest) and
    # rule-id assertions below, not only the caplog one.
    summary = _skip_summary()
    foreign = discovered(
        FIX / "mssql2012_instance_xccdf.xml",
        origin="library",
        source_artifact="U_Zebra.zip",
        source_document="U_Foreign_Copy/x-xccdf.xml",  # matches neither correction fragment
    )
    benchmarks = [foreign, *mssql_pair()]

    with caplog.at_level("WARNING"):
        newest = orchestrator_module._newest_benchmarks(benchmarks, summary)

    assert set(newest) == {
        ("MS_SQL_Server_2012_Database_STIG", "1"),
        ("MS_SQL_Server_2012_Instance_STIG", "1"),
    }
    database, _ = newest[("MS_SQL_Server_2012_Database_STIG", "1")]
    assert {rule.rule_id for rule in database.rules} == {"SV-40911r1_rule"}
    # The foreign document cannot be corrected, so it is warned about and dropped, not stored.
    assert "U_Foreign_Copy/x-xccdf.xml" in caplog.text


def test_newest_benchmarks__the_pair_is_interleaved_with_a_foreign_document__still_splits():
    # _find_collision scans every pair in the group, not only adjacent arrivals: the two true
    # halves are not guaranteed to sit next to each other once a third document sharing the
    # published id lands between them. An adjacent-only scan would compare (database, foreign)
    # and (foreign, instance), never (database, instance), and miss the pair entirely.
    summary = _skip_summary()
    database, instance = mssql_pair()
    foreign = discovered(
        FIX / "mssql2012_instance_xccdf.xml",
        origin="library",
        source_artifact="U_Zebra.zip",
        source_document="U_Foreign_Copy/x-xccdf.xml",
    )
    benchmarks = [database, foreign, instance]

    newest = orchestrator_module._newest_benchmarks(benchmarks, summary)

    assert set(newest) == {
        ("MS_SQL_Server_2012_Database_STIG", "1"),
        ("MS_SQL_Server_2012_Instance_STIG", "1"),
    }


def test_newest_benchmarks__a_split_pair_with_mismatched_status_dates__still_splits(tmp_path):
    # _contest also compares status_date, so two documents from one artifact at one release are
    # not always a tie for it, and the split must not depend on being one. Every split fixture
    # above shares status date="2019-01-08", so a build gated on
    # _contest(...) == _contest(*current) would pass every one of them; this one does not.
    database_xml = (FIX / "mssql2012_database_xccdf.xml").read_text()
    instance_xml = (FIX / "mssql2012_instance_xccdf.xml").read_text().replace('date="2019-01-08"', 'date="2020-06-01"')
    database_path = tmp_path / "database-xccdf.xml"
    instance_path = tmp_path / "instance-xccdf.xml"
    database_path.write_text(database_xml)
    instance_path.write_text(instance_xml)
    summary = _skip_summary()
    benchmarks = [
        discovered(
            database_path,
            origin="library",
            source_artifact="U_SRG-STIG_Library_2020_01.zip",
            source_member="U_MS_SQL_Server_2012_V1R18_STIG.zip",
            source_document=MSSQL_DATABASE_DOCUMENT,
        ),
        discovered(
            instance_path,
            origin="library",
            source_artifact="U_SRG-STIG_Library_2020_01.zip",
            source_member="U_MS_SQL_Server_2012_V1R18_STIG.zip",
            source_document=MSSQL_INSTANCE_DOCUMENT,
        ),
    ]

    newest = orchestrator_module._newest_benchmarks(benchmarks, summary)

    assert set(newest) == {
        ("MS_SQL_Server_2012_Database_STIG", "1"),
        ("MS_SQL_Server_2012_Instance_STIG", "1"),
    }
    assert summary["same_key_content_collision"] == 1
    assert summary["same_key_departures"] == 0


def test_newest_benchmarks__document_is_an_srg__is_skipped_and_counted():
    summary = _skip_summary()
    benchmarks = [discovered(FIX / "rhel9_xccdf.xml"), discovered(FIX / "srg_xccdf.xml")]
    newest = orchestrator_module._newest_benchmarks(benchmarks, summary)
    assert set(newest) == {("RHEL_9_STIG", "1")}
    assert summary["skipped_srg"] == 1
    assert summary["stig_files"] == 1


def test_newest_benchmarks__document_status_is_draft__is_skipped_and_counted():
    summary = _skip_summary()
    newest = orchestrator_module._newest_benchmarks([discovered(FIX / "draft_stig_xccdf.xml")], summary)
    assert newest == {}
    assert summary["skipped_draft"] == 1
    assert summary["stig_files"] == 0


def test_newest_benchmarks__document_identifies_as_neither__is_skipped_and_named_in_the_log(caplog):
    # Named individually, not aggregated: this counter is the tripwire for DISA changing
    # their titling convention, and each hit is a decision someone may need to make.
    summary = _skip_summary()
    with caplog.at_level("WARNING"):
        newest = orchestrator_module._newest_benchmarks([discovered(FIX / "unclassified_xccdf.xml")], summary)
    assert newest == {}
    assert summary["skipped_unclassified"] == 1
    assert "Microsoft_Access_2010" in caplog.text


def test_skip_non_stig__any_skip__names_the_document_and_artifact(caplog):
    # kind="neither" already has its own WARNING naming both fields in _skip_non_stig, so
    # asserting on it would pass even without the DEBUG line. kind="srg" logs nothing else,
    # so only the DEBUG call can satisfy this.
    summary = _skip_summary()
    benchmark = discovered(FIX / "srg_xccdf.xml", source_artifact="U_Mystery_Vendor_SRG.zip")
    with caplog.at_level(logging.DEBUG):
        orchestrator_module._newest_benchmarks([benchmark], summary)
    debug_records = [r for r in caplog.records if r.levelno == logging.DEBUG]
    assert any(
        "AAA_Services_SRG" in r.getMessage() and "U_Mystery_Vendor_SRG.zip" in r.getMessage() for r in debug_records
    )


def test_build_kb__sources_hold_an_srg_and_a_draft__neither_reaches_the_stigs_table(minimal_sources, tmp_path):
    minimal_sources.benchmarks.append(discovered(FIX / "srg_xccdf.xml"))
    minimal_sources.benchmarks.append(discovered(FIX / "draft_stig_xccdf.xml"))
    out = tmp_path / "kb.sqlite"
    summary = build_kb(minimal_sources, out)
    assert summary["skipped_srg"] == 1
    assert summary["skipped_draft"] == 1
    conn = open_db_for_test(out)
    ids = {row[0] for row in conn.execute("select stig_id from stigs")}
    conn.close()
    assert ids == {"RHEL_9_STIG"}


def test_select__local_zip_newer_than_the_compilation__is_kept():
    kept, _ = _select(
        [_entry("Some_STIG", "2", "library"), _entry("Some_STIG", "3", "product_zip", artifact="U_Some_V3R1.zip")]
    )
    assert kept == [("Some_STIG", "2"), ("Some_STIG", "3")]


def test_select__library_ships_two_majors__keeps_both():
    # vSphere 8.0 is the only product in the library shipping two majors at once, and
    # applicability.yaml arbitrates them by product build.
    kept, _ = _select(
        [_entry("VMW_vSphere_8-0_ESXi_STIG", "1", "library"), _entry("VMW_vSphere_8-0_ESXi_STIG", "2", "library")]
    )
    assert kept == [("VMW_vSphere_8-0_ESXi_STIG", "1"), ("VMW_vSphere_8-0_ESXi_STIG", "2")]


def test_select__id_absent_from_the_library__keeps_only_the_highest_major():
    # U_CD_PGSQL_V3R2_STIG.zip against the archive's V2R2, neither in the library.
    kept, summary = _select(
        [
            _entry("Crunchy_Data_PostgreSQL_STIG", "2", "sunset"),
            _entry("Crunchy_Data_PostgreSQL_STIG", "3", "product_zip", artifact="U_CD_PGSQL_V3R2_STIG.zip"),
        ]
    )
    assert kept == [("Crunchy_Data_PostgreSQL_STIG", "3")]
    assert summary["superseded_by_newer_major"] == 1


def test_select__id_absent_from_the_library_at_one_major__keeps_it():
    kept, summary = _select([_entry("Apple_iOS-iPadOS_17_STIG", "1", "sunset")])
    assert kept == [("Apple_iOS-iPadOS_17_STIG", "1")]
    assert summary == {"superseded_by_library": 0, "superseded_by_newer_major": 0}


def test_collect_then_build__inner_zip_holds_an_srg__it_is_extracted_but_not_ingested(minimal_sources, tmp_path):
    # The walkers extract an SRG rather than rejecting it by name, and the orchestrator is
    # what drops it. Both halves have to be right: extraction alone would ingest it, and a
    # name filter alone would lose the z/OS content.
    comp = tmp_path / "U_SRG-STIG_Library_July_2026.zip"
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as z:
        z.writestr("U_AAA_Manual_SRG/U_AAA_Services_Manual-xccdf.xml", (FIX / "srg_xccdf.xml").read_bytes())
    with zipfile.ZipFile(comp, "w") as outer:
        outer.writestr("U_AAA_Services_V2R2_SRG.zip", inner.getvalue())

    found = collect([Artifact(kind="library", path=comp)], tmp_path / "out")
    assert len(found) == 1, "the SRG must be extracted, not filtered out by name"

    minimal_sources.benchmarks.extend(found)
    summary = build_kb(minimal_sources, tmp_path / "kb.sqlite")
    assert summary["skipped_srg"] == 1


def test_build_kb__an_artifact_stamping_two_benchmarks_with_one_id__stores_both_and_all_their_rules(
    tmp_path, minimal_sources
):
    # The end the whole split exists for: without it one of these two rule sets is destroyed,
    # and which one depends on zipfile.namelist() order.
    minimal_sources.benchmarks = mssql_pair()
    out = tmp_path / "kb.sqlite"

    summary = build_kb(minimal_sources, out)

    conn = open_db_for_test(out)
    stored = dict(conn.execute("SELECT stig_id, title FROM stigs").fetchall())
    assert set(stored) == {"MS_SQL_Server_2012_Database_STIG", "MS_SQL_Server_2012_Instance_STIG"}
    rules = dict(conn.execute("SELECT rule_id, stig_id FROM stig_rules").fetchall())
    assert rules == {
        "SV-40911r1_rule": "MS_SQL_Server_2012_Database_STIG",
        "SV-40905r1_rule": "MS_SQL_Server_2012_Instance_STIG",
        "SV-40906r1_rule": "MS_SQL_Server_2012_Instance_STIG",
    }
    assert summary["rule_id_collisions"] == 0
    assert summary["id_corrections_applied"] == 2


def test_build_kb__a_split_benchmark__is_reachable_by_the_resolver_under_each_half(tmp_path, minimal_sources):
    # Correcting the id alone would leave both rows holding "database" and "instance" from the
    # shared title, with identical token sets and identical scores. The corrected TITLE is what
    # makes each half separately reachable, so it is pinned here rather than assumed.
    minimal_sources.benchmarks = mssql_pair()
    out = tmp_path / "kb.sqlite"
    build_kb(minimal_sources, out)

    conn = open_db_for_test(out)
    keywords = dict(conn.execute("SELECT stig_id, product_keywords FROM stigs").fetchall())
    assert "instance" not in keywords["MS_SQL_Server_2012_Database_STIG"]
    assert "database" not in keywords["MS_SQL_Server_2012_Instance_STIG"]


def _main_with_paths(monkeypatch, tmp_path, *, overrides_path, overrides_from_env, artifacts=()):
    """Run orchestrator.main() against scratch paths, capturing the IngestSources it builds.

    build_kb and the inventory walk are stubbed because this is about what main() RESOLVES,
    not about the ETL: the ETL has its own tests, and letting it run would need a full source
    tree per case.
    """
    data_dir = tmp_path / "data"
    # main() parses sys.argv itself (for --help support under `python -m`), and pytest's
    # own invocation arguments would otherwise leak in and fail that parse.
    monkeypatch.setattr("sys.argv", ["stig-mcp-ingest"])
    monkeypatch.setattr(config, "DATA_DIR", data_dir)
    monkeypatch.setattr(config, "SOURCES_DIR", data_dir / "sources")
    monkeypatch.setattr(config, "KB_PATH", data_dir / "stig_kb.sqlite")
    monkeypatch.setattr(config, "OVERRIDES_PATH", overrides_path)
    monkeypatch.setattr(config, "OVERRIDES_FROM_ENV", overrides_from_env)
    monkeypatch.setattr(orchestrator_module.inventory, "classify", lambda _dir: list(artifacts))
    monkeypatch.setattr(orchestrator_module.inventory, "collect", lambda _artifacts, _dest: [])
    captured = {}
    monkeypatch.setattr(orchestrator_module, "build_kb", lambda sources, out: captured.update(sources=sources, out=out))
    orchestrator_module.main()
    return data_dir, captured


def test_main__named_overrides_file_is_missing__refuses_and_names_the_variable(monkeypatch, tmp_path):
    named = tmp_path / "elsewhere" / "overrides.yaml"
    with pytest.raises(FileNotFoundError) as excinfo:
        _main_with_paths(monkeypatch, tmp_path, overrides_path=named, overrides_from_env=True)
    message = str(excinfo.value)
    assert "STIG_MCP_OVERRIDES" in message
    assert str(named) in message


def test_main__named_overrides_file_is_missing__refuses_before_creating_anything(monkeypatch, tmp_path):
    # The refusal is worth nothing if it lands after the ingest has already started work.
    data_dir = tmp_path / "data"
    with pytest.raises(FileNotFoundError):
        _main_with_paths(monkeypatch, tmp_path, overrides_path=tmp_path / "nope.yaml", overrides_from_env=True)
    assert not data_dir.exists()


def test_main__default_overrides_file_is_missing__stays_silent(monkeypatch, tmp_path):
    # docs/operations.md documents overrides.yaml as optional at its default location, and
    # every existing checkout without one has to keep working.
    _data_dir, captured = _main_with_paths(
        monkeypatch, tmp_path, overrides_path=tmp_path / "absent.yaml", overrides_from_env=False
    )
    assert captured["sources"].overrides_path == tmp_path / "absent.yaml"


def test_main__a_data_directory_that_does_not_exist_yet__is_created(monkeypatch, tmp_path):
    # An installed operator's XDG data directory does not exist on the first run, and build_kb
    # never creates the knowledge base's parent.
    data_dir, _captured = _main_with_paths(
        monkeypatch, tmp_path, overrides_path=tmp_path / "absent.yaml", overrides_from_env=False
    )
    assert data_dir.is_dir()


def test_main__a_data_directory_that_already_exists__is_not_an_error(monkeypatch, tmp_path):
    # exist_ok is the NORMAL path, not the edge one: fetch_public creates SOURCES_DIR and
    # DATA_DIR is its parent, so in the documented fetch-then-ingest order the directory is
    # always already there, and every real checkout has stig_mcp/data from the start.
    (tmp_path / "data").mkdir()
    data_dir, _captured = _main_with_paths(
        monkeypatch, tmp_path, overrides_path=tmp_path / "absent.yaml", overrides_from_env=False
    )
    assert data_dir.is_dir()


def test_main__a_data_directory_whose_parent_is_missing_too__is_created(monkeypatch, tmp_path):
    # The first run of an installed copy: ~/.local/share/stig-mcp has no ~/.local/share above
    # it on a fresh account, so parents is what carries it.
    nested = tmp_path / "fresh" / "home" / "share"
    monkeypatch.setattr("sys.argv", ["stig-mcp-ingest"])
    monkeypatch.setattr(config, "DATA_DIR", nested / "data")
    monkeypatch.setattr(config, "SOURCES_DIR", nested / "data" / "sources")
    monkeypatch.setattr(config, "KB_PATH", nested / "data" / "stig_kb.sqlite")
    monkeypatch.setattr(config, "OVERRIDES_PATH", tmp_path / "absent.yaml")
    monkeypatch.setattr(config, "OVERRIDES_FROM_ENV", False)
    monkeypatch.setattr(orchestrator_module.inventory, "classify", lambda _dir: [])
    monkeypatch.setattr(orchestrator_module.inventory, "collect", lambda _artifacts, _dest: [])
    monkeypatch.setattr(orchestrator_module, "build_kb", lambda _sources, _out: None)
    orchestrator_module.main()
    assert (nested / "data").is_dir()


def test_main__named_overrides_path_is_a_directory__refuses_like_a_missing_file(monkeypatch, tmp_path):
    # exists() is satisfied by a directory, which would then reach load_overrides as an
    # unhelpful IsADirectoryError from inside build_kb.
    named = tmp_path / "overrides.yaml"
    named.mkdir()
    with pytest.raises(FileNotFoundError) as excinfo:
        _main_with_paths(monkeypatch, tmp_path, overrides_path=named, overrides_from_env=True)
    message = str(excinfo.value)
    assert "STIG_MCP_OVERRIDES" in message
    # "does not exist" would be false about a directory that does.
    assert "not a readable file" in message


def test_main__the_overrides_path__comes_from_config_not_from_the_package_location(monkeypatch, tmp_path):
    # A path derived from the package location resolves to site-packages/overrides.yaml under
    # an install, so an installed operator's file would be ignored without a word.
    named = tmp_path / "named" / "overrides.yaml"
    named.parent.mkdir()
    named.write_text("add: []\n")
    _data_dir, captured = _main_with_paths(monkeypatch, tmp_path, overrides_path=named, overrides_from_env=True)
    assert captured["sources"].overrides_path == named


def test_main__a_classified_artifact__reaches_build_kb_as_an_artifact_path(monkeypatch, tmp_path):
    # source_files records the archives a build read only through artifact_paths, and nothing
    # but main() fills it in from what classify found.
    archive = tmp_path / "U_RHEL_9_V1R1_STIG.zip"
    _data_dir, captured = _main_with_paths(
        monkeypatch,
        tmp_path,
        overrides_path=tmp_path / "absent.yaml",
        overrides_from_env=False,
        artifacts=[Artifact(kind="product_zip", path=archive)],
    )
    assert captured["sources"].artifact_paths == (archive,)


def test_build_kb__a_token_one_document_inside_the_gate__warns_naming_the_token(tmp_path, caplog):
    # The operator rebuilding from a newer DISA library is the person who causes a crossing,
    # and this log line is the only thing that makes it visible to them.
    # 20 benchmarks puts the gate at exactly 1.00, so 'rhel' at df 1 is one document inside it.
    directory = tmp_path / "sources"
    directory.mkdir()
    out = tmp_path / "kb.sqlite"
    sources = _sources(
        benchmarks=[discovered(FIX / "rhel9_xccdf.xml"), *_filler_benchmarks(directory, count=19)],
    )
    with caplog.at_level(logging.WARNING, logger="stig_mcp.ingest.orchestrator"):
        build_kb(sources, out)
    warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    losing = [m for m in warnings if "sit inside the distinctiveness gate by one document or less" in m]
    assert len(losing) == 1
    assert "'rhel' df 1" in losing[0]
    # Gate and n pinned together, in one substring, because the %d/%.2f/%d slots accept each
    # other's arguments silently. len(band.losing) is 25 on this corpus and the gate is 1.00,
    # so swapping them renders "(gate df <= 25.00 at n=20)" with no TypeError.
    assert "(gate df <= 1.00 at n=20)" in losing[0]


def test_build_kb__a_token_one_document_inside_the_gate__counts_it_in_the_summary(tmp_path):
    directory = tmp_path / "sources"
    directory.mkdir()
    out = tmp_path / "kb.sqlite"
    summary = build_kb(
        _sources(benchmarks=[discovered(FIX / "rhel9_xccdf.xml"), *_filler_benchmarks(directory, count=19)]),
        out,
    )
    assert summary["distinctiveness_margin_tokens"] > 0


def test_check_distinctiveness_margin__a_corpus_with_nothing_near_the_gate__says_nothing(tmp_path, caplog):
    # An empty band must produce no line at all rather than a line reading "0 token(s)",
    # which would be noise on every such build. Driven through the check function directly
    # against a stigs-free database, because build_kb refuses an empty benchmarks list in
    # _validate_sources and so cannot reach an empty corpus.
    summary = {}
    with (
        closing(create_db(tmp_path / "empty.sqlite")) as conn,
        caplog.at_level(logging.INFO, logger="stig_mcp.ingest.orchestrator"),
    ):
        _check_distinctiveness_margin(conn, summary)
    assert not [r for r in caplog.records if "distinctiveness margin" in r.getMessage()]
    assert summary["distinctiveness_margin_tokens"] == 0


def test_build_kb__a_token_one_document_outside_the_gate__informs_naming_the_token(tmp_path, caplog):
    # 20 benchmarks puts the gate at exactly 1.00, and 'windows' is held by both
    # win2022_xccdf.xml and chrome_current_xccdf.xml, so it sits at df 2, one document
    # outside the gate. The INFO message's rendered content is asserted because a mismatch in
    # its %d, %s and %s argument order would only surface as a stderr traceback from
    # logging.Handler.handleError, which no test would fail on.
    directory = tmp_path / "sources"
    directory.mkdir()
    out = tmp_path / "kb.sqlite"
    sources = _sources(
        benchmarks=[
            discovered(FIX / "rhel9_xccdf.xml"),
            discovered(FIX / "win2022_xccdf.xml"),
            discovered(FIX / "chrome_current_xccdf.xml"),
            *_filler_benchmarks(directory, count=17),
        ],
    )
    with caplog.at_level(logging.INFO, logger="stig_mcp.ingest.orchestrator"):
        build_kb(sources, out)
    infos = [r.getMessage() for r in caplog.records if r.levelno == logging.INFO]
    gaining = [m for m in infos if "sit outside the distinctiveness gate by one document or less" in m]
    assert len(gaining) == 1
    assert "'windows' df 2" in gaining[0]
    assert "the ratio (0.05)" in gaining[0]


def test_build_kb__a_corpus_with_tokens_on_both_sides__counts_both_sides_in_the_summary(tmp_path, caplog):
    # The counter is len(losing) + len(gaining), and the losing-only corpus above cannot tell
    # that apart from len(losing) alone, because its gaining list is empty. This corpus, the
    # same 20-benchmark one the gaining test uses, populates both sides: 30 tokens inside the
    # gate and 'windows' outside it. The expected count is read back off the two rendered
    # lines rather than written as a literal, so the assertion pins the composition rather
    # than this fixture's vocabulary.
    directory = tmp_path / "sources"
    directory.mkdir()
    out = tmp_path / "kb.sqlite"
    sources = _sources(
        benchmarks=[
            discovered(FIX / "rhel9_xccdf.xml"),
            discovered(FIX / "win2022_xccdf.xml"),
            discovered(FIX / "chrome_current_xccdf.xml"),
            *_filler_benchmarks(directory, count=17),
        ],
    )
    with caplog.at_level(logging.INFO, logger="stig_mcp.ingest.orchestrator"):
        summary = build_kb(sources, out)
    lines = [m for m in (r.getMessage() for r in caplog.records) if "distinctiveness margin" in m]
    assert len(lines) == 2
    # Each named token renders as `'token' df N`; the warning's own "gate df <= 1.00" carries
    # no apostrophe, so it is not counted.
    named = sum(line.count("' df ") for line in lines)
    assert summary["distinctiveness_margin_tokens"] == named


def _rules_by_stig(kb_path):
    conn = open_db_for_test(kb_path)
    rows = conn.execute("SELECT stig_id, COUNT(*) AS n FROM stig_rules GROUP BY stig_id").fetchall()
    return {row["stig_id"]: row["n"] for row in rows}


def test_build_kb__two_benchmarks_sharing_rule_ids__attributes_them_to_the_newer_status_date(tmp_path):
    # rule_id is a global PRIMARY KEY and _insert_rules keeps the first occurrence, so the
    # order benchmarks are inserted in decides which one a shared id is attributed to. The
    # two fixtures model the OpenShift pair: three rules each, two ids shared, and
    # the shared rules byte-identical, so nothing is lost either way and only the attribution
    # moves. Both discovery orders are built so walk order cannot decide the winner: on real
    # data the wrong order leaves the current benchmark answering with a fraction of its rules.
    old = discovered(FIX / "shared_rules_2024_xccdf.xml", origin="product_zip", source_artifact="old.zip")
    new = discovered(FIX / "shared_rules_2026_xccdf.xml")
    for index, order in enumerate(([old, new], [new, old])):
        out = tmp_path / f"kb{index}.sqlite"
        summary = build_kb(_sources(benchmarks=order), out)
        assert summary["rule_id_collisions"] == 2
        assert _rules_by_stig(out) == {"ZZCONTAINER_PLATFORM_4-X_STIG": 3, "ZZCONTAINER_PLATFORM_4-12_STIG": 1}


def test_build_kb__benchmarks_sharing_rule_ids_at_one_status_date__attribute_them_to_the_library(tmp_path):
    # Both fixtures state 2024-12-06, so the date decides nothing and the origin has to. A
    # loose product zip is a snapshot of one release; the library compilation is what DISA
    # currently ships, which is the same reason _contest prefers it one level down.
    # The library holds the LARGER stig_id on purpose. With the roles the other way round the
    # ascending stig_id tiebreak elects the same winner on its own, and dropping _origin_rank
    # from the key would leave this test green.
    zipped = discovered(FIX / "shared_rules_same_date_xccdf.xml", origin="product_zip", source_artifact="old.zip")
    library = discovered(FIX / "shared_rules_2024_xccdf.xml")
    for index, order in enumerate(([zipped, library], [library, zipped])):
        out = tmp_path / f"kb{index}.sqlite"
        build_kb(_sources(benchmarks=order), out)
        assert _rules_by_stig(out) == {"ZZCONTAINER_PLATFORM_4-12_STIG": 3, "ZZCONTAINER_PLATFORM_4-11_STIG": 1}


def test_build_kb__benchmarks_sharing_rule_ids_at_one_date_and_origin__attribute_them_by_stig_id(tmp_path):
    # Nothing about the two documents separates them, so without a final tiebreak the sort is
    # stable and DISCOVERY order decides, which is the defect this ordering exists to remove.
    # Ascending stig_id is arbitrary in itself; what matters is that it is stated, so the
    # winner cannot move when a directory walk yields the same two files in another order.
    first = discovered(FIX / "shared_rules_same_date_twin_xccdf.xml")
    second = discovered(FIX / "shared_rules_same_date_xccdf.xml")
    for index, order in enumerate(([first, second], [second, first])):
        out = tmp_path / f"kb{index}.sqlite"
        build_kb(_sources(benchmarks=order), out)
        assert _rules_by_stig(out) == {"ZZCONTAINER_PLATFORM_4-10_STIG": 3, "ZZCONTAINER_PLATFORM_4-11_STIG": 1}


def _collision_warnings(caplog):
    return [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING and "rule id(s)" in r.getMessage()]


def test_build_kb__a_benchmark_left_short_by_a_collision__warns_once_naming_it_and_both_counts(tmp_path, caplog):
    # One WARNING per rule buries the count on a real corpus. One line per LOSING BENCHMARK is
    # what an operator can act on: which benchmark is short, by how much, and out of what.
    old = discovered(FIX / "shared_rules_2024_xccdf.xml", origin="product_zip", source_artifact="old.zip")
    new = discovered(FIX / "shared_rules_2026_xccdf.xml")
    out = tmp_path / "kb.sqlite"
    with caplog.at_level(logging.DEBUG, logger="stig_mcp.ingest.orchestrator"):
        build_kb(_sources(benchmarks=[old, new]), out)
    warnings = _collision_warnings(caplog)
    assert len(warnings) == 1
    assert "ZZCONTAINER_PLATFORM_4-12_STIG" in warnings[0]
    assert "stores 1 of the 3 rules parsed from it" in warnings[0]
    assert "2 rule id(s)" in warnings[0]
    # Naming the HOLDER is the point of this line: without it an operator has to query the
    # knowledge base to find out where the guidance went. docs/operations.md carries that SQL
    # for the cases this cannot cover.
    assert "ZZCONTAINER_PLATFORM_4-X_STIG 2 (2)" in warnings[0]
    # The cross-benchmark case gets the attribution sentence and NOT the within-document one.
    assert "what moved is attribution" in warnings[0]
    # Naming the LOSER in the tail, not just in the prefix. The tests filter on the prefix, so a
    # wrong benchmark name in the closing sentence is caught only here.
    assert "a query scoped to ZZCONTAINER_PLATFORM_4-12_STIG is short by them" in warnings[0]
    assert "duplicate inside this document" not in warnings[0]
    # Every holder is named, so the summary clause must be absent. Without this, dropping the
    # `if remaining:` guard and always appending "0 further benchmark(s)" passes the suite.
    assert "further benchmark(s)" not in warnings[0]


def test_build_kb__ids_held_by_two_benchmarks__names_both_with_their_counts(tmp_path, caplog):
    # A loser's ids are not necessarily all held by ONE benchmark: on the 2020_01 corpus
    # Network_-_Infrastructure_Router_-_Cisco loses its ids to four different holders. A
    # single-holder message would name one of them and be silently wrong about the rest.
    newest = discovered(FIX / "shared_rules_2026_xccdf.xml")
    middle = discovered(FIX / "shared_rules_same_date_xccdf.xml")
    oldest = discovered(FIX / "shared_rules_two_holders_xccdf.xml", origin="product_zip", source_artifact="old.zip")
    out = tmp_path / "kb.sqlite"
    with caplog.at_level(logging.DEBUG, logger="stig_mcp.ingest.orchestrator"):
        build_kb(_sources(benchmarks=[newest, middle, oldest]), out)
    # Every other collision fixture is version 2, which leaves the DEBUG line's two version
    # slots interchangeable. This one is version 3, which makes the loser's version and the
    # holder's distinguishable in that message.
    per_rule = sorted(r.getMessage() for r in caplog.records if "Duplicate rule_id SV-950112" in r.getMessage())
    assert "(in ZZCONTAINER_PLATFORM_4-8_STIG 3)" in per_rule[0]
    assert "which ZZCONTAINER_PLATFORM_4-11_STIG 2 stored" in per_rule[0]
    short = [w for w in _collision_warnings(caplog) if "ZZCONTAINER_PLATFORM_4-8_STIG" in w]
    assert len(short) == 1
    assert "stores 1 of the 3 rules parsed from it" in short[0]
    assert "ZZCONTAINER_PLATFORM_4-X_STIG 2 (1)" in short[0]
    assert "ZZCONTAINER_PLATFORM_4-11_STIG 2 (1)" in short[0]
    # Two holders against a cap of three, so nothing is summarized. This also fails a remainder
    # computed against the cap rather than against what was named, which would print
    # "-1 further benchmark(s)" here.
    assert "further benchmark(s)" not in short[0]


def test_build_kb__a_duplicate_id_within_one_document__says_the_dropped_rule_is_stored_nowhere(tmp_path, caplog):
    # DISA ships SV-6802r1_rule twice inside SAN and SV-7031r1_rule twice inside
    # MULTI-FUNCTION_DEVICE, one collision each. Naming the losing benchmark as its own holder
    # would read as a bug in the message; saying it is a duplicate within the document tells
    # the operator no ordering can affect it.
    only = discovered(FIX / "duplicate_rule_id_xccdf.xml")
    out = tmp_path / "kb.sqlite"
    with caplog.at_level(logging.DEBUG, logger="stig_mcp.ingest.orchestrator"):
        build_kb(_sources(benchmarks=[only]), out)
    warnings = _collision_warnings(caplog)
    assert len(warnings) == 1
    assert "stores 2 of the 3 rules parsed from it" in warnings[0]
    # The dropped GROUP is named in the WARNING itself, not deferred to a DEBUG line: main()
    # hardcodes logging.basicConfig(level=logging.INFO) and parses no options, so an operator
    # running stig-mcp-ingest cannot reach DEBUG at all. group_id is the only column separating
    # two occurrences inside one document, so without it nothing says WHICH requirement went.
    assert "dropping group(s) V-950202" in warnings[0]
    assert "ZZSTORAGE_FABRIC_STIG 2 (" not in warnings[0]
    # The dropped occurrence is a DIFFERENT requirement, so the message must not say the loss is
    # only bookkeeping: on both of DISA's real cases, "No guidance is missing" would be false.
    assert "different requirement carrying an id already used" in warnings[0]
    assert "is stored under no benchmark" in warnings[0]
    # The remedy has to name group_id. A (stig_id, stig_version, rule_id) key would not
    # separate them: BOTH occurrences share all three, so a remedy naming only that key would
    # send a reader to a fix that leaves this case exactly where it is.
    assert "needs group_id in the key, which is necessary and not sufficient" in warnings[0]
    # rule_cci.rule_id is a foreign key onto stig_rules(rule_id) and PRAGMA foreign_keys is ON,
    # so widening that key alone fails on the first rule_cci insert.
    assert "rule_cci.rule_id is a foreign key" in warnings[0]
    # Attribution did not move anywhere, so the cross-benchmark sentence must not appear.
    assert "what moved is attribution" not in warnings[0]


def test_build_kb__a_benchmark_losing_ids_to_itself_and_to_another__gets_both_sentences(tmp_path, caplog):
    # A benchmark losing ids BOTH to itself and to another must get both closing sentences, or
    # its within-document drop goes unexplained. The two sentences are composed, not chosen,
    # and this is the only fixture with that shape.
    newest = discovered(FIX / "shared_rules_2026_xccdf.xml")
    mixed = discovered(FIX / "mixed_holders_xccdf.xml", origin="product_zip", source_artifact="old.zip")
    out = tmp_path / "kb.sqlite"
    with caplog.at_level(logging.DEBUG, logger="stig_mcp.ingest.orchestrator"):
        build_kb(_sources(benchmarks=[newest, mixed]), out)
    short = [w for w in _collision_warnings(caplog) if "ZZCONTAINER_PLATFORM_4-7_STIG" in w]
    assert len(short) == 1
    assert "stores 2 of the 4 rules parsed from it" in short[0]
    assert "what moved is attribution" in short[0]
    assert "different requirement carrying an id already used" in short[0]
    # The within-document entry is named FIRST, ahead of the larger cross-benchmark share, so it
    # cannot be truncated away by the cap and the tail sentence always has its referent.
    assert short[0].index("a duplicate id within the document") < short[0].index("ZZCONTAINER_PLATFORM_4-X_STIG")
    assert "dropping group(s) V-950302" in short[0]


def test_holder_phrase__more_holders_than_the_line_names__names_the_largest_and_counts_the_rest():
    # The cap is reached on real data, not only in principle: on the 2020_01 corpus
    # Network_-_Infrastructure_Router_-_Cisco loses its ids to four holders, the shares used
    # below. Driven from a Counter rather than five more fixtures because what is under test
    # is the phrase, and the insertion order that produces one is pinned above.
    parsed = ParsedStig(
        stig_id="ZZLOSER_STIG",
        version="1",
        title="t",
        benchmark_id="b",
        release_info=None,
        status=None,
        status_date=None,
        rules=[],
    )
    # Inserted SMALLEST first, so insertion order disagrees with share order at every position.
    # Built the other way round the phrase is identical whether the code sorts or just slices.
    holders = {
        ("ZZD_STIG", "8"): ["V-1"] * 8,
        ("ZZC_STIG", "8"): ["V-2"] * 10,
        ("ZZB_STIG", "8"): ["V-3"] * 26,
        ("ZZA_STIG", "8"): ["V-4"] * 44,
    }
    phrase = orchestrator_module._holder_phrase(parsed, holders)
    assert phrase == "ZZA_STIG 8 (44), ZZB_STIG 8 (26), ZZC_STIG 8 (10), 1 further benchmark(s)"


def test_holder_phrase__a_self_held_id_below_the_cap__is_still_named_and_not_counted_as_a_benchmark():
    # The self entry carries the smallest share here, so a plain most_common(3) drops it into
    # "N further benchmark(s)", which both calls it a benchmark and loses the fact the closing
    # sentence depends on. It is named first instead, and the remainder counts only the others.
    parsed = ParsedStig(
        stig_id="ZZLOSER_STIG",
        version="1",
        title="t",
        benchmark_id="b",
        release_info=None,
        status=None,
        status_date=None,
        rules=[],
    )
    # Smallest first here too, and the self entry inserted FIRST as well as carrying the smallest
    # share, so neither sorting nor slicing can put it where it belongs by accident.
    holders = {
        ("ZZLOSER_STIG", "1"): ["V-950999"],
        ("ZZD_STIG", "8"): ["V-5"] * 6,
        ("ZZC_STIG", "8"): ["V-6"] * 7,
        ("ZZB_STIG", "8"): ["V-7"] * 8,
        ("ZZA_STIG", "8"): ["V-8"] * 9,
    }
    assert orchestrator_module._holder_phrase(parsed, holders) == (
        "a duplicate id within the document, dropping group(s) V-950999, ZZA_STIG 8 (9), "
        "ZZB_STIG 8 (8), ZZC_STIG 8 (7), 1 further benchmark(s)"
    )


def test_build_kb__a_rule_id_collision__is_not_warned_once_per_rule(tmp_path, caplog):
    # Per-rule detail is still emitted, at DEBUG, because it names the individual ids and a
    # summary line cannot. At WARNING it would bury the count on a real corpus.
    old = discovered(FIX / "shared_rules_2024_xccdf.xml", origin="product_zip", source_artifact="old.zip")
    new = discovered(FIX / "shared_rules_2026_xccdf.xml")
    out = tmp_path / "kb.sqlite"
    with caplog.at_level(logging.DEBUG, logger="stig_mcp.ingest.orchestrator"):
        build_kb(_sources(benchmarks=[old, new]), out)
    per_rule = [r for r in caplog.records if "Duplicate rule_id" in r.getMessage()]
    assert len(per_rule) == 2
    assert {r.levelno for r in per_rule} == {logging.DEBUG}
    # It must name the HOLDER and the dropped rule's GROUP, both of which docs/operations.md
    # tells an operator to read here. Counting records and checking their level cannot see
    # the message. group_id is the load-bearing half, because it is the only column separating two
    # occurrences inside one document, so without it this line names an id that is still stored.
    messages = sorted(r.getMessage() for r in per_rule)
    assert "from group V-950101" in messages[0]
    assert "which ZZCONTAINER_PLATFORM_4-X_STIG 2 stored" in messages[0]


def test_build_kb__a_benchmark_stating_no_status_date__loses_the_shared_id_to_one_that_does(tmp_path):
    # Preferring a benchmark that states its currency is the whole reason the key reads
    # `status_date or ""`. Every other fixture sharing an id states a date, so only this pair
    # catches the fallback being inverted to a date in the far future.
    dateless = discovered(FIX / "shared_rules_no_date_xccdf.xml")
    dated = discovered(FIX / "shared_rules_2026_xccdf.xml")
    for index, order in enumerate(([dateless, dated], [dated, dateless])):
        out = tmp_path / f"kb{index}.sqlite"
        build_kb(_sources(benchmarks=order), out)
        assert _rules_by_stig(out) == {"ZZCONTAINER_PLATFORM_4-X_STIG": 3, "ZZCONTAINER_PLATFORM_4-10_STIG": 1}


def test_build_kb__two_majors_of_one_benchmark_sharing_rule_ids__attribute_them_to_the_newer_major(tmp_path):
    # `newest_by_key` is keyed (stig_id, version) and _select keeps EVERY library row, so two
    # majors of one id coexist and tie on the stig_id tiebreak. The vSphere 8-0 families in the
    # real knowledge base have this shape. They are safe only because each pair carries
    # distinct dates and shares no rule id; with both equal the order would fall through to
    # dict order, which is what this ordering exists to prevent.
    first = discovered(FIX / "shared_rules_major1_xccdf.xml")
    second = discovered(FIX / "shared_rules_major2_xccdf.xml")
    for index, order in enumerate(([first, second], [second, first])):
        out = tmp_path / f"kb{index}.sqlite"
        build_kb(_sources(benchmarks=order), out)
        conn = open_db_for_test(out)
        by_version = {
            row["stig_version"]: row["n"]
            for row in conn.execute(
                "SELECT stig_version, COUNT(*) AS n FROM stig_rules "
                "WHERE stig_id='ZZCONTAINER_PLATFORM_4-9_STIG' GROUP BY stig_version"
            )
        }
        assert by_version == {"2": 3, "1": 1}


def test_main__an_argv_argument__is_parsed_instead_of_sys_argv(monkeypatch):
    # A CLI that can only read the real sys.argv can be tested only by patching it, and taking
    # argv explicitly is a change of the same size. sys.argv here carries a flag argparse would
    # reject, so a main() still reading it exits 2 rather than 0.
    monkeypatch.setattr("sys.argv", ["stig-mcp-ingest", "--not-a-flag"])
    with pytest.raises(SystemExit) as excinfo:
        orchestrator_module.main(["--help"])
    assert excinfo.value.code == 0


def _currency_sources(tmp_path, attack_index=True, suppress_mapped=False):
    """A build covering every CTID status and every no-controls cause. ATT&CK 19.1 against a
    16.1 mapping released 2024-11-12: T1078 mapped (suppressed when suppress_mapped), T8001
    non_mappable, T9000 absent and created before the release, T9500 absent and created after."""
    techniques = {"T1078": "2019-01-01", "T8001": "2019-01-01", "T9000": "2024-11-12", "T9500": "2024-11-13"}
    bundle = {
        "objects": [{"type": "x-mitre-collection", "x_mitre_version": "19.1"}]
        + [
            {
                "type": "attack-pattern",
                "id": f"attack-pattern--{tid}",
                "name": tid,
                "created": f"{day}T00:00:00.000Z",
                "external_references": [{"source_name": "mitre-attack", "external_id": tid}],
            }
            for tid, day in techniques.items()
        ]
    }
    (tmp_path / "bundle.json").write_text(json.dumps(bundle))
    overrides_path = None
    if suppress_mapped:
        overrides_path = tmp_path / "overrides.yaml"
        overrides_path.write_text("suppress:\n  - technique: T1078\n    control: AC-2\n")
    ctid = {
        "metadata": {"attack_version": "16.1", "mapping_framework_version": "rev5", "last_update": "04/16/2025"},
        "mapping_objects": [
            {"attack_object_id": "T1078", "capability_id": "AC-2", "mapping_type": "mitigates", "status": "complete"},
            {"attack_object_id": "T8001", "capability_id": None, "mapping_type": None, "status": "non_mappable"},
        ],
    }
    (tmp_path / "ctid.json").write_text(json.dumps(ctid))
    index_path = None
    if attack_index:
        index = {
            "collections": [
                {
                    "name": "Enterprise ATT&CK",
                    "versions": [
                        {
                            "version": "16.1",
                            "url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/x.json",
                            "modified": "2024-11-12T14:00:00Z",
                        }
                    ],
                }
            ]
        }
        index_path = tmp_path / "attack_index.json"
        index_path.write_text(json.dumps(index))
    return IngestSources(
        benchmarks=[discovered(FIX / "rhel9_xccdf.xml")],
        cci_path=FIX / "cci_list.xml",
        attack_path=tmp_path / "bundle.json",
        ctid_path=tmp_path / "ctid.json",
        overrides_path=overrides_path,
        catalog_path=FIX / "oscal_catalog.json",
        attack_index_path=index_path,
    )


def test_build_kb__ctid_json_with_statuses__records_each_techniques_ctid_status(tmp_path):
    build_kb(_currency_sources(tmp_path), tmp_path / "kb.sqlite")
    conn = open_db_for_test(tmp_path / "kb.sqlite")
    status = dict(conn.execute("SELECT technique_id, ctid_status FROM techniques").fetchall())
    assert status["T1078"] == "mapped"
    assert status["T8001"] == "non_mappable"
    assert status["T9000"] == "absent"


def test_build_kb__attack_index_present__records_the_mappings_attack_release(tmp_path):
    build_kb(_currency_sources(tmp_path), tmp_path / "kb.sqlite")
    conn = open_db_for_test(tmp_path / "kb.sqlite")
    meta = {r[0]: r[1] for r in conn.execute("SELECT source_name, source_version FROM ingest_meta")}
    assert meta["ctid_attack_version"] == "16.1"
    assert meta["ctid_attack_release"] == "2024-11-12"


def test_build_kb__no_attack_index__ingests_without_a_release_row(tmp_path):
    # Hand-placed sources rarely include attack_index.json.
    build_kb(_currency_sources(tmp_path, attack_index=False), tmp_path / "kb.sqlite")
    conn = open_db_for_test(tmp_path / "kb.sqlite")
    names = {r[0] for r in conn.execute("SELECT source_name FROM ingest_meta")}
    assert "ctid_attack_version" in names and "ctid_attack_release" not in names


def test_load_ctid_status__non_mappable_names_a_revoked_id__marks_its_replacement(tmp_path):
    from stig_mcp.ingest.attack_parser import Revocation  # noqa: PLC0415
    from stig_mcp.ingest.mapping_loader import MappingSet  # noqa: PLC0415
    from stig_mcp.ingest.orchestrator import _load_ctid_status  # noqa: PLC0415
    from stig_mcp.kb.db import create_db  # noqa: PLC0415
    from tests.conftest import _OPENED_BY_TESTS  # noqa: PLC0415

    conn = create_db(tmp_path / "kb.sqlite")
    _OPENED_BY_TESTS.append(conn)
    conn.execute("INSERT INTO techniques(technique_id, name) VALUES ('T2', 'replacement')")
    _load_ctid_status(conn, MappingSet("v", [], non_mappable=frozenset({"T1"})), [Revocation("T1", "T2", "old")])
    status = conn.execute("SELECT ctid_status FROM techniques WHERE technique_id = 'T2'").fetchone()[0]
    conn.close()
    assert status == "non_mappable"


def test_load_ctid_status__id_is_both_mapped_and_non_mappable__stays_mapped(tmp_path):
    """Pins two lines of _load_ctid_status that no other fixture reaches, because none puts one
    technique id in both `ctid.pairs` and `ctid.non_mappable`: the `- mapped` on the
    `reviewed` line, and the `replacement.get(t, t)` follow it uses.

    T10 is in both sets directly. T20 is revoked to T21, which `pairs` maps, and T20 itself is
    named in `non_mappable`; only the follow makes that an overlap. Without `- mapped`, T10 and
    T21 turn non_mappable; without the follow, the literal T20 row turns non_mappable instead of
    staying absent. T30 is non_mappable only and must not flip to mapped just because the rest
    of this fixture does."""
    from stig_mcp.ingest.attack_parser import Revocation  # noqa: PLC0415
    from stig_mcp.ingest.mapping_loader import MappingSet, TechniqueControl  # noqa: PLC0415
    from stig_mcp.ingest.orchestrator import _load_ctid_status  # noqa: PLC0415
    from stig_mcp.kb.db import create_db  # noqa: PLC0415
    from tests.conftest import _OPENED_BY_TESTS  # noqa: PLC0415

    conn = create_db(tmp_path / "kb.sqlite")
    _OPENED_BY_TESTS.append(conn)
    for technique_id in ("T10", "T20", "T21", "T30"):
        conn.execute("INSERT INTO techniques(technique_id, name) VALUES (?, ?)", (technique_id, technique_id))
    ctid = MappingSet(
        "v",
        [TechniqueControl("T10", "AC-2", "ctid"), TechniqueControl("T21", "AC-2", "ctid")],
        non_mappable=frozenset({"T10", "T20", "T30"}),
    )
    _load_ctid_status(conn, ctid, [Revocation("T20", "T21", "old")])
    status = dict(conn.execute("SELECT technique_id, ctid_status FROM techniques").fetchall())
    conn.close()
    assert status["T10"] == "mapped"
    assert status["T21"] == "mapped"
    assert status["T30"] == "non_mappable"
    assert status["T20"] == "absent"


def test_build_kb__malformed_attack_index__warns_and_ingests(tmp_path, caplog):
    sources = _currency_sources(tmp_path)
    sources.attack_index_path.write_text("not json")
    build_kb(sources, tmp_path / "kb.sqlite")
    assert "attack_index.json" in caplog.text


_REPO = Path(__file__).parent.parent.parent


def _declared_license_files():
    """What pyproject.toml's license-files packages, as repository-relative paths."""
    patterns = tomllib.loads((_REPO / "pyproject.toml").read_text(encoding="utf-8"))["project"]["license-files"]
    return {p.relative_to(_REPO).as_posix() for pattern in patterns for p in _REPO.glob(pattern) if p.is_file()}


def test_build_kb__any_sources__stores_every_packaged_license_file_verbatim(tmp_path):
    out = tmp_path / "kb.sqlite"
    build_kb(_sources(), out)
    with closing(open_db_for_test(out)) as conn:
        stored = {r["name"]: r["text"] for r in conn.execute("SELECT name, text FROM notices")}
    assert set(stored) == _declared_license_files()
    for name, text in stored.items():
        expected = (_REPO / name).read_text(encoding="utf-8")
        assert text == expected, f"{name} differs: run uv sync --reinstall-package stig-mcp"


def test_license_texts__distribution_not_installed__names_the_install_step(monkeypatch):
    monkeypatch.setattr(orchestrator_module, "distributions", lambda **kwargs: iter(()))
    with pytest.raises(RuntimeError, match="is not installed"):
        orchestrator_module._license_texts()


def test_license_texts__distribution_ships_no_license_files__refuses(monkeypatch):
    class Bare:
        files = []

    monkeypatch.setattr(orchestrator_module, "distributions", lambda **kwargs: iter([Bare()]))
    with pytest.raises(RuntimeError, match="license-files"):
        orchestrator_module._license_texts()


class _FakeDistFile:
    """Stands in for importlib.metadata's PackagePath: a tuple of parts plus read_text."""

    def __init__(self, parts, text):
        self.parts = parts
        self._text = text

    def read_text(self, encoding):
        assert encoding == "utf-8"
        return self._text


def test_license_texts__dist_info_holds_a_non_license_subdirectory__stores_only_licenses(monkeypatch):
    """PEP 770 SBOMs live under dist-info/sboms/, which passes the depth check alone."""

    class WithSbom:
        files = [
            _FakeDistFile(("stig_mcp-0.1.0.dist-info", "sboms", "x.json"), "{}"),
            _FakeDistFile(("stig_mcp-0.1.0.dist-info", "licenses", "LICENSE"), "license text"),
        ]

    monkeypatch.setattr(orchestrator_module, "distributions", lambda **kwargs: iter([WithSbom()]))
    assert orchestrator_module._license_texts() == {"LICENSE": "license text"}


def test_license_texts__egg_info_shadows_the_install__reads_the_installed_dist_info(monkeypatch):
    """setuptools' editable build writes an egg-info into the source root, which pytest's
    sys.path can surface ahead of the real install; the loop must skip past it rather than
    stop on its license-free files."""

    class EggInfoShadow:
        files = [
            _FakeDistFile(("LICENSE",), "shadow license text"),
            _FakeDistFile(("licenses", "apache-2.0.txt"), "shadow apache text"),
        ]

    class RealDistInfo:
        files = [
            _FakeDistFile(("stig_mcp-0.1.0.dist-info", "licenses", "LICENSE"), "real license text"),
        ]

    monkeypatch.setattr(orchestrator_module, "distributions", lambda **kwargs: iter([EggInfoShadow(), RealDistInfo()]))
    assert orchestrator_module._license_texts() == {"LICENSE": "real license text"}


def test_build_kb__supporting_sources_and_artifacts__records_each_file_with_its_digest(tmp_path):
    archive = tmp_path / "U_Example_V1R1_STIG.zip"
    archive.write_bytes(b"not really a zip, only hashed")
    out = tmp_path / "kb.sqlite"
    sources = _sources(artifact_paths=(archive,))
    build_kb(sources, out)
    with closing(open_db_for_test(out)) as conn:
        rows = {r["name"]: (r["sha256"], r["size"]) for r in conn.execute("SELECT * FROM source_files")}
    expected = [archive, sources.cci_path, sources.attack_path, sources.ctid_path, sources.overrides_path]
    assert set(rows) == {p.name for p in expected}
    for path in expected:
        assert rows[path.name] == (hashlib.sha256(path.read_bytes()).hexdigest(), path.stat().st_size)


def test_build_kb__optional_source_absent__is_not_recorded(tmp_path):
    out = tmp_path / "kb.sqlite"
    build_kb(_sources(attack_index_path=tmp_path / "attack_index.json"), out)
    with closing(open_db_for_test(out)) as conn:
        names = {r["name"] for r in conn.execute("SELECT name FROM source_files")}
    assert "attack_index.json" not in names


def test_build_kb__two_inputs_share_a_basename__names_both_paths(tmp_path):
    clash = tmp_path / "elsewhere"
    clash.mkdir()
    twin = clash / "overrides.yaml"
    twin.write_text("{}\n")
    with pytest.raises(RuntimeError, match=r"overrides\.yaml.*elsewhere") as excinfo:
        build_kb(_sources(artifact_paths=(twin,)), tmp_path / "kb.sqlite")
    assert str(FIX / "overrides.yaml") in str(excinfo.value)


def test_select__a_newer_loose_release_of_a_major_the_library_ships__is_kept_beside_the_newer_major():
    # The vSphere shape after the same-key contest: the library shipped 7 and 8, the loose V7R4
    # beat the library's V7R3 at key (id, "7"), so only the library's 8 survived to _select.
    kept, summary = _select(
        [_entry("VMW_vSphere_STIG", "8", "library"), _entry("VMW_vSphere_STIG", "7", "product_zip", release=4)],
        library_keys={("VMW_vSphere_STIG", "8"), ("VMW_vSphere_STIG", "7")},
    )
    assert kept == [("VMW_vSphere_STIG", "7"), ("VMW_vSphere_STIG", "8")]
    assert summary["superseded_by_library"] == 0


def test_select__a_loose_major_the_library_no_longer_ships__is_still_dropped():
    # Same rows, but the library offered only 8: 7 is a retired major and must not come back.
    kept, summary = _select(
        [_entry("VMW_vSphere_STIG", "8", "library"), _entry("VMW_vSphere_STIG", "7", "product_zip", release=4)],
        library_keys={("VMW_vSphere_STIG", "8")},
    )
    assert kept == [("VMW_vSphere_STIG", "8")]
    assert summary["superseded_by_library"] == 1


def test_select__a_loose_copy_spelled_differently_at_a_shipped_major__is_still_dropped():
    # The library ships Foo_STIG 7 and the loose zip spells it foo_stig 7. The two literal keys
    # never meet in the release contest, so the loose row is not resident by beating the
    # library's copy, and the library row wins.
    kept, summary = _select(
        [
            _entry("Foo_STIG", "8", "library"),
            _entry("Foo_STIG", "7", "library", release=3),
            _entry("foo_stig", "7", "product_zip", release=4),
        ],
        library_keys={("Foo_STIG", "8"), ("Foo_STIG", "7")},
    )
    assert kept == [("Foo_STIG", "7"), ("Foo_STIG", "8")]
    assert summary["superseded_by_library"] == 1


_MAJOR_XCCDF = """<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1" id="{stig_id}">
  <title>Majortest {stig_id} Security Technical Implementation Guide</title>
  <version>{major}</version>
  <plain-text id="release-info">Release: {release} Benchmark Date: 01 Jul 2026</plain-text>
  <Group id="V-{serial}">
    <Rule id="SV-{serial}r1_rule" severity="medium">
      <title>Majortest rule {serial}.</title>
      <description>&lt;VulnDiscussion&gt;Test.&lt;/VulnDiscussion&gt;</description>
      <fixtext>Fix it.</fixtext>
      <check><check-content>Check it.</check-content></check>
      <ident system="http://iase.disa.mil/cci">CCI-000015</ident>
    </Rule>
  </Group>
</Benchmark>
"""


_VSPHERE = "VMW_vSphere_STIG"


def _major_file(tmp_path, major, release, serial, stig_id=_VSPHERE):
    path = tmp_path / f"{serial}.xml"
    path.write_text(_MAJOR_XCCDF.format(stig_id=stig_id, major=major, release=release, serial=serial))
    return path


def _two_major_library(tmp_path, loose_release):
    """The vSphere shape: the library ships majors 8 and 7, a loose zip supplies major 7."""
    return [
        discovered(_major_file(tmp_path, 8, 1, 900001)),
        discovered(_major_file(tmp_path, 7, 3, 900002)),
        discovered(
            _major_file(tmp_path, 7, loose_release, 900003),
            origin="product_zip",
            source_artifact=f"U_VMW_vSphere_V7R{loose_release}_STIG.zip",
        ),
    ]


def test_newest_benchmarks__library_keys__collects_the_library_key_that_lost_the_contest(tmp_path):
    summary = _skip_summary()
    library_keys = set()
    newest = orchestrator_module._newest_benchmarks(_two_major_library(tmp_path, 4), summary, library_keys=library_keys)
    assert library_keys == {("VMW_vSphere_STIG", "8"), ("VMW_vSphere_STIG", "7")}
    assert newest[("VMW_vSphere_STIG", "7")][1].origin == "product_zip"


def test_select__an_older_loose_release_of_a_shipped_major__leaves_the_library_copy(tmp_path):
    summary = _skip_summary()
    library_keys = set()
    newest = orchestrator_module._newest_benchmarks(_two_major_library(tmp_path, 2), summary, library_keys=library_keys)
    kept = select_benchmarks(newest, summary, library_keys=library_keys)
    assert {key: source.origin for key, (_parsed, source) in kept.items()} == {
        ("VMW_vSphere_STIG", "8"): "library",
        ("VMW_vSphere_STIG", "7"): "library",
    }


def test_build_kb__a_newer_loose_release_of_a_shipped_major__stores_it_beside_the_library_major(tmp_path, caplog):
    out = tmp_path / "kb.sqlite"
    with caplog.at_level(logging.WARNING):
        summary = build_kb(_sources(benchmarks=_two_major_library(tmp_path, 4)), out)
    conn = open_db_for_test(out)
    rows = sorted(tuple(r) for r in conn.execute("SELECT stig_id, version, origin, source_artifact FROM stigs"))
    assert rows == [
        ("VMW_vSphere_STIG", "7", "product_zip", "U_VMW_vSphere_V7R4_STIG.zip"),
        ("VMW_vSphere_STIG", "8", "library", "U_SRG-STIG_Library_July_2026.zip"),
    ]
    assert (summary["superseded_same_key"], summary["superseded_by_library"]) == (1, 0)
    assert "was not ingested" not in caplog.text


def _loose(path, artifact):
    return discovered(path, origin="product_zip", source_artifact=artifact)


def test_select__a_loose_zip_newer_at_both_shipped_majors__keeps_both(tmp_path):
    # The likeliest real trigger: DISA's vSphere 8.0 product zip carries both majors, so a zip
    # release between libraries beats the library at BOTH keys and no library row survives
    # for the id. Nothing may then fall to the local-major branch and drop the lower major.
    summary = _skip_summary()
    library_keys = set()
    benchmarks = [
        discovered(_major_file(tmp_path, 8, 1, 900011)),
        discovered(_major_file(tmp_path, 7, 3, 900012)),
        _loose(_major_file(tmp_path, 8, 2, 900013), "U_VMW_vSphere_Y26M09_STIG.zip"),
        _loose(_major_file(tmp_path, 7, 4, 900014), "U_VMW_vSphere_Y26M09_STIG.zip"),
    ]
    newest = orchestrator_module._newest_benchmarks(benchmarks, summary, library_keys=library_keys)
    kept = select_benchmarks(newest, summary, library_keys=library_keys)
    assert {key: source.origin for key, (_parsed, source) in kept.items()} == {
        (_VSPHERE, "8"): "product_zip",
        (_VSPHERE, "7"): "product_zip",
    }
    assert summary["superseded_by_newer_major"] == 0


def test_build_kb__a_governed_id_kept_from_a_loose_zip__raises_no_applicability_drift(tmp_path, caplog):
    # applicability.yaml maps vSphere 8.0 builds to majors 1 and 2 by id pattern, so dropping
    # the loose major-1 row would make the build warn that it holds no major 1.
    governed = "VMW_vSphere_8-0_ESXi_STIG"
    benchmarks = [
        discovered(_major_file(tmp_path, 2, 1, 900021, governed)),
        discovered(_major_file(tmp_path, 1, 1, 900022, governed)),
        _loose(_major_file(tmp_path, 1, 2, 900023, governed), "U_VMW_vSphere_8-0_Y26M09_STIG.zip"),
    ]
    with caplog.at_level(logging.WARNING):
        build_kb(_sources(benchmarks=benchmarks), tmp_path / "kb.sqlite")
    conn = open_db_for_test(tmp_path / "kb.sqlite")
    assert sorted(tuple(r) for r in conn.execute("SELECT version, origin FROM stigs")) == [
        ("1", "product_zip"),
        ("2", "library"),
    ]
    assert "Applicability entry" not in caplog.text
