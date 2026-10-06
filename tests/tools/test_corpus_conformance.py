import io
import logging
import shutil
import sqlite3
import zipfile
from contextlib import closing
from dataclasses import replace
from pathlib import Path

import pytest

from stig_mcp.ingest import id_corrections, inventory
from stig_mcp.ingest.orchestrator import build_kb
from stig_mcp.ingest.stig_parser import ParsedStig, parse_stig
from stig_mcp.kb.db import create_db
from tests.conftest import discovered, mssql_pair, open_db_for_test
from tools import corpus_conformance

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _corpus(tmp_path, *, with_junk=True):
    """A tiny corpus directory: one real product zip, plus files that must be accounted for."""
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    zip_path = corpus / "U_Test_Product_V1R1_STIG.zip"
    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.write(FIXTURES / "test_stig_xccdf.xml", "U_Test_Product_STIG_Manual-xccdf.xml")
    if with_junk:
        with zipfile.ZipFile(corpus / "U_Test_Product_V1R1_STIG_Ansible.zip", "w") as archive:
            archive.writestr("playbook.yml", "- hosts: all\n")
        (corpus / "RPM-GPG-KEY-SCC-5.11").write_text("not an archive", encoding="utf-8")
    return corpus


def test_phase_accounting__every_file_in_the_corpus__is_classified_or_reported(tmp_path):
    artifacts, findings = corpus_conformance.phase_accounting(_corpus(tmp_path))
    names = {artifact.path.name for artifact in artifacts}
    assert "U_Test_Product_V1R1_STIG.zip" in names
    # A non-archive is legitimately ignored, so it must not be reported as a defect.
    assert not [f for f in findings if f.severity == "error"]


def test_phase_accounting__an_unreadable_archive__is_reported_and_does_not_raise(tmp_path):
    corpus = _corpus(tmp_path, with_junk=False)
    (corpus / "U_Corrupt_V1R1_STIG.zip").write_bytes(b"PK\x03\x04 truncated")
    artifacts, findings = corpus_conformance.phase_accounting(corpus)
    assert any("U_Corrupt_V1R1_STIG.zip" in f.message for f in findings)


def test_unreadable_archive_finding__a_directory_named_like_a_zip__is_reported_not_raised(tmp_path):
    # zipfile.ZipFile() on a directory raises IsADirectoryError, a plain OSError that is
    # neither BadZipFile nor EOFError, so this fails against inventory.py's narrower pair and
    # only passes with the deliberately broad "except Exception" this phase needs.
    #
    # Fed directly to _unreadable_archive_finding rather than through phase_accounting:
    # inventory.classify() only classifies path.is_file() entries, so a directory can never
    # reach phase_accounting as an artifact in the first place, and this test is about what
    # the open step does with a corruption shape classify's name-only test cannot filter out.
    directory = tmp_path / "U_Test_V1R1_STIG.zip"
    directory.mkdir()
    artifact = inventory.Artifact(kind="product_zip", path=directory)

    finding = corpus_conformance._unreadable_archive_finding(artifact)

    assert finding is not None
    assert finding.severity == "error"
    assert "U_Test_V1R1_STIG.zip" in finding.message


def test_collect_benchmarks__a_corrupt_zip_among_the_artifacts__reports_it_in_log_messages(tmp_path):
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "U_Corrupt_V1R1_STIG.zip").write_bytes(b"PK\x03\x04 truncated")
    artifacts, _ = corpus_conformance.phase_accounting(corpus)
    staging = tmp_path / "extract"

    benchmarks, log_messages = corpus_conformance.collect_benchmarks(artifacts, staging)

    assert not benchmarks
    assert any("U_Corrupt_V1R1_STIG.zip" in message for message in log_messages)
    shutil.rmtree(staging)


def test_phase_parse__every_discovered_benchmark__yields_a_release_label(tmp_path):
    artifacts, _ = corpus_conformance.phase_accounting(_corpus(tmp_path))
    staging = tmp_path / "extract"
    benchmarks, _ = corpus_conformance.collect_benchmarks(artifacts, staging)
    parsed, findings = corpus_conformance.phase_parse(benchmarks)
    assert len(parsed) == 1
    assert not [f for f in findings if f.severity == "error"]
    shutil.rmtree(staging)


def test_compose_build_dir__product_zips_and_one_compilation__links_both_without_copying(tmp_path):
    # The published directory carries nine library compilations and inventory.classify refuses
    # more than one, so a run pairs the products with one compilation at a time.
    corpus = _corpus(tmp_path, with_junk=False)
    compilations = tmp_path / "compilations"
    compilations.mkdir()
    first = compilations / "U_SRG-STIG_Library_July_2026.zip"
    first.write_bytes(b"PK\x03\x04 pretend compilation")
    (compilations / "U_SRG-STIG_Library_April_2026.zip").write_bytes(b"PK\x03\x04 another")

    build = corpus_conformance.compose_build_dir(corpus, (first,), tmp_path / "build")
    names = sorted(p.name for p in build.iterdir())
    assert "U_Test_Product_V1R1_STIG.zip" in names
    assert "U_SRG-STIG_Library_July_2026.zip" in names
    # Exactly one compilation, or classify raises.
    assert "U_SRG-STIG_Library_April_2026.zip" not in names
    # Symlinked, not copied: nine 1GB compilations must not be duplicated per build.
    assert all((build / name).is_symlink() for name in names)
    assert (build / "U_SRG-STIG_Library_July_2026.zip").read_bytes() == b"PK\x03\x04 pretend compilation"


def test_compose_build_dir__no_compilation__links_only_the_products(tmp_path):
    corpus = _corpus(tmp_path, with_junk=False)
    build = corpus_conformance.compose_build_dir(corpus, (), tmp_path / "build")
    assert sorted(p.name for p in build.iterdir()) == ["U_Test_Product_V1R1_STIG.zip"]


def test_phase_accounting__a_loose_xccdf_file__is_not_reported_as_an_unreadable_archive(tmp_path):
    # A "loose" artifact is a bare *xccdf.xml file, not a zip, so phase_accounting must not
    # try to open it with zipfile: that would misreport every loose benchmark as corrupt.
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    shutil.copy(FIXTURES / "test_stig_xccdf.xml", corpus / "U_Test_Product_STIG_Manual-xccdf.xml")
    artifacts, findings = corpus_conformance.phase_accounting(corpus)
    assert {a.kind for a in artifacts} == {"loose"}
    assert not findings


def _unreadable(path, data=b"<?xml version='1.0'?><Benchmark id='X_STIG'/>"):
    """Write a file this user cannot read, or skip. Returns the path for a try/finally restore."""
    path.write_bytes(data)
    path.chmod(0o000)
    try:
        path.read_bytes()
    except OSError:
        return path
    path.chmod(0o644)
    pytest.skip("cannot make a file unreadable as this user")


def test_phase_accounting__an_unreadable_xml_the_glob_cannot_reach__is_reported_as_an_error(tmp_path):
    # The name has to be one LOOSE_GLOB misses, which is the whole population at risk. A file
    # named `..._Manual-xccdf.xml` is classified `loose` on its NAME without being read, so it
    # never reaches this loop; only a name _kind_of has to open can fail the read and arrive
    # here indistinguishable from a PDF. An unreadable .xml may be a benchmark just
    # lost, so calling it "legitimately ignored" at info is the mistake
    # _unreadable_archive_finding already prevents for a truncated zip. The warning inventory
    # logs cannot serve instead: _capture_logs wraps collect(), and the read fails earlier,
    # inside classify().
    corpus = _corpus(tmp_path, with_junk=False)
    locked = _unreadable(corpus / "EDB_Postgres_Advanced_Server_STIG.xml")
    try:
        _artifacts, findings = corpus_conformance.phase_accounting(corpus)
        errors = [f for f in findings if f.severity == "error" and "EDB_Postgres" in f.message]
        assert len(errors) == 1
        assert not [f for f in findings if f.severity == "info" and "EDB_Postgres" in f.message]
    finally:
        locked.chmod(0o644)


def test_phase_accounting__an_unreadable_xml_named_like_a_benchmark__is_classified_not_ignored(tmp_path):
    # The boundary that keeps the rule above honest, and the reason it is scoped to names the
    # glob misses. This file is taken on its name, so it becomes an artifact and travels on to
    # the parser, which reports the failure against it. It is neither ignored nor an accounting
    # error, and promoting it here would double-report it.
    corpus = _corpus(tmp_path, with_junk=False)
    locked = _unreadable(corpus / "U_Locked_STIG_Manual-xccdf.xml")
    try:
        artifacts, findings = corpus_conformance.phase_accounting(corpus)
        assert "U_Locked_STIG_Manual-xccdf.xml" in {a.path.name for a in artifacts}
        assert not [f for f in findings if "U_Locked_STIG" in f.message]
    finally:
        locked.chmod(0o644)


def test_phase_accounting__a_readable_xml_that_is_not_a_benchmark__stays_info(tmp_path):
    # The floor on the rule above. U_CCI_List.xml sits in a real sources dir and is genuinely
    # not an artifact, so it must not be promoted to an error just for being .xml.
    corpus = _corpus(tmp_path, with_junk=False)
    (corpus / "U_CCI_List.xml").write_bytes(b"<?xml version='1.0'?><cci_list><cci_items/></cci_list>")
    _artifacts, findings = corpus_conformance.phase_accounting(corpus)
    assert not [f for f in findings if f.severity == "error"]
    assert [f for f in findings if f.severity == "info" and "U_CCI_List.xml" in f.message]


def test_phase_accounting__an_unreadable_leading_dot_xml__is_still_reported_as_an_error(tmp_path):
    # The two suffix tests have to agree. inventory._kind_of asks `name.endswith(".xml")`, so
    # it opens this file; `Path(".xml").suffix` is EMPTY, because a leading-dot name is all
    # stem, so a harness guard written with Path.suffix would skip exactly the file _kind_of
    # had just read and failed on, and wave it through at info. No DISA artifact is named this
    # way; the point is that the two spellings of one rule cannot be allowed to drift.
    corpus = _corpus(tmp_path, with_junk=False)
    locked = _unreadable(corpus / ".xml")
    try:
        _artifacts, findings = corpus_conformance.phase_accounting(corpus)
        assert [f.severity for f in findings if ".xml" in f.message and "U_Test" not in f.message] == ["error"]
    finally:
        locked.chmod(0o644)


def test_phase_accounting__an_unreadable_uppercase_xml__is_still_reported_as_an_error(tmp_path):
    # The other axis the constant does not pin. _kind_of lowercases before testing, so it opens
    # A.XML; a harness guard that forgot to lowercase would skip the file _kind_of had just
    # failed on and wave it through at info, the same bug one axis over. Reaching for the
    # shared constant fixes the suffix, not the case, so the case needs its own fixture.
    corpus = _corpus(tmp_path, with_junk=False)
    locked = _unreadable(corpus / "U_LOCKED_STIG.XML")
    try:
        _artifacts, findings = corpus_conformance.phase_accounting(corpus)
        assert [f.severity for f in findings if "U_LOCKED" in f.message] == ["error"]
    finally:
        locked.chmod(0o644)


def test_phase_accounting__an_unreadable_file_that_is_not_xml__stays_info(tmp_path):
    # The other floor: nothing reads a PDF, so an unreadable one is still just ignorable junk.
    # Only .xml is a candidate benchmark, so only .xml earns the error.
    corpus = _corpus(tmp_path, with_junk=False)
    locked = _unreadable(corpus / "U_Overview.pdf", data=b"%PDF-1.4")
    try:
        _artifacts, findings = corpus_conformance.phase_accounting(corpus)
        assert not [f for f in findings if f.severity == "error"]
        assert [f for f in findings if f.severity == "info" and "U_Overview.pdf" in f.message]
    finally:
        locked.chmod(0o644)


def test_compose_build_dir__a_subdirectory_in_the_corpus__is_not_symlinked(tmp_path):
    corpus = _corpus(tmp_path, with_junk=False)
    (corpus / "leftover_extract_dir").mkdir()
    build = corpus_conformance.compose_build_dir(corpus, (), tmp_path / "build")
    assert "leftover_extract_dir" not in {p.name for p in build.iterdir()}


def test_phase_parse__a_benchmark_file_that_is_not_xml__is_reported_as_a_parse_error(tmp_path):
    broken = inventory.DiscoveredBenchmark(
        path=FIXTURES / "broken-xccdf.xml", origin="loose", source_artifact="broken-xccdf.xml", source_member=None
    )
    parsed, findings = corpus_conformance.phase_parse([broken])
    assert not parsed
    assert any("parse failed" in f.message for f in findings)


def test_phase_parse__a_benchmark_with_no_release_info__is_reported_not_silently_dropped(tmp_path):
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    broken = corpus / "U_Broken_V1R1_STIG.zip"
    xccdf = (
        '<?xml version="1.0"?>'
        '<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1" id="Broken_STIG">'
        "<title>Broken</title><version>1</version></Benchmark>"
    )
    with zipfile.ZipFile(broken, "w") as archive:
        archive.writestr("U_Broken_STIG_Manual-xccdf.xml", xccdf)
    artifacts, _ = corpus_conformance.phase_accounting(corpus)
    staging = tmp_path / "extract"
    benchmarks, _ = corpus_conformance.collect_benchmarks(artifacts, staging)
    _, findings = corpus_conformance.phase_parse(benchmarks)
    assert any("release" in f.message.lower() for f in findings)
    shutil.rmtree(staging)


FIX = FIXTURES


def _inputs_dir(tmp_path):
    """The non-STIG ingest inputs, copied so the harness never reads the real sources dir."""
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    for name, target in (
        ("test_stig_cci_list.xml", "U_CCI_List.xml"),
        ("attack_bundle.json", "enterprise-attack.json"),
        ("ctid_mappings.json", "ctid_mappings.json"),
        ("oscal_catalog.json", "nist_800_53_rev5_catalog.json"),
    ):
        shutil.copy(FIX / name, inputs / target)
    return inputs


def test_phase_invariants__a_clean_corpus_build__reports_no_error(tmp_path):
    artifacts, _ = corpus_conformance.phase_accounting(_corpus(tmp_path))
    kb = tmp_path / "kb.sqlite"
    summary = corpus_conformance.build_corpus_kb(artifacts, _inputs_dir(tmp_path), kb, tmp_path / "stage1")
    conn = corpus_conformance.open_kb(kb)
    findings = corpus_conformance.phase_invariants(conn, summary)
    conn.close()
    assert not [f for f in findings if f.severity == "error"], [f.message for f in findings]


def _permissive_kb(rows):
    """A stigs table without the real schema's NOT NULL constraints.

    phase_invariants must be tested against states the production schema forbids, because
    an invariant that can only be exercised on data the schema already rejects is not
    actually being tested. Building the table by hand is how the check gets proven."""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute(
        "CREATE TABLE stigs(stig_id TEXT, version TEXT, origin TEXT, source_artifact TEXT, release_label TEXT)"
    )
    conn.executemany("INSERT INTO stigs VALUES(?, ?, ?, ?, ?)", rows)
    for table in corpus_conformance._DEFENSE_TABLES:
        conn.execute(f"CREATE TABLE {table}(id TEXT)")  # noqa: S608
        conn.execute(f"INSERT INTO {table} VALUES('x')")  # noqa: S608
    return conn


def test_phase_invariants__a_row_missing_provenance__is_reported():
    conn = _permissive_kb([("A_STIG", "1", None, None, "V1R1")])
    findings = corpus_conformance.phase_invariants(conn, {"stig_files": 1, "rule_id_collisions": 0})
    conn.close()
    assert any("provenance" in f.message.lower() for f in findings)


def test_phase_invariants__the_same_key_stored_twice__is_reported():
    conn = _permissive_kb([("A_STIG", "1", "library", "lib.zip", "V1R1"), ("A_STIG", "1", "sunset", "sun.zip", "V1R1")])
    findings = corpus_conformance.phase_invariants(conn, {"stig_files": 2, "rule_id_collisions": 0})
    conn.close()
    assert any("stored 2 times" in f.message for f in findings)


def test_phase_invariants__two_spellings_of_one_id_both_stored__is_an_error():
    # The state orchestrator._id_key exists to prevent, and the one nothing else in this
    # harness can see: the reconciliation reads the ingest's own counters so it stays balanced,
    # the same_key replay never reaches _select, and the multi-major INFO groups on the literal
    # stig_id. The real shape is Solaris_11_X86_STIG v3 beside Solaris_11_x86_STIG v2.
    conn = _permissive_kb(
        [
            ("Solaris_11_X86_STIG", "3", "library", "lib.zip", "V3R1"),
            ("Solaris_11_x86_STIG", "2", "sunset", "sun.zip", "V2R9"),
        ]
    )
    findings = corpus_conformance.phase_invariants(conn, {"stig_files": 2, "rule_id_collisions": 0})
    conn.close()
    cased = [f for f in findings if "differ only in case" in f.message]
    # WARNING, not ERROR: eight true findings live in the staged corpus, and eight permanent
    # known-true errors would be the noise that hides the ninth.
    assert [f.severity for f in cased] == [corpus_conformance.WARNING]
    assert "Solaris_11_X86_STIG" in cased[0].message and "Solaris_11_x86_STIG" in cased[0].message


def test_phase_invariants__a_non_ascii_case_pair__is_still_reported():
    # The check folds with the ingest's own _id_key rather than SQL lower(): SQLite's lower() is
    # ASCII-only, so `ÄÖÜ_STIG` folds in the ingest and would not fold in the check. One
    # definition, not two.
    conn = _permissive_kb(
        [("ÄÖÜ_STIG", "2", "library", "lib.zip", "V2R1"), ("äöü_stig", "1", "sunset", "sun.zip", "V1R1")]
    )
    findings = corpus_conformance.phase_invariants(conn, {"stig_files": 2, "rule_id_collisions": 0})
    conn.close()
    assert [f.severity for f in findings if "differ only in case" in f.message] == [corpus_conformance.WARNING]


def test_phase_invariants__ids_that_differ_by_more_than_case__are_not_reported():
    # The other direction, and what makes the check mean something: a fold that collapsed two
    # genuinely different products would pass the test above while destroying the knowledge
    # base. _id_key returning a constant, or a truncation, is caught here.
    conn = _permissive_kb(
        [
            ("Solaris_11_X86_STIG", "3", "library", "lib.zip", "V3R1"),
            ("Solaris_11_SPARC_STIG", "3", "library", "lib.zip", "V3R1"),
        ]
    )
    findings = corpus_conformance.phase_invariants(conn, {"stig_files": 2, "rule_id_collisions": 0})
    conn.close()
    assert not [f for f in findings if "differ only in case" in f.message]


def test_phase_invariants__counts_that_do_not_reconcile__are_reported():
    # 5 parsed, 1 dropped, 1 stored. The missing 3 vanished without a counter, which is the
    # silent-drop class this whole harness exists to catch.
    conn = _permissive_kb([("A_STIG", "1", "library", "lib.zip", "V1R1")])
    summary = {"stig_files": 5, "rule_id_collisions": 0, "superseded_by_library": 1}
    findings = corpus_conformance.phase_invariants(conn, summary)
    conn.close()
    assert any("reconcile" in f.message for f in findings)


def _fake_parsed(stig_id="A_STIG", version="1", release=1, title=None):
    return ParsedStig(
        stig_id=stig_id,
        title=title or stig_id,
        benchmark_id=stig_id,
        version=version,
        release_info=f"Release: {release}",
    )


def _fake_discovered(origin, source_artifact):
    return inventory.DiscoveredBenchmark(
        path=Path("unused"), origin=origin, source_artifact=source_artifact, source_member=None
    )


def test__same_key_departures__a_non_library_winner_with_a_newer_release__reports_it_as_the_winner():
    library = (_fake_parsed(release=3), _fake_discovered("library", "lib.zip"))
    product = (_fake_parsed(release=5), _fake_discovered("product_zip", "product.zip"))
    assert corpus_conformance._same_key_departures([library, product]) == (1, {("A_STIG", "1"): "product.zip"})


def test__same_key_departures__the_library_wins_the_tie__reports_it_as_the_winner():
    # The counts in these two are identical by construction, since the total is the pair count
    # minus the distinct-key count. Only the winner distinguishes them, which is the point: the
    # count cannot observe the comparator and the winner is the only thing here that can.
    library = (_fake_parsed(release=5), _fake_discovered("library", "lib.zip"))
    product = (_fake_parsed(release=3), _fake_discovered("product_zip", "product.zip"))
    assert corpus_conformance._same_key_departures([library, product]) == (1, {("A_STIG", "1"): "lib.zip"})


def test_phase_invariants__the_stored_artifact_is_not_the_one_contest_picks__is_reported():
    # The check that watches the arbitration rather than the accounting. The departure count is
    # blind to _contest, so without this nothing in the harness would notice the comparator
    # changing: the corpus rows would move and every count would still agree.
    conn = _permissive_kb([("A_STIG", "1", "library", "lib.zip", "V1R3")])
    pairs = [
        (_fake_parsed(release=3), _fake_discovered("library", "lib.zip")),
        (_fake_parsed(release=5), _fake_discovered("product_zip", "product.zip")),
    ]
    summary = {
        "stig_files": 2,
        "rule_id_collisions": 0,
        "superseded_by_library": 0,
        "superseded_same_key": 1,
        "same_key_departures": 1,
        "superseded_by_newer_major": 0,
    }
    findings = corpus_conformance.phase_invariants(conn, summary, pairs)
    conn.close()
    assert any("stored a different artifact" in f.message for f in findings)
    assert any("stored lib.zip, replay product.zip" in f.message for f in findings)


def test_phase_invariants__the_ingest_counted_fewer_departures_than_the_replay__is_reported():
    # The harness is a conformance instrument, so it must be able to catch the ingest failing to
    # count, which is the exact defect this check exists for. Trusting the ingest's number here
    # would leave a future regression invisible.
    conn = _permissive_kb([("A_STIG", "1", "product_zip", "product.zip", "V1R5")])
    pairs = [
        (_fake_parsed(release=3), _fake_discovered("library", "lib.zip")),
        (_fake_parsed(release=5), _fake_discovered("product_zip", "product.zip")),
    ]
    # The departure is real but uncounted, so the reconciliation is deliberately left short by
    # one as well: that is the shape a build with this defect actually has. Both errors are
    # asserted, so a regression cannot pass by leaving only the other one firing.
    findings = corpus_conformance.phase_invariants(
        conn,
        {"stig_files": 2, "superseded_by_library": 0, "superseded_same_key": 0, "same_key_departures": 0},
        pairs,
    )
    conn.close()
    assert any("counted 0 of 1" in f.message for f in findings)
    assert any("minus dropped 0 is not stored 1" in f.message for f in findings)


def test_phase_invariants__the_major_level_contest_inflated_superseded_by_library__is_not_read_as_a_departure():
    # Why the check reads same_key_departures and not the two bins' sum. _select also writes
    # superseded_by_library for the major-level contest, which accounts for most of that bin on
    # a real build, so a harness adding the bins would report a false error on every healthy build.
    conn = _permissive_kb([("A_STIG", "1", "product_zip", "product.zip", "V1R5")])
    pairs = [
        (_fake_parsed(release=3), _fake_discovered("library", "lib.zip")),
        (_fake_parsed(release=5), _fake_discovered("product_zip", "product.zip")),
    ]
    summary = {
        "stig_files": 3,
        "rule_id_collisions": 0,
        # Written by _select's major-level contest, NOT by the same-key contest. This is the
        # inflation the check must ignore, and the fixture fails under a design that sums the
        # bins: it would compare 2 against the replay's 1 and report a false error.
        "superseded_by_library": 1,
        "superseded_same_key": 1,
        "same_key_departures": 1,
        "superseded_by_newer_major": 0,
    }
    findings = corpus_conformance.phase_invariants(conn, summary, pairs)
    conn.close()
    assert not [f for f in findings if f.severity == corpus_conformance.ERROR], [f.message for f in findings]


def test__same_key_departures__an_srg_shares_a_key_with_a_stig__is_not_a_departure():
    # _newest_benchmarks skips what document_kind rejects before the contest runs, so an SRG
    # sharing a key with a STIG never contests it. phase_parse keeps SRGs in parsed_pairs on
    # purpose, for its release_info and V#R# checks, so the replay has to drop them itself or
    # it predicts departures the ingest never had.
    stig = (_fake_parsed(release=3), _fake_discovered("library", "lib.zip"))
    srg = (
        _fake_parsed(release=5, title="A Security Requirements Guide"),
        _fake_discovered("product_zip", "srg.zip"),
    )
    assert corpus_conformance._same_key_departures([stig, srg])[0] == 0
    assert corpus_conformance._same_key_departures([stig, stig])[0] == 1


def test_phase_invariants__a_same_key_contest_resolved_by_a_non_library_winner__reconciles_without_a_false_error():
    # A newer-release product zip wins the same-key contest against the library's copy, so the
    # library's loss is not counted into superseded_by_library: the winner is not library-origin.
    # The ingest counts that loss into superseded_same_key instead, the summary here carries what
    # a real build of this input produces, and the reconciliation must close on the ingest's own
    # numbers rather than on an allowance the harness makes for it.
    conn = _permissive_kb([("A_STIG", "1", "product_zip", "product.zip", "V1R5")])
    library = (_fake_parsed(release=3), _fake_discovered("library", "lib.zip"))
    product = (_fake_parsed(release=5), _fake_discovered("product_zip", "product.zip"))
    summary = {
        "stig_files": 2,
        "rule_id_collisions": 0,
        "superseded_by_library": 0,
        "superseded_same_key": 1,
        "same_key_departures": 1,
        "superseded_by_newer_major": 0,
    }
    findings = corpus_conformance.phase_invariants(conn, summary, [library, product])
    conn.close()
    assert not [f for f in findings if f.severity == corpus_conformance.ERROR], [f.message for f in findings]


def test_phase_invariants__a_benchmark_that_vanishes_outside_any_same_key_contest__is_still_reported():
    # Every parsed pair here has a distinct key, so the same-key departure population measured
    # from parsed_pairs is zero. The mismatch must still be reported: a same-key allowance must
    # not mask an unrelated silent drop.
    conn = _permissive_kb([("A_STIG", "1", "library", "lib.zip", "V1R1")])
    first = (_fake_parsed(stig_id="A_STIG", version="1"), _fake_discovered("library", "lib.zip"))
    second = (_fake_parsed(stig_id="B_STIG", version="1"), _fake_discovered("product_zip", "b.zip"))
    summary = {"stig_files": 2, "rule_id_collisions": 0}
    findings = corpus_conformance.phase_invariants(conn, summary, [first, second])
    conn.close()
    assert any(f.severity == corpus_conformance.ERROR and "reconcile" in f.message for f in findings)


def _parsed_pairs(benchmarks):
    """What phase_parse hands the replay, for benchmarks assembled by hand rather than collected."""
    return [(parse_stig(benchmark.path), benchmark) for benchmark in benchmarks]


_SPLIT_KEYS = {("MS_SQL_Server_2012_Database_STIG", "1"), ("MS_SQL_Server_2012_Instance_STIG", "1")}
_PUBLISHED_KEY = ("MS_SQL_Server_2012_Database_Instance_STIG", "1")


def test_phase_invariants__a_build_that_split_a_same_key_collision__reports_no_error(tmp_path, minimal_sources):
    # Exercised through a whole build, not only the unit tests below: a corpus build carrying a
    # 2020-era library splits this collision, and a replay unaware of the split would report
    # "the ingest counted 0 of 1 same-key departure(s)" on a healthy build.
    minimal_sources.benchmarks = mssql_pair()
    out = tmp_path / "kb.sqlite"
    summary = build_kb(minimal_sources, out)

    conn = open_db_for_test(out)
    findings = corpus_conformance.phase_invariants(conn, summary, _parsed_pairs(mssql_pair()))
    conn.close()

    assert not [f for f in findings if f.severity == corpus_conformance.ERROR], [f.message for f in findings]
    assert any(f.severity == corpus_conformance.INFO and "id_corrections" in f.message for f in findings)


def test__same_key_departures__a_split_pair__counts_no_departure_and_predicts_both_winners():
    # The replay and the ingest must agree, or every corpus build carrying a 2020-era library
    # reports a phantom accounting error.
    total, winners = corpus_conformance._same_key_departures(_parsed_pairs(mssql_pair()))

    assert total == 0
    assert winners == dict.fromkeys(_SPLIT_KEYS, "U_SRG-STIG_Library_2020_01.zip")


def test__same_key_departures__a_half_the_map_cannot_name__declines_the_split_and_counts_a_departure():
    # The curation gap. _correct_pair returns None for a pair it cannot name in full, the ingest
    # degrades to the pre-split contest under the published id, and the replay must degrade with
    # it rather than predicting two rows that the build never stored.
    database, instance = mssql_pair()
    unnamed = replace(database, source_document="U_Unnamed_Copy/x-xccdf.xml")

    total, winners = corpus_conformance._same_key_departures(_parsed_pairs([unnamed, instance]))

    assert total == 1
    assert set(winners) == {_PUBLISHED_KEY}


def test__same_key_departures__an_uncorrectable_document_at_a_split_id__is_counted_as_a_departure():
    # A third document claiming an id this build already split, which the map cannot name. The
    # ingest routes that discard through _drop into superseded_same_key, so it is a real
    # departure: a replay that quietly ignored it would under-count and report a false error.
    foreign = discovered(
        FIXTURES / "mssql2012_instance_xccdf.xml",
        origin="library",
        source_artifact="U_Zebra.zip",
        source_document="U_Foreign_Copy/x-xccdf.xml",  # matches neither correction fragment
    )

    total, winners = corpus_conformance._same_key_departures(_parsed_pairs([foreign, *mssql_pair()]))

    assert total == 1
    assert set(winners) == _SPLIT_KEYS


def test__same_key_departures__a_correctable_document_at_a_split_id__contests_at_its_corrected_key():
    # The same arrival the map CAN name. It does not resurrect the published id; it contests at
    # its own corrected key, and wins here on _contest's source_artifact tiebreak, every earlier
    # component being equal. The winner is what proves the comparator ran: a replay that merely
    # counted the arrival would leave the library's copy resident and still report one departure.
    late_instance = replace(mssql_pair()[1], source_artifact="U_Second_Lib.zip")

    total, winners = corpus_conformance._same_key_departures(_parsed_pairs([*mssql_pair(), late_instance]))

    assert total == 1
    assert winners[("MS_SQL_Server_2012_Instance_STIG", "1")] == "U_Second_Lib.zip"
    assert winners[("MS_SQL_Server_2012_Database_STIG", "1")] == "U_SRG-STIG_Library_2020_01.zip"


def test__same_key_departures__a_corrected_id_already_held_by_another_benchmark__declines_the_split():
    # orchestrator._keys_available refuses to overwrite an id an earlier group already stored,
    # and declines the split rather than the incumbent. The replay carries one map across every
    # group for exactly this reason: without the occupancy check it would split, count nothing,
    # and report a false error against a build that ran the ordinary contest instead.
    occupant = discovered(FIXTURES / "rhel9_xccdf.xml", origin="library", source_artifact="U_Occupant.zip")
    occupant_parsed = replace(parse_stig(occupant.path), stig_id="MS_SQL_Server_2012_Database_STIG")
    assert occupant_parsed.version == "1", "the occupant has to claim the corrected key, not merely the id"

    total, winners = corpus_conformance._same_key_departures(
        [(occupant_parsed, occupant), *_parsed_pairs(mssql_pair())]
    )

    assert total == 1
    assert set(winners) == {("MS_SQL_Server_2012_Database_STIG", "1"), _PUBLISHED_KEY}
    assert winners[("MS_SQL_Server_2012_Database_STIG", "1")] == "U_Occupant.zip"


def test__same_key_departures__a_byte_identical_duplicate_of_one_half__is_still_routed_and_counted():
    # The split halves are excluded from the arrival loop by identity, as the ingest excludes
    # them. ParsedStig and DiscoveredBenchmark are both dataclasses, so a third document byte
    # identical to one half compares EQUAL to it while being a different object: an equality test
    # would drop it silently and predict no departure where the ingest counts one.
    duplicate = _parsed_pairs([mssql_pair()[1]])[0]
    pairs = [*_parsed_pairs(mssql_pair()), duplicate]
    assert duplicate == pairs[1], "the duplicate has to be equal to the instance half"
    assert duplicate is not pairs[1], "and it has to be a different object, or identity proves nothing"

    total, winners = corpus_conformance._same_key_departures(pairs)

    assert total == 1
    assert set(winners) == _SPLIT_KEYS


def test__same_key_departures__a_map_correcting_both_halves_to_one_id__declines_the_split():
    # The condition orchestrator._keys_available keeps live for a hand-built map: correcting both
    # halves to one id would re-create the collision the split exists to resolve, so the ingest
    # declines it. The shipped id_corrections.yaml cannot express this (id_corrections._unique
    # rejects it), which is why the map is injected rather than read from disk.
    merged = {
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

    total, winners = corpus_conformance._same_key_departures(_parsed_pairs(mssql_pair()), merged)

    assert total == 1
    assert set(winners) == {_PUBLISHED_KEY}


def test_phase_invariants__a_same_key_document_that_could_not_be_re_keyed__reports_an_error():
    # One counter carries three orchestrator events, and one of them, _warn_occupied, happens
    # with a map that names both documents correctly. A message blaming id_corrections.yaml on
    # every path sends that operator to add an entry that already exists, so both failure modes
    # are asserted rather than only the finding's existence: this line is their only record of
    # the event, since the composition keeps no trace of the discarded benchmark.
    conn = _permissive_kb([("A_STIG", "1", "library", "lib.zip", "V1R1")])
    findings = corpus_conformance.phase_invariants(conn, {"stig_files": 1, "same_key_collision_unmapped": 1})
    conn.close()
    errors = [f.message for f in findings if f.severity == corpus_conformance.ERROR]
    assert any("id_corrections" in message for message in errors), errors
    assert any("does not name the document" in message and "already held" in message for message in errors), errors


def test_phase_invariants__documents_re_keyed_by_id_corrections__are_reported_as_info():
    conn = _permissive_kb(
        [("A_STIG", "1", "library", "lib.zip", "V1R1"), ("B_STIG", "1", "library", "lib.zip", "V1R1")]
    )
    findings = corpus_conformance.phase_invariants(conn, {"stig_files": 2, "id_corrections_applied": 2})
    conn.close()
    assert any(f.severity == corpus_conformance.INFO and "id_corrections" in f.message for f in findings)
    # A correction that was applied is news, not a defect: it must not raise the error count of
    # an otherwise clean corpus build.
    assert not [f for f in findings if f.severity == corpus_conformance.ERROR], [f.message for f in findings]


def test_phase_determinism__the_same_corpus_in_reverse_order__builds_the_same_composition(tmp_path):
    # The same-key arbitration must make the winner independent of classify's filename
    # ordering. Reversing the artifact list is the maximal perturbation of that.
    artifacts, _ = corpus_conformance.phase_accounting(_corpus(tmp_path))
    findings = corpus_conformance.phase_determinism(artifacts, _inputs_dir(tmp_path), tmp_path / "det")
    assert not [f for f in findings if f.severity == "error"], [f.message for f in findings]


def test_phase_invariants__rule_id_collisions_in_the_summary__is_reported():
    conn = _permissive_kb([("A_STIG", "1", "library", "lib.zip", "V1R1")])
    findings = corpus_conformance.phase_invariants(conn, {"stig_files": 1, "rule_id_collisions": 3})
    conn.close()
    assert any("collision" in f.message.lower() for f in findings)


def test_phase_invariants__documents_that_identify_as_neither__are_reported():
    # The tripwire for DISA changing how they title benchmarks. Silence here would mean
    # content dropping out of the KB with only a summary integer to show for it.
    conn = _permissive_kb([("A_STIG", "1", "library", "lib.zip", "V1R1")])
    findings = corpus_conformance.phase_invariants(conn, {"stig_files": 1, "skipped_unclassified": 8})
    conn.close()
    assert any("neither STIG nor SRG" in f.message for f in findings)


def test_phase_determinism__two_same_origin_duplicates__agree_in_either_order(tmp_path):
    # Both zips are product_zip supplying one key at one release, so the origin tiebreak alone
    # cannot separate them. _contest's status_date and source_artifact components still order
    # them, so the forward and reverse builds must agree at the whole-build scale
    # phase_determinism measures.
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    with zipfile.ZipFile(corpus / "U_TestDup_V1R1_STIG_A.zip", "w") as archive:
        archive.write(FIXTURES / "test_stig_xccdf.xml", "U_TestDup_STIG_Manual-xccdf.xml")
    with zipfile.ZipFile(corpus / "U_TestDup_V1R1_STIG_B.zip", "w") as archive:
        archive.write(FIXTURES / "test_stig_xccdf.xml", "U_TestDup_STIG_Manual-xccdf.xml")
    artifacts, _ = corpus_conformance.phase_accounting(corpus)
    findings = corpus_conformance.phase_determinism(artifacts, _inputs_dir(tmp_path), tmp_path / "det")
    assert not [f for f in findings if f.severity == corpus_conformance.ERROR], [f.message for f in findings]


def test_phase_determinism__the_two_builds_disagree__is_reported(tmp_path, monkeypatch):
    # The alarm itself. _contest is a total order, so no corpus this harness can be handed will
    # make the forward and reverse builds disagree, and the branch that reports a disagreement is
    # precisely what would catch a future change reintroducing walk-order dependence. Forcing
    # the two compositions apart is the only way to prove that branch still fires.
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    with zipfile.ZipFile(corpus / "U_TestDup_V1R1_STIG_A.zip", "w") as archive:
        archive.write(FIXTURES / "test_stig_xccdf.xml", "U_TestDup_STIG_Manual-xccdf.xml")
    artifacts, _ = corpus_conformance.phase_accounting(corpus)
    divergent = iter(
        [
            [("A_STIG", "1", "product_zip", "walked_first.zip", "V1R1")],
            [("A_STIG", "1", "product_zip", "walked_second.zip", "V1R1")],
        ]
    )
    monkeypatch.setattr(corpus_conformance, "composition", lambda conn: next(divergent))
    findings = corpus_conformance.phase_determinism(artifacts, _inputs_dir(tmp_path), tmp_path / "det")
    assert any("composition depends on artifact order" in f.message for f in findings)
    assert any("1 row(s) differ" in f.message for f in findings)


def test_phase_determinism__a_library_copy_against_a_hand_placed_product_zip__the_library_wins_either_order(
    tmp_path,
):
    # The bug this whole check exists to catch, reproduced at fixture scale rather than
    # only argued from the two-fixture unit test: a library compilation and a hand-placed
    # product zip supply the identical (stig_id, version, release), and _origin_rank must
    # make the library win regardless of which artifact classify/collect walks first.
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    with zipfile.ZipFile(corpus / "U_Test_Product_V1R1_STIG.zip", "w") as archive:
        archive.write(FIXTURES / "test_stig_xccdf.xml", "U_Test_Product_STIG_Manual-xccdf.xml")

    compilations = tmp_path / "compilations"
    compilations.mkdir()
    library_zip = compilations / "U_SRG-STIG_Library_July_2026.zip"
    inner_buffer = io.BytesIO()
    with zipfile.ZipFile(inner_buffer, "w") as inner:
        inner.write(FIXTURES / "test_stig_xccdf.xml", "U_Test_Product_STIG_Manual-xccdf.xml")
    with zipfile.ZipFile(library_zip, "w") as outer:
        outer.writestr("U_Test_Product_STIG.zip", inner_buffer.getvalue())

    build = corpus_conformance.compose_build_dir(corpus, (library_zip,), tmp_path / "build")
    artifacts, _ = corpus_conformance.phase_accounting(build)
    findings = corpus_conformance.phase_determinism(artifacts, _inputs_dir(tmp_path), tmp_path / "det")
    assert not [f for f in findings if f.severity == "error"], [f.message for f in findings]


def test_phase_resolver__a_corpus_holding_none_of_the_pinned_products__reports_info_not_error(tmp_path):
    # The tiny test corpus holds one invented product, so every pinned query is expected to
    # miss. A miss on a corpus that does not contain the product is not a regression.
    artifacts, _ = corpus_conformance.phase_accounting(_corpus(tmp_path))
    kb = tmp_path / "kb.sqlite"
    corpus_conformance.build_corpus_kb(artifacts, _inputs_dir(tmp_path), kb, tmp_path / "stage1")
    conn = corpus_conformance.open_kb(kb)
    findings = corpus_conformance.phase_resolver(conn)
    conn.close()
    assert findings
    assert not [f for f in findings if f.severity == "error"]


def test_write_report__findings_and_a_summary__writes_a_readable_markdown_file(tmp_path):
    findings = [
        corpus_conformance.Finding("invariants", corpus_conformance.ERROR, "something reconciled badly"),
        corpus_conformance.Finding("parse", corpus_conformance.INFO, "a note"),
    ]
    summaries = [("no compilation", {"stigs": 3, "stig_files": 4})]
    path = corpus_conformance.write_report(findings, summaries, tmp_path / "report.md")
    text = path.read_text(encoding="utf-8")
    assert "something reconciled badly" in text
    # The error count is what a reader looks at first, so it has to be in the report.
    assert "1 error" in text
    assert "### no compilation" in text


def test_write_report__no_findings__reports_none_in_the_findings_section(tmp_path):
    path = corpus_conformance.write_report([], [("no compilation", {"stigs": 0})], tmp_path / "report.md")
    text = path.read_text(encoding="utf-8")
    assert "0 error, 0 warning, 0 info" in text
    assert "None." in text


def test_write_report__two_builds__renders_each_summary_under_its_own_heading(tmp_path):
    # One summary per build, under its own heading: see write_report's docstring for why.
    summaries = [
        ("U_SRG-STIG_Library_April_2026.zip", {"stigs": 1, "stig_files": 1}),
        ("U_SRG-STIG_Library_July_2026.zip", {"stigs": 2, "stig_files": 2}),
    ]
    path = corpus_conformance.write_report([], summaries, tmp_path / "report.md")
    text = path.read_text(encoding="utf-8")
    assert "### U_SRG-STIG_Library_April_2026.zip" in text
    assert "### U_SRG-STIG_Library_July_2026.zip" in text
    # Each build's own counters, not a merge of the two: the second build's summary must not
    # overwrite the first's in the rendered text.
    assert "{'stigs': 1, 'stig_files': 1}" in text
    assert "{'stigs': 2, 'stig_files': 2}" in text


def _rhel_corpus(tmp_path):
    """A corpus holding a real RHEL 9 benchmark, whose stig_id matches a pinned query."""
    corpus = tmp_path / "rhel_corpus"
    corpus.mkdir()
    with zipfile.ZipFile(corpus / "U_RHEL_9_V1R1_STIG.zip", "w") as archive:
        archive.write(FIXTURES / "rhel9_xccdf.xml", "U_RHEL_9_STIG_Manual-xccdf.xml")
    return corpus


def _rhel_inputs_dir(tmp_path):
    """Ingest inputs whose CCI list actually covers the RHEL 9 fixture's CCI references.

    _inputs_dir's test_stig_cci_list.xml only carries the CCIs the tiny invented product
    references; the real rhel9_xccdf.xml fixture needs the fuller cci_list.xml fixture,
    the same one tests/ingest and tests/kb use alongside this benchmark."""
    inputs = tmp_path / "rhel_inputs"
    inputs.mkdir()
    for name, target in (
        ("cci_list.xml", "U_CCI_List.xml"),
        ("attack_bundle.json", "enterprise-attack.json"),
        ("ctid_mappings.json", "ctid_mappings.json"),
        ("oscal_catalog.json", "nist_800_53_rev5_catalog.json"),
    ):
        shutil.copy(FIX / name, inputs / target)
    return inputs


def test_phase_resolver__a_corpus_holding_a_pinned_product__resolves_it_without_error(tmp_path):
    artifacts, _ = corpus_conformance.phase_accounting(_rhel_corpus(tmp_path))
    kb = tmp_path / "kb.sqlite"
    corpus_conformance.build_corpus_kb(artifacts, _rhel_inputs_dir(tmp_path), kb, tmp_path / "stage1")
    conn = corpus_conformance.open_kb(kb)
    findings = corpus_conformance.phase_resolver(conn)
    conn.close()
    # 'RedHat Linux Server 9' must resolve to the RHEL_9 benchmark held by this corpus,
    # cleanly enough that neither the wrong-product error nor the low-confidence warning fires.
    assert not [f for f in findings if "RHEL_9" in f.message or "RedHat" in f.message]


def test_phase_resolver__resolve_returns_the_wrong_product__reports_error(tmp_path, monkeypatch):
    # The held-product check only lets the RHEL_9 query through to resolve(); the other four
    # pinned queries are skipped at info because this corpus holds none of those products.
    # resolve() itself is patched here so the wrong-product branch is exercised directly,
    # rather than depending on a real confusion between two fuzzy-matched benchmarks.
    artifacts, _ = corpus_conformance.phase_accounting(_rhel_corpus(tmp_path))
    kb = tmp_path / "kb.sqlite"
    corpus_conformance.build_corpus_kb(artifacts, _rhel_inputs_dir(tmp_path), kb, tmp_path / "stage1")
    conn = corpus_conformance.open_kb(kb)
    monkeypatch.setattr(
        corpus_conformance,
        "resolve",
        lambda conn, query: [{"stig_id": "Windows_11_STIG", "high_confidence": True, "version_coverage": []}],
    )
    findings = corpus_conformance.phase_resolver(conn)
    conn.close()
    assert any(f.severity == corpus_conformance.ERROR and "resolved to Windows_11_STIG" in f.message for f in findings)


def test_phase_resolver__resolve_returns_a_low_confidence_match__reports_warning(tmp_path, monkeypatch):
    artifacts, _ = corpus_conformance.phase_accounting(_rhel_corpus(tmp_path))
    kb = tmp_path / "kb.sqlite"
    corpus_conformance.build_corpus_kb(artifacts, _rhel_inputs_dir(tmp_path), kb, tmp_path / "stage1")
    conn = corpus_conformance.open_kb(kb)
    monkeypatch.setattr(
        corpus_conformance,
        "resolve",
        lambda conn, query: [{"stig_id": "RHEL_9_STIG", "high_confidence": False, "version_coverage": []}],
    )
    findings = corpus_conformance.phase_resolver(conn)
    conn.close()
    assert any(f.severity == corpus_conformance.WARNING and "not high confidence" in f.message for f in findings)


def test__compilations_in__no_directory__returns_a_single_empty_build():
    assert corpus_conformance._compilations_in(None) == [()]


def test__compilations_in__an_empty_directory__falls_back_to_a_single_empty_build(tmp_path):
    empty = tmp_path / "compilations"
    empty.mkdir()
    assert corpus_conformance._compilations_in(empty) == [()]


def test__compilations_in__a_directory_of_libraries_and_no_sunset__returns_one_build_per_library(tmp_path):
    compilations = tmp_path / "compilations"
    compilations.mkdir()
    (compilations / "U_SRG-STIG_Library_July_2026.zip").write_bytes(b"PK\x03\x04 b")
    (compilations / "U_SRG-STIG_Library_April_2026.zip").write_bytes(b"PK\x03\x04 a")

    found = corpus_conformance._compilations_in(compilations)

    assert [tuple(path.name for path in build) for build in found] == [
        ("U_SRG-STIG_Library_April_2026.zip",),
        ("U_SRG-STIG_Library_July_2026.zip",),
    ]


def test__compilations_in__a_sunset_archive_staged_with_libraries__is_paired_into_every_build(tmp_path):
    # The sunset archive pairs with each library rather than getting a solo build, or the
    # library-vs-sunset arbitration _select exists for is never exercised at corpus scale.
    compilations = tmp_path / "compilations"
    compilations.mkdir()
    (compilations / "U_SRG-STIG_Library_July_2026.zip").write_bytes(b"PK\x03\x04 b")
    (compilations / "U_SRG-STIG_Library_April_2026.zip").write_bytes(b"PK\x03\x04 a")
    (compilations / "U_Rev_4_SRG-STIG_Sunset_Compilation.zip").write_bytes(b"PK\x03\x04 s")

    found = corpus_conformance._compilations_in(compilations)

    assert [tuple(path.name for path in build) for build in found] == [
        ("U_SRG-STIG_Library_April_2026.zip", "U_Rev_4_SRG-STIG_Sunset_Compilation.zip"),
        ("U_SRG-STIG_Library_July_2026.zip", "U_Rev_4_SRG-STIG_Sunset_Compilation.zip"),
    ]


def test__compilations_in__a_sunset_archive_with_no_library_staged__gets_a_build_of_its_own(tmp_path):
    compilations = tmp_path / "compilations"
    compilations.mkdir()
    (compilations / "U_Rev_4_SRG-STIG_Sunset_Compilation.zip").write_bytes(b"PK\x03\x04 s")

    found = corpus_conformance._compilations_in(compilations)

    assert [tuple(path.name for path in build) for build in found] == [("U_Rev_4_SRG-STIG_Sunset_Compilation.zip",)]


def test_run_once__a_clean_corpus_with_no_compilation__labels_every_finding(tmp_path):
    findings, summary = corpus_conformance.run_once(
        _corpus(tmp_path), _inputs_dir(tmp_path), tmp_path / "work", (), skip_determinism=True
    )
    assert summary["stigs"] == 1
    assert all(f.message.startswith("[no compilation] ") for f in findings)
    assert not [f for f in findings if f.severity == "error"], [f.message for f in findings]
    assert any(f.phase == "cost" for f in findings)
    # Pins the wiring: without the call in run_once, phase_margin exists and never runs.
    assert any("distinctiveness margin" in f.message for f in findings)


def test_run_once__a_compilation_paired_with_the_products__labels_findings_with_its_name(tmp_path):
    corpus = _corpus(tmp_path, with_junk=False)
    compilations = tmp_path / "compilations"
    compilations.mkdir()
    library_zip = compilations / "U_SRG-STIG_Library_July_2026.zip"
    inner_buffer = io.BytesIO()
    with zipfile.ZipFile(inner_buffer, "w") as inner:
        inner.write(FIXTURES / "test_stig_xccdf.xml", "U_Test_Product_STIG_Manual-xccdf.xml")
    with zipfile.ZipFile(library_zip, "w") as outer:
        outer.writestr("U_Test_Product_STIG.zip", inner_buffer.getvalue())

    findings, summary = corpus_conformance.run_once(
        corpus, _inputs_dir(tmp_path), tmp_path / "work", (library_zip,), skip_determinism=False
    )

    assert summary["stigs"] == 1
    assert all(f.message.startswith("[U_SRG-STIG_Library_July_2026.zip] ") for f in findings)


def test_run_once__a_truncated_compilation__reports_an_error_and_does_not_raise(tmp_path):
    # inventory._from_compilation opens the outer zip with no guard at all, unlike a product
    # zip. A truncated compilation is the most likely artifact to get here: compilations are
    # 150-400MB downloads, the ones most likely to fail partway.
    corpus = _corpus(tmp_path, with_junk=False)
    compilations = tmp_path / "compilations"
    compilations.mkdir()
    corrupt = compilations / "U_SRG-STIG_Library_July_2026.zip"
    corrupt.write_bytes(b"PK\x03\x04 truncated")

    findings, summary = corpus_conformance.run_once(
        corpus, _inputs_dir(tmp_path), tmp_path / "work", (corrupt,), skip_determinism=True
    )

    assert summary == {}
    assert any(f.severity == corpus_conformance.ERROR for f in findings)
    assert all(f.message.startswith("[U_SRG-STIG_Library_July_2026.zip] ") for f in findings)


def test_main__a_cli_invocation_over_a_clean_corpus__writes_a_report_and_exits_zero(monkeypatch, tmp_path, capsys):
    report_path = tmp_path / "report.md"
    monkeypatch.setattr(
        "sys.argv",
        [
            "corpus_conformance",
            "--corpus",
            str(_corpus(tmp_path)),
            "--inputs",
            str(_inputs_dir(tmp_path)),
            "--report",
            str(report_path),
            "--skip-determinism",
        ],
    )

    with pytest.raises(SystemExit) as exc_info:
        corpus_conformance.main()

    assert exc_info.value.code == 0
    text = report_path.read_text(encoding="utf-8")
    assert "0 error" in text
    captured = capsys.readouterr()
    assert "0 error(s)" in captured.out


def test_main__a_cli_invocation_with_a_compilations_directory__runs_once_per_compilation(monkeypatch, tmp_path):
    corpus = _corpus(tmp_path, with_junk=False)
    compilations = tmp_path / "compilations"
    compilations.mkdir()
    library_zip = compilations / "U_SRG-STIG_Library_July_2026.zip"
    inner_buffer = io.BytesIO()
    with zipfile.ZipFile(inner_buffer, "w") as inner:
        inner.write(FIXTURES / "test_stig_xccdf.xml", "U_Test_Product_STIG_Manual-xccdf.xml")
    with zipfile.ZipFile(library_zip, "w") as outer:
        outer.writestr("U_Test_Product_STIG.zip", inner_buffer.getvalue())
    report_path = tmp_path / "report.md"
    monkeypatch.setattr(
        "sys.argv",
        [
            "corpus_conformance",
            "--corpus",
            str(corpus),
            "--inputs",
            str(_inputs_dir(tmp_path)),
            "--compilations",
            str(compilations),
            "--report",
            str(report_path),
            "--skip-determinism",
        ],
    )

    with pytest.raises(SystemExit) as exc_info:
        corpus_conformance.main()

    assert exc_info.value.code == 0
    text = report_path.read_text(encoding="utf-8")
    assert "[U_SRG-STIG_Library_July_2026.zip]" in text


def test_main__one_compilation_raises__the_others_still_produce_findings_in_the_report(monkeypatch, tmp_path):
    # After a multi-hour run over nine compilations, one build raising must not discard the
    # findings from every other build and leave no report at all.
    corpus = _corpus(tmp_path, with_junk=False)
    compilations = tmp_path / "compilations"
    compilations.mkdir()
    good = compilations / "U_SRG-STIG_Library_April_2026.zip"
    inner_buffer = io.BytesIO()
    with zipfile.ZipFile(inner_buffer, "w") as inner:
        inner.write(FIXTURES / "test_stig_xccdf.xml", "U_Test_Product_STIG_Manual-xccdf.xml")
    with zipfile.ZipFile(good, "w") as outer:
        outer.writestr("U_Test_Product_STIG.zip", inner_buffer.getvalue())
    bad = compilations / "U_SRG-STIG_Library_July_2026.zip"
    bad.write_bytes(b"irrelevant: run_once is patched to raise for this one below")

    real_run_once = corpus_conformance.run_once

    def flaky_run_once(corpus_dir, inputs_dir, work, build_compilations, skip_determinism):
        if any(path.name == bad.name for path in build_compilations):
            raise RuntimeError("simulated build failure")
        return real_run_once(corpus_dir, inputs_dir, work, build_compilations, skip_determinism)

    monkeypatch.setattr(corpus_conformance, "run_once", flaky_run_once)
    report_path = tmp_path / "report.md"
    monkeypatch.setattr(
        "sys.argv",
        [
            "corpus_conformance",
            "--corpus",
            str(corpus),
            "--inputs",
            str(_inputs_dir(tmp_path)),
            "--compilations",
            str(compilations),
            "--report",
            str(report_path),
            "--skip-determinism",
        ],
    )

    with pytest.raises(SystemExit) as exc_info:
        corpus_conformance.main()

    assert exc_info.value.code == 1
    text = report_path.read_text(encoding="utf-8")
    assert "simulated build failure" in text
    assert "[U_SRG-STIG_Library_April_2026.zip]" in text


def _library_zip(path):
    """A valid zip-of-zips at path, holding one benchmark, so it classifies as `library`."""
    inner_buffer = io.BytesIO()
    with zipfile.ZipFile(inner_buffer, "w") as inner:
        inner.write(FIXTURES / "test_stig_xccdf.xml", "U_Test_Product_STIG_Manual-xccdf.xml")
    with zipfile.ZipFile(path, "w") as outer:
        outer.writestr("U_Test_Product_STIG.zip", inner_buffer.getvalue())


def test_main__two_compilations__the_report_carries_each_builds_own_summary(monkeypatch, tmp_path):
    # Through the CLI, not only write_report (whose docstring gives the reason): with two
    # library compilations staged, a run produces two builds and the report's Ingest summary
    # must show both.
    corpus = _corpus(tmp_path, with_junk=False)
    compilations = tmp_path / "compilations"
    compilations.mkdir()
    _library_zip(compilations / "U_SRG-STIG_Library_April_2026.zip")
    _library_zip(compilations / "U_SRG-STIG_Library_July_2026.zip")
    report_path = tmp_path / "report.md"
    monkeypatch.setattr(
        "sys.argv",
        [
            "corpus_conformance",
            "--corpus",
            str(corpus),
            "--inputs",
            str(_inputs_dir(tmp_path)),
            "--compilations",
            str(compilations),
            "--report",
            str(report_path),
            "--skip-determinism",
        ],
    )

    with pytest.raises(SystemExit):
        corpus_conformance.main()

    text = report_path.read_text(encoding="utf-8")
    assert "### U_SRG-STIG_Library_April_2026.zip" in text
    assert "### U_SRG-STIG_Library_July_2026.zip" in text


def test__tier_divergence_findings__no_directory__reports_nothing():
    assert corpus_conformance._tier_divergence_findings(None) == []


def test__tier_divergence_findings__names_matching_their_own_globs__report_nothing(tmp_path):
    compilations = tmp_path / "compilations"
    compilations.mkdir()
    (compilations / "U_SRG-STIG_Library_July_2026.zip").write_bytes(b"PK\x03\x04 lib, never opened")
    (compilations / "U_Rev_4_SRG-STIG_Sunset_Compilation.zip").write_bytes(b"PK\x03\x04 sunset, never opened")
    # A plain product zip is tiered BENCHMARK, not COMPILATION, so it must be skipped before
    # the glob check even runs, not merely pass the glob check by accident.
    (compilations / "U_RHEL_9_V1R1_STIG.zip").write_bytes(b"PK\x03\x04 product, never opened")
    assert corpus_conformance._tier_divergence_findings(compilations) == []


def test__tier_divergence_findings__a_manifest_tiered_compilation_matching_neither_glob__is_reported(tmp_path):
    # The dormant divergence this check exists to catch: catalog._COMPILATION_MARKERS
    # is broader than inventory's LIBRARY_GLOB/SUNSET_GLOB pair, so a name tiered COMPILATION
    # here but matching neither glob would build into no compilation at all, silently.
    compilations = tmp_path / "compilations"
    compilations.mkdir()
    (compilations / "U_SRG-STIG_Bundle_2027.zip").write_bytes(b"PK\x03\x04 not opened, name only")

    findings = corpus_conformance._tier_divergence_findings(compilations)

    assert [f.severity for f in findings] == [corpus_conformance.INFO]
    assert "U_SRG-STIG_Bundle_2027.zip" in findings[0].message
    assert "tiered COMPILATION" in findings[0].message


def test__tier_divergence_findings__a_cui_name__is_skipped_not_raised(tmp_path):
    # tier_of raises ValueError on a CUI_ name; a corpus-wide check must not crash over one,
    # even though this project refuses to stage CUI content everywhere else already.
    compilations = tmp_path / "compilations"
    compilations.mkdir()
    (compilations / "CUI_SRG-STIG_Library_July_2026.zip").write_bytes(b"PK\x03\x04 cui, never opened")
    assert corpus_conformance._tier_divergence_findings(compilations) == []


def test_main__a_manifest_tiered_compilation_matching_no_glob__reports_it(monkeypatch, tmp_path):
    # Pins the wiring: without the call in main() the check exists and never runs, the same
    # shape as test_phase_resolver__a_benchmark_with_a_padded_major__reports_it.
    corpus = _corpus(tmp_path, with_junk=False)
    compilations = tmp_path / "compilations"
    compilations.mkdir()
    _library_zip(compilations / "U_SRG-STIG_Library_July_2026.zip")
    (compilations / "U_SRG-STIG_Bundle_2027.zip").write_bytes(b"PK\x03\x04 not opened, name only")
    report_path = tmp_path / "report.md"
    monkeypatch.setattr(
        "sys.argv",
        [
            "corpus_conformance",
            "--corpus",
            str(corpus),
            "--inputs",
            str(_inputs_dir(tmp_path)),
            "--compilations",
            str(compilations),
            "--report",
            str(report_path),
            "--skip-determinism",
        ],
    )

    with pytest.raises(SystemExit):
        corpus_conformance.main()

    text = report_path.read_text(encoding="utf-8")
    assert "U_SRG-STIG_Bundle_2027.zip" in text
    assert "tiered COMPILATION" in text


def test_collect_benchmarks__an_archive_with_no_benchmark__is_logged_under_pytests_default_logging(tmp_path):
    # The cost metric's population source. inventory.py logs this at INFO, and pytest leaves
    # the root logger at its default WARNING with no log_level configured in pyproject.toml,
    # so unless _capture_logs forces INFO this record is never produced and the message list
    # stays empty regardless of what the pipeline actually did.
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    with zipfile.ZipFile(corpus / "U_Empty_V1R1_STIG.zip", "w") as archive:
        archive.writestr("README.txt", "no benchmark here")
    artifacts, _ = corpus_conformance.phase_accounting(corpus)
    staging = tmp_path / "extract"

    _, log_messages = corpus_conformance.collect_benchmarks(artifacts, staging)

    assert any("contains no XCCDF benchmark" in message for message in log_messages)
    shutil.rmtree(staging)


def test__capture_logs__restores_the_loggers_original_level_afterward():
    logger = logging.getLogger("stig_mcp.ingest.inventory")
    original = logger.level
    logger.setLevel(logging.DEBUG)
    try:
        with corpus_conformance._capture_logs("stig_mcp.ingest.inventory") as records:
            assert logger.getEffectiveLevel() == logging.INFO
            assert records == []
        assert logger.level == logging.DEBUG
    finally:
        logger.setLevel(original)


def test_phase_resolver__pinned_query_reports_its_version_uncovered__passes(wide_kb):
    # RHEL 8 is absent from this corpus and RHEL_9_STIG is present, which is the same shape
    # as 'Microsoft SQL Server 2019' against the real library. wide_kb, not kb_path: a pin
    # asserting a verdict cannot pass against a corpus too small to produce one.
    conn = open_db_for_test(wide_kb)
    findings = corpus_conformance.phase_resolver(conn, pins=(("RHEL 8", corpus_conformance.UNCOVERED_VERSION),))
    assert findings == []


def test_phase_resolver__pinned_uncovered_query_resolves_normally__is_an_error(wide_kb):
    # A pin expecting "uncovered" must fail loudly when the resolver stops saying so; a
    # substring pin cannot, since it passes whichever version won.
    conn = open_db_for_test(wide_kb)
    findings = corpus_conformance.phase_resolver(conn, pins=(("RHEL 9", corpus_conformance.UNCOVERED_VERSION),))
    assert [f.severity for f in findings] == [corpus_conformance.ERROR]
    assert "expected it to report the version as uncovered" in findings[0].message


def test_phase_resolver__default_pins__still_check_the_substring_expectations(kb_path):
    conn = open_db_for_test(kb_path)
    findings = corpus_conformance.phase_resolver(conn)
    assert any("skipped: corpus holds no" in f.message for f in findings)


def test_pinned_queries__the_sql_server_2019_entry__expects_an_uncovered_version():
    # Why the harness pins this entry exactly: a substring expectation here passes
    # whichever SQL Server version happens to win.
    pins = dict(corpus_conformance.PINNED_QUERIES)
    assert pins["Microsoft SQL Server 2019"] is corpus_conformance.UNCOVERED_VERSION


def _resolver_stig(stig_id, title, keywords=""):
    """One row shaped as stigs_for_resolver returns it, which is all _padded_version_findings reads."""
    return {"stig_id": stig_id, "title": title, "product_keywords": keywords}


def _resolver_kb(rows):
    """A stigs table with the columns stigs_for_resolver selects, so phase_resolver runs end to end.

    Hand-built for the same reason _permissive_kb is: no fixture benchmark carries a zero-padded
    major, and adding one would change the corpora that every other resolver test shares.
    """
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute(
        "CREATE TABLE stigs(stig_id TEXT, title TEXT, version TEXT, release_label TEXT, "
        "release_info TEXT, origin TEXT, source_artifact TEXT, source_member TEXT, "
        "xccdf_status TEXT, xccdf_status_date TEXT, product_keywords TEXT)"
    )
    conn.executemany(
        "INSERT INTO stigs VALUES(?, ?, '1', 'V1R1', 'Release: 1', 'library', 'a.zip', 'm.zip', "
        "'accepted', '2026-01-01', ?)",
        rows,
    )
    return conn


def test__padded_version_findings__a_title_writing_a_padded_major__is_reported():
    # The day DISA titles a benchmark this way, _version_matched tells a caller who asks for
    # version 8 that this knowledge base does not hold it.
    findings = corpus_conformance._padded_version_findings(
        [_resolver_stig("ACME_08_STIG", "Acme Platform 08 Security Technical Implementation Guide")]
    )
    assert [f.severity for f in findings] == [corpus_conformance.ERROR]
    assert "ACME_08_STIG" in findings[0].message
    assert "['08']" in findings[0].message


def test__padded_version_findings__ubuntus_padded_minor__is_not_reported():
    # The exclusion, in DISA's own spelling. Both real Ubuntu rows carry the token `04`, so a check
    # that flagged every padded token would fail on every corpus build and be turned off.
    findings = corpus_conformance._padded_version_findings(
        [
            _resolver_stig(
                "CAN_Ubuntu_22-04_LTS_STIG",
                "Canonical Ubuntu 22.04 LTS Security Technical Implementation Guide",
            )
        ]
    )
    assert findings == []


def test__padded_version_findings__a_v_prefixed_padded_major__is_reported():
    # The glued channel. `normalize` keeps `v08` as a PRODUCT token and emits no version token,
    # so reading normalize alone sees nothing, while glued_versions puts `08` straight into the
    # set the classifier compares against. DISA writes this spelling already: v11, v9 and v8
    # are all in the real library, none of them padded yet.
    findings = corpus_conformance._padded_version_findings(
        [_resolver_stig("ACME_V08_STIG", "Acme Platform v08 Security Technical Implementation Guide")]
    )
    assert [f.severity for f in findings] == [corpus_conformance.ERROR]
    assert "['08']" in findings[0].message


def test__padded_version_findings__the_real_v_prefixed_titles__are_not_reported():
    # The spellings DISA actually ships. Reading the glued channel must report only a padded
    # v-prefixed token, not every v-prefixed benchmark.
    findings = corpus_conformance._padded_version_findings(
        [
            _resolver_stig("EDB_V11_STIG", "EDB Postgres Advanced Server v11 on Windows STIG"),
            _resolver_stig("JAMF_STIG", "Jamf Pro v9 Security Technical Implementation Guide"),
            _resolver_stig("ORACLE_19C_STIG", "Oracle Database 19c Security Technical Implementation Guide"),
        ]
    )
    assert findings == []


def test__padded_version_findings__a_padded_major_and_a_padded_minor_in_one_title__is_reported():
    # The sets are flat across every run in the title, so `08` is a major of one run and a minor of
    # another. Excusing it on the second reading would excuse the exact case this exists to catch.
    findings = corpus_conformance._padded_version_findings(
        [
            _resolver_stig(
                "ACMEWARE_08_STIG",
                "Acmeware 08 vCenter Appliance Photon OS 4.08 Security Technical Implementation Guide",
            )
        ]
    )
    assert [f.severity for f in findings] == [corpus_conformance.ERROR]


def test__padded_version_findings__a_benchmark_carrying_two_majors__is_reported_once():
    # stigs_for_resolver returns one row per (stig_id, version), and 12 real ids carry two majors.
    # Two distinct dicts, as two rows are: `[row] * 2` is the same object twice and lets a dedupe
    # keyed on object identity pass.
    title = "Acme Platform v08 Security Technical Implementation Guide"
    rows = [_resolver_stig("ACME_V08_STIG", title), _resolver_stig("ACME_V08_STIG", title)]
    assert len(corpus_conformance._padded_version_findings(rows)) == 1


def test__padded_version_findings__a_padded_token_only_in_the_keywords__is_reported():
    # The token reaches `covered` from product_keywords, and the title offers no evidence it is a
    # minor. Reported rather than excused: the classifier will compare against it either way.
    findings = corpus_conformance._padded_version_findings(
        [_resolver_stig("ACME_STIG", "Acme Platform Security Technical Implementation Guide", "acme 09")]
    )
    assert [f.severity for f in findings] == [corpus_conformance.ERROR]


def test_straddling_pair_findings__a_title_containing_a_separator__is_reported_at_info():
    # The protected set is DATA: a future DISA title carrying a separator changes how every
    # description splits, with no code change and no review. The harness is what makes that
    # visible at the next library refresh.
    findings = corpus_conformance._straddling_pair_findings(
        [_resolver_stig("APP_SEC_DEV_STIG", "Application Security and Development STIG")]
    )
    assert [f.severity for f in findings] == [corpus_conformance.INFO]
    assert "security" in findings[0].message and "development" in findings[0].message


def test_straddling_pair_findings__no_title_carries_a_separator__reports_nothing():
    findings = corpus_conformance._straddling_pair_findings(
        [_resolver_stig("ACME_STIG", "Acme Platform Security Technical Implementation Guide")]
    )
    assert findings == []


def test_straddling_pair_findings__two_titles_carrying_separators__is_reported_one_per_pair():
    # A combined single Finding would leave this count at 1 no matter how many pairs the set
    # holds, which is exactly the gap this closes: the INFO count must move when the set does.
    findings = corpus_conformance._straddling_pair_findings(
        [
            _resolver_stig("APP_SEC_DEV_STIG", "Application Security and Development STIG"),
            _resolver_stig("SDSF_RACF_STIG", "System Display and Search Facility for RACF STIG"),
        ]
    )
    assert [f.severity for f in findings] == [corpus_conformance.INFO, corpus_conformance.INFO]
    messages = {f.message for f in findings}
    assert any("security" in m and "development" in m for m in messages)
    assert any("display" in m and "search" in m for m in messages)


def test_phase_resolver__a_benchmark_with_a_padded_major__reports_it():
    # Pins the wiring: without the call in phase_resolver the check exists and never runs.
    rows = [("ACME_08_STIG", "Acme Platform 08 Security Technical Implementation Guide", "")]
    with closing(_resolver_kb(rows)) as conn:
        findings = corpus_conformance.phase_resolver(conn, pins=())
    assert [f.severity for f in findings] == [corpus_conformance.ERROR]
    assert "zero-padded version token" in findings[0].message


def test_phase_resolver__the_real_ubuntu_titles__report_nothing():
    rows = [
        ("CAN_Ubuntu_22-04_LTS_STIG", "Canonical Ubuntu 22.04 LTS Security Technical Implementation Guide", ""),
        ("CAN_Ubuntu_24-04_STIG", "Canonical Ubuntu 24.04 LTS Security Technical Implementation Guide", ""),
    ]
    with closing(_resolver_kb(rows)) as conn:
        assert corpus_conformance.phase_resolver(conn, pins=()) == []


def test_phase_margin__a_corpus_with_tokens_near_the_gate__reports_one_finding_per_token(wide_kb):
    # One per token, not one naming the set, so the report's info COUNT moves when the band
    # changes. _straddling_pair_findings reports one finding per pair for the same reason.
    conn = open_db_for_test(wide_kb)
    findings = corpus_conformance.phase_margin(conn)
    assert {f.severity for f in findings} == {corpus_conformance.INFO}
    chrome = [f for f in findings if "'chrome' df 1" in f.message]
    windows = [f for f in findings if "'windows' df 2" in f.message]
    assert len(chrome) == 1
    assert len(windows) == 1
    # A combined Finding naming the whole band would still pass the two counts above,
    # since both substrings would sit inside that one Finding's message; this line is what
    # catches it, because chrome and windows would then be the same Finding.
    assert chrome[0] != windows[0]
    assert not [f for f in findings if "'padding'" in f.message]


def test_phase_margin__a_token_inside_the_gate__is_reported_as_losing(wide_kb):
    conn = open_db_for_test(wide_kb)
    findings = corpus_conformance.phase_margin(conn)
    chrome = [f.message for f in findings if "'chrome' df 1" in f.message]
    assert "losing" in chrome[0]
    assert "n=29" in chrome[0]


def test_phase_margin__a_token_beyond_the_gate__is_reported_as_gaining(wide_kb):
    conn = open_db_for_test(wide_kb)
    findings = corpus_conformance.phase_margin(conn)
    windows = [f.message for f in findings if "'windows' df 2" in f.message]
    assert "gaining" in windows[0]
    assert "n=29" in windows[0]


def test_phase_margin__a_corpus_holding_no_benchmarks__reports_nothing(tmp_path):
    # create_db rather than build_kb: _validate_sources refuses an empty benchmarks list
    # before _populate runs, so an empty corpus cannot be built through build_kb at all.
    with closing(create_db(tmp_path / "empty.sqlite")) as conn:
        assert corpus_conformance.phase_margin(conn) == []


def test_phase_invariants__defense_tables_empty__is_an_error_naming_the_table(kb_path, tmp_path):
    copy = tmp_path / "kb.sqlite"
    shutil.copyfile(kb_path, copy)
    with closing(sqlite3.connect(copy)) as writable:
        writable.execute("DELETE FROM analytic_log_sources")
        writable.commit()
    with closing(corpus_conformance.open_kb(copy)) as conn:
        findings = corpus_conformance.phase_invariants(conn, {})
    messages = [f.message for f in findings if f.severity == corpus_conformance.ERROR]
    assert any("analytic_log_sources holds 0 rows" in m for m in messages)


def test_defense_counts__the_fixture__reports_every_table(kb_path):
    with closing(corpus_conformance.open_kb(kb_path)) as conn:
        counts = corpus_conformance.defense_counts(conn)
    assert counts == {
        "mitigations": 2,
        "technique_mitigation": 3,
        "detection_strategies": 2,
        "analytics": 3,
        "analytic_log_sources": 5,
        "data_components": 2,
    }
