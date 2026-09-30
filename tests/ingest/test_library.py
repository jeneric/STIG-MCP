import fnmatch
import io
import logging
import zipfile

import pytest

from stig_mcp.ingest import config, inventory, library
from stig_mcp.ingest.inventory import _kind_of
from stig_mcp.ingest.library import extract_stig_xccdfs, find_compilation_zip


def _inner_zip(members):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in members.items():
            z.writestr(name, data)
    return buf.getvalue()


def _compilation(path, entries):
    with zipfile.ZipFile(path, "w") as z:
        for name, data in entries.items():
            z.writestr(name, data)


SCAP_DATASTREAM = (
    b'<?xml version="1.0" encoding="UTF-8"?>'
    b'<data-stream-collection xmlns="http://scap.nist.gov/schema/scap/source/1.2" '
    b'id="scap_mil.disa.stig_collection_x"/>'
)
GPO_BACKUP = (
    b'<?xml version="1.0"?><GroupPolicyBackupScheme xmlns="http://www.microsoft.com/GroupPolicy/GPOOperations"/>'
)
BENCHMARK = b'<?xml version="1.0"?><Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1" id="EPAS_STIG"/>'
SRG_BENCHMARK = (
    b'<?xml version="1.0"?><Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1" id="AAA_Services_SRG">'
    b"<title>AAA Services Security Requirements Guide</title></Benchmark>"
)
ZOS_BENCHMARK = (
    b'<?xml version="1.0"?><Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1" '
    b'id="zOS_BMC_CONTROL-D_for_RACF_STIG"><title>z/OS BMC CONTROL-D for RACF</title></Benchmark>'
)


def test_extract_stig_xccdfs__benchmark_under_a_non_xccdf_filename__is_extracted(tmp_path):
    # U_EPAS_V2R1_STIG.zip in the real July 2026 library ships its benchmark as
    # EDB_Postgres_Advanced_Server_STIG.xml, so a suffix-only match loses it entirely.
    comp = tmp_path / "U_SRG-STIG_Library_July_2026.zip"
    inner = _inner_zip({"U_EPAS_V2R1_Manual_STIG/EDB_Postgres_Advanced_Server_STIG.xml": BENCHMARK})
    _compilation(comp, {"U_EPAS_V2R1_STIG.zip": inner})
    written = extract_stig_xccdfs(comp, tmp_path / "out")
    assert {p.name for p in written} == {"EDB_Postgres_Advanced_Server_STIG.xml"}


def test_extract_stig_xccdfs__scap_datastream__is_not_treated_as_a_benchmark(tmp_path):
    comp = tmp_path / "U_SRG-STIG_Library_July_2026.zip"
    inner = _inner_zip({"U_Adobe_V2R5_STIG_SCAP_1-3_Benchmark.xml": SCAP_DATASTREAM})
    _compilation(comp, {"U_Adobe_V2R5_STIG_SCAP.zip": inner})
    assert extract_stig_xccdfs(comp, tmp_path / "out") == []


def test_extract_stig_xccdfs__group_policy_xml__is_not_treated_as_a_benchmark(tmp_path):
    comp = tmp_path / "U_SRG-STIG_Library_July_2026.zip"
    inner = _inner_zip({"Backup/gpreport.xml": GPO_BACKUP, "Backup/Backup.xml": GPO_BACKUP})
    _compilation(comp, {"U_STIG_GPO_Package.zip": inner})
    assert extract_stig_xccdfs(comp, tmp_path / "out") == []


def test_pick_xccdf__manual_xccdf_present__never_reads_any_member(tmp_path):
    # The fast path must not pay for root parsing: 383 of 384 real benchmarks hit it.
    def explode(_name):
        raise AssertionError("read() must not be called when a Manual XCCDF matches by name")

    names = ["U_Foo_STIG_V1R1_Manual-xccdf.xml", "overview.pdf"]
    assert library.pick_xccdf(names, explode) == ["U_Foo_STIG_V1R1_Manual-xccdf.xml"]


def test_pick_xccdf__xccdf_named_without_manual__returns_it_without_reading():
    def explode(_name):
        raise AssertionError("read() must not be called when an XCCDF matches by name")

    names = ["U_Foo/U_Foo_STIG-xccdf.xml", "U_Foo/U_Foo_Overview.xml"]
    assert library.pick_xccdf(names, explode) == ["U_Foo/U_Foo_STIG-xccdf.xml"]


def test_extract_stig_xccdfs__zip_of_zips__writes_the_stig_and_not_the_srg(tmp_path):
    comp = tmp_path / "U_SRG-STIG_Library_July_2026.zip"
    stig = _inner_zip(
        {
            "U_Foo_V1R1_STIG/U_Foo_STIG_V1R1_Manual-xccdf.xml": b"<Benchmark id='FOO_STIG'/>",
            "U_Foo_V1R1_STIG/overview.pdf": b"pdf",
        }
    )
    srg = _inner_zip({"U_Web_Server_V4R5_SRG/U_Web_Server_SRG_Manual-xccdf.xml": b"<Benchmark id='SRG'/>"})
    _compilation(
        comp,
        {
            "U_Foo_V1R1_STIG.zip": stig,
            "U_Web_Server_V4R5_SRG.zip": srg,  # SRG -> read, classified, and dropped
            "U_Readme.pdf": b"pdf",  # non-zip -> ignored
        },
    )
    written = extract_stig_xccdfs(comp, tmp_path / "out")
    names = {p.name for p in written}
    assert "U_Foo_STIG_V1R1_Manual-xccdf.xml" in names
    assert "U_Web_Server_SRG_Manual-xccdf.xml" not in names


def test_extract_stig_xccdfs__compilation_holds_a_Products_zip__its_benchmarks_are_written(tmp_path):
    comp = tmp_path / "U_SRG-STIG_Library_July_2026.zip"
    inner = _inner_zip({"U_zOS_RACF_Manual_STIG/U_zOS_BMC_CONTROL-D_Manual-xccdf.xml": ZOS_BENCHMARK})
    _compilation(comp, {"U_zOS_RACF_Y26M07_Products.zip": inner})
    written = extract_stig_xccdfs(comp, tmp_path / "out")
    assert {p.name for p in written} == {"U_zOS_BMC_CONTROL-D_Manual-xccdf.xml"}


def test_extract_stig_xccdfs__inner_zip_holds_an_srg__nothing_is_written(tmp_path):
    comp = tmp_path / "U_SRG-STIG_Library_July_2026.zip"
    inner = _inner_zip({"U_AAA_Manual_SRG/U_AAA_Services_Manual-xccdf.xml": SRG_BENCHMARK})
    _compilation(comp, {"U_AAA_Services_V2R2_SRG.zip": inner})
    assert extract_stig_xccdfs(comp, tmp_path / "out") == []


def test_extract_stig_xccdfs__inner_zip_holds_an_srg__the_log_counts_it_as_skipped(tmp_path, caplog):
    comp = tmp_path / "U_SRG-STIG_Library_July_2026.zip"
    inner = _inner_zip({"U_AAA_Manual_SRG/U_AAA_Services_Manual-xccdf.xml": SRG_BENCHMARK})
    _compilation(comp, {"U_AAA_Services_V2R2_SRG.zip": inner})
    with caplog.at_level("INFO", logger="stig_mcp.ingest.library"):
        extract_stig_xccdfs(comp, tmp_path / "out")
    assert "skipped 1 non-STIG document(s) {'srg': 1}" in caplog.text


def test_extract_stig_xccdfs__manual_xccdf_member_that_will_not_parse__is_skipped_not_raised(tmp_path):
    # This member's name matches pick_xccdf's first (Manual-xccdf.xml) fast path, so it is
    # returned without ever being read or checked by _is_benchmark; iter_stig_members reads it
    # and yields it unconditionally. Only extract_stig_xccdfs's own parse_stig_bytes call, inside
    # its try/except, ever looks at these bytes: that is the branch this test exercises.
    comp = tmp_path / "U_SRG-STIG_Library_2026.zip"
    broken = _inner_zip({"U_Broken_V1R1_STIG/U_Broken_STIG_V1R1_Manual-xccdf.xml": b"not xml at all"})
    good = _inner_zip({"U_Good_STIG/U_Good_STIG_Manual-xccdf.xml": b"<Benchmark id='G_STIG'/>"})
    _compilation(comp, {"U_Broken_V1R1_STIG.zip": broken, "U_Good_STIG.zip": good})
    written = extract_stig_xccdfs(comp, tmp_path / "out")  # must not raise
    assert {p.name for p in written} == {"U_Good_STIG_Manual-xccdf.xml"}


def test_extract_stig_xccdfs__an_unparseable_member__is_counted_in_skipped(tmp_path, caplog):
    comp = tmp_path / "U_SRG-STIG_Library_2026.zip"
    broken = _inner_zip({"U_Broken_V1R1_STIG/U_Broken_STIG_V1R1_Manual-xccdf.xml": b"not xml at all"})
    good = _inner_zip({"U_Good_STIG/U_Good_STIG_Manual-xccdf.xml": b"<Benchmark id='G_STIG'/>"})
    _compilation(comp, {"U_Broken_V1R1_STIG.zip": broken, "U_Good_STIG.zip": good})
    with caplog.at_level("INFO", logger="stig_mcp.ingest.library"):
        written = extract_stig_xccdfs(comp, tmp_path / "out")
    assert {p.name for p in written} == {"U_Good_STIG_Manual-xccdf.xml"}
    assert "skipped 1 non-STIG document(s) {'unparseable': 1}" in caplog.text


def _colliding_compilation(path, foo_bytes, bar_bytes):
    """Two inner zips whose Manual XCCDFs share one basename, which is what DISA ships.

    outer.namelist() walks insertion order, so U_Foo is extracted first and U_Bar is the
    member that finds the name already taken.
    """
    foo = _inner_zip({"U_Foo_V1R1_STIG/U_Shared_Manual-xccdf.xml": foo_bytes})
    bar = _inner_zip({"U_Bar_V1R1_STIG/U_Shared_Manual-xccdf.xml": bar_bytes})
    _compilation(path, {"U_Foo_V1R1_STIG.zip": foo, "U_Bar_V1R1_STIG.zip": bar})


def test_extract_stig_xccdfs__a_shared_basename_over_differing_bytes__keeps_both_documents(tmp_path):
    # Without this, the second member overwrites the first and is still counted, so the caller
    # is told two files were written when one document was destroyed.
    comp = tmp_path / "U_SRG-STIG_Library_2026.zip"
    _colliding_compilation(comp, b"<Benchmark id='FOO_STIG'/>", b"<Benchmark id='BAR_STIG'/>")
    written = extract_stig_xccdfs(comp, tmp_path / "out")
    assert [p.name for p in written] == ["U_Shared_Manual-xccdf.xml", "2_U_Shared_Manual-xccdf.xml"]
    assert (tmp_path / "out" / "U_Shared_Manual-xccdf.xml").read_bytes() == b"<Benchmark id='FOO_STIG'/>"
    assert (tmp_path / "out" / "2_U_Shared_Manual-xccdf.xml").read_bytes() == b"<Benchmark id='BAR_STIG'/>"


def test_extract_stig_xccdfs__a_rescued_document__is_still_visible_to_ingest(tmp_path):
    # The rename has to keep the `xccdf.xml` tail, and asserting only that _kind_of says
    # "loose" cannot prove it: a suffixed U_Shared_Manual-xccdf.2.xml is classified loose too,
    # by the root-element fallback opening and parsing it. So this asserts the rescued file is
    # still matched by the NAME rule, which is what the prefix buys.
    comp = tmp_path / "U_SRG-STIG_Library_2026.zip"
    _colliding_compilation(comp, b"<Benchmark id='FOO_STIG'/>", b"<Benchmark id='BAR_STIG'/>")
    written = extract_stig_xccdfs(comp, tmp_path / "out")
    assert [_kind_of(path) for path in written] == ["loose", "loose"]
    assert all(fnmatch.fnmatch(path.name.lower(), inventory.LOOSE_GLOB) for path in written)


def test_extract_stig_xccdfs__a_shared_basename_over_differing_bytes__warns_naming_the_member(tmp_path, caplog):
    comp = tmp_path / "U_SRG-STIG_Library_2026.zip"
    _colliding_compilation(comp, b"<Benchmark id='FOO_STIG'/>", b"<Benchmark id='BAR_STIG'/>")
    with caplog.at_level("WARNING", logger="stig_mcp.ingest.library"):
        extract_stig_xccdfs(comp, tmp_path / "out")
    warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert any(
        "U_Bar_V1R1_STIG/U_Shared_Manual-xccdf.xml" in message and "2_U_Shared_Manual-xccdf.xml" in message
        for message in warnings
    )


def test_extract_stig_xccdfs__a_shared_basename_over_identical_bytes__writes_one_file(tmp_path):
    # The real 2020_01 library ships two such pairs, U_Riverbed_SteelHead_CX_v8 and
    # U_zOS_RACF_V6R43, byte-identical both times: DISA bundles one benchmark under two inner
    # zip names. A second copy under a `2_` name would be a wrong answer, not a safe one.
    comp = tmp_path / "U_SRG-STIG_Library_2026.zip"
    _colliding_compilation(comp, b"<Benchmark id='FOO_STIG'/>", b"<Benchmark id='FOO_STIG'/>")
    written = extract_stig_xccdfs(comp, tmp_path / "out")
    assert [p.name for p in written] == ["U_Shared_Manual-xccdf.xml"]
    assert [p.name for p in (tmp_path / "out").iterdir()] == ["U_Shared_Manual-xccdf.xml"]


def test_extract_stig_xccdfs__a_file_left_by_an_earlier_run__is_overwritten_not_renamed(tmp_path, caplog):
    # `taken` is per-call, so a name is only "already chosen" within one run. Re-extracting the
    # same compilation must refresh the file in place rather than accumulate 2_, 3_, 4_ copies.
    # This is the only test that reaches the overwrite branch, because within a single run an
    # unclaimed name is by definition one nothing has written yet.
    comp = tmp_path / "U_SRG-STIG_Library_2026.zip"
    inner = _inner_zip({"U_Foo_V1R1_STIG/U_Shared_Manual-xccdf.xml": b"<Benchmark id='FOO_STIG'/>"})
    _compilation(comp, {"U_Foo_V1R1_STIG.zip": inner})
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    (out_dir / "U_Shared_Manual-xccdf.xml").write_bytes(b"<Benchmark id='STALE_STIG'/>")
    with caplog.at_level("DEBUG", logger="stig_mcp.ingest.library"):
        written = extract_stig_xccdfs(comp, out_dir)
    assert [p.name for p in written] == ["U_Shared_Manual-xccdf.xml"]
    assert [p.name for p in out_dir.iterdir()] == ["U_Shared_Manual-xccdf.xml"]
    assert (out_dir / "U_Shared_Manual-xccdf.xml").read_bytes() == b"<Benchmark id='FOO_STIG'/>"
    assert any("overwrites it" in record.getMessage() for record in caplog.records)


def test_extract_stig_xccdfs__a_shared_basename_over_identical_bytes__counts_the_duplicate(tmp_path, caplog):
    comp = tmp_path / "U_SRG-STIG_Library_2026.zip"
    _colliding_compilation(comp, b"<Benchmark id='FOO_STIG'/>", b"<Benchmark id='FOO_STIG'/>")
    with caplog.at_level("INFO", logger="stig_mcp.ingest.library"):
        extract_stig_xccdfs(comp, tmp_path / "out")
    assert "1 duplicate(s)" in caplog.text


def test_extract_stig_xccdfs__bad_inner_zip__skips_and_continues(tmp_path):
    comp = tmp_path / "U_SRG-STIG_Library_2026.zip"
    good = _inner_zip({"U_Good_STIG/U_Good_STIG_Manual-xccdf.xml": b"<Benchmark id='G_STIG'/>"})
    _compilation(
        comp,
        {
            "U_Bad_STIG.zip": b"not a real zip",  # corrupt inner zip -> warn + skip
            "U_Good_STIG.zip": good,
        },
    )
    written = extract_stig_xccdfs(comp, tmp_path / "out")
    assert {p.name for p in written} == {"U_Good_STIG_Manual-xccdf.xml"}


def test_extract_stig_xccdfs__corrupt_member_in_valid_zip__skips_and_continues(tmp_path):
    # An inner zip whose central directory is intact but whose member data is
    # corrupt raises on inner.read(member); it must be skipped, not abort the run.
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        z.writestr("U_Corrupt_STIG/U_Corrupt_STIG_Manual-xccdf.xml", b"<Benchmark id='C'/>")
    raw = bytearray(buf.getvalue())
    idx = raw.find(b"<Benchmark")  # stored (uncompressed) content
    raw[idx] ^= 0xFF  # flip a content byte -> CRC mismatch on read
    good = _inner_zip({"U_Good_STIG/U_Good_STIG_Manual-xccdf.xml": b"<Benchmark id='G_STIG'/>"})
    comp = tmp_path / "U_SRG-STIG_Library_2026.zip"
    _compilation(comp, {"U_Corrupt_STIG.zip": bytes(raw), "U_Good_STIG.zip": good})
    written = extract_stig_xccdfs(comp, tmp_path / "out")  # must not raise
    assert {p.name for p in written} == {"U_Good_STIG_Manual-xccdf.xml"}


def test_pick_xccdf__malformed_root_element_candidate__logs_debug_naming_the_member(tmp_path, caplog):
    # A non-xccdf.xml candidate that is truncated or malformed falls to the root-element
    # fallback and fails to parse. Inside a product zip the same failure gets a census
    # line naming the artifact; this DEBUG line is what names it on the compilation path.
    names = ["U_Broken_STIG.xml"]
    reads = {"U_Broken_STIG.xml": b"not xml at all"}
    with caplog.at_level("DEBUG", logger="stig_mcp.ingest.library"):
        assert library.pick_xccdf(names, reads.__getitem__) == []
    assert "U_Broken_STIG.xml" in caplog.text


def test_extract_stig_xccdfs__no_manual_xccdf__falls_back_to_any_xccdf(tmp_path):
    comp = tmp_path / "U_SRG-STIG_Library_2026.zip"
    inner = _inner_zip({"U_NoManual_STIG/U_NoManual_STIG-xccdf.xml": b"<Benchmark id='N_STIG'/>"})
    _compilation(comp, {"U_NoManual_STIG.zip": inner})
    written = extract_stig_xccdfs(comp, tmp_path / "out")
    assert {p.name for p in written} == {"U_NoManual_STIG-xccdf.xml"}


def test_iter_stig_members__inner_zip_named_Products__its_benchmark_is_yielded(tmp_path):
    # U_zOS_RACF_Y26M07_Products.zip in the current July 2026 library holds 31 real STIG
    # benchmarks and is named _Products, not _STIG.
    comp = tmp_path / "U_SRG-STIG_Library_July_2026.zip"
    inner = _inner_zip({"U_zOS_RACF_Manual_STIG/U_zOS_BMC_CONTROL-D_for_RACF_Manual-xccdf.xml": BENCHMARK})
    _compilation(comp, {"U_zOS_RACF_Y26M07_Products.zip": inner})
    with zipfile.ZipFile(comp) as outer:
        found = list(library.iter_stig_members(outer, comp.name))
    assert [name for name, _member, _data in found] == ["U_zOS_RACF_Y26M07_Products.zip"]


def test_iter_stig_members__members_nested_under_an_SRG_named_directory__are_yielded(tmp_path):
    # U_SRG-STIG_Library_April_2025.zip nests every inner zip under a directory named after
    # itself, so a name test applied to the full member path would match "_srg" in the
    # DIRECTORY and reject every one of them.
    comp = tmp_path / "U_SRG-STIG_Library_April_2025.zip"
    inner = _inner_zip({"U_RHEL_9_Manual_STIG/U_RHEL_9_Manual-xccdf.xml": BENCHMARK})
    _compilation(comp, {"U_SRG-STIG_Library_April_2025/U_RHEL_9_V1R1_STIG.zip": inner})
    with zipfile.ZipFile(comp) as outer:
        found = list(library.iter_stig_members(outer, comp.name))
    assert len(found) == 1


def test_find_compilation_zip__present__returns_it(tmp_path):
    (tmp_path / "U_SRG-STIG_Library_July_2026.zip").write_bytes(b"PK")
    (tmp_path / "U_RHEL_9_V2R8_STIG.zip").write_bytes(b"PK")  # individual STIG, not the library
    found = find_compilation_zip(tmp_path)
    assert found is not None and "STIG_Library" in found.name


def test_find_compilation_zip__absent__returns_none(tmp_path):
    (tmp_path / "enterprise-attack.json").write_text("{}")
    assert find_compilation_zip(tmp_path) is None


def test_find_compilation_zip__missing_directory__returns_none(tmp_path):
    assert find_compilation_zip(tmp_path / "absent") is None


def test_find_compilation_zip__mixed_case_name__still_matches(tmp_path):
    # Case-insensitive, as inventory.classify is, so the two entry points agree on whether
    # a compilation is present at all.
    (tmp_path / "u_srg-stig_library_july_2026.ZIP").write_bytes(b"PK")
    found = find_compilation_zip(tmp_path)
    assert found is not None and found.name == "u_srg-stig_library_july_2026.ZIP"


def test_find_compilation_zip__two_compilations__raises_naming_both(tmp_path):
    # Month names do not sort chronologically, so picking one of two compilations could
    # silently extract a stale quarter's zip. This refuses, as inventory.classify does.
    #
    # They agree on the message and not on the TYPE: classify raises inventory.TwoLibrariesError
    # so source_status can catch that one condition and let any other RuntimeError through,
    # while this site raises a plain RuntimeError that nothing catches.
    (tmp_path / "U_SRG-STIG_Library_July_2026.zip").write_bytes(b"PK")
    (tmp_path / "U_SRG-STIG_Library_October_2026.zip").write_bytes(b"PK")
    with pytest.raises(RuntimeError) as excinfo:
        find_compilation_zip(tmp_path)
    message = str(excinfo.value)
    assert "U_SRG-STIG_Library_July_2026.zip" in message
    assert "U_SRG-STIG_Library_October_2026.zip" in message
    assert str(tmp_path) in message


def test_main__no_compilation_zip__error_names_the_real_sources_dir(tmp_path, monkeypatch):
    # The success path reports config.SOURCES_DIR, so this error must name the same
    # directory or it contradicts the same command's own output.
    monkeypatch.setattr(config, "SOURCES_DIR", tmp_path / "empty-sources")
    monkeypatch.setattr("sys.argv", ["stig-mcp-extract"])
    with pytest.raises(SystemExit) as excinfo:
        library.main()
    assert str(config.SOURCES_DIR) in str(excinfo.value)


def test_main__nonexistent_path_argument__names_the_path_not_the_sources_dir(tmp_path, monkeypatch):
    # A nonexistent path argument must name that path, not tell the caller to place a file
    # in config.SOURCES_DIR: they passed a path, and that path is wrong.
    monkeypatch.setattr(config, "SOURCES_DIR", tmp_path / "unrelated-sources")
    bad_path = tmp_path / "does-not-exist.zip"
    monkeypatch.setattr("sys.argv", ["stig-mcp-extract", str(bad_path)])
    with pytest.raises(SystemExit) as excinfo:
        library.main()
    message = str(excinfo.value)
    assert str(bad_path) in message
    assert "does not exist" in message
    assert str(config.SOURCES_DIR) not in message


def test_main__empty_string_argument__is_treated_as_no_argument(tmp_path, monkeypatch):
    # An empty string can reach argv from an unquoted, empty shell expansion, e.g.
    # `stig-mcp-extract "$MAYBE_EMPTY"`. It is falsy, not a path: Path("") normalizes to
    # the current directory, which exists, so a literal `if arg is not None:` would sail
    # past the exists() guard and crash deep inside extract_stig_xccdfs instead of giving
    # the clean no-argument message.
    monkeypatch.setattr(config, "SOURCES_DIR", tmp_path / "empty-sources")
    monkeypatch.setattr("sys.argv", ["stig-mcp-extract", ""])
    with pytest.raises(SystemExit) as excinfo:
        library.main()
    assert str(config.SOURCES_DIR) in str(excinfo.value)


def test_main__no_argument_and_no_compilation_zip__keeps_the_sources_dir_message(tmp_path, monkeypatch):
    # Companion to the test above: re-merging the two branches back into the bad-path
    # phrasing would drop the sources-dir mention this case still needs.
    monkeypatch.setattr(config, "SOURCES_DIR", tmp_path / "empty-sources")
    monkeypatch.setattr("sys.argv", ["stig-mcp-extract"])
    with pytest.raises(SystemExit) as excinfo:
        library.main()
    message = str(excinfo.value)
    assert str(config.SOURCES_DIR) in message
    assert "does not exist" not in message


def test_main__no_argument_and_a_compilation_present__extracts_it(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(config, "SOURCES_DIR", tmp_path)
    comp = tmp_path / "U_SRG-STIG_Library_July_2026.zip"
    inner = _inner_zip({"U_Foo_V1R1_STIG/U_Foo_STIG_V1R1_Manual-xccdf.xml": BENCHMARK})
    _compilation(comp, {"U_Foo_V1R1_STIG.zip": inner})
    monkeypatch.setattr("sys.argv", ["stig-mcp-extract"])
    library.main()
    captured = capsys.readouterr()
    assert "Extracted 1 STIG XCCDF file(s)" in captured.out
    assert (tmp_path / "U_Foo_STIG_V1R1_Manual-xccdf.xml").exists()


def test_main__sunset_compilation__refuses_rather_than_flattening_it(tmp_path, monkeypatch):
    # Extracting flattens a compilation into sources/ as loose XCCDFs, which erases
    # origin. Done to the sunset archive, the superseded-major skip rule would stop applying
    # and its retired majors and rule_id collisions would come back.
    monkeypatch.setattr(config, "SOURCES_DIR", tmp_path)
    zip_path = tmp_path / "U_Rev_4_SRG-STIG_Sunset_Compilation.zip"
    zip_path.write_bytes(b"PK")
    monkeypatch.setattr("sys.argv", ["stig-mcp-extract", str(zip_path)])
    with pytest.raises(SystemExit) as excinfo:
        library.main()
    message = str(excinfo.value)
    # Not `"sunset" in message`: main() echoes zip_path.name, and this fixture is NAMED
    # U_Rev_4_SRG-STIG_Sunset_Compilation.zip, so that assertion would pass on the filename alone.
    assert "would flatten it into loose XCCDFs" in message
    assert "stig-mcp-ingest" in message
