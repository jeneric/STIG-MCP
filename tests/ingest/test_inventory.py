import io
import zipfile
import zlib
from pathlib import Path

import pytest

from stig_mcp.ingest import inventory

FIX = Path(__file__).parent.parent / "fixtures"


def _touch(directory, *names):
    directory.mkdir(parents=True, exist_ok=True)
    for name in names:
        (directory / name).write_bytes(b"PK")


def test_classify__one_of_each_kind__labels_them_all(tmp_path):
    _touch(
        tmp_path,
        "U_SRG-STIG_Library_July_2026.zip",
        "U_Rev_4_SRG-STIG_Sunset_Compilation.zip",
        "U_MS_Windows_Server_2019_V3R9_STIG.zip",
        "U_Foo_STIG_V1R1_Manual-xccdf.xml",
    )
    got = {a.path.name: a.kind for a in inventory.classify(tmp_path)}
    assert got == {
        "U_SRG-STIG_Library_July_2026.zip": "library",
        "U_Rev_4_SRG-STIG_Sunset_Compilation.zip": "sunset",
        "U_MS_Windows_Server_2019_V3R9_STIG.zip": "product_zip",
        "U_Foo_STIG_V1R1_Manual-xccdf.xml": "loose",
    }


def test_classify__mixed_case_names__still_match(tmp_path):
    # DISA may recase a name, so classification is case-insensitive.
    _touch(tmp_path, "u_srg-stig_library_july_2026.ZIP", "U_FOO_STIG_MANUAL-XCCDF.XML")
    got = sorted(a.kind for a in inventory.classify(tmp_path))
    assert got == ["library", "loose"]


def test_classify__two_library_compilations__raises_naming_both(tmp_path):
    _touch(tmp_path, "U_SRG-STIG_Library_July_2026.zip", "U_SRG-STIG_Library_October_2026.zip")
    with pytest.raises(RuntimeError) as excinfo:
        inventory.classify(tmp_path)
    message = str(excinfo.value)
    assert "U_SRG-STIG_Library_July_2026.zip" in message
    assert "U_SRG-STIG_Library_October_2026.zip" in message
    assert str(tmp_path) in message
    assert "stig-mcp-ingest" in message


def test_classify__two_sunset_compilations__keeps_both(tmp_path):
    # Sunset archives are additive; the major-tie rule makes edition order irrelevant,
    # so N of them is legal where two library compilations are not.
    _touch(tmp_path, "U_Rev_4_SRG-STIG_Sunset_Compilation.zip", "U_Rev_5_SRG-STIG_Sunset_Compilation.zip")
    assert [a.kind for a in inventory.classify(tmp_path)] == ["sunset", "sunset"]


CCI_LIST = b'<?xml version="1.0"?><cci_list xmlns="http://iase.disa.mil/cci"><cci_items/></cci_list>'
SCAP_DATASTREAM = (
    b'<?xml version="1.0"?><data-stream-collection '
    b'xmlns="http://scap.nist.gov/schema/scap/source/1.2" id="scap_mil.disa.stig_collection_x"/>'
)


def test_classify__unrelated_source_files__are_not_artifacts(tmp_path):
    # Real content, not b"PK": once a loose .xml is judged by its root element, a placeholder
    # would be rejected for failing to parse at all, which is not what this test is about.
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / "U_CCI_List.xml").write_bytes(CCI_LIST)
    _touch(tmp_path, "enterprise-attack.json", "ctid_mappings.json")
    assert inventory.classify(tmp_path) == []


def test_classify__a_benchmark_under_a_non_xccdf_filename__is_loose(tmp_path):
    # The library's INNER U_EPAS_V2R1_STIG.zip ships its benchmark as
    # EDB_Postgres_Advanced_Server_STIG.xml, which library.pick_xccdf accepts only on the
    # root-element fallback. Once extracted, LOOSE_GLOB alone (`*xccdf.xml`) would drop it
    # silently, so a loose .xml is also judged by its root element.
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / "EDB_Postgres_Advanced_Server_STIG.xml").write_bytes(BENCHMARK)
    assert [(a.kind, a.path.name) for a in inventory.classify(tmp_path)] == [
        ("loose", "EDB_Postgres_Advanced_Server_STIG.xml")
    ]


def test_classify__a_doubled_xml_extension__is_loose(tmp_path):
    # DISA's own name in the 2020_01 libraries. It ends `.xml.xml`, not `xccdf.xml`, so a
    # suffix glob alone misses it.
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / "U_Samsung_Android_with_Knox2_x_V1R3_Manual_xccdf.xml.xml").write_bytes(BENCHMARK)
    assert [a.kind for a in inventory.classify(tmp_path)] == ["loose"]


def test_classify__a_corrupt_file_named_like_a_benchmark__is_still_loose(tmp_path):
    # Pins that the NAME rule survives alongside the content rule. A file DISA named
    # `Manual-xccdf.xml` whose bytes are damaged must still reach the parser, so the failure
    # is reported against that file. This fails if loose files are judged by content alone,
    # which would trade one invisible drop for another. It does NOT pin the order of the two
    # rules: a corrupt named file falls through the content test and the name rule catches it
    # anyway, so order costs a wasted read, not a behavior.
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / "U_Foo_STIG_V1R1_Manual-xccdf.xml").write_bytes(b"not xml at all")
    assert [a.kind for a in inventory.classify(tmp_path)] == ["loose"]


def test_classify__a_scap_datastream_loose_on_disk__is_not_an_artifact(tmp_path):
    # The breadth has a floor: a data-stream embeds XCCDF content, so anything short of
    # parsing and checking the ROOT element would admit it.
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / "U_Adobe_V2R5_STIG_SCAP_1-3_Benchmark.xml").write_bytes(SCAP_DATASTREAM)
    assert inventory.classify(tmp_path) == []


def test_classify__an_xml_that_cannot_be_read__is_not_an_artifact(tmp_path, caplog):
    # _is_benchmark catches parse failures on bytes it was handed, never the read itself.
    # An unreadable file must not abort the whole ingest before it starts, and the operator
    # has to be told which file it was: silently returning [] would leave someone hunting a
    # benchmark that is sitting right there with the wrong mode bits.
    tmp_path.mkdir(parents=True, exist_ok=True)
    unreadable = tmp_path / "U_Locked_STIG.xml"
    unreadable.write_bytes(BENCHMARK)
    unreadable.chmod(0o000)
    try:
        if unreadable.read_bytes():  # running as root: the chmod buys nothing, so skip
            pytest.skip("cannot make a file unreadable as this user")
    except OSError:
        pass
    try:
        with caplog.at_level("WARNING", logger="stig_mcp.ingest.inventory"):
            assert inventory.classify(tmp_path) == []
        assert any("U_Locked_STIG.xml" in record.getMessage() for record in caplog.records)
    finally:
        unreadable.chmod(0o644)


def test_classify__missing_directory__returns_nothing(tmp_path):
    assert inventory.classify(tmp_path / "absent") == []


BENCHMARK = b'<?xml version="1.0"?><Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1" id="X_STIG"/>'
GPO_BACKUP = (
    b'<?xml version="1.0"?><GroupPolicyBackupScheme xmlns="http://www.microsoft.com/GroupPolicy/GPOOperations"/>'
)


def _zip_bytes(members):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in members.items():
            z.writestr(name, data)
    return buf.getvalue()


def _write_zip(path, members):
    path.write_bytes(_zip_bytes(members))


def _zip_with_flags(member, flag_bit, rename_to=None):
    """Bytes of a one-member zip with `flag_bit` set in both of its headers.

    The general-purpose flags are what make an archive encrypted (bit 0) or declare its member
    name UTF-8 (0x800), and both are set on an otherwise ordinary zip rather than produced by an
    external tool, so the fixture needs nothing but the standard library. `rename_to` replaces
    the member name with raw bytes, which is the only way to put invalid UTF-8 there.
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        archive.writestr(member, BENCHMARK)
    raw = bytearray(buf.getvalue())
    for signature, offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        at = raw.find(signature)
        flags = int.from_bytes(raw[at + offset : at + offset + 2], "little") | flag_bit
        raw[at + offset : at + offset + 2] = flags.to_bytes(2, "little")
    return bytes(raw).replace(member.encode(), rename_to) if rename_to else bytes(raw)


def _deflated_zip_failing_to_decompress(member, data):
    """Bytes of a zip whose directory is intact and whose member read raises zlib.error.

    The byte to flip is SEARCHED rather than hardcoded. Which one works depends on the deflate
    stream, and a flip in the wrong place decompresses cleanly and then fails the CRC check,
    which raises BadZipFile and exercises a different member of library.UNREADABLE_ZIP than the
    caller asked for. Raises rather than returning a near-miss, because a fixture that quietly
    tests the wrong exception is the failure this helper exists to prevent.
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(member, data + bytes(range(256)) * 40)
    base = buf.getvalue()
    start = base.find(b"PK\x03\x04") + 30 + len(member)
    for offset in range(start, base.find(b"PK\x01\x02")):
        candidate = bytearray(base)
        candidate[offset] ^= 0xFF
        if _read_failure(bytes(candidate), member) is zlib.error:
            return bytes(candidate)
    raise AssertionError(f"no single-byte flip in {member} produced a zlib.error")


def _read_failure(raw, member):
    """The exception type reading `member` out of these zip bytes raises, or None on success."""
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            archive.read(member)
    except Exception as exc:  # noqa: BLE001  a search over corrupted bytes: any type is an answer
        return type(exc)
    return None


def test_collect__product_zip_with_two_benchmarks__yields_both(tmp_path):
    # U_Google_Android_17_Y26M06_STIG.zip ships COBO and COPE in one zip.
    zip_path = tmp_path / "U_Google_Android_17_Y26M06_STIG.zip"
    _write_zip(
        zip_path,
        {
            "U_Google_Android_17_COBO_V1R1_Manual_STIG/COBO-xccdf.xml": BENCHMARK,
            "U_Google_Android_17_COPE_V1R1_Manual_STIG/COPE-xccdf.xml": BENCHMARK,
        },
    )
    found = inventory.collect([inventory.Artifact("product_zip", zip_path)], tmp_path / "out")
    assert len(found) == 2
    assert {b.origin for b in found} == {"product_zip"}
    assert {b.source_artifact for b in found} == {"U_Google_Android_17_Y26M06_STIG.zip"}
    assert sorted(b.source_member for b in found) == [
        "U_Google_Android_17_COBO_V1R1_Manual_STIG/COBO-xccdf.xml",
        "U_Google_Android_17_COPE_V1R1_Manual_STIG/COPE-xccdf.xml",
    ]


def test_collect__product_zip_with_no_benchmark__logs_a_census_and_yields_nothing(tmp_path, caplog):
    zip_path = tmp_path / "U_STIG_GPO_Package_July_2026.zip"
    _write_zip(zip_path, {"Backup/gpreport.xml": GPO_BACKUP, "ADMX Templates/chrome.admx": b"x", "a.pol": b"x"})
    with caplog.at_level("INFO"):
        found = inventory.collect([inventory.Artifact("product_zip", zip_path)], tmp_path / "out")
    assert found == []
    message = caplog.text
    assert "U_STIG_GPO_Package_July_2026.zip" in message
    assert ".xml" in message and ".admx" in message and ".pol" in message
    assert "SCAP" in message


def test_collect__product_zip_named_srg__its_benchmark_is_discovered_not_filtered_by_name(tmp_path):
    # Whether a document is an SRG is decided by stig_parser.document_kind once orchestrator
    # has parsed it, not here by the zip's name.
    zip_path = tmp_path / "U_Firewall_V2R3_SRG.zip"
    _write_zip(zip_path, {"U_Firewall_SRG_Manual-xccdf.xml": BENCHMARK})
    found = inventory.collect([inventory.Artifact("product_zip", zip_path)], tmp_path / "out")
    assert [d.source_artifact for d in found] == ["U_Firewall_V2R3_SRG.zip"]


def test_from_product_zip__zip_named_Products__its_benchmark_is_discovered(tmp_path):
    src = tmp_path / "sources"
    src.mkdir()
    zpath = src / "U_zOS_TSS_Y26M07_Products.zip"
    with zipfile.ZipFile(zpath, "w") as z:
        z.writestr("U_zOS_TSS_Manual_STIG/U_zOS_CA_Auditor_for_TSS_Manual-xccdf.xml", BENCHMARK)
    found = inventory.collect(inventory.classify(src), tmp_path / "out")
    assert [d.source_artifact for d in found] == ["U_zOS_TSS_Y26M07_Products.zip"]


def test_collect__nested_zip_inside_a_product_zip__is_not_recursed_into(tmp_path):
    # The Intune package carries a 298-member inner zip; only a compilation is a zip-of-zips.
    inner = _zip_bytes({"deep/U_Deep_STIG_Manual-xccdf.xml": BENCHMARK})
    zip_path = tmp_path / "U_Intune_Policy_Package_July_2026.zip"
    _write_zip(zip_path, {"Support Files/DSC 4.0 App Source Files.zip": inner})
    assert inventory.collect([inventory.Artifact("product_zip", zip_path)], tmp_path / "out") == []


def test_collect__loose_xccdf__is_recorded_with_no_member(tmp_path):
    loose = tmp_path / "U_Foo_STIG_V1R1_Manual-xccdf.xml"
    loose.write_bytes(BENCHMARK)
    found = inventory.collect([inventory.Artifact("loose", loose)], tmp_path / "out")
    assert len(found) == 1
    assert found[0].origin == "loose"
    assert found[0].source_artifact == "U_Foo_STIG_V1R1_Manual-xccdf.xml"
    assert found[0].source_member is None
    assert found[0].path == loose


def test_collect__compilation__records_the_inner_zip_as_the_member(tmp_path):
    # source_member is the string DISA's revision history lists under sunset content.
    inner = _zip_bytes({"U_EPAS_V2R1_Manual_STIG/EDB_Postgres_Advanced_Server_STIG.xml": BENCHMARK})
    comp = tmp_path / "U_SRG-STIG_Library_July_2026.zip"
    _write_zip(comp, {"U_EPAS_V2R1_STIG.zip": inner})
    found = inventory.collect([inventory.Artifact("library", comp)], tmp_path / "out")
    assert len(found) == 1
    assert found[0].origin == "library"
    assert found[0].source_artifact == "U_SRG-STIG_Library_July_2026.zip"
    assert found[0].source_member == "U_EPAS_V2R1_STIG.zip"


def test_collect__benchmark_inside_a_compilation__records_the_document_path_not_only_the_inner_zip(tmp_path):
    # source_member is the inner ZIP name, which is identical for two documents shipped in one
    # product zip. source_document is the path inside that zip, which is what tells them apart.
    inner = _zip_bytes({"U_Alpha_V1R1_Manual_STIG/U_Alpha_STIG_V1R1_Manual-xccdf.xml": BENCHMARK})
    comp = tmp_path / "U_SRG-STIG_Library_July_2026.zip"
    _write_zip(comp, {"U_Alpha_V1R1_STIG.zip": inner})
    found = inventory.collect([inventory.Artifact("library", comp)], tmp_path / "out")
    assert len(found) == 1
    assert found[0].source_member == "U_Alpha_V1R1_STIG.zip"
    assert found[0].source_document == "U_Alpha_V1R1_Manual_STIG/U_Alpha_STIG_V1R1_Manual-xccdf.xml"


def test_collect__benchmark_inside_a_product_zip__records_the_member_as_the_document(tmp_path):
    zip_path = tmp_path / "U_Alpha_V1R1_STIG.zip"
    _write_zip(zip_path, {"U_Alpha_V1R1_Manual_STIG/U_Alpha_STIG_V1R1_Manual-xccdf.xml": BENCHMARK})
    found = inventory.collect([inventory.Artifact("product_zip", zip_path)], tmp_path / "out")
    assert found[0].source_document == "U_Alpha_V1R1_Manual_STIG/U_Alpha_STIG_V1R1_Manual-xccdf.xml"


def test_collect__loose_xccdf_file__records_its_filename_as_the_document(tmp_path):
    path = tmp_path / "U_Alpha_STIG_V1R1_Manual-xccdf.xml"
    path.write_bytes(BENCHMARK)
    found = inventory.collect([inventory.Artifact("loose", path)], tmp_path / "out")
    assert found[0].source_document == "U_Alpha_STIG_V1R1_Manual-xccdf.xml"


def test_collect__compilation_with_no_benchmark__warns_naming_the_artifact(tmp_path, caplog):
    # A compilation holding only a Group Policy backup inner zip (or a truncated download
    # that lost every STIG inner zip) yields zero benchmarks, because pick_xccdf finds no
    # benchmark inside it, not because any inner zip was rejected by name. The module
    # docstring promises every artifact either contributes benchmarks or produces a log
    # line naming it and saying why.
    gpo_inner = _zip_bytes({"Backup/gpreport.xml": GPO_BACKUP})
    comp = tmp_path / "U_SRG-STIG_Library_July_2026.zip"
    _write_zip(comp, {"U_STIG_GPO_Package.zip": gpo_inner})
    with caplog.at_level("WARNING"):
        found = inventory.collect([inventory.Artifact("library", comp)], tmp_path / "out")
    assert found == []
    assert "U_SRG-STIG_Library_July_2026.zip" in caplog.text


def test_collect__unreadable_zip__warns_and_continues(tmp_path, caplog):
    bad = tmp_path / "U_Broken_STIG.zip"
    bad.write_bytes(b"not a zip at all")
    good = tmp_path / "U_Good_STIG.zip"
    _write_zip(good, {"U_Good_STIG_Manual-xccdf.xml": BENCHMARK})
    with caplog.at_level("WARNING"):
        found = inventory.collect(
            [inventory.Artifact("product_zip", bad), inventory.Artifact("product_zip", good)], tmp_path / "out"
        )
    assert len(found) == 1
    assert "U_Broken_STIG.zip" in caplog.text


def test_collect__corrupt_member_in_product_zip__skips_and_continues(tmp_path, caplog):
    # The corrupt zip opens fine (its central directory is intact); the failure only
    # surfaces on archive.read(member), unlike the open-time failure
    # test_collect__unreadable_zip__ covers.
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        z.writestr("U_Corrupt_STIG_Manual-xccdf.xml", BENCHMARK)
    raw = bytearray(buf.getvalue())
    idx = raw.find(b"<Benchmark")
    raw[idx] ^= 0xFF
    corrupt = tmp_path / "U_Corrupt_STIG.zip"
    corrupt.write_bytes(bytes(raw))
    good = tmp_path / "U_Good_STIG.zip"
    _write_zip(good, {"U_Good_STIG_Manual-xccdf.xml": BENCHMARK})
    with caplog.at_level("WARNING"):
        found = inventory.collect(
            [inventory.Artifact("product_zip", corrupt), inventory.Artifact("product_zip", good)], tmp_path / "out"
        )
    assert len(found) == 1
    assert found[0].source_artifact == "U_Good_STIG.zip"
    assert "U_Corrupt_STIG.zip" in caplog.text


def test_collect__a_corrupt_deflated_member__skips_and_continues(tmp_path, caplog):
    # The zlib.error member of library.UNREADABLE_ZIP, pinned at a site that USES the tuple.
    # The CRC test above does not cover it: those bytes decompress cleanly and fail the
    # checksum, which raises BadZipFile. This member is not named xccdf.xml, so pick_xccdf's
    # third tier must inflate it.
    corrupt = tmp_path / "U_Corrupt_Deflate_STIG.zip"
    corrupt.write_bytes(_deflated_zip_failing_to_decompress("payload.xml", BENCHMARK))
    good = tmp_path / "U_Good_STIG.zip"
    _write_zip(good, {"U_Good_STIG_Manual-xccdf.xml": BENCHMARK})
    with caplog.at_level("WARNING"):
        found = inventory.collect(
            [inventory.Artifact("product_zip", corrupt), inventory.Artifact("product_zip", good)], tmp_path / "out"
        )
    assert [b.source_artifact for b in found] == ["U_Good_STIG.zip"]
    assert "U_Corrupt_Deflate_STIG.zip" in caplog.text


def test_source_status__empty_directory__reports_every_class_missing(tmp_path):
    assert inventory.source_status(tmp_path) == {
        "ATT&CK": False,
        "CTID": False,
        "800-53r5 catalog": False,
        "DISA CCI list": False,
        "STIG benchmarks": False,
    }


def test_source_status__a_loose_benchmark__reports_benchmarks_present(tmp_path):
    # Benchmarks are reported via classify, not a filename guess, so this agrees with what
    # the ingest will actually find. A .json or .xml that is not a benchmark must not count.
    (tmp_path / "rhel9_xccdf.xml").write_bytes((FIX / "rhel9_xccdf.xml").read_bytes())
    status = inventory.source_status(tmp_path)
    assert status["STIG benchmarks"] is True
    assert status["ATT&CK"] is False


def test_source_status__a_missing_directory__reports_every_class_missing(tmp_path):
    assert set(inventory.source_status(tmp_path / "nope").values()) == {False}


def test_source_status__two_library_compilations__still_reports_benchmarks_present(tmp_path):
    # classify refuses to guess between two compilations; benchmarks are certainly present
    # and the ingest will refuse for its own reason and say so itself.
    #
    # These two .zip names match no `*xccdf.xml` glob, so this is the test that catches
    # source_status answering from a filename guess instead of from classify(), whose
    # deliberate TwoLibrariesError (see its docstring) makes this True.
    _touch(tmp_path, "U_SRG-STIG_Library_July_2026.zip", "U_SRG-STIG_Library_October_2026.zip")
    assert inventory.source_status(tmp_path)["STIG benchmarks"] is True


def test_source_status__unrelated_json_and_xml__reports_benchmarks_absent(tmp_path):
    # Pins the claim in the loose-benchmark test's comment above: a .json or an .xml that
    # is not a benchmark must not count. Neither name matches LOOSE_GLOB, so classify() falls
    # through to judging the .xml by its root element (CCI_LIST is well-formed XML rooted at
    # <cci_list>, not <Benchmark>), and this fails if that content check is loosened to accept
    # any .xml.
    (tmp_path / "not_a_benchmark.xml").write_bytes(CCI_LIST)
    (tmp_path / "not_a_benchmark.json").write_bytes(b"{}")
    assert inventory.source_status(tmp_path)["STIG benchmarks"] is False


def test_source_status__a_runtime_error_that_is_not_the_two_library_case__propagates(tmp_path, monkeypatch):
    # The except here exists for two conditions, two library compilations or a refused CUI
    # file, where benchmarks are certainly present and the ingest refuses for its own reason.
    # Any other RuntimeError out of classify must propagate rather than be reported as
    # benchmarks present on the strength of a failure nothing looked at.
    def boom(_sources_dir):
        raise RuntimeError("something else entirely")

    monkeypatch.setattr(inventory, "classify", boom)
    with pytest.raises(RuntimeError, match="something else entirely"):
        inventory.source_status(tmp_path)


def test_source_status__a_directory_holding_only_the_CCI_archive__reports_no_benchmarks(tmp_path):
    # _kind_of judges archives by name and its last rule is "any .zip is a product zip", so
    # U_CCI_List.zip classifies as one. Answering "STIG benchmarks" from bool(artifacts) would
    # report an archive holding no benchmark as benchmarks staged, beside "DISA CCI list": False
    # for the same file, since that class looks for the extracted U_CCI_List.xml.
    _write_zip(tmp_path / "U_CCI_List.zip", {"U_CCI_List.xml": CCI_LIST})
    status = inventory.source_status(tmp_path)
    assert status["STIG benchmarks"] is False
    assert status["DISA CCI list"] is False


def test_source_status__a_product_zip_holding_no_benchmark_beside_one_that_does__reports_benchmarks_present(tmp_path):
    # The predicate is any(), not all(). A corpus normally holds hundreds of archives that carry
    # no Manual STIG content, so letting one of them veto the answer would report an empty
    # corpus for almost every real directory.
    _write_zip(tmp_path / "U_CCI_List.zip", {"U_CCI_List.xml": CCI_LIST})
    _write_zip(tmp_path / "U_Good_STIG.zip", {"U_Good_STIG_Manual-xccdf.xml": BENCHMARK})
    assert inventory.source_status(tmp_path)["STIG benchmarks"] is True


def test_source_status__a_product_zip_whose_benchmark_lacks_the_xccdf_suffix__reports_benchmarks_present(tmp_path):
    # Pins that the check calls pick_xccdf and not a cheaper namelist suffix test. The suffix
    # alone loses U_EPAS_V2R1_STIG.zip, which ships EDB_Postgres_Advanced_Server_STIG.xml, and
    # only pick_xccdf's root-element fallback finds it.
    _write_zip(tmp_path / "U_EPAS_V2R1_STIG.zip", {"EDB_Postgres_Advanced_Server_STIG.xml": BENCHMARK})
    assert inventory.source_status(tmp_path)["STIG benchmarks"] is True


def test_source_status__an_unreadable_product_zip__reports_no_benchmarks(tmp_path):
    # An archive nothing can open cannot be evidence that benchmarks are staged. The ingest
    # warns about this file when it runs; the status report answers False and stays quiet,
    # which is the property the logging test below pins.
    (tmp_path / "U_Broken_STIG.zip").write_bytes(b"not a zip at all")
    assert inventory.source_status(tmp_path)["STIG benchmarks"] is False


def test_source_status__a_library_compilation_holding_nothing__reports_benchmarks_present(tmp_path):
    # A compilation is trusted on its name and never opened, deliberately. Walking one means
    # library.iter_stig_members reading every inner zip's bytes in full, which is the whole
    # archive, on a path that runs while the server is answering a tool call. This file is the
    # bytes b"PK" and is not a zip, so any change that opens compilations here fails this test.
    _touch(tmp_path, "U_SRG-STIG_Library_July_2026.zip")
    assert inventory.source_status(tmp_path)["STIG benchmarks"] is True


def test_source_status__a_product_zip_holding_no_benchmark__logs_nothing(tmp_path, caplog):
    # collect's census INFO explains why an archive was SKIPPED during an ingest. Nothing is
    # being skipped here, and readiness.payload calls this on every tool call made while the
    # knowledge base is unusable, so emitting one line per archive would put hundreds on stderr
    # each time. Silence is the contract; _holds_benchmark must not reuse collect's logging.
    _write_zip(tmp_path / "U_CCI_List.zip", {"U_CCI_List.xml": CCI_LIST})
    # Captured at DEBUG, not INFO. at_level("INFO") raises the capturing handler to INFO, so a
    # logger.debug added to _holds_benchmark would satisfy `records == []` by the capture level
    # rather than by the behavior. Scoped to this module's logger because library._is_benchmark
    # does log at DEBUG, once per .xml member it cannot parse, as _holds_benchmark's docstring says.
    with caplog.at_level("DEBUG", logger="stig_mcp.ingest.inventory"):
        assert inventory.source_status(tmp_path)["STIG benchmarks"] is False
    assert [r for r in caplog.records if r.name == "stig_mcp.ingest.inventory"] == []


def test_source_status__an_early_artifact_holds_a_benchmark__stops_opening_the_rest(tmp_path, monkeypatch):
    # source_status's docstring rests half its cost argument on any() short-circuiting. classify
    # walks sorted(iterdir()), so the good archive is named to sort first and the second must
    # never be opened.
    _write_zip(tmp_path / "U_A_Good_STIG.zip", {"U_A_Good_STIG_Manual-xccdf.xml": BENCHMARK})
    _write_zip(tmp_path / "U_B_Empty_STIG.zip", {"readme.txt": b"nothing here"})
    asked = []
    real = inventory._holds_benchmark
    monkeypatch.setattr(inventory, "_holds_benchmark", lambda a: asked.append(a.path.name) or real(a))
    assert inventory.source_status(tmp_path)["STIG benchmarks"] is True
    assert asked == ["U_A_Good_STIG.zip"]


def test_source_status__a_sunset_compilation__reports_benchmarks_present_without_opening_it(tmp_path):
    # Pins the sunset kind in the trust branch, which the library case alone does not. A sunset
    # archive is a zip-of-zips whose outer namelist holds only .zip members, so pick_xccdf over
    # it returns nothing while collect finds benchmarks inside; opening one here would report a
    # real archive missing. The bytes b"PK" are not a zip, so any change that opens it fails
    # rather than passing by luck.
    _touch(tmp_path, "U_Rev_4_SRG-STIG_Sunset_Compilation.zip")
    assert inventory.source_status(tmp_path)["STIG benchmarks"] is True


def test_source_status__a_zip_whose_permissions_deny_it__reports_no_benchmarks(tmp_path):
    # readiness.payload calls this on the not-ready path, which is exactly when an operator is
    # part-way through a chmod, a cp or an rm in sources/, and an exception here would reach
    # them as a traceback in place of the report. PermissionError and FileNotFoundError are
    # OSError; neither is in UNREADABLE_ZIP.
    zip_path = tmp_path / "U_Locked_STIG.zip"
    _write_zip(zip_path, {"U_Locked_STIG_Manual-xccdf.xml": BENCHMARK})
    zip_path.chmod(0o000)
    try:
        readable = True
        try:
            readable = bool(zip_path.read_bytes())
        except OSError:
            readable = False
        if readable:  # running as root: the chmod buys nothing, so skip
            pytest.skip("cannot make a file unreadable as this user")
        assert inventory.source_status(tmp_path)["STIG benchmarks"] is False
    finally:
        # One finally, so the mode is restored on the skip path too. tmp_path is torn down by
        # pytest, which needs the bit back.
        zip_path.chmod(0o644)


def test_holds_benchmark__an_artifact_deleted_after_classify__is_false(tmp_path):
    # classify() lists the directory and _holds_benchmark opens it, so the file can go away in
    # between. Tested through the artifact rather than source_status because the race cannot be
    # driven from outside the one call.
    zip_path = tmp_path / "U_Ghost_STIG.zip"
    _write_zip(zip_path, {"U_Ghost_STIG_Manual-xccdf.xml": BENCHMARK})
    artifact = inventory.classify(tmp_path)[0]
    zip_path.unlink()
    assert inventory._holds_benchmark(artifact) is False


def test_source_status__a_member_in_an_unsupported_compression_method__reports_no_benchmarks(tmp_path):
    # archive.read raises NotImplementedError, not a zipfile error, for a compression method no
    # Python supports; 99 is not one this build merely lacks. _is_benchmark's broad catch cannot
    # absorb it: read(n) is evaluated as an ARGUMENT in pick_xccdf's third tier, before
    # _is_benchmark is entered.
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("payload.xml", BENCHMARK)
    raw = bytearray(buf.getvalue())
    for signature, offset in ((b"PK\x03\x04", 8), (b"PK\x01\x02", 10)):
        at = raw.find(signature)
        raw[at + offset : at + offset + 2] = (99).to_bytes(2, "little")
    (tmp_path / "U_Exotic_STIG.zip").write_bytes(bytes(raw))
    assert inventory.source_status(tmp_path)["STIG benchmarks"] is False


def test_source_status__an_encrypted_member__reports_no_benchmarks(tmp_path):
    # RuntimeError, from ZipFile.open, and not an OSError, so an enumerated tuple of zip and OS
    # errors would let it through. Reached only when pick_xccdf falls to its third tier, which is
    # why the member is NOT named xccdf.xml: that is the EPAS shape, the one form that needs
    # decompressing.
    (tmp_path / "U_Sealed_STIG.zip").write_bytes(_zip_with_flags("payload.xml", 0x1))
    assert inventory.source_status(tmp_path)["STIG benchmarks"] is False


def test_source_status__a_member_name_that_is_not_utf8__reports_no_benchmarks(tmp_path):
    # UnicodeDecodeError is a ValueError, which an enumerated tuple would also miss, and it comes
    # out of ZipFile.__init__ rather than a read: no third tier needed, any such archive staged
    # in sources/ is enough. Together with the encrypted case these are why the catch is broad.
    (tmp_path / "U_Mojibake_STIG.zip").write_bytes(_zip_with_flags("payload.xml", 0x800, b"pay\xffoad.xml"))
    assert inventory.source_status(tmp_path)["STIG benchmarks"] is False


def test_source_status__a_corrupt_deflated_member__reports_no_benchmarks(tmp_path):
    # The zlib.error member of UNREADABLE_ZIP at this call site, where the other unreadable
    # fixtures fail at OPEN. This one opens cleanly, its central directory intact, and fails
    # inside pick_xccdf's third tier. The member is not named xccdf.xml precisely so that tier
    # has to decompress it.
    corrupt = tmp_path / "U_Corrupt_Deflate_STIG.zip"
    corrupt.write_bytes(_deflated_zip_failing_to_decompress("payload.xml", BENCHMARK))
    with pytest.raises(zlib.error):  # the fixture is worth nothing unless it really raises this
        with zipfile.ZipFile(corrupt) as archive:
            archive.read("payload.xml")
    assert inventory.source_status(tmp_path)["STIG benchmarks"] is False
