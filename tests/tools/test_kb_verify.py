import shutil
import sqlite3

import pytest

from stig_mcp.ingest import catalog, fetch
from stig_mcp.server import tools
from tools import kb_verify


def _recorded_sources(tmp_path):
    """A sources directory whose manifest records one real file, so verify gets past its
    empty-manifest refusal and reaches the checks a test is about."""
    sources = tmp_path / "sources"
    sources.mkdir()
    (sources / "U_Foo_V1R1_STIG.zip").write_bytes(b"z")
    fetch.write_manifest(sources, [catalog.Entry(name="U_Foo_V1R1_STIG.zip", href="x", date="d", size_bytes=1)])
    return sources


def _stigs(tmp_path, rows):
    """A stigs table alone, which is all tripwire reads."""
    conn = sqlite3.connect(tmp_path / "t.sqlite")
    conn.row_factory = sqlite3.Row
    conn.execute("CREATE TABLE stigs (origin TEXT, source_artifact TEXT, source_member TEXT)")
    conn.executemany("INSERT INTO stigs VALUES (?, ?, ?)", rows)
    return conn


def test_tripwire__a_loose_revision_newer_than_the_library__passes_when_the_loose_one_is_stored(tmp_path):
    conn = _stigs(tmp_path, [("product_zip", "U_MS_Windows_11_V2R9_STIG.zip", "x/y-xccdf.xml")])
    try:
        assert kb_verify.tripwire(conn, ["U_MS_Windows_11_V2R9_STIG.zip"])["stale"] == []
    finally:
        conn.close()


def test_tripwire__the_library_revision_stored_over_a_newer_loose_one__is_stale(tmp_path):
    # The regression the tripwire exists for: _contest ranking origin before release.
    conn = _stigs(tmp_path, [("library", "U_SRG-STIG_Library_July_2026.zip", "U_MS_Windows_11_V2R8_STIG.zip")])
    try:
        stale = kb_verify.tripwire(conn, ["U_MS_Windows_11_V2R9_STIG.zip"])["stale"]
    finally:
        conn.close()
    assert stale == ["U_MS_Windows_11_V2R9_STIG.zip (knowledge base holds V2R8)"]


def test_tripwire__two_majors_stored__compares_only_the_matching_major(tmp_path):
    # V3R1 stored at major 3 must not satisfy a V2R9 on the index; V2R8 is what major 2 holds.
    conn = _stigs(
        tmp_path,
        [
            ("library", "L.zip", "U_Foo_V2R8_STIG.zip"),
            ("product_zip", "U_Foo_V3R1_STIG.zip", "m"),
        ],
    )
    try:
        result = kb_verify.tripwire(conn, ["U_Foo_V2R9_STIG.zip", "U_Foo_V3R1_STIG.zip"])
    finally:
        conn.close()
    assert result["stale"] == ["U_Foo_V2R9_STIG.zip (knowledge base holds V2R8)"]


def test_tripwire__a_newer_major_held_back_by_the_library__is_other_major_not_stale(tmp_path):
    conn = _stigs(tmp_path, [("library", "L.zip", "U_Foo_V2R9_STIG.zip")])
    try:
        result = kb_verify.tripwire(conn, ["U_Foo_V3R1_STIG.zip"])
    finally:
        conn.close()
    assert result == {"stale": [], "other_major": ["U_Foo_V3R1_STIG.zip"], "unmatched": []}


def test_tripwire__compilations_the_cci_list_and_unversioned_names__are_skipped(tmp_path):
    conn = _stigs(tmp_path, [])
    try:
        result = kb_verify.tripwire(
            conn,
            ["U_SRG-STIG_Library_July_2026.zip", "U_CCI_List.zip", "U_Unversioned_STIG.zip", "U_Bar_V1R1_STIG.zip"],
        )
    finally:
        conn.close()
    assert result == {"stale": [], "other_major": [], "unmatched": ["U_Bar_V1R1_STIG.zip"]}


def test_tripwire__a_library_row_with_no_member_name__is_skipped_not_raised(tmp_path):
    # Measured on the kb_path fixture: its library rows carry source_member NULL.
    conn = _stigs(tmp_path, [("library", "U_SRG-STIG_Library_July_2026.zip", None)])
    try:
        assert kb_verify.tripwire(conn, ["U_Foo_V1R1_STIG.zip"])["unmatched"] == ["U_Foo_V1R1_STIG.zip"]
    finally:
        conn.close()


def test_tripwire__a_folder_prefixed_library_member__is_stale_not_unmatched(tmp_path):
    # DISA nests every inner zip of a library compilation under a folder, so source_member is a
    # full path (e.g. "U_SRG-STIG_Library_April_2025/U_MS_Windows_11_V2R8_STIG.zip"), not a bare
    # name. source_file (tools.kb_package) must strip that folder before tripwire keys it, or a
    # real stale release reads as unmatched instead.
    conn = _stigs(
        tmp_path,
        [
            (
                "library",
                "U_SRG-STIG_Library_April_2025.zip",
                "U_SRG-STIG_Library_April_2025/U_MS_Windows_11_V2R8_STIG.zip",
            )
        ],
    )
    try:
        stale = kb_verify.tripwire(conn, ["U_MS_Windows_11_V2R9_STIG.zip"])["stale"]
    finally:
        conn.close()
    assert stale == ["U_MS_Windows_11_V2R9_STIG.zip (knowledge base holds V2R8)"]


def test_tripwire__the_stored_prefix_differs_in_case_from_the_index__still_matches(tmp_path):
    # The library and the loose zip come from different DISA packagers, so the same product
    # can be spelled with different casing in each; the key must fold case or this pair, which
    # is the same product at the same major, reads as two unrelated products instead of stale.
    conn = _stigs(tmp_path, [("library", "L.zip", "U_Ms_Windows_11_V2R8_STIG.zip")])
    try:
        stale = kb_verify.tripwire(conn, ["U_MS_Windows_11_V2R9_STIG.zip"])["stale"]
    finally:
        conn.close()
    assert stale == ["U_MS_Windows_11_V2R9_STIG.zip (knowledge base holds V2R8)"]


def test_unrecorded_files__only_fetch_written_files__is_empty(tmp_path):
    entries = [catalog.Entry(name="U_Foo_V1R1_STIG.zip", href="x", date="d", size_bytes=1)]
    (tmp_path / "U_Foo_V1R1_STIG.zip").write_bytes(b"z")
    fetch.write_manifest(tmp_path, entries)
    for name in (*fetch._TARGET_FILENAMES.values(), fetch.ATTACK_INDEX_NAME, "U_CCI_List.xml"):
        (tmp_path / name).write_text("{}")
    assert kb_verify.unrecorded_files(tmp_path) == []


def test_unrecorded_files__a_zip_and_an_xml_nothing_recorded__are_both_named(tmp_path):
    fetch.write_manifest(tmp_path, [])
    (tmp_path / "U_Leftover_V1R1_STIG.zip").write_bytes(b"z")
    (tmp_path / "loose-xccdf.xml").write_text("<x/>")
    assert kb_verify.unrecorded_files(tmp_path) == ["U_Leftover_V1R1_STIG.zip", "loose-xccdf.xml"]


def test_golden_failures__the_fixture__passes_rhel_and_names_what_it_lacks(kb_path, tmp_path):
    # The fixture holds RHEL 9 and Windows Server 2022 (and T1078 and APT29 in its ATT&CK bundle),
    # so the RHEL check must pass and the Windows 11 check must fail by name: a harness where
    # every check passes proves nothing.
    copy = tmp_path / "kb.sqlite"
    shutil.copyfile(kb_path, copy)
    failures = kb_verify.golden_failures(copy)
    assert not any(f.startswith("RHEL 9") for f in failures)
    assert any(f.startswith("T1078 on Windows 11") for f in failures)


def test_golden_failures__a_check_the_tools_refuse__is_a_named_failure_not_a_crash(kb_path, tmp_path):
    copy = tmp_path / "kb.sqlite"
    shutil.copyfile(kb_path, copy)

    def unknown_actor(kb):
        return tools.techniques_for_actor(kb, "No Such Group") and None

    failures = kb_verify.golden_failures(copy, (kb_verify.Golden("unknown actor", unknown_actor),))
    assert failures == [
        "unknown actor: Unknown actor 'No Such Group'. Provide an ATT&CK group id (e.g. 'G0016') or a known name/alias."
    ]


def test_verify__every_failure__is_named_in_one_refusal(kb_path, tmp_path):
    copy = tmp_path / "kb.sqlite"
    shutil.copyfile(kb_path, copy)
    sources = _recorded_sources(tmp_path)
    (sources / "U_Leftover_V1R1_STIG.zip").write_bytes(b"z")
    with pytest.raises(kb_verify.VerifyError) as refused:
        kb_verify.verify(copy, sources)
    message = str(refused.value)
    assert "U_Leftover_V1R1_STIG.zip" in message
    assert "T1078 on Windows 11" in message


def test_verify__a_knowledge_base_that_is_not_ready__is_refused_first(tmp_path):
    sources = tmp_path / "sources"
    sources.mkdir()
    with pytest.raises(kb_verify.VerifyError, match="no_knowledge_base"):
        kb_verify.verify(tmp_path / "missing.sqlite", sources)


def test_verify__no_manifest__is_refused_because_the_tripwire_has_no_index(kb_path, tmp_path):
    copy = tmp_path / "kb.sqlite"
    shutil.copyfile(kb_path, copy)
    sources = tmp_path / "sources"
    sources.mkdir()
    with pytest.raises(kb_verify.VerifyError, match="stig-mcp-fetch --refresh --drop-withdrawn"):
        kb_verify.verify(copy, sources, golden=())


def _kb_with_a_loose_release(kb_path, tmp_path):
    """A copy of kb_path with MS_Windows_Server_2022_STIG's row rewritten as a loose product
    zip release V1R1, so the tripwire has a real key to compare a higher index release against.

    kb_path's own rows cannot drive this test: both are origin='library' with source_member
    NULL (source_file returns None for both, per test_tripwire__a_library_row_with_no_member_
    name__is_skipped_not_raised), so neither contributes a key to tripwire's `held` at all.
    Rewriting one row's origin/source_artifact to a loose zip is the smallest change that gives
    tripwire something stored to compare against, without touching readiness or the golden
    queries, which read resolved systems and technique/actor data untouched by this row."""
    copy = tmp_path / "kb.sqlite"
    shutil.copyfile(kb_path, copy)
    conn = sqlite3.connect(copy)
    try:
        conn.execute(
            "UPDATE stigs SET origin = 'product_zip', source_artifact = ?, source_member = NULL "
            "WHERE stig_id = 'MS_Windows_Server_2022_STIG'",
            ("U_MS_Windows_Server_2022_V1R1_STIG.zip",),
        )
        conn.commit()
    finally:
        conn.close()
    return copy


def test_verify__the_index_names_a_higher_release_than_the_kb_stores__raises_naming_stale(kb_path, tmp_path):
    copy = _kb_with_a_loose_release(kb_path, tmp_path)
    sources = tmp_path / "sources"
    sources.mkdir()
    (sources / "U_MS_Windows_Server_2022_V1R2_STIG.zip").write_bytes(b"z")
    fetch.write_manifest(
        sources, [catalog.Entry(name="U_MS_Windows_Server_2022_V1R2_STIG.zip", href="x", date="d", size_bytes=1)]
    )
    with pytest.raises(kb_verify.VerifyError, match="stale:") as refused:
        kb_verify.verify(copy, sources, golden=())
    assert "U_MS_Windows_Server_2022_V1R2_STIG.zip (knowledge base holds V1R1)" in str(refused.value)


def test_verify__a_clean_build_against_its_own_index__returns_the_tripwire_with_no_stale(kb_path, tmp_path):
    copy = tmp_path / "kb.sqlite"
    shutil.copyfile(kb_path, copy)
    sources = _recorded_sources(tmp_path)
    result = kb_verify.verify(copy, sources, golden=())
    assert result["tripwire"]["stale"] == []


@pytest.mark.parametrize(
    ("findings", "fix_text", "expected"),
    [
        ({}, "", "no STIG findings under any control"),
        ({"SV-1r1_rule": {}}, "Configure it.", None),
        ({"SV-1r1_rule": {}}, "", "finding_details returned no fix text"),
    ],
)
def test_windows_11_check__findings_and_their_details__decide_the_result(monkeypatch, findings, fix_text, expected):
    answer = {"resolved_systems": [{"stig_id": "Microsoft_Windows_11_STIG"}], "findings": findings}
    monkeypatch.setattr(kb_verify.tools, "mitigations_for_technique", lambda kb, *a, **k: answer)
    monkeypatch.setattr(kb_verify.tools, "finding_details", lambda kb, ids: {"findings": [{"fix_text": fix_text}]})
    assert kb_verify._windows_11(object()) == expected
