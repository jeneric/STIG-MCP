import hashlib
import lzma
import os
import re
import shutil
import sqlite3
import ssl
import urllib.error
from contextlib import closing
from pathlib import Path

import pytest

from stig_mcp import applicability, tls
from stig_mcp.ingest import config
from stig_mcp.ingest.orchestrator import IngestSources, build_kb
from stig_mcp.kb import queries, releases
from stig_mcp.kb.db import create_db
from stig_mcp.kb.queries import stigs_for_resolver
from stig_mcp.resolver.normalize import normalize
from stig_mcp.resolver.resolver import resolve as real_resolve
from stig_mcp.server import app as app_module
from stig_mcp.server import tools
from tests.conftest import FIX, discovered, kb_holder, open_db_for_test
from tests.kb.fake_github import FakeGitHub, http_error, refuse_network


@pytest.fixture(autouse=True)
def _close_the_connections_kb_holder_opens(monkeypatch):
    """kb_holder hands out a real KnowledgeBase, and acquire() opens its own connection
    through app.open_db rather than reusing the fixture connection it was built from. Routing
    that through the test helper hands every such connection to the teardown that closes it,
    the same fix test_app.py already applies for the same reason."""
    monkeypatch.setattr(app_module, "open_db", open_db_for_test)


def test_defenses_for_technique__known_technique_and_system__returns_controls_with_rules(kb_path):
    conn = open_db_for_test(kb_path)
    result = tools.defenses_for_technique(kb_holder(conn), "T1078", "RHEL 9 web server")
    assert result["technique"]["id"] == "T1078"
    assert result["resolved_systems"][0]["stig_id"] == "RHEL_9_STIG"
    ac2_1 = next((c for c in result["protect"]["controls"] if c["control_id"] == "AC-2(1)"), None)
    assert ac2_1 is not None and ac2_1["rules"]


def test_defenses_for_technique__no_system_supplied__returns_controls_without_findings_and_note(kb_path):
    conn = open_db_for_test(kb_path)
    result = tools.defenses_for_technique(kb_holder(conn), "T1078")
    assert result["protect"]["controls"]
    assert result["protect"]["findings"] == {}
    assert all(c["rules"] == [] for c in result["protect"]["controls"])
    assert any("system" in note.lower() for note in result["notes"])


def test_defenses_for_technique__explicit_benchmark_ids__bypasses_resolver(kb_path):
    conn = open_db_for_test(kb_path)
    result = tools.defenses_for_technique(
        kb_holder(conn), "T1078", system_description="ignored text", benchmark_ids=["RHEL_9_STIG"]
    )
    # Same shape as the resolver path, so a caller never branches on which produced it.
    assert result["resolved_systems"] == [
        {
            "stig_id": "RHEL_9_STIG",
            "title": "Red Hat Enterprise Linux 9 Security Technical Implementation Guide",
            "version": "1",
            "release_label": "V1R1",
            "release_info": "Release: 1 Benchmark Date: 24 Jul 2024",
            "origin": "library",
            "source_artifact": "U_SRG-STIG_Library_July_2026.zip",
            "source_member": None,
            "xccdf_status": None,
            "xccdf_status_date": None,
            "score": 100.0,
            "matched_on": "explicit",
            "high_confidence": True,
            "applicable": True,
            "applicability": None,
            "wanted_version": None,
            "build": None,
            "version_coverage": [],
            "tied_omitted": 0,
            "catalog": "disa",
        }
    ]
    assert any(c["rules"] for c in result["protect"]["controls"])


def test_defenses_for_technique__explicit_ids_match_the_resolver_shape(kb_path):
    conn = open_db_for_test(kb_path)
    explicit = tools.defenses_for_technique(kb_holder(conn), "T1078", benchmark_ids=["RHEL_9_STIG"])
    resolved = tools.defenses_for_technique(kb_holder(conn), "T1078", system_description="Red Hat Enterprise Linux 9")
    assert set(explicit["resolved_systems"][0]) == set(resolved["resolved_systems"][0])


def test_defenses_for_technique__unknown_stig_id__keeps_it_and_explains_the_empty_result(kb_path):
    conn = open_db_for_test(kb_path)
    result = tools.defenses_for_technique(kb_holder(conn), "T1078", benchmark_ids=["NOPE_STIG"])
    entry = next(s for s in result["resolved_systems"] if s["stig_id"] == "NOPE_STIG")
    assert entry["title"] is None and entry["high_confidence"] is False
    assert any("NOPE_STIG" in note and "list_stigs" in note for note in result["notes"])


def test_defenses_for_technique__repeated_unknown_stig_id__keeps_it_once(kb_path):
    conn = open_db_for_test(kb_path)
    result = tools.defenses_for_technique(kb_holder(conn), "T1078", benchmark_ids=["NOPE_STIG", "NOPE_STIG"])
    entries = [s for s in result["resolved_systems"] if s["stig_id"] == "NOPE_STIG"]
    assert len(entries) == 1
    notes = [note for note in result["notes"] if "NOPE_STIG" in note]
    assert len(notes) == 1


def test_defenses_for_technique__benchmark_ids_none_of_which_exist__explains_once_without_per_control_noise(kb_path):
    # When every named stig_id is unknown, scope is empty, so the caller already gets one
    # explicit note per unknown id (asserted below). A "Control X has no rules, ... in the
    # resolved STIG(s)" note on top of that, once per control, would repeat the same fact
    # the unknown-id note already gave: deliberately absent, do not add it back.
    conn = open_db_for_test(kb_path)
    result = tools.defenses_for_technique(kb_holder(conn), "T1078", benchmark_ids=["NOPE_STIG"])
    entry = next(s for s in result["resolved_systems"] if s["stig_id"] == "NOPE_STIG")
    assert entry["title"] is None and entry["high_confidence"] is False
    assert any("NOPE_STIG" in note and "list_stigs" in note for note in result["notes"])
    assert not any("has no" in note for note in result["notes"])


def test_defenses_for_technique__id_with_two_majors__lists_every_version(tmp_path):
    # A bare benchmark id scopes to all its versions, so the echo has to show both or
    # the caller cannot tell which release the findings came from.
    fixtures = Path(__file__).parent.parent / "fixtures"
    out = tmp_path / "kb.sqlite"
    build_kb(
        IngestSources(
            benchmarks=[discovered(fixtures / "rhel9_xccdf.xml"), discovered(fixtures / "rhel9_v2_xccdf.xml")],
            cci_path=fixtures / "cci_list.xml",
            attack_path=fixtures / "attack_bundle.json",
            ctid_path=fixtures / "ctid_mappings.csv",
            overrides_path=fixtures / "overrides.yaml",
        ),
        out,
    )
    conn = open_db_for_test(out)
    result = tools.defenses_for_technique(kb_holder(conn), "T1078", benchmark_ids=["RHEL_9_STIG"])
    assert sorted(s["version"] for s in result["resolved_systems"]) == ["1", "2"]


def test_defenses_for_technique__two_majors_of_one_benchmark__keep_distinct_benchmark_keys(tmp_path, monkeypatch):
    conn = _governed_kb(tmp_path, monkeypatch)
    result = tools.defenses_for_technique(kb_holder(conn), "T1078", benchmark_ids=["RHEL_9_STIG"])
    assert {f["benchmark"] for f in result["protect"]["findings"].values()} == {"RHEL_9_STIG/1", "RHEL_9_STIG/2"}


def test_finding_details__list_answers_drop_ccis__finding_details_still_returns_them(kb_path):
    kb = app_module.KnowledgeBase(kb_path)
    listed = tools.defenses_for_technique(kb, "T1078", benchmark_ids=["RHEL_9_STIG"])["protect"]["findings"]
    assert listed and not any("ccis" in f for f in listed.values())
    details = tools.finding_details(kb, list(listed))["findings"]
    assert all(row["ccis"] for row in details)


RULES_YAML = (
    "TEST_RHEL:\n"
    "  id_pattern: '^RHEL_9_STIG$'\n"
    "  build_pattern: '\\b(?:u(?P<n>\\d+)[a-z]?|ga)\\b'\n"
    "  source: 'test fixture'\n"
    "  verified_against: 'test fixture'\n"
    "  thresholds:\n"
    "    - min: 3\n"
    '      version: "2"\n'
    "    - min: 2\n"
    '      version: "1"\n'
    "    - min: 0\n"
    "      version: null\n"
)


def _governed_kb(tmp_path, monkeypatch, extra_stig_paths=()):
    """A KB holding RHEL_9_STIG at majors 1 and 2 under a governing applicability rule. The
    shared kb_path fixture is single-major on purpose and must not be changed.
    extra_stig_paths adds further compilations to the same build; despite the name, each
    element must be a DiscoveredBenchmark (use discovered()), not a bare path."""
    rules = tmp_path / "rules.yaml"
    rules.write_text(RULES_YAML)
    monkeypatch.setattr(applicability, "RULES_PATH", rules)
    out = tmp_path / "kb.sqlite"
    build_kb(
        IngestSources(
            benchmarks=[discovered(FIX / "rhel9_xccdf.xml"), discovered(FIX / "rhel9_v2_xccdf.xml"), *extra_stig_paths],
            cci_path=FIX / "cci_list.xml",
            attack_path=FIX / "attack_bundle.json",
            ctid_path=FIX / "ctid_mappings.csv",
            overrides_path=FIX / "overrides.yaml",
            catalog_path=FIX / "oscal_catalog.json",
        ),
        out,
    )
    return open_db_for_test(out)


def test_defenses_for_technique__explicit_multi_major_id__is_flagged_and_single_major_is_not(tmp_path, monkeypatch):
    # The flag is driven by how many majors the KB holds for the id, not by whether an
    # applicability rule governs it: _explicit_scope never consults applicability rules.
    # RHEL_9_STIG is governed by the injected test rule here (via _governed_kb), and still
    # must be flagged for the same reason it would be if ungoverned, because it resolves to
    # two majors in this KB; MS_Windows_Server_2022_STIG, present at one major, must not be.
    conn = _governed_kb(tmp_path, monkeypatch, extra_stig_paths=[discovered(FIX / "win2022_xccdf.xml")])
    result = tools.defenses_for_technique(
        kb_holder(conn), "T1078", benchmark_ids=["RHEL_9_STIG", "MS_Windows_Server_2022_STIG"]
    )
    by_id = {}
    for row in result["resolved_systems"]:
        by_id.setdefault(row["stig_id"], []).append(row["applicability"])
    assert by_id["RHEL_9_STIG"] == ["multi-major-explicit", "multi-major-explicit"]
    assert by_id["MS_Windows_Server_2022_STIG"] == [None]


def test_defenses_for_technique__unknown_technique__raises_with_guidance(kb_path):
    conn = open_db_for_test(kb_path)
    with pytest.raises(ValueError, match="search_techniques"):
        tools.defenses_for_technique(kb_holder(conn), "T9999")


def test_defenses_for_technique__override_suppresses_ctid_pair__pair_absent(kb_path):
    conn = open_db_for_test(kb_path)
    result = tools.defenses_for_technique(kb_holder(conn), "T1078", benchmark_ids=["RHEL_9_STIG"])
    control_ids = {c["control_id"] for c in result["protect"]["controls"]}
    assert "AC-8" not in control_ids


def test_defenses_for_technique__mixed_severity_findings__ordered_cat_i_first(tmp_path):
    # Against its own knowledge base, because kb_path cannot express the case: kb_path's only CAT-II
    # rule maps via CCI-000048 to AC-8, AC-8 is suppressed for T1078, so `cats` would be the
    # single-element ['I'] and any ordering assertion would hold trivially.
    #
    # mixed_severity_xccdf.xml makes BOTH tiebreaks disagree with severity order, document order and
    # rule_id order, because findings_for_control sorts by `_CAT_ORDER, stig_id, stig_version, rule_id`
    # and these three rules share the first two. Removing only `_CAT_ORDER` from that ORDER BY leaves
    # rule_id deciding, which fails here only because the fixture's rule ids do not follow severity.
    # See the fixture's header comment.
    out = tmp_path / "kb.sqlite"
    build_kb(
        IngestSources(
            benchmarks=[discovered(FIX / "mixed_severity_xccdf.xml")],
            cci_path=FIX / "cci_list.xml",
            attack_path=FIX / "attack_bundle.json",
            ctid_path=FIX / "ctid_mappings.csv",
            overrides_path=FIX / "overrides.yaml",
            catalog_path=FIX / "oscal_catalog.json",
        ),
        out,
    )
    conn = open_db_for_test(out)
    result = tools.defenses_for_technique(kb_holder(conn), "T1078", benchmark_ids=["MIXED_SEVERITY_STIG"])
    ac2_1 = next(c for c in result["protect"]["controls"] if c["control_id"] == "AC-2(1)")
    cats = [result["protect"]["findings"][rule]["severity"] for rule in ac2_1["rules"]]
    # Both halves matter: the equality pins the order, and the set pins that the fixture still
    # supplies three severities, so the order check cannot go quietly vacuous.
    assert set(cats) == {"I", "II", "III"}, "the fixture must supply every severity"
    assert cats == ["I", "II", "III"]


def test_techniques_for_actor__actor_and_systems_with_include_defenses__returns_findings(kb_path):
    conn = open_db_for_test(kb_path)
    result = tools.techniques_for_actor(kb_holder(conn), "APT29", system_description="RHEL 9", include_defenses=True)
    assert result["actor"]["id"] == "G0016"
    technique = next(t for t in result["techniques"] if t["technique_id"] == "T1078")
    assert technique["controls"]
    assert result["findings"]


def test_techniques_for_actor__build_predates_any_stig__the_answer_carries_the_explanation(tmp_path, monkeypatch):
    # A build that predates the first official STIG returns zero findings; without the note
    # the empty answer would have no explanation anywhere.
    conn = _governed_kb(tmp_path, monkeypatch)
    result = tools.techniques_for_actor(kb_holder(conn), "APT29", system_description="RHEL 9 U1", include_defenses=True)
    assert result["findings"] == {}
    assert any("predates the first official STIG" in n for n in result["notes"])


def test_resolve_scope__non_exact_version__does_not_auto_scope(kb_path):
    # "Windows Server 2019" has no exact benchmark; must NOT auto-scope to WS2022.
    conn = open_db_for_test(kb_path)
    scoped_ids, _, notes = tools._resolve_scope(conn, "Windows Server 2019", None)
    assert scoped_ids == []
    assert notes  # a "no confident match" note is returned


def test_resolve_scope__foreign_product_shares_server_year__does_not_auto_scope(kb_path):
    # "Exchange Server 2022" shares 'server' and '2022' with the Windows Server 2022
    # STIG but is a different product entirely; it must not auto-scope to Windows.
    conn = open_db_for_test(kb_path)
    scoped_ids, _resolved, _notes = tools._resolve_scope(conn, "Exchange Server 2022", None)
    assert scoped_ids == []


def test_resolve_scope__bare_version__does_not_auto_scope(kb_path):
    # A version-only query has no distinctive product token, so it must never
    # auto-scope even though "2022" exactly matches the Windows Server 2022 STIG.
    conn = open_db_for_test(kb_path)
    scoped_ids, _resolved, _notes = tools._resolve_scope(conn, "2022", None)
    assert scoped_ids == []


def test_resolve_scope__no_confident_match__omits_applicability_notes_for_the_candidates(kb_path, monkeypatch):
    # Regression: this branch's scope is unconditionally [], so nothing was actually
    # scoped. Emitting "Scoped to ..." notes about candidates it just said it could not
    # confidently identify asserts something false. Crafted hits pin the branch directly,
    # rather than depending on which real fixture query happens to miss the confidence
    # gate: every vCenter query does on real data,
    # but nothing in this fixture KB reproduces that shape.
    conn = open_db_for_test(kb_path)
    hits = [
        {
            "stig_id": "FAKE_A_STIG",
            "title": "Fake A",
            "version": "2",
            "score": 50.0,
            "matched_on": "keyword",
            "high_confidence": False,
            "applicable": True,
            "applicability": "scoped",
            "build": 3,
            "version_coverage": [],
            "tied_omitted": 0,
        },
        {
            "stig_id": "FAKE_B_STIG",
            "title": "Fake B",
            "version": "2",
            "score": 45.0,
            "matched_on": "keyword",
            "high_confidence": False,
            "applicable": True,
            "applicability": "scoped",
            "build": 3,
            "version_coverage": [],
            "tied_omitted": 0,
        },
    ]
    monkeypatch.setattr(tools, "resolve", lambda conn, description: hits)
    scope, resolved, notes = tools._resolve_scope(conn, "vCenter 8.0 U3", None)
    assert scope == []
    assert resolved == hits
    assert any("No STIG confidently matched" in n for n in notes)
    assert not any(n.startswith("Scoped to") for n in notes)


def test_resolve_scope__a_confident_hit_ties_within_the_cap__notes_the_omitted_benchmarks(kb_path, monkeypatch):
    # The comment above _resolve_scope's confident branch claims this note matters more there
    # than anywhere else, because a benchmark cut inside an ALREADY CAPPED tier can be a
    # confident one dropped out of the scope itself. Nothing in component_family_kb reaches
    # this branch (every hit there is high_confidence=False), so a crafted hit pins it
    # directly, the same way the unconfident branch above is pinned.
    conn = open_db_for_test(kb_path)
    hits = [
        {
            "stig_id": "FAKE_A_STIG",
            "title": "Fake A",
            "version": "2",
            "score": 100.0,
            "matched_on": "keyword",
            "high_confidence": True,
            "applicable": True,
            "applicability": "scoped",
            "build": 3,
            "version_coverage": [],
            "tied_omitted": 2,
        },
    ]
    monkeypatch.setattr(tools, "resolve", lambda conn, description: hits)
    _scope, resolved, notes = tools._resolve_scope(conn, "vCenter 8.0 U3", None)
    assert resolved == hits
    assert any(note.startswith("2 further benchmarks scored exactly as well as") for note in notes)


def test_defenses_for_technique__revoked_technique_id__answers_for_the_replacement(kb_path):
    # An analyst working from a report written against an older ATT&CK release has no
    # way to know the id was renumbered, so failing on it hides an answer the knowledge base holds.
    conn = open_db_for_test(kb_path)
    result = tools.defenses_for_technique(kb_holder(conn), "T8001")
    assert result["technique"]["id"] == "T9000"
    assert result["technique"]["redirected_from"] == "T8001"
    assert any("T8001" in note and "T9000" in note for note in result["notes"])


def test_defenses_for_technique__live_technique_id__reports_no_redirect(kb_path):
    conn = open_db_for_test(kb_path)
    result = tools.defenses_for_technique(kb_holder(conn), "T1078")
    assert result["technique"]["redirected_from"] is None
    assert not any("revoked" in note.lower() for note in result["notes"])


def test_defenses_for_technique__id_in_neither_table__still_raises_with_guidance(kb_path):
    conn = open_db_for_test(kb_path)
    with pytest.raises(ValueError, match="search_techniques"):
        tools.defenses_for_technique(kb_holder(conn), "T9999")


def test_defenses_for_technique__build_selects_a_major__returns_only_that_versions_findings(tmp_path, monkeypatch):
    conn = _governed_kb(tmp_path, monkeypatch)
    result = tools.defenses_for_technique(kb_holder(conn), "T1078", system_description="RHEL 9 U3")
    versions = {f["benchmark"].rpartition("/")[2] for f in result["protect"]["findings"].values()}
    assert versions == {"2"}
    assert any("build update 3" in n for n in result["notes"])


def test_defenses_for_technique__no_build_supplied__still_returns_both_majors_with_a_note(tmp_path, monkeypatch):
    conn = _governed_kb(tmp_path, monkeypatch)
    result = tools.defenses_for_technique(kb_holder(conn), "T1078", system_description="RHEL 9")
    versions = {f["benchmark"].rpartition("/")[2] for f in result["protect"]["findings"].values()}
    assert versions == {"1", "2"}
    assert any("Supply a build" in n for n in result["notes"])


def test_defenses_for_technique__build_predates_any_stig__returns_controls_and_no_findings(tmp_path, monkeypatch):
    conn = _governed_kb(tmp_path, monkeypatch)
    result = tools.defenses_for_technique(kb_holder(conn), "T1078", system_description="RHEL 9 U1")
    assert result["protect"]["controls"]
    assert result["protect"]["findings"] == {}
    assert all(c["rules"] == [] for c in result["protect"]["controls"])
    assert [s["applicable"] for s in result["resolved_systems"]] == [False, False]
    assert any("predates the first official STIG" in n for n in result["notes"])


def test_defenses_for_technique__ungoverned_benchmark_with_a_build__says_the_build_was_ignored(kb_path):
    conn = open_db_for_test(kb_path)
    result = tools.defenses_for_technique(kb_holder(conn), "T1078", system_description="RHEL 9 U3")
    assert any("did not affect scoping" in n for n in result["notes"])


def test_defenses_for_technique__explicit_benchmark_ids__are_unaffected_by_applicability(tmp_path, monkeypatch):
    conn = _governed_kb(tmp_path, monkeypatch)
    result = tools.defenses_for_technique(kb_holder(conn), "T1078", benchmark_ids=["RHEL_9_STIG"])
    versions = {f["benchmark"].rpartition("/")[2] for f in result["protect"]["findings"].values()}
    assert versions == {"1", "2"}


def test_defenses_for_technique__limit_would_split_a_benchmarks_majors__keeps_the_applicable_findings(
    tmp_path, monkeypatch
):
    # Pinned at the tool layer, not just resolve()'s rows: a cut applicable benchmark means
    # 0 findings and 0 notes mentioning it. `resolve()` is the real implementation forced to
    # limit=2, where a row-based cut would drop RHEL_9_STIG's applicable v2 row and keep its
    # superseded v1 (see test_resolver.py's version for why limit=2 triggers it on this
    # fixture). A row-based slice makes `rhel_versions` below {"1"} instead of {"2"}.
    conn = _governed_kb(tmp_path, monkeypatch, extra_stig_paths=[discovered(FIX / "win2022_xccdf.xml")])
    monkeypatch.setattr(tools, "resolve", lambda conn, description: real_resolve(conn, description, limit=2))
    result = tools.defenses_for_technique(kb_holder(conn), "T1078", system_description="Windows Server 2022, RHEL 9 U3")
    rhel_versions = {
        f["benchmark"].rpartition("/")[2]
        for f in result["protect"]["findings"].values()
        if f["benchmark"].startswith("RHEL_9_STIG/")
    }
    assert rhel_versions == {"2"}
    assert any("build update 3" in n for n in result["notes"])


def test_defenses_for_technique__build_selects_a_major__no_redundant_superseded_note(tmp_path, monkeypatch):
    # The scoped sibling's own note already explains the choice; a second note about the
    # superseded major saying the same thing would be redundant noise on every vSphere-
    # shaped query. Keep the silence when a scoped sibling is present in the response.
    conn = _governed_kb(tmp_path, monkeypatch)
    result = tools.defenses_for_technique(kb_holder(conn), "T1078", system_description="RHEL 9 U3")
    assert not any("is only held here" in n for n in result["notes"])


def test_defenses_for_technique__benchmark_holds_only_the_superseded_major__explains_the_empty_result(
    tmp_path, monkeypatch
):
    # Regression: a benchmark whose only surviving row is superseded must not go mute. This
    # KB holds RHEL_9_STIG at major 1 ONLY; the rule says build update 3 needs major 2,
    # which this KB does not have, so there is no scoped sibling left to explain anything.
    rules = tmp_path / "rules.yaml"
    rules.write_text(RULES_YAML)
    monkeypatch.setattr(applicability, "RULES_PATH", rules)
    out = tmp_path / "kb.sqlite"
    build_kb(
        IngestSources(
            benchmarks=[discovered(FIX / "rhel9_xccdf.xml")],
            cci_path=FIX / "cci_list.xml",
            attack_path=FIX / "attack_bundle.json",
            ctid_path=FIX / "ctid_mappings.csv",
            overrides_path=FIX / "overrides.yaml",
            catalog_path=FIX / "oscal_catalog.json",
        ),
        out,
    )
    conn = open_db_for_test(out)
    result = tools.defenses_for_technique(kb_holder(conn), "T1078", system_description="RHEL 9 U3")
    assert result["protect"]["controls"]
    assert result["protect"]["findings"] == {}
    assert all(c["rules"] == [] for c in result["protect"]["controls"])
    assert [s["applicable"] for s in result["resolved_systems"]] == [False]
    assert any("V2" in n and "does not hold" in n for n in result["notes"])


def test_defenses_for_technique__explicit_id_spanning_two_majors__says_so_without_narrowing(tmp_path, monkeypatch):
    # Scoping is deliberately unchanged on this path: naming a benchmark returns every
    # version of it. The note is what tells the caller that findings from two majors, which
    # can carry different fix text for the same group id, are mixed in the answer.
    conn = _governed_kb(tmp_path, monkeypatch)
    result = tools.defenses_for_technique(kb_holder(conn), "T1078", benchmark_ids=["RHEL_9_STIG"])
    versions = {f["benchmark"].rpartition("/")[2] for f in result["protect"]["findings"].values()}
    assert versions == {"1", "2"}
    assert any("exists at more than one major" in n and "drop benchmark_ids" in n for n in result["notes"])
    assert not any("Supply a build in the system description" in n for n in result["notes"])
    assert not any("system_description" in n for n in result["notes"])


def test_defenses_for_technique__benchmark_ids_and_description_together__says_the_description_was_ignored(
    tmp_path, monkeypatch
):
    # The multi-major-explicit note's example ("describe the system with its
    # build instead, for example 'ESXi 8.0 U3'") can read back the caller's own
    # system_description verbatim, which looks like advice to do something they already
    # did. This note makes explicit that the description was supplied but never consulted,
    # because benchmark_ids bypasses the resolver entirely.
    conn = _governed_kb(tmp_path, monkeypatch)
    result = tools.defenses_for_technique(
        kb_holder(conn), "T1078", system_description="RHEL 9 U3", benchmark_ids=["RHEL_9_STIG"]
    )
    assert any("system_description" in n and "ignored" in n and "RHEL 9 U3" in n for n in result["notes"])


def test_defenses_for_technique__any_response__cites_the_sources_it_was_built_from(kb_conn):
    result = tools.defenses_for_technique(kb_holder(kb_conn), "T1078", benchmark_ids=["TEST_STIG"])
    assert "attack" in result["sources"]
    assert "ctid" in result["sources"]


def test_techniques_for_actor__any_response__cites_the_sources_it_was_built_from(kb_conn):
    result = tools.techniques_for_actor(kb_holder(kb_conn), "G0016")
    assert "attack" in result["sources"]


def test_defenses_for_technique__deprecated_benchmark__says_disa_marked_it(deprecated_kb):
    result = tools.defenses_for_technique(kb_holder(deprecated_kb), "T1078", benchmark_ids=["DEPRECATED_STIG"])
    note = " ".join(result["notes"])
    assert "deprecated" in note and "2026-05-19" in note


def test_defenses_for_technique__sunset_origin__says_it_came_from_a_sunset_compilation(sunset_kb):
    result = tools.defenses_for_technique(kb_holder(sunset_kb), "T1078", benchmark_ids=["SUNSET_STIG"])
    note = " ".join(result["notes"])
    assert "sunset compilation" in note
    assert "U_SRG-STIG_Library_July_2026.zip" in note


def test_defenses_for_technique__local_artifact_newer_than_the_library__does_not_imply_retirement(local_kb):
    # Google_Android_17 is newer than the July 2026 compilation, not retired. Saying only
    # "not in the library" would read as retirement, which is backwards for this case.
    result = tools.defenses_for_technique(kb_holder(local_kb), "T1078", benchmark_ids=["LOCAL_STIG"])
    note = " ".join(result["notes"])
    assert "supplied as a local artifact" in note
    assert "may be newer" in note


def test_defenses_for_technique__no_library_compilation__declines_to_judge_currency(no_library_kb):
    result = tools.defenses_for_technique(kb_holder(no_library_kb), "T1078", benchmark_ids=["LOOSE_STIG"])
    note = " ".join(result["notes"])
    assert "without a library compilation" in note
    assert "not in" not in note


def test_defenses_for_technique__library_present_but_empty__declines_and_names_it(broken_library_kb):
    # A truncated or SRG-only compilation classifies correctly (stig_library ingest_meta
    # row exists, so sources.stig_library still cites it) but contributes zero
    # library-origin benchmarks. The "was supplied as a local artifact and is not in <zip>"
    # wording would assert LOOSE_STIG's absence from a compilation that was never actually
    # read: a false claim, not the "cannot be determined" decline this case requires.
    result = tools.defenses_for_technique(kb_holder(broken_library_kb), "T1078", benchmark_ids=["LOOSE_STIG"])
    note = " ".join(result["notes"])
    assert "U_SRG-STIG_Library_July_2026.zip" in note
    assert "contributed no benchmarks" in note
    assert "cannot be determined" in note
    assert "not in" not in note
    assert "supplied as a local artifact" not in note


def test_defenses_for_technique__sources_block__no_value_is_an_absolute_path(kb_path):
    # kb_path is built from FIX, an absolute fixtures directory, so cci/attack/ctid
    # sources are absolute Paths going in. Storing str(path) for them in ingest_meta would
    # leak the operator's home directory and username into a response an LLM surfaces to a
    # user. Every value the caller sees here must be free of that leak.
    conn = open_db_for_test(kb_path)
    result = tools.defenses_for_technique(kb_holder(conn), "T1078", benchmark_ids=["RHEL_9_STIG"])
    # Path(value).is_absolute() alone would miss a leaked Windows path (C:\...) when this
    # suite runs on POSIX, since PurePosixPath does not treat a drive letter as absolute;
    # the explicit drive-letter check closes that regardless of which platform runs the test.
    for key, value in result["sources"].items():
        if not isinstance(value, str):
            continue
        assert not Path(value).is_absolute(), f"{key} looks like an absolute path: {value}"
        assert not re.match(r"^[A-Za-z]:[\\/]", value), f"{key} looks like a Windows absolute path: {value}"


def test_defenses_for_technique__catalog_with_no_extracted_version__omits_control_catalog_key(kb_path):
    # The repo fixture oscal_catalog.json carries no metadata.version, so its recorded
    # source_version is empty even though the catalog row exists in ingest_meta. A citation
    # key whose value asserts nothing is worse than an absent key in a block meant for
    # verification.
    conn = open_db_for_test(kb_path)
    result = tools.defenses_for_technique(kb_holder(conn), "T1078", benchmark_ids=["RHEL_9_STIG"])
    assert "control_catalog" not in result["sources"]


UNCOVERED = {
    "verdict": "uncovered",
    "benchmarks": ["MS_SQL_Server_2016_Database_STIG", "MS_SQL_Server_2022_Database_STIG"],
    "covered_versions": ["2016", "2022"],
    "query_versions": ["2019"],
    "fragment": "Microsoft SQL Server 2019",
    "fragment_confident": False,
    "matched_benchmarks": ["MS_SQL_Server_2016_Database_STIG", "MS_SQL_Server_2022_Database_STIG"],
}
ONE_BENCHMARK = {**UNCOVERED, "benchmarks": ["Amazon_Linux_2023_STIG"], "covered_versions": ["2023"]}
AGNOSTIC = {
    "verdict": "version-agnostic",
    "benchmarks": ["Google_Chrome_Current_Windows"],
    "covered_versions": [],
    "query_versions": ["120"],
    "fragment": "Google Chrome 120",
    "fragment_confident": False,
    "matched_benchmarks": ["Google_Chrome_Current_Windows"],
}


def test_note_version_uncovered__several_benchmarks__names_them_and_their_versions():
    note = tools._note_version_uncovered("Microsoft SQL Server 2019", UNCOVERED)
    assert "holds no STIG for 'Microsoft SQL Server 2019'" in note
    assert "MS_SQL_Server_2016_Database_STIG, MS_SQL_Server_2022_Database_STIG" in note
    assert "covering 2016, 2022" in note
    assert "None of them applies" in note


def test_note_version_uncovered__one_benchmark__uses_singular_wording():
    note = tools._note_version_uncovered("Amazon Linux 2024", ONE_BENCHMARK)
    assert "The closest benchmark is Amazon_Linux_2023_STIG" in note
    assert "It does not apply" in note
    assert "None of them" not in note


def test_note_version_uncovered__more_than_four_benchmarks__truncates_the_list():
    many = {**UNCOVERED, "benchmarks": [f"B{i}_STIG" for i in range(6)]}
    note = tools._note_version_uncovered("thing 9", many)
    assert "B0_STIG, B1_STIG, B2_STIG, B3_STIG and 2 more" in note
    assert "B4_STIG" not in note


def test_note_version_agnostic__names_the_benchmark_without_asserting_it_applies():
    note = tools._note_version_agnostic("Google Chrome 120", AGNOSTIC)
    assert "Google_Chrome_Current_Windows is not version-specific" in note
    assert "is not evidence that it does not apply" in note
    # It must never claim coverage it cannot support. The negation has to be on the bare verb:
    # asserting that "applies to Google Chrome 120" is absent can never fail, because the note
    # quotes the description, and a sentence claiming applicability outright would slip past.
    assert " applies to " not in note


def test_version_coverage_notes__uncovered_verdict__dispatches_to_the_uncovered_builder():
    hits = [{"version_coverage": [UNCOVERED], "high_confidence": False, "stig_id": "X"}]
    assert tools._version_coverage_notes(hits) == [
        tools._note_version_uncovered("Microsoft SQL Server 2019", UNCOVERED)
    ]


def test_version_coverage_notes__agnostic_verdict__dispatches_to_the_agnostic_builder():
    hits = [{"version_coverage": [AGNOSTIC], "high_confidence": False, "stig_id": "X"}]
    assert tools._version_coverage_notes(hits) == [tools._note_version_agnostic("Google Chrome 120", AGNOSTIC)]


def test_version_coverage_notes__each_verdict__is_quoted_with_its_own_fragment():
    # The note builders receive the FRAGMENT, never the whole description. Two notes quoting
    # 'RHEL 8 and Google Chrome 120' at each other would each be making a claim about a product
    # the other one names, which is the merged reading this feature exists to replace.
    hits = [{"version_coverage": [UNCOVERED, AGNOSTIC], "high_confidence": False, "stig_id": "X"}]
    notes = tools._version_coverage_notes(hits)
    assert len(notes) == 2
    assert "'Microsoft SQL Server 2019'" in notes[0] and "Google Chrome" not in notes[0]
    assert "'Google Chrome 120'" in notes[1] and "SQL" not in notes[1]


def test_version_coverage_notes__the_fragment_matched_confidently__suppresses_its_note():
    # The contradiction the gate exists for, unchanged: an alias makes the version-denying
    # query a confident hit for this same fragment, and saying both is worse than saying
    # neither.
    confident = {**UNCOVERED, "fragment_confident": True}
    hits = [{"version_coverage": [confident], "high_confidence": True, "stig_id": "X"}]
    assert tools._version_coverage_notes(hits) == []


def test_version_coverage_notes__a_confident_row_this_fragment_did_not_earn__leaves_the_note_alone():
    # Why the gate reads the VERDICT rather than the rows. A row's high_confidence belongs to
    # whichever fragment won that key in the merged map, so reading rows would silence the SQL
    # half of 'SQL Server 2019 and Windows Server 2022': the SQL fragment is a candidate for the
    # Windows benchmark on the shared token 'server', and that benchmark is confident thanks to
    # the OTHER fragment. Every row here is confident and the note must still fire, because this
    # fragment earned none of it.
    hits = [
        {"version_coverage": [UNCOVERED], "high_confidence": True, "stig_id": "MS_Windows_Server_2022_STIG"},
        {"version_coverage": [UNCOVERED], "high_confidence": True, "stig_id": "MS_SQL_Server_2016_Database_STIG"},
    ]
    assert tools._version_coverage_notes(hits) == [
        tools._note_version_uncovered("Microsoft SQL Server 2019", UNCOVERED)
    ]


def test_resolve_scope__nothing_matched_and_no_verdict__keeps_the_generic_note(wide_kb):
    # On wide_kb, so the "no verdict" half is a tested outcome rather than a fixture guarantee
    # (a two-benchmark corpus such as kb_path cannot produce a verdict at all).
    # 'Fillerware Padding' names tokens the filler benchmarks share, so nothing is distinctive,
    # the default limit of 5 candidates come back, none is confident, and the query carries no
    # version token. All 19 filler benchmarks tie at 100.0, so the 14 the cap drops are a tied
    # tier, not a merit cut, and the tied-omitted note fires alongside the generic one.
    #
    # The second assertion is what makes the first mean something: the SAME knowledge base does
    # produce a verdict for 'RHEL 8', so silence here is a property of this query and not of the
    # fixture being too small to speak.
    conn = open_db_for_test(wide_kb)
    _scope, resolved, notes = tools._resolve_scope(conn, "Fillerware Padding", None)
    assert resolved, "the fallback under test is the one for a query that DID find candidates"
    assert all(hit["version_coverage"] == [] for hit in resolved), "this query must produce no verdict"
    assert notes == [
        "No STIG confidently matched 'Fillerware Padding'. Call resolve_system "
        "or list_stigs to see candidates, or pass benchmark_ids explicitly.",
        "14 further benchmarks scored exactly as well as the last one shown for "
        "'Fillerware Padding' and were omitted. Call resolve_system with a higher limit to see "
        "them, or name the product more precisely.",
    ]

    _, verdict_resolved, _ = tools._resolve_scope(conn, "RHEL 8", None)
    # `verdict_resolved and` first, so an empty result fails this assertion instead of raising
    # IndexError from inside it.
    assert verdict_resolved and verdict_resolved[0]["version_coverage"], (
        "the fixture must be able to produce a verdict at all"
    )


def test_resolve_scope__nothing_in_the_corpus_resembles_the_query__does_not_offer_candidates(kb_path):
    # Sending the caller to resolve_system is a dead end when there is nothing to see: it runs the
    # same resolver and returns the same nothing.
    conn = open_db_for_test(kb_path)
    _scope, resolved, notes = tools._resolve_scope(conn, "a mainframe running zOS", None)
    assert resolved == []
    assert notes == [
        "Nothing in this knowledge base resembles 'a mainframe running zOS', so there are no "
        "candidates to browse. Check the spelling, name the product as DISA does, or call "
        "list_stigs to see what is held."
    ]


def test_wide_kb__corpus_size__is_large_enough_for_a_one_benchmark_token_to_be_distinctive(wide_kb):
    # Guards every end-to-end test below. The gate is df <= 0.05 * n, so a token appearing
    # in a single benchmark needs n >= 20; trim this fixture and they all pass vacuously
    # instead of failing.
    assert len(stigs_for_resolver(open_db_for_test(wide_kb))) >= 20


def test_wide_kb__filler_benchmarks__share_no_token_with_the_real_ones(wide_kb):
    # The other half of the guard above. The filler exists to raise the corpus size without
    # touching any document frequency the tests depend on, and the constraint is easy to
    # break by editing a title, so it is asserted rather than trusted to a comment.
    conn = open_db_for_test(wide_kb)
    real, filler = set(), set()
    for row in stigs_for_resolver(conn):
        product, version, _ = normalize(f"{row['title']} {row['product_keywords']}")
        (filler if row["stig_id"].startswith("FILLER_") else real).update(product | version)
    assert real & filler == set()


def test_wide_kb__filler_tokens__are_too_long_to_appear_in_query_prose(wide_kb):
    # Disjointness from the real titles is not enough: a one-letter filler token is
    # distinctive at this corpus size, so a query as ordinary as "a RHEL 8 server" would
    # lose its verdict to the article, and the loss is a silence rather than a failure.
    conn = open_db_for_test(wide_kb)
    for row in stigs_for_resolver(conn):
        if not row["stig_id"].startswith("FILLER_"):
            continue
        product, version, _ = normalize(f"{row['title']} {row['product_keywords']}")
        assert all(len(token) >= 3 for token in product | version)


def test_resolve_scope__version_not_held__replaces_the_generic_note(wide_kb):
    # The whole point of the version-coverage note, driven through real scoring: RHEL_9_STIG is
    # the only benchmark carrying every distinctive token of 'RHEL 8', and it covers 9, not 8.
    conn = open_db_for_test(wide_kb)
    _scope, _resolved, notes = tools._resolve_scope(conn, "RHEL 8", None)
    assert len(notes) == 1
    assert "holds no STIG for 'RHEL 8'" in notes[0]
    assert "The closest benchmark is RHEL_9_STIG, covering 9" in notes[0]
    assert "No STIG confidently matched" not in notes[0]


def test_resolve_scope__a_version_glued_to_a_letter_in_the_title__names_the_version_held(wide_kb):
    # The note path for the Oracle 19c shape, and the sentence this whole feature exists to
    # produce. normalize reads the 19 out of '19c', so the note names the version held rather
    # than calling NOVAFLOW_DATABASE_19C_STIG "not version-specific" or staying silent.
    conn = open_db_for_test(wide_kb)
    _scope, _resolved, notes = tools._resolve_scope(conn, "Novaflow Database 12", None)
    assert notes == [
        "This knowledge base holds no STIG for 'Novaflow Database 12'. The closest benchmark is "
        "NOVAFLOW_DATABASE_19C_STIG, covering 19. It does not apply to that version; to use one "
        "anyway, pass it in benchmark_ids."
    ]


def test_resolve_scope__a_title_run_no_version_token_confirms__keeps_the_generic_note(wide_kb):
    # The note path for the `SEL-2740S` and `HPE 3PAR SSMC` shape. SENTINEL_4180X_RELAY's title
    # writes `4180` and nothing confirms it is a version, so the caller must NOT be told the
    # benchmark is version-agnostic and invited to scope to it. The generic note is merely
    # unhelpful; the version-agnostic one would be false.
    conn = open_db_for_test(wide_kb)
    _scope, _resolved, notes = tools._resolve_scope(conn, "Sentinel 4180X Relay 9", None)
    assert notes == [
        "No STIG confidently matched 'Sentinel 4180X Relay 9'. Call resolve_system "
        "or list_stigs to see candidates, or pass benchmark_ids explicitly."
    ]


def test_resolve_scope__version_agnostic_benchmark__explains_the_silence(wide_kb):
    # Google_Chrome_Current_Windows carries no digit in its title, so the tier holds no
    # version at all and the mismatch is not evidence the benchmark does not apply.
    conn = open_db_for_test(wide_kb)
    _scope, _resolved, notes = tools._resolve_scope(conn, "Google Chrome 120", None)
    assert len(notes) == 1
    assert "Google_Chrome_Current_Windows is not version-specific" in notes[0]
    assert "is not evidence that it does not apply" in notes[0]


def test_defenses_for_technique__uncovered_version__carries_the_note(wide_kb):
    conn = open_db_for_test(wide_kb)
    result = tools.defenses_for_technique(kb_holder(conn), "T1078", "RHEL 8")
    assert any("holds no STIG for 'RHEL 8'" in note for note in result["notes"])


def test_resolve_scope__hits_carry_an_uncovered_verdict__replaces_the_generic_note(kb_path, monkeypatch):
    # Crafted hits, so this pins _resolve_scope's note replacement independent of resolver
    # scoring: if a future scoring change stops producing verdicts, the end-to-end tests
    # above fail and this one does not, which is what tells the two failures apart.
    conn = open_db_for_test(kb_path)
    hits = [
        {
            "stig_id": "FAKE_A_STIG",
            "title": "Fake A",
            "version": "2",
            "score": 50.0,
            "matched_on": "keyword",
            "high_confidence": False,
            "applicable": True,
            "applicability": "scoped",
            "build": 3,
            "version_coverage": [UNCOVERED],
            "tied_omitted": 0,
        },
    ]
    monkeypatch.setattr(tools, "resolve", lambda conn, description: hits)
    _scope, resolved, notes = tools._resolve_scope(conn, "Microsoft SQL Server 2019", None)
    assert resolved == hits
    assert len(notes) == 1
    assert "holds no STIG for 'Microsoft SQL Server 2019'" in notes[0]
    assert "No STIG confidently matched" not in notes[0]


def test_defenses_for_technique__hits_carry_an_uncovered_verdict__carries_the_note(kb_path, monkeypatch):
    # Same crafted-hit technique as the _resolve_scope test above, one level up: this
    # confirms the note reaches the server layer's actual output, not just _resolve_scope's
    # return value.
    conn = open_db_for_test(kb_path)
    hits = [
        {
            "stig_id": "FAKE_A_STIG",
            "title": "Fake A",
            "version": "2",
            "score": 50.0,
            "matched_on": "keyword",
            "high_confidence": False,
            "applicable": True,
            "applicability": "scoped",
            "build": 3,
            "version_coverage": [UNCOVERED],
            "tied_omitted": 0,
        },
    ]
    monkeypatch.setattr(tools, "resolve", lambda conn, description: hits)
    result = tools.defenses_for_technique(kb_holder(conn), "T1078", "Microsoft SQL Server 2019")
    assert any("holds no STIG for 'Microsoft SQL Server 2019'" in note for note in result["notes"])


def test_note_version_agnostic__several_benchmarks__uses_plural_wording():
    # Real shape on the 387-benchmark knowledge base: 'Kubernetes 1.29' ties two
    # version-less benchmarks, and the singular wording then contradicts its own subject.
    several = {**AGNOSTIC, "benchmarks": ["Kubernetes_STIG", "Mirantis_Kubernetes_Engine_STIG"]}
    note = tools._note_version_agnostic("Kubernetes 1.29", several)
    assert "Kubernetes_STIG, Mirantis_Kubernetes_Engine_STIG are not version-specific" in note
    assert "does not appear in them" in note
    assert "they do not apply" in note
    assert "holds no per-release benchmark" in note


def test_note_version_agnostic__a_dotted_version__never_echoes_it_decomposed():
    # normalize turns 120.0.6099 into three tokens, so quoting them back reorders the
    # caller's own words. The description carries the version verbatim instead.
    coverage = {**AGNOSTIC, "query_versions": ["0", "120", "6099"]}
    note = tools._note_version_agnostic("Google Chrome 120.0.6099", coverage)
    assert "0, 120, 6099" not in note
    assert "Google Chrome 120.0.6099" in note


def test_resolve_system__any_query__returns_candidates_and_notes(kb_path):
    conn = open_db_for_test(kb_path)
    result = tools.resolve_system(kb_holder(conn), "RHEL 9")
    assert result["candidates"][0]["stig_id"] == "RHEL_9_STIG"
    assert result["notes"] == []


def test_resolve_system__uncovered_version__carries_the_note(wide_kb):
    # wide_kb, not kb_path: no verdict is possible below twenty benchmarks.
    conn = open_db_for_test(wide_kb)
    result = tools.resolve_system(kb_holder(conn), "RHEL 8")
    assert result["candidates"]
    assert any("holds no STIG for 'RHEL 8'" in note for note in result["notes"])


def test_resolve_system__a_confident_hit_and_a_verdict__says_nothing(wide_kb):
    # 'RHEL 8.9' is a confident RHEL_9_STIG hit by alias AND carries an uncovered verdict,
    # because the major 8 is absent. resolve_system asks for the note unconditionally, so
    # without the confidence gate it would hand the caller a benchmark and a denial of it.
    conn = open_db_for_test(wide_kb)
    result = tools.resolve_system(kb_holder(conn), "RHEL 8.9")
    assert any(hit["high_confidence"] for hit in result["candidates"])
    assert result["candidates"][0]["version_coverage"][0]["verdict"] == "uncovered"
    assert result["notes"] == []


def test_resolve_system__limit__still_caps_the_candidates(kb_path):
    conn = open_db_for_test(kb_path)
    assert len(tools.resolve_system(kb_holder(conn), "server", limit=1)["candidates"]) == 1


def test_resolve_scope__a_digit_in_the_products_name__explains_the_silence(wide_kb):
    # The user-visible half of the same case, and the reason the rule exists: this note is true
    # and useful, and reading the name's digit as a version would withhold it.
    conn = open_db_for_test(wide_kb)
    _scope, _resolved, notes = tools._resolve_scope(conn, "Nimbus7 Relay 3", None)
    assert len(notes) == 1
    assert "NIMBUS7_RELAY_STIG is not version-specific" in notes[0]


def test_resolve_scope__the_acronym_for_a_role_phrase_in_the_title__reports_version_agnostic(wide_kb):
    # QUASAR_FABRIC_L2S_STIG's title says "Layer 2 Switch". Its only digit is the 2 of "Layer 2", a
    # role phrase rather than a version, so normalize reads it as a product token and the
    # benchmark carries no version at all. Read as a version, that 2 would meet the same 2
    # supplied by the caller's L2S acronym and the classifier's intersection would go silent.
    # The true statement is that the benchmark is version-agnostic, and that is what it must say.
    conn = open_db_for_test(wide_kb)
    _scope, _resolved, notes = tools._resolve_scope(conn, "Quasar Fabric L2S 11", None)
    assert notes == [
        "QUASAR_FABRIC_L2S_STIG is not version-specific: this knowledge base holds no "
        "per-release benchmark for this product. The version you named does not appear in "
        "it, which is why nothing was auto-scoped, and is not evidence that it does not "
        "apply to 'Quasar Fabric L2S 11'. Pass benchmark_ids=['QUASAR_FABRIC_L2S_STIG'] to "
        "scope to it."
    ]


def test_resolve_system__tier_wider_than_the_limit__notes_the_omitted_candidates(component_family_kb):
    conn = open_db_for_test(component_family_kb)
    result = tools.resolve_system(kb_holder(conn), "Vectrix Orchestrator", limit=2)
    assert len(result["notes"]) == 1
    assert result["notes"][0].startswith("2 further benchmarks scored exactly as well as")
    assert "resolve_system with a higher limit" in result["notes"][0]


def test_resolve_system__tier_fits_inside_the_limit__adds_no_note(component_family_kb):
    conn = open_db_for_test(component_family_kb)
    result = tools.resolve_system(kb_holder(conn), "Vectrix Orchestrator", limit=4)
    assert result["notes"] == []


def test_resolve_system__exactly_one_benchmark_tied_within_the_cap__uses_singular_wording(component_family_kb):
    # Naming the ledger scores it above its siblings, and the limit=2 cap keeps the ledger
    # plus one of the two remaining siblings, which tie with each other (see the resolver-level
    # pin of these scores). That drops exactly one benchmark, the one fixture shape that
    # actually renders the singular branch of the note: changing "was" to "were", or "it" to
    # "them", unconditionally would leave every other test in this file green, the same reason
    # test_note_version_agnostic__several_benchmarks__uses_plural_wording exists for the
    # sibling note.
    conn = open_db_for_test(component_family_kb)
    result = tools.resolve_system(kb_holder(conn), "Vectrix Orchestrator Cluster Ledger", limit=2)
    assert result["notes"] == [
        "1 further benchmark scored exactly as well as the last one shown for "
        "'Vectrix Orchestrator Cluster Ledger' and was omitted. Call resolve_system with a "
        "higher limit to see it, or name the product more precisely."
    ]


def test_defenses_for_technique__tier_wider_than_the_limit__notes_the_omitted_candidates(
    component_family_kb, monkeypatch
):
    # The mitigations path caps at 5 with no caller parameter, so force a narrower limit to
    # reach the same cut. This path needs the note for a reason beyond information: it filters
    # high_confidence out of an ALREADY CAPPED list, so a cut inside a tier can remove a
    # confident benchmark from the scope itself.
    monkeypatch.setattr(tools, "resolve", lambda conn, description: real_resolve(conn, description, limit=2))
    conn = open_db_for_test(component_family_kb)
    result = tools.defenses_for_technique(kb_holder(conn), "T1078", system_description="Vectrix Orchestrator")
    assert any(note.startswith("2 further benchmarks scored exactly as well as") for note in result["notes"])


def test_resolve_scope__one_fragment_scoped_and_another_unheld__explains_the_unheld_one(wide_kb):
    # The remediation path, which returns actual fix and check steps. It returns early as soon
    # as anything matched confidently, yet the RHEL half must still get the sentence 'RHEL 8'
    # alone gets. The two statements do not contradict each other: they are about different
    # products, which is exactly what the per-fragment gate tells apart.
    conn = open_db_for_test(wide_kb)
    scoped, hits, notes = tools._resolve_scope(conn, "RHEL 8 and Windows Server 2022", None)
    assert {stig_id for stig_id, _version in scoped} == {"MS_Windows_Server_2022_STIG"}
    assert any("holds no STIG for 'RHEL 8'" in note for note in notes)


def test_resolve_scope__a_single_fragment_scoped_confidently__gains_no_version_note(wide_kb):
    # A confident single-fragment answer must carry no version note. On wide_kb this query is
    # COVERED, so it produces no verdict and guards the confident-branch wiring rather than the
    # gate; the gate is pinned at the resolver level, where 'RHEL 8.9' produces a verdict whose
    # fragment_confident is True.
    conn = open_db_for_test(wide_kb)
    _scoped, _hits, notes = tools._resolve_scope(conn, "Windows Server 2022", None)
    assert not any("holds no STIG" in note for note in notes)


def test_defenses_for_technique__more_benchmark_ids_than_the_cap__raises_naming_what_to_change(kb_path):
    # The cap exists because nothing bounded this list: `benchmark_ids` is `list[str]` at the MCP
    # boundary, and every id becomes a bound SQL parameter in stigs_by_ids and, doubled, in
    # findings_for_control's scope. A caller naming more benchmarks than a real system has is
    # making a mistake the tool should name, not one it should answer slowly.
    conn = open_db_for_test(kb_path)
    too_many = [f"FILLER_{i}_STIG" for i in range(tools._MAX_BENCHMARK_IDS + 1)]
    with pytest.raises(ValueError) as excinfo:
        tools.defenses_for_technique(kb_holder(conn), "T1078", None, too_many)
    message = str(excinfo.value)
    assert "benchmark_ids" in message
    assert str(tools._MAX_BENCHMARK_IDS) in message
    assert str(len(too_many)) in message
    assert "system_description" in message


def test_techniques_for_actor__more_benchmark_ids_than_the_cap__raises_the_same_way(kb_path):
    # The second entry point, tested separately rather than trusted to share the choke point.
    # A rule wired into only one of two caller paths leaves the other path returning results
    # with no explanation.
    conn = open_db_for_test(kb_path)
    too_many = [f"FILLER_{i}_STIG" for i in range(tools._MAX_BENCHMARK_IDS + 1)]
    with pytest.raises(ValueError, match="benchmark_ids"):
        tools.techniques_for_actor(kb_holder(conn), "G0016", None, too_many)


def test_defenses_for_technique__exactly_the_cap__is_answered(kb_path):
    # The boundary is inclusive, and this is the assertion that fails if the comparison is
    # written `>=`. One real id so the call resolves something rather than only surviving.
    conn = open_db_for_test(kb_path)
    ids = ["RHEL_9_STIG", *[f"FILLER_{i}_STIG" for i in range(tools._MAX_BENCHMARK_IDS - 1)]]
    result = tools.defenses_for_technique(kb_holder(conn), "T1078", None, ids)
    assert any(system["stig_id"] == "RHEL_9_STIG" for system in result["resolved_systems"])


def _at_limit(kb_path, limit):
    """A connection whose variable limit really is `limit`, on a statement cache that never saw
    a higher one. sqlite3 caches prepared statements, so lowering the limit on a connection that
    already ran the SQL is silently a no-op; and setlimit CLAMPS to the build maximum rather than
    failing, so the value has to be read back."""
    conn = open_db_for_test(kb_path)
    conn.setlimit(sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER, limit)
    assert conn.getlimit(sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER) == limit
    return conn


def test_the_cap__both_queries_it_sizes__stay_under_the_sqlite_variable_floor(kb_path):
    """The cap's VALUE is load bearing, and no other test can pin it: they all size their input
    from _MAX_BENCHMARK_IDS, so moving the constant moves their input with it.

    Executed rather than restated: a pure-Python arithmetic check sees the constant and not the
    query, which is the half that changes (binding each pair twice would pass it while a real
    call raised).

    999 is SQLITE_LIMIT_VARIABLE_NUMBER's compile-time default below SQLite 3.32. Both queries
    the cap sizes are covered: findings_for_control binds `5 + 2 * len(scope)`, and scope holds
    one pair per knowledge-base VERSION of each named id, at most 2 on the real corpus;
    stigs_by_ids binds one per id, unchunked.

    Each positive control is DERIVED from the parameter count, never a literal, so lowering the
    cap (the direction the comment beside the constant implies a third major would force) cannot
    make this fail spuriously.
    """
    scope = [(f"FILLER_{i}_STIG", "1") for i in range(2 * tools._MAX_BENCHMARK_IDS)]
    ids = [f"FILLER_{i}_STIG" for i in range(tools._MAX_BENCHMARK_IDS)]
    for call, params in (
        (lambda conn: queries.findings_for_control(conn, "AC-2(1)", scope), 5 + 2 * len(scope)),
        (lambda conn: queries.stigs_by_ids(conn, ids), len(ids)),
    ):
        assert params < 999, params
        with pytest.raises(sqlite3.OperationalError, match="too many SQL variables"):
            call(_at_limit(kb_path, params - 1))
        assert call(_at_limit(kb_path, 999)) == []


def test_every_public_tool__no_knowledge_base__returns_not_ready_rather_than_raising(tmp_path, monkeypatch):
    # Returned, not raised. The benchmark_ids cap raises because that is a caller error the
    # caller must fix; not_ready is not a caller error, the request is fine and the server
    # cannot serve it yet. In VS Code a raise is a failed tool call, a return is a result.
    #
    # SOURCES_DIR is monkeypatched because readiness.payload reads it unconditionally: without
    # this every reason-reaching test scans the real sources directory of whoever runs it.
    monkeypatch.setattr(config, "SOURCES_DIR", tmp_path)
    kb = app_module.KnowledgeBase(tmp_path / "absent.sqlite")
    calls = (
        lambda: tools.defenses_for_technique(kb, "T1078"),
        lambda: tools.techniques_for_actor(kb, "G0016"),
        lambda: tools.resolve_system(kb, "RHEL 9"),
        lambda: tools.list_stigs(kb),
        lambda: tools.search_techniques(kb, "valid"),
        lambda: tools.finding_details(kb, ["V-1"]),
    )
    for call in calls:
        body = call()
        assert body["status"] == "not_ready"
        assert body["reason"] == "no_knowledge_base"
        # [{}] would satisfy a bare truthiness check. Pin the content, and pin it PAIRED:
        # readiness._SCRIPTS is keyed the same as _MODULES but the two dicts could disagree
        # with each other and no set-membership check on either alone would notice a step
        # whose as_installed names a different command than its own run module does.
        steps = {step["as_installed"].split()[-1]: step["run"] for step in body["next"]}
        assert steps.keys() == {"stig-mcp-install-kb", "stig-mcp-fetch", "stig-mcp-ingest"}
        assert steps["stig-mcp-install-kb"].endswith("stig_mcp.kb.install")
        assert steps["stig-mcp-fetch"].endswith("stig_mcp.ingest.fetch")
        assert steps["stig-mcp-ingest"].endswith("stig_mcp.ingest.orchestrator")


def test_defenses_for_technique__a_ready_knowledge_base__answers_normally(kb_path):
    kb = app_module.KnowledgeBase(kb_path)
    result = tools.defenses_for_technique(kb, "T1078", "RHEL 9 web server")
    assert result["technique"]["id"] == "T1078"
    assert "status" not in result


def test_defenses_for_technique__schema_outdated_kb__returns_not_ready_naming_the_reason(tmp_path, monkeypatch):
    # The "schema version" paragraph in docs/operations.md claims a stale-schema knowledge
    # base "reports the outdated schema and tells you to re-run the ingest" through the tools.
    # This is the test that holds the tools to that claim.
    #
    # INSERT, not UPDATE: create_db leaves ingest_meta EMPTY, so an UPDATE hits zero rows and
    # this would pass through the empty-table path instead of a real version mismatch (the
    # same vacuous-UPDATE trap test_readiness.py already documents).
    monkeypatch.setattr(config, "SOURCES_DIR", tmp_path)
    db_path = tmp_path / "stale.sqlite"
    conn = create_db(db_path)
    conn.execute("INSERT INTO ingest_meta (schema_version) VALUES ('0')")
    conn.commit()
    conn.close()
    kb = app_module.KnowledgeBase(db_path)
    result = tools.defenses_for_technique(kb, "T1078")
    assert result["status"] == "not_ready"
    assert result["reason"] == "schema_outdated"
    assert any("rebuild" in step["why"].lower() for step in result["next"])


def test_defenses_for_technique__unreadable_kb__returns_not_ready_naming_the_file(tmp_path, monkeypatch):
    # Covers readiness.payload(kb, "unreadable") the way a caller reaches it: through a public tool.
    monkeypatch.setattr(config, "SOURCES_DIR", tmp_path)
    corrupt = tmp_path / "corrupt.sqlite"
    corrupt.write_bytes(b"not a database, just bytes")
    kb = app_module.KnowledgeBase(corrupt)
    result = tools.defenses_for_technique(kb, "T1078")
    assert result["status"] == "not_ready"
    assert result["reason"] == "unreadable"
    assert any(str(corrupt) in step["why"] for step in result["next"])


def test_techniques_for_actor__include_defenses__acquires_the_connection_only_once(kb_path, monkeypatch):
    # The per-technique expansion loop must reuse the connection techniques_for_actor already
    # acquired, not call kb.acquire() again per technique: acquire() closes any connection it
    # is holding on a not-ready or rebuilt transition (KnowledgeBase._close), so a second
    # acquire per technique risks closing the very connection the outer frame still needs for
    # _sources_block once the loop returns, and costs a fresh readiness.check() per technique
    # for nothing. Pinned by making the holder answerable exactly once: a version that
    # re-acquires per technique raises here instead of completing.
    kb = app_module.KnowledgeBase(kb_path)
    real_acquire = kb.acquire
    calls = {"n": 0}

    def acquire_once():
        calls["n"] += 1
        if calls["n"] > 1:
            raise AssertionError("techniques_for_actor must acquire the connection only once")
        return real_acquire()

    monkeypatch.setattr(kb, "acquire", acquire_once)
    result = tools.techniques_for_actor(kb, "APT29", system_description="RHEL 9", include_defenses=True)
    technique = next(t for t in result["techniques"] if t["technique_id"] == "T1078")
    assert technique["controls"]


def test_defenses_for_technique__no_knowledge_base_and_over_cap_benchmark_ids__returns_not_ready(tmp_path, monkeypatch):
    # The ordering is load bearing: readiness is checked BEFORE _check_benchmark_ids,
    # because a caller cannot fix a malformed argument usefully while the server has no data
    # to answer from. Nothing else in this suite reaches the intersection of "no knowledge
    # base" and "benchmark_ids over the cap": the not_ready tests all pass benchmark_ids=None, and the
    # cap tests all use a ready knowledge base. This is that intersection.
    monkeypatch.setattr(config, "SOURCES_DIR", tmp_path)
    kb = app_module.KnowledgeBase(tmp_path / "absent.sqlite")
    too_many = [f"FILLER_{i}_STIG" for i in range(tools._MAX_BENCHMARK_IDS + 1)]
    result = tools.defenses_for_technique(kb, "T1078", None, too_many)
    assert result["status"] == "not_ready"
    assert result["reason"] == "no_knowledge_base"


def test_techniques_for_actor__no_knowledge_base_and_over_cap_benchmark_ids__returns_not_ready(tmp_path, monkeypatch):
    # The second entry point, tested separately for the same reason the cap tests are: a rule
    # wired into only one of two caller paths leaves the other unguarded.
    monkeypatch.setattr(config, "SOURCES_DIR", tmp_path)
    kb = app_module.KnowledgeBase(tmp_path / "absent.sqlite")
    too_many = [f"FILLER_{i}_STIG" for i in range(tools._MAX_BENCHMARK_IDS + 1)]
    result = tools.techniques_for_actor(kb, "G0016", None, too_many)
    assert result["status"] == "not_ready"
    assert result["reason"] == "no_knowledge_base"


_MAPPING = {"attack": "19.1", "ctid_attack": "16.1", "ctid_release": "2024-11-12"}


def test_no_controls_note__mapped_but_suppressed__blames_overrides_not_ctid():
    note = tools._no_controls_note("T1", {"created": None, "ctid_status": "mapped"}, _MAPPING)
    assert note == "All CTID-mapped controls for T1 are suppressed in overrides.yaml."


def test_no_controls_note__non_mappable__says_ctid_reviewed_it():
    note = tools._no_controls_note("T1", {"created": "2020-01-01", "ctid_status": "non_mappable"}, _MAPPING)
    assert note == "CTID reviewed T1 and found no 800-53r5 control that mitigates it."


def test_no_controls_note__created_one_day_after_release__is_newer_than_the_mapping():
    note = tools._no_controls_note("T1", {"created": "2024-11-13", "ctid_status": "absent"}, _MAPPING)
    assert note == (
        "T1 was added to ATT&CK on 2024-11-13, after ATT&CK 16.1 (2024-11-12), which the CTID mapping covers."
    )


def test_no_controls_note__newer_than_release_but_ctid_attack_version_unknown__names_it_unknown():
    # The `mapping["ctid_attack"] or "unknown"` fallback: a release date can be known (so the
    # created > released branch fires) while the mapping's own ATT&CK version is not.
    mapping = {**_MAPPING, "ctid_attack": None}
    note = tools._no_controls_note("T1", {"created": "2024-11-13", "ctid_status": "absent"}, mapping)
    assert note == (
        "T1 was added to ATT&CK on 2024-11-13, after ATT&CK unknown (2024-11-12), which the CTID mapping covers."
    )


def test_no_controls_note__created_on_the_release_date__is_not_covered_and_suggests_overrides():
    # Pulls against the answer above: the boundary day belongs to the release, not after it.
    note = tools._no_controls_note("T1", {"created": "2024-11-12", "ctid_status": "absent"}, _MAPPING)
    assert note == "The CTID mapping does not cover T1. Add a mapping in overrides.yaml if this is a gap."


def test_no_controls_note__release_date_unknown__asks_for_attack_index():
    mapping = {**_MAPPING, "ctid_release": None}
    note = tools._no_controls_note("T1", {"created": "2025-01-01", "ctid_status": "absent"}, mapping)
    assert note == (
        "T1 is not in the CTID mapping file (ATT&CK 16.1); provide attack_index.json to tell a newer "
        "technique from an uncovered one."
    )


def test_no_controls_note__technique_without_created__asks_for_attack_index_not_newer():
    # The repo's own attack_bundle.json fixture carries no created dates.
    note = tools._no_controls_note("T1", {"created": None, "ctid_status": "absent"}, _MAPPING)
    assert note.startswith("T1 is not in the CTID mapping file")


def test_version_gap_note__versions_differ__names_both():
    assert tools._version_gap_note(_MAPPING) == (
        "Controls come from the CTID mapping for ATT&CK 16.1; technique data is ATT&CK 19.1."
    )


def test_version_gap_note__versions_equal_or_unknown__returns_none():
    assert tools._version_gap_note({**_MAPPING, "attack": "16.1"}) is None
    assert tools._version_gap_note({**_MAPPING, "ctid_attack": None}) is None


@pytest.mark.parametrize(
    ("technique_id", "build", "expected_start"),
    [
        ("T1078", {"suppress_mapped": True}, "All CTID-mapped controls for T1078 are suppressed"),
        ("T8001", {}, "CTID reviewed T8001"),
        ("T9500", {}, "T9500 was added to ATT&CK on 2024-11-13, after ATT&CK 16.1 (2024-11-12)"),
        ("T9000", {}, "The CTID mapping does not cover T9000."),
        ("T9500", {"attack_index": False}, "T9500 is not in the CTID mapping file (ATT&CK 16.1)"),
    ],
)
def test_defenses_for_technique__currency_build__names_each_cause_end_to_end(
    tmp_path, technique_id, build, expected_start
):
    # Cause 1 needs the real ingest: _load_ctid_status reads CTID's raw pairs while the override
    # suppression happens in _effective_pairs, and only their combination yields "mapped, no controls".
    from tests.ingest.test_orchestrator import _currency_sources  # noqa: PLC0415 (shared fixture builder)

    build_kb(_currency_sources(tmp_path, **build), tmp_path / "kb.sqlite")
    conn = open_db_for_test(tmp_path / "kb.sqlite")
    result = tools.defenses_for_technique(kb_holder(conn), technique_id)
    assert result["protect"]["controls"] == []
    assert any(n.startswith(expected_start) for n in result["notes"]), result["notes"]
    assert "Controls come from the CTID mapping for ATT&CK 16.1; technique data is ATT&CK 19.1." in result["notes"]
    assert result["sources"]["ctid_attack_version"] == "16.1"


def test_check_sources__kb_not_built__reports_install_and_the_not_ready_payload(tmp_path, monkeypatch, kb_path):
    monkeypatch.setattr(config, "SOURCES_DIR", tmp_path)
    github = FakeGitHub()
    github.publish("kb-2026-10-04", kb_path.read_bytes())
    kb = app_module.KnowledgeBase(tmp_path / "absent.sqlite")
    result = tools.check_sources(kb, opener=github)
    assert result["kb_ready"] is False
    assert result["not_ready"] == tools.search_techniques(kb, "anything")
    assert result["action"] == "install"


def test_check_sources__contacts_only_the_releases_listing_and_release_json(kb_path):
    # No SOURCES_DIR monkeypatch: kb_path is ready, so check_sources never reaches the
    # not_ready payload that reads it.
    github = FakeGitHub()
    github.publish("kb-2026-10-04", kb_path.read_bytes())
    result = tools.check_sources(app_module.KnowledgeBase(kb_path), opener=github)
    assert github.requested == [releases.LISTING_URL, f"{releases.DOWNLOAD_PREFIX}kb-2026-10-04/release.json"]
    assert result["kb_ready"] is True
    assert result["not_ready"] is None
    assert result["action"] == "none"


def test_check_sources__ready_kb_with_a_newer_upstream_release__action_install(kb_path):
    github = FakeGitHub()
    github.publish("kb-2026-10-04", b"other", upstream={"attack": "99.0"})
    result = tools.check_sources(app_module.KnowledgeBase(kb_path), opener=github)
    assert result["action"] == "install"


def test_check_sources__rate_limited__raises_caller_error_with_the_reset_time(kb_path):
    github = FakeGitHub()
    github.bodies[releases.LISTING_URL] = http_error(
        releases.LISTING_URL, 403, {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "1790559566"}
    )
    with pytest.raises(tools.CallerError, match="resets at 2026-09-28"):
        tools.check_sources(app_module.KnowledgeBase(kb_path), opener=github)


def test_check_sources__schema_outdated_kb_with_a_release__action_install_via_the_tool(tmp_path, monkeypatch, kb_path):
    # No release record, so the only thing that makes this "install" is treating the outdated
    # file as not installed; hashing it would judge it a local build as current as the release.
    monkeypatch.setattr(config, "SOURCES_DIR", tmp_path)
    target = tmp_path / "stig_kb.sqlite"
    shutil.copyfile(kb_path, target)
    with sqlite3.connect(target) as conn:
        conn.execute("UPDATE ingest_meta SET schema_version = '5'")
    conn.close()
    github = FakeGitHub()
    github.publish("kb-2026-10-04", kb_path.read_bytes())
    result = tools.check_sources(app_module.KnowledgeBase(target), opener=github)
    assert result["not_ready"]["reason"] == "schema_outdated"
    assert result["not_ready"]["next"][0]["tool"] == "install_knowledge_base"
    assert result["action"] == "install"
    assert result["reason"] == "The installed knowledge base cannot be used (schema_outdated)."


def test_check_sources__nothing_installed_and_no_release__action_build_locally(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "SOURCES_DIR", tmp_path)
    result = tools.check_sources(app_module.KnowledgeBase(tmp_path / "absent.sqlite"), opener=FakeGitHub())
    assert result["action"] == "build_locally"
    assert result["not_ready"]["reason"] == "no_knowledge_base"
    assert result["reason"].startswith("No published knowledge-base release")


def _xz_of(tmp_path, kb_path):
    source = tmp_path / "kb.sqlite.xz"
    source.write_bytes(lzma.compress(kb_path.read_bytes()))
    return source, hashlib.sha256(source.read_bytes()).hexdigest()


def test_install_knowledge_base__offline_file__installs_and_the_next_call_answers(tmp_path, kb_path):
    kb = app_module.KnowledgeBase(tmp_path / "data" / "stig_kb.sqlite")
    assert tools.list_stigs(kb)["status"] == "not_ready"
    source, sha = _xz_of(tmp_path, kb_path)
    result = tools.install_knowledge_base(kb, path=str(source), sha256=sha, opener=refuse_network)
    assert result["status"] == "installed"
    assert "not_ready" not in result
    assert result["installed"]["file"] == source.name
    assert isinstance(tools.list_stigs(kb), list)


def test_install_knowledge_base__from_releases__closes_the_held_connection_first(tmp_path, kb_path, monkeypatch):
    target = tmp_path / "data" / "stig_kb.sqlite"
    target.parent.mkdir(parents=True)
    shutil.copyfile(kb_path, target)
    kb = app_module.KnowledgeBase(target)
    held, _ = kb.acquire()
    github = FakeGitHub()
    github.publish("kb-2026-10-04", kb_path.read_bytes())
    tools.install_knowledge_base(kb, opener=github)
    with pytest.raises(sqlite3.ProgrammingError):
        held.execute("SELECT 1")


def test_install_knowledge_base__from_releases__closes_the_connection_before_os_replaces_the_file(
    tmp_path, kb_path, monkeypatch
):
    # The test above only proves the connection is closed by the time the tool RETURNS, which
    # the tool's own post-install _answerable call would also achieve by reopening on a changed
    # file identity, even with before_replace dropped entirely. This proves the connection is
    # closed BEFORE os.replace runs, which is the Windows-safety property before_replace exists
    # for: Windows refuses to replace a file a connection still holds open.
    target = tmp_path / "data" / "stig_kb.sqlite"
    target.parent.mkdir(parents=True)
    shutil.copyfile(kb_path, target)
    kb = app_module.KnowledgeBase(target)
    held, _ = kb.acquire()
    github = FakeGitHub()
    github.publish("kb-2026-10-04", kb_path.read_bytes())
    real_replace = os.replace
    checked = []

    def replace_after_close(src, dst):
        if Path(dst) == target:
            checked.append(True)
            with pytest.raises(sqlite3.ProgrammingError):
                held.execute("SELECT 1")
        return real_replace(src, dst)

    monkeypatch.setattr("os.replace", replace_after_close)
    tools.install_knowledge_base(kb, opener=github)
    assert checked


@pytest.mark.parametrize(
    ("arguments", "guidance"),
    [
        ({"path": "x.sqlite.xz"}, "sha256"),
        ({"sha256": "0" * 64}, "path"),
        ({"release": "kb-2026-10-04", "path": "x", "sha256": "0" * 64}, "either"),
    ],
)
def test_install_knowledge_base__arguments_that_do_not_fit__raise_caller_error(tmp_path, arguments, guidance):
    kb = app_module.KnowledgeBase(tmp_path / "data" / "stig_kb.sqlite")
    with pytest.raises(tools.CallerError, match=guidance):
        tools.install_knowledge_base(kb, opener=refuse_network, **arguments)


def test_install_knowledge_base__path_without_sha256__names_the_missing_argument(tmp_path):
    # The parametrized case above (arguments={"path": ...}) matches "sha256" for its guidance,
    # which the fallback install.InstallError message ("sha256 must be the 64 hexadecimal
    # characters...") also contains, so it does not prove the argument-shape guard raised at
    # all rather than the file having been opened and rejected downstream. This matches text
    # only that guard's own message carries.
    kb = app_module.KnowledgeBase(tmp_path / "data" / "stig_kb.sqlite")
    with pytest.raises(tools.CallerError, match="go together"):
        tools.install_knowledge_base(kb, opener=refuse_network, path="x.sqlite.xz")


def test_install_knowledge_base__no_release_published__reaches_the_caller_as_caller_error(tmp_path):
    kb = app_module.KnowledgeBase(tmp_path / "data" / "stig_kb.sqlite")
    with pytest.raises(tools.CallerError, match="stig-mcp-fetch"):
        tools.install_knowledge_base(kb, opener=FakeGitHub())


def test_install_knowledge_base__github_unreachable__caller_error_names_the_offline_route(tmp_path):
    github = FakeGitHub()
    github.bodies[releases.LISTING_URL] = urllib.error.URLError(OSError("Name or service not known"))
    kb = app_module.KnowledgeBase(tmp_path / "data" / "stig_kb.sqlite")
    with pytest.raises(tools.CallerError, match=r"Could not reach api\.github\.com.*--file PATH --sha256 HEX"):
        tools.install_knowledge_base(kb, opener=github)


def test_install_knowledge_base__tls_intercepted__caller_error_names_the_os_store(tmp_path):
    github = FakeGitHub()
    github.bodies[releases.LISTING_URL] = urllib.error.URLError(ssl.SSLError(1, "CERTIFICATE_VERIFY_FAILED"))
    kb = app_module.KnowledgeBase(tmp_path / "data" / "stig_kb.sqlite")
    with pytest.raises(tools.CallerError, match=r"operating system's certificate store"):
        tools.install_knowledge_base(kb, opener=github)


def test_install_knowledge_base__offline_file__closes_the_connection_before_os_replaces_the_file(
    tmp_path, kb_path, monkeypatch
):
    target = tmp_path / "data" / "stig_kb.sqlite"
    target.parent.mkdir(parents=True)
    shutil.copyfile(kb_path, target)
    kb = app_module.KnowledgeBase(target)
    held, _ = kb.acquire()
    source, sha = _xz_of(tmp_path, kb_path)
    real_replace = os.replace
    checked = []

    def replace_after_close(src, dst):
        if Path(dst) == target:
            checked.append(True)
            with pytest.raises(sqlite3.ProgrammingError):
                held.execute("SELECT 1")
        return real_replace(src, dst)

    monkeypatch.setattr("os.replace", replace_after_close)
    tools.install_knowledge_base(kb, path=str(source), sha256=sha, opener=refuse_network)
    assert checked


def test_knowledge_base_sha256__same_file__is_computed_once(kb_path, monkeypatch):
    kb = app_module.KnowledgeBase(kb_path)
    calls = []
    real = app_module.install.file_sha256
    monkeypatch.setattr(app_module.install, "file_sha256", lambda path: calls.append(path) or real(path))
    assert kb.sha256() == kb.sha256() == hashlib.sha256(kb_path.read_bytes()).hexdigest()
    assert len(calls) == 1


def test_knowledge_base_sha256__file_replaced__is_recomputed(tmp_path, kb_path):
    target = tmp_path / "stig_kb.sqlite"
    shutil.copyfile(kb_path, target)
    kb = app_module.KnowledgeBase(target)
    first = kb.sha256()
    with sqlite3.connect(target) as conn:
        conn.execute("UPDATE ingest_meta SET ingested_at = 'changed'")
    conn.close()
    assert kb.sha256() != first
    assert kb.sha256() == hashlib.sha256(target.read_bytes()).hexdigest()


def test_knowledge_base_sha256__file_removed_after_hashing__is_none_without_opening_it(tmp_path, kb_path, monkeypatch):
    target = tmp_path / "stig_kb.sqlite"
    shutil.copyfile(kb_path, target)
    kb = app_module.KnowledgeBase(target)
    assert kb.sha256() is not None
    target.unlink()
    calls = []
    real = app_module.install.file_sha256
    monkeypatch.setattr(app_module.install, "file_sha256", lambda path: calls.append(path) or real(path))
    assert kb.sha256() is None
    assert calls == []


def test_knowledge_base_sha256__file_cannot_be_read__is_none_and_not_cached(tmp_path, kb_path, monkeypatch):
    # Present to os.stat but gone or unreadable by the time it is opened: the race between
    # readiness.identity and the hash.
    target = tmp_path / "stig_kb.sqlite"
    shutil.copyfile(kb_path, target)
    kb = app_module.KnowledgeBase(target)
    real = app_module.install.file_sha256

    def vanished(path):
        raise FileNotFoundError(2, "No such file or directory", str(path))

    monkeypatch.setattr(app_module.install, "file_sha256", vanished)
    assert kb.sha256() is None
    monkeypatch.setattr(app_module.install, "file_sha256", real)
    assert kb.sha256() == hashlib.sha256(kb_path.read_bytes()).hexdigest()


def test_knowledge_base_sha256__cached_then_the_read_fails__clears_the_cache(tmp_path, kb_path, monkeypatch):
    target = tmp_path / "stig_kb.sqlite"
    shutil.copyfile(kb_path, target)
    kb = app_module.KnowledgeBase(target)
    assert kb.sha256() is not None
    with sqlite3.connect(target) as conn:
        conn.execute("UPDATE ingest_meta SET ingested_at = 'changed'")
    conn.close()

    def unreadable(path):
        raise PermissionError(13, "Permission denied", str(path))

    monkeypatch.setattr(app_module.install, "file_sha256", unreadable)
    assert kb.sha256() is None
    assert kb._sha256 is None
    assert kb._sha256_identity is None


def test_install_knowledge_base__path_with_a_tilde__expands_it(tmp_path, kb_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    kb = app_module.KnowledgeBase(tmp_path / "data" / "stig_kb.sqlite")
    source, sha = _xz_of(tmp_path, kb_path)
    result = tools.install_knowledge_base(kb, path=f"~/{source.name}", sha256=sha, opener=refuse_network)
    assert result["status"] == "installed"


def test_defenses_for_technique__sources_block__carries_the_installed_file_sha256(kb_path):
    result = tools.defenses_for_technique(app_module.KnowledgeBase(kb_path), "T1078")
    assert result["sources"]["kb_sha256"] == hashlib.sha256(kb_path.read_bytes()).hexdigest()


def test_techniques_for_actor__sources_block__carries_the_installed_file_sha256(kb_path):
    result = tools.techniques_for_actor(app_module.KnowledgeBase(kb_path), "Cozy Bear")
    assert result["sources"]["kb_sha256"] == hashlib.sha256(kb_path.read_bytes()).hexdigest()


def _kb_with_actors(kb_path, tmp_path, rows):
    """A copy of the fixture knowledge base with extra actor rows; kb_path is session-scoped."""
    copy = tmp_path / "actors_kb.sqlite"
    shutil.copy(kb_path, copy)
    with closing(sqlite3.connect(copy)) as conn:
        conn.executemany("INSERT INTO actors (actor_id, name, aliases) VALUES (?, ?, ?)", rows)
        conn.commit()
    return app_module.KnowledgeBase(copy)


def test_techniques_for_actor__loosely_typed_name__reports_what_it_matched(kb_path):
    result = tools.techniques_for_actor(app_module.KnowledgeBase(kb_path), "APT-29")
    assert result["actor"]["id"] == "G0016"
    assert result["actor"]["matched_as"] == "APT29"
    assert [t["technique_id"] for t in result["techniques"]] == ["T1078"]


def test_techniques_for_actor__exact_name__carries_no_matched_as(kb_path):
    result = tools.techniques_for_actor(app_module.KnowledgeBase(kb_path), "APT29")
    assert "matched_as" not in result["actor"]


def test_techniques_for_actor__misspelled_alias__names_the_group_and_the_alias_it_resembles(kb_path):
    with pytest.raises(tools.CallerError) as raised:
        tools.techniques_for_actor(app_module.KnowledgeBase(kb_path), "Cosy Bear")
    assert str(raised.value) == (
        "Unknown actor 'Cosy Bear'. Closest ATT&CK groups: APT29 (G0016, as 'Cozy Bear'). "
        "Call again with the group id of the one you mean."
    )


def test_techniques_for_actor__alias_of_two_groups__refuses_and_names_both(kb_path, tmp_path):
    kb = _kb_with_actors(
        kb_path,
        tmp_path,
        [("G1003", "Ember Bear", "Ember Bear,UAC-0056"), ("G1031", "Saint Bear", "Saint Bear,UAC-0056")],
    )
    with pytest.raises(tools.CallerError) as raised:
        tools.techniques_for_actor(kb, "UAC-0056")
    assert str(raised.value) == (
        "Actor 'UAC-0056' names more than one ATT&CK group: Ember Bear (G1003), Saint Bear (G1031). "
        "Call again with the group id of the one you mean."
    )


def test_techniques_for_actor__nothing_close__keeps_the_plain_guidance(kb_path):
    with pytest.raises(tools.CallerError) as raised:
        tools.techniques_for_actor(app_module.KnowledgeBase(kb_path), "No Such Group")
    assert str(raised.value) == (
        "Unknown actor 'No Such Group'. Provide an ATT&CK group id (e.g. 'G0016') or a known name/alias."
    )


def test_techniques_for_actor__misspelled_name__suggests_the_group_without_an_alias(kb_path):
    with pytest.raises(tools.CallerError) as raised:
        tools.techniques_for_actor(app_module.KnowledgeBase(kb_path), "APT92")
    assert str(raised.value) == (
        "Unknown actor 'APT92'. Closest ATT&CK groups: APT29 (G0016). Call again with the group id of the one you mean."
    )


def test_techniques_for_actor__label_another_group_shares__reports_it_in_also_matches(kb_path, tmp_path):
    kb = _kb_with_actors(
        kb_path,
        tmp_path,
        [("G1014", "LuminousMoth", "LuminousMoth"), ("G0129", "Mustang Panda", "Mustang Panda,LUMINOUS MOTH")],
    )
    result = tools.techniques_for_actor(kb, "Luminous Moth")
    assert result["actor"]["id"] == "G0129"
    assert result["actor"]["also_matches"] == [{"id": "G1014", "name": "LuminousMoth", "via": None}]


def test_techniques_for_actor__label_no_other_group_shares__carries_no_also_matches(kb_path):
    result = tools.techniques_for_actor(app_module.KnowledgeBase(kb_path), "APT29")
    assert "also_matches" not in result["actor"]


def test_install_knowledge_base__no_opener_given__downloads_through_the_truststore_opener(
    tmp_path, kb_path, monkeypatch
):
    def tls_failure(*_handlers):
        def open_url(request, timeout=None):
            raise urllib.error.URLError(ssl.SSLError(1, "truststore-opener-reached"))

        return open_url

    monkeypatch.setattr(tls, "opener", tls_failure)
    target = tmp_path / "data" / "stig_kb.sqlite"
    target.parent.mkdir(parents=True)
    shutil.copyfile(kb_path, target)
    with pytest.raises(tools.CallerError, match="truststore-opener-reached"):
        tools.install_knowledge_base(app_module.KnowledgeBase(target))


def test_defenses_for_technique__t1078__carries_protect_and_detect_sections(kb_path):
    result = tools.defenses_for_technique(app_module.KnowledgeBase(kb_path), "T1078", system_description="RHEL 9")
    assert list(result) == ["summary", "technique", "resolved_systems", "protect", "detect", "notes", "sources"]
    assert result["protect"]["mitigations"] == [
        {"id": "M1026", "name": "Privileged Account Management"},
        {"id": "M1027", "name": "Password Policies"},
    ]
    assert result["detect"]["detection_strategy"] == {"id": "DET0001", "name": "Detect Valid Account Abuse"}
    assert [a["id"] for a in result["detect"]["analytics"]] == ["AN0001", "AN0002"]
    assert all(system["catalog"] == "disa" for system in result["resolved_systems"])
    assert result["protect"]["findings"]
    details = tools.finding_details(app_module.KnowledgeBase(kb_path), list(result["protect"]["findings"]))
    assert all(finding["catalog"] == "disa" for finding in details["findings"])
    assert "description" not in result["protect"]["mitigations"][0]


def test_defenses_for_technique__technique_without_a_strategy__detect_is_none_and_counts_zero(kb_path):
    result = tools.defenses_for_technique(app_module.KnowledgeBase(kb_path), "T1078.001")
    assert result["detect"] is None
    assert result["summary"]["detection"] == {"analytics": 0}


def test_defenses_for_technique__platforms_and_log_sources__flag_analytics_and_count_them(kb_path):
    result = tools.defenses_for_technique(
        app_module.KnowledgeBase(kb_path),
        "T1078",
        platforms=["Windows"],
        log_sources=["WinEventLog:Security", "WinEventLog:Sysmon"],
    )
    flags = {a["id"]: (a["applicable"], a["detectable"]) for a in result["detect"]["analytics"]}
    assert flags == {"AN0001": (True, True), "AN0002": (False, False)}
    assert result["summary"]["detection"] == {"analytics": 2, "applicable": 1, "detectable": 1}


def test_defenses_for_technique__platforms_only__omits_the_detectable_count(kb_path):
    result = tools.defenses_for_technique(app_module.KnowledgeBase(kb_path), "T1078", platforms=["Linux"])
    assert result["summary"]["detection"] == {"analytics": 2, "applicable": 1}
    assert all(a["detectable"] is None for a in result["detect"]["analytics"])


def test_defenses_for_technique__unknown_platform__refuses_listing_the_vocabulary(kb_path):
    with pytest.raises(tools.CallerError) as excinfo:
        tools.defenses_for_technique(app_module.KnowledgeBase(kb_path), "T1078", platforms=["Windoze"])
    message = str(excinfo.value)
    assert "Windoze" in message
    assert "Linux, Windows" in message


def test_defenses_for_technique__unknown_log_source__refuses_naming_the_closest_names(kb_path):
    with pytest.raises(tools.CallerError) as excinfo:
        tools.defenses_for_technique(app_module.KnowledgeBase(kb_path), "T1078", log_sources=["WinEventLog:Secur"])
    message = str(excinfo.value)
    assert "WinEventLog:Secur" in message
    assert "WinEventLog:Security" in message


# A slice of ATT&CK 19.2's log source names, chosen so plain character similarity picks wrong.
_ATTACK_NAMES = [
    "macos:unifiedlog",
    "WinEventLog:Microsoft-Windows-COM/Operational",
    "WinEventLog:Microsoft-Windows-CodeIntegrity/Operational",
    "WinEventLog:Microsoft-Windows-Windows Defender/Operational",
    "WinEventLog:Sysmon",
    "linux:Sysmon",
    "systemd:unit",
    "snmp:syslog",
    "WinEventLog:PowerShell",
    "esxi:shell",
    "linux:shell",
    "WinEventLog:Security",
    "WinEventLog:System",
    "macOS:unifiedlog",
    "macos:syslog",
]


@pytest.mark.parametrize(
    ("asked", "expected"),
    [
        ("WinEventLog:Microsoft-Windows-Sysmon/Operational", "WinEventLog:Sysmon"),
        ("Microsoft-Windows-PowerShell/Operational", "WinEventLog:PowerShell"),
        ("powershell", "WinEventLog:PowerShell"),
        ("WinEventLog:Securty", "WinEventLog:Security"),
    ],
)
def test_closest__a_name_attack_spells_differently__suggests_it_first(asked, expected):
    assert tools._closest(asked, tools._spellings_by_key(_ATTACK_NAMES))[0] == expected


def test_closest__sysmon__suggests_both_sysmon_logs():
    assert set(tools._closest("sysmon", tools._spellings_by_key(_ATTACK_NAMES))[:2]) == {
        "WinEventLog:Sysmon",
        "linux:Sysmon",
    }


def test_closest__a_name_spelled_two_ways__is_suggested_once_in_the_first_spelling():
    closest = tools._closest("macos:unifedlog", tools._spellings_by_key(_ATTACK_NAMES))
    assert closest[0] == "macos:unifiedlog"
    assert "macOS:unifiedlog" not in closest


def test_defenses_for_technique__unknown_log_source__suggests_the_spelling_most_analytics_use(minority_spelling_kb):
    with pytest.raises(tools.CallerError) as excinfo:
        tools.defenses_for_technique(minority_spelling_kb, "T9001", log_sources=["WinEventLog:Securty"])
    message = str(excinfo.value)
    assert "WinEventLog:Security" in message
    assert "WinEventLog:SECURITY" not in message


def test_defenses_for_technique__platform_in_another_case__is_accepted(kb_path):
    result = tools.defenses_for_technique(app_module.KnowledgeBase(kb_path), "T1078", platforms=["windows"])
    assert {a["id"]: a["applicable"] for a in result["detect"]["analytics"]} == {"AN0001": True, "AN0002": False}


@pytest.mark.parametrize("bad", ["Windows", "WinEventLog:Security", []])
def test_defenses_for_technique__a_bare_string_or_empty_list_for_a_filter__is_refused_not_iterated(kb_path, bad):
    kb = app_module.KnowledgeBase(kb_path)
    with pytest.raises(tools.CallerError, match="must be a non-empty list"):
        tools.defenses_for_technique(kb, "T1078", platforms=bad)
    with pytest.raises(tools.CallerError, match="must be a non-empty list"):
        tools.defenses_for_technique(kb, "T1078", log_sources=bad)


def test_defenses_for_technique__more_log_sources_than_the_cap__raises_naming_the_cap(kb_path):
    too_many = [f"Source{i}" for i in range(tools._MAX_LOG_SOURCES + 1)]
    with pytest.raises(tools.CallerError) as excinfo:
        tools.defenses_for_technique(app_module.KnowledgeBase(kb_path), "T1078", log_sources=too_many)
    message = str(excinfo.value)
    assert str(tools._MAX_LOG_SOURCES) in message
    assert str(len(too_many)) in message


def test_defenses_for_technique__filters_are_validated_before_the_technique(kb_path):
    # The vocabulary check happens even when the technique id is wrong, as severity is.
    with pytest.raises(tools.CallerError, match="Windoze"):
        tools.defenses_for_technique(app_module.KnowledgeBase(kb_path), "T9999", platforms=["Windoze"])


def test_defenses_for_technique__log_sources_exactly_at_the_cap__are_not_refused_for_count(kb_path, monkeypatch):
    monkeypatch.setattr(tools, "_MAX_LOG_SOURCES", 2)
    kb = app_module.KnowledgeBase(kb_path)
    result = tools.defenses_for_technique(kb, "T1078", log_sources=["WinEventLog:Security", "WinEventLog:Sysmon"])
    assert result["summary"]["detection"]["detectable"] == 1
    with pytest.raises(tools.CallerError, match="over the limit of 2"):
        tools.defenses_for_technique(
            kb, "T1078", log_sources=["WinEventLog:Security", "WinEventLog:Sysmon", "auditd:SYSCALL"]
        )


def test_defenses_for_technique__unknown_log_source_with_an_unknown_technique__refuses_the_log_source(kb_path):
    with pytest.raises(tools.CallerError, match="WinEventLog:Secur"):
        tools.defenses_for_technique(app_module.KnowledgeBase(kb_path), "T9999", log_sources=["WinEventLog:Secur"])


_TELEMETRY = ["WinEventLog:Security", "WinEventLog:Sysmon"]


def _apt29_coverage(defenses_kb, **kwargs):
    kb = app_module.KnowledgeBase(defenses_kb)
    return tools.techniques_for_actor(kb, "APT29", include_defenses=True, **kwargs)


def test_techniques_for_actor__include_defenses__counts_every_coverage_class_distinctly(defenses_kb):
    result = _apt29_coverage(defenses_kb, system_description="RHEL 9", platforms=["Windows"], log_sources=_TELEMETRY)
    assert result["summary"]["coverage"] == {
        "techniques": 8,
        "without_mitigation": 3,
        "mitigated_without_rules": 4,
        "without_applicable_analytic": 1,
        "detectable": 2,
        "undetectable": 5,
    }
    keys = list(result["summary"])
    # Every count comes before cat_i so it lands inside a client's preview.
    assert keys.index("control_counts") < keys.index("coverage") < keys.index("mitigations")
    assert keys.index("mitigations") < keys.index("detection") < keys.index("cat_i")
    assert keys[-1] == "controls_with_rules"
    assert result["summary"]["mitigations"] == 6
    assert result["summary"]["detection"] == {"analytics": 10, "applicable": 7, "detectable": 2}


@pytest.fixture
def minority_spelling_kb(defenses_kb, tmp_path):
    """defenses_kb with AN0004 (T9001) needing 'WinEventLog:SECURITY', as ATT&CK 19.2 spells four
    names two ways; AN0001 keeps 'WinEventLog:Security'. The rare spelling sorts first, so
    alphabetical order cannot pick the common one by accident."""
    target = tmp_path / "kb.sqlite"
    shutil.copyfile(defenses_kb, target)
    with closing(sqlite3.connect(target)) as conn, conn:
        changed = conn.execute(
            "UPDATE analytic_log_sources SET name = 'WinEventLog:SECURITY' "
            "WHERE analytic_id = 'AN0004' AND name = 'WinEventLog:Security'"
        ).rowcount
    assert changed == 1
    return app_module.KnowledgeBase(target)


def test_defenses_for_technique__log_source_spelled_another_case_in_attack__matches_it(minority_spelling_kb):
    result = tools.defenses_for_technique(minority_spelling_kb, "T9001", log_sources=["WinEventLog:Security"])
    assert [(a["id"], a["detectable"]) for a in result["detect"]["analytics"]] == [("AN0004", True)]


def test_techniques_for_actor__one_spelling_of_a_log_source__matches_both_spellings(minority_spelling_kb):
    result = tools.techniques_for_actor(
        minority_spelling_kb, "APT29", include_defenses=True, log_sources=["WinEventLog:Security"]
    )
    by_id = {t["technique_id"]: t for t in result["techniques"]}
    assert by_id["T9001"]["analytics"][0]["detectable"] is True
    assert "undetectable" not in by_id["T9001"]["gaps"]


def test_defenses_for_technique__log_source_in_a_case_attack_never_uses__is_accepted_and_matches(defenses_kb):
    kb = app_module.KnowledgeBase(defenses_kb)
    result = tools.defenses_for_technique(kb, "T1078", log_sources=["WINEVENTLOG:SECURITY", "wineventlog:sysmon"])
    flagged = {a["id"]: a["detectable"] for a in result["detect"]["analytics"]}
    assert flagged["AN0001"] is True


def test_techniques_for_actor__include_defenses_without_log_sources__judges_no_technique_undetectable(defenses_kb):
    with_telemetry = _apt29_coverage(defenses_kb, log_sources=_TELEMETRY)
    undetectable = [t["technique_id"] for t in with_telemetry["techniques"] if "undetectable" in t["gaps"]]
    assert undetectable
    without = {t["technique_id"]: t["gaps"] for t in _apt29_coverage(defenses_kb)["techniques"]}
    assert not any("undetectable" in without[technique_id] for technique_id in undetectable)


def test_techniques_for_actor__include_defenses__each_technique_lists_its_defense_ids(defenses_kb):
    result = _apt29_coverage(defenses_kb, platforms=["Windows"], log_sources=_TELEMETRY)
    by_id = {t["technique_id"]: t for t in result["techniques"]}
    assert by_id["T1078"]["mitigations"] == ["M1026", "M1027"]
    assert by_id["T1078"]["detection_strategy"] == "DET0001"
    assert [(a["id"], a["applicable"], a["detectable"]) for a in by_id["T1078"]["analytics"]] == [
        ("AN0001", True, True),
        ("AN0002", False, False),
    ]
    assert by_id["T9000"]["mitigations"] == ["M1027"]  # arrives only through the revoked-by redirect
    assert by_id["T9002"]["mitigations"] == []
    assert result["mitigations"] == {
        "M1026": {"name": "Privileged Account Management"},
        "M1027": {"name": "Password Policies"},
    }
    assert "description" not in result["mitigations"]["M1026"]


def test_techniques_for_actor__one_of_two_sources__flips_t1078_to_undetectable(defenses_kb):
    result = _apt29_coverage(defenses_kb, platforms=["Windows"], log_sources=["WinEventLog:Security"])
    assert (result["summary"]["coverage"]["detectable"], result["summary"]["coverage"]["undetectable"]) == (1, 6)


def test_techniques_for_actor__platforms_only__counts_only_the_applicability_gap(defenses_kb):
    coverage = _apt29_coverage(defenses_kb, platforms=["Windows"])["summary"]["coverage"]
    assert coverage == {"techniques": 8, "without_mitigation": 3, "without_applicable_analytic": 1}


def test_techniques_for_actor__log_sources_only__partitions_every_technique(defenses_kb):
    coverage = _apt29_coverage(defenses_kb, log_sources=_TELEMETRY)["summary"]["coverage"]
    assert coverage == {"techniques": 8, "without_mitigation": 3, "detectable": 2, "undetectable": 6}


def test_techniques_for_actor__no_scope__omits_mitigated_without_rules(defenses_kb):
    coverage = _apt29_coverage(defenses_kb)["summary"]["coverage"]
    assert coverage == {"techniques": 8, "without_mitigation": 3}


def test_techniques_for_actor__without_include_defenses__carries_no_defense_fields(defenses_kb):
    result = tools.techniques_for_actor(app_module.KnowledgeBase(defenses_kb), "APT29", platforms=["Windows"])
    assert result["summary"] == {"techniques": 8}
    assert all("mitigations" not in t and "analytics" not in t for t in result["techniques"])


def test_techniques_for_actor__filters_are_validated_even_without_include_defenses(defenses_kb):
    with pytest.raises(tools.CallerError, match="Windoze"):
        tools.techniques_for_actor(app_module.KnowledgeBase(defenses_kb), "APT29", platforms=["Windoze"])


def test_techniques_for_actor__inapplicable_detectable_analytic__does_not_make_the_technique_detectable(defenses_kb):
    coverage = _apt29_coverage(defenses_kb, platforms=["Windows"], log_sources=["auditd:SYSCALL"])["summary"][
        "coverage"
    ]
    assert (coverage["detectable"], coverage["undetectable"]) == (1, 6)


@pytest.mark.parametrize(
    ("name", "bare", "example"),
    [("log_sources", "WinEventLog:Security", "['WinEventLog:Security']"), ("platforms", "Windows", "['Windows']")],
)
def test_techniques_for_actor__a_bare_string_filter__shows_the_example_for_that_parameter(
    defenses_kb, name, bare, example
):
    with pytest.raises(tools.CallerError, match=re.escape(f"{name}={example}")):
        tools.techniques_for_actor(app_module.KnowledgeBase(defenses_kb), "APT29", **{name: bare})


def test_techniques_for_actor__invalid_platform_with_an_unknown_actor__refuses_the_platform(defenses_kb):
    with pytest.raises(tools.CallerError, match="Windoze"):
        tools.techniques_for_actor(app_module.KnowledgeBase(defenses_kb), "No Such Actor", platforms=["Windoze"])


def test_defense_details__mixed_ids__expand_each_and_list_the_misses(kb_path):
    result = tools.defense_details(app_module.KnowledgeBase(kb_path), ["M1026", "det0001", "AN0003", "AN9999"])
    assert [m["id"] for m in result["mitigations"]] == ["M1026"]
    assert [s["id"] for s in result["detection_strategies"]] == ["DET0001"]
    assert [a["id"] for a in result["analytics"]] == ["AN0003"]
    assert result["not_found"] == ["AN9999"]
    assert result["technique"] is None
    assert "kb_sha256" in result["sources"]


def test_defense_details__technique_id__adds_pair_text_and_follows_a_revoked_id(kb_path):
    result = tools.defense_details(app_module.KnowledgeBase(kb_path), ["M1027"], technique_id="T8001")
    assert result["technique"]["id"] == "T9000"
    assert result["technique"]["redirected_from"] == "T8001"
    assert result["mitigations"][0]["technique_description"] == "Reaches T9000 through the revocation."


def test_defense_details__no_id_matches__refuses_naming_the_ids(kb_path):
    with pytest.raises(tools.CallerError, match="'M9999'"):
        tools.defense_details(app_module.KnowledgeBase(kb_path), ["M9999"])


def test_defense_details__empty_or_over_cap__refuses_naming_the_cap(kb_path):
    kb = app_module.KnowledgeBase(kb_path)
    with pytest.raises(tools.CallerError, match="at least one"):
        tools.defense_details(kb, [])
    too_many = [f"AN{i:04d}" for i in range(tools._MAX_DEFENSE_IDS + 1)]
    with pytest.raises(tools.CallerError, match=rf"over the limit of {tools._MAX_DEFENSE_IDS}"):
        tools.defense_details(kb, too_many)


def test_defense_details__exactly_the_cap__is_accepted(kb_path):
    ids = [f"AN{i:04d}" for i in range(9000, 9000 + tools._MAX_DEFENSE_IDS - 1)] + ["M1026"]
    assert len(ids) == tools._MAX_DEFENSE_IDS
    result = tools.defense_details(app_module.KnowledgeBase(kb_path), ids)
    assert [m["id"] for m in result["mitigations"]] == ["M1026"]
    assert len(result["not_found"]) == tools._MAX_DEFENSE_IDS - 1


def test_defense_details__padded_id__is_matched_not_reported_missing(kb_path):
    result = tools.defense_details(app_module.KnowledgeBase(kb_path), [" M1026 "])
    assert [m["id"] for m in result["mitigations"]] == ["M1026"]
    assert result["not_found"] == []


def test_defense_details__unknown_technique_id__refuses_with_search_guidance(kb_path):
    with pytest.raises(tools.CallerError, match="Unknown technique_id 'T9999'"):
        tools.defense_details(app_module.KnowledgeBase(kb_path), ["M1026"], technique_id="T9999")


def test_defense_details__schema_outdated_knowledge_base__returns_not_ready(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "SOURCES_DIR", tmp_path)
    db = tmp_path / "old.sqlite"
    conn = create_db(db)
    conn.execute("INSERT INTO ingest_meta (source_name, schema_version) VALUES ('test', '6')")
    conn.commit()
    conn.close()
    result = tools.defense_details(app_module.KnowledgeBase(db), ["M1026"])
    assert (result["status"], result["reason"]) == ("not_ready", "schema_outdated")


_GAP_KEYS = ("without_mitigation", "mitigated_without_rules", "without_applicable_analytic", "undetectable")


@pytest.mark.parametrize(
    "filters",
    [
        {"system_description": "RHEL 9", "platforms": ["Windows"], "log_sources": _TELEMETRY},
        {"system_description": "RHEL 9"},
        {"platforms": ["Windows"]},
        {"log_sources": _TELEMETRY},
        {"platforms": ["Windows"], "log_sources": ["WinEventLog:Security"]},
        {},
    ],
)
def test_techniques_for_actor__include_defenses__each_gap_count_equals_the_techniques_naming_it(defenses_kb, filters):
    result = _apt29_coverage(defenses_kb, **filters)
    coverage = result["summary"]["coverage"]
    for key in _GAP_KEYS:
        naming = sum(1 for technique in result["techniques"] if key in technique["gaps"])
        assert naming == coverage.get(key, 0), key


def test_techniques_for_actor__include_defenses__lists_each_techniques_gaps_in_coverage_order(defenses_kb):
    # The expected classes are the table in tests/fixtures/attack_defenses.py.
    result = _apt29_coverage(defenses_kb, system_description="RHEL 9", platforms=["Windows"], log_sources=_TELEMETRY)
    assert {t["technique_id"]: t["gaps"] for t in result["techniques"]} == {
        "T1078": [],
        "T9000": ["mitigated_without_rules", "without_applicable_analytic"],
        "T9001": ["mitigated_without_rules"],
        "T9002": ["without_mitigation", "undetectable"],
        "T9003": ["mitigated_without_rules", "undetectable"],
        "T9004": ["without_mitigation", "undetectable"],
        "T9005": ["without_mitigation", "undetectable"],
        "T9006": ["mitigated_without_rules", "undetectable"],
    }


def test_techniques_for_actor__without_include_defenses__lists_no_gaps(defenses_kb):
    result = tools.techniques_for_actor(app_module.KnowledgeBase(defenses_kb), "APT29")
    assert all("gaps" not in t for t in result["techniques"])


def test_check_list__padded_and_repeated_names__are_stripped_and_deduplicated_in_order():
    assert tools._check_list("log_sources", [" auditd:SYSCALL ", "WinEventLog:Security", "auditd:SYSCALL"]) == (
        "auditd:SYSCALL",
        "WinEventLog:Security",
    )


def test_defenses_for_technique__a_source_stored_with_trailing_whitespace__is_accepted_and_satisfies(kb_path):
    # The fixture stores AN0002's second source as "auditd:EXECVE " with a trailing space.
    result = tools.defenses_for_technique(
        app_module.KnowledgeBase(kb_path), "T1078", log_sources=["auditd:SYSCALL", "auditd:EXECVE"]
    )
    assert {a["id"]: a["detectable"] for a in result["detect"]["analytics"]} == {"AN0001": False, "AN0002": True}
