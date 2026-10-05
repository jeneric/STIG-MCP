import asyncio
import json
import sqlite3
from contextlib import closing

import pytest

from stig_mcp.ingest.orchestrator import IngestSources, build_kb
from stig_mcp.kb import queries
from stig_mcp.kb.db import create_db
from stig_mcp.server import app as app_module
from stig_mcp.server import tools
from tests.conftest import FIX, discovered, open_db_for_test

_LIST_FINDING_KEYS = {"stig_id", "stig_version", "rule_id", "group_id", "severity", "title", "ccis"}


@pytest.fixture(autouse=True)
def _close_the_connections_the_holder_opens(monkeypatch):
    monkeypatch.setattr(app_module, "open_db", open_db_for_test)


@pytest.fixture
def mixed_kb(tmp_path):
    """RHEL 9 (one CAT I rule under AC-2(1)) and a benchmark with one rule at each CAT."""
    out = tmp_path / "mixed.sqlite"
    build_kb(
        IngestSources(
            benchmarks=[discovered(FIX / "rhel9_xccdf.xml"), discovered(FIX / "mixed_severity_xccdf.xml")],
            cci_path=FIX / "cci_list.xml",
            attack_path=FIX / "attack_bundle.json",
            ctid_path=FIX / "ctid_mappings.csv",
            overrides_path=FIX / "overrides.yaml",
            catalog_path=FIX / "oscal_catalog.json",
        ),
        out,
    )
    return app_module.KnowledgeBase(out)


def _with_second_technique(kb):
    """APT29 also uses T1078.001, which maps to AC-2(1) through an override, so its findings
    overlap T1078's."""
    with closing(sqlite3.connect(kb.path)) as conn:
        conn.execute(
            "INSERT INTO technique_control (technique_id, control_id, source, suppressed) "
            "VALUES ('T1078.001', 'AC-2(1)', 'override', 0)"
        )
        conn.execute("INSERT INTO actor_technique (actor_id, technique_id) VALUES ('G0016', 'T1078.001')")
        conn.commit()
    return kb


@pytest.fixture
def two_benchmark_rules_db(tmp_path):
    """One V- id carried by two benchmarks, as a renamed product's STIG carries it."""
    with closing(create_db(tmp_path / "two.sqlite")) as conn:
        for stig_id, release in (("OLD_NAME_STIG", "V3R1"), ("NEW_NAME_STIG", "V1R1")):
            conn.execute(
                "INSERT INTO stigs (stig_id, version, title, release_label, origin, source_artifact) "
                "VALUES (?, '1', ?, ?, 'library', 'test fixture')",
                (stig_id, f"{stig_id} title", release),
            )
        for rule_id, stig_id in (("SV-251008r1_rule", "OLD_NAME_STIG"), ("SV-251008r2_rule", "NEW_NAME_STIG")):
            conn.execute(
                "INSERT INTO stig_rules (rule_id, group_id, stig_id, stig_version, severity_cat, severity_level, "
                "title, fix_text, check_text) VALUES (?, 'V-251008', ?, '1', 'II', 'medium', 'shared', 'fix', 'check')",
                (rule_id, stig_id),
            )
        conn.commit()
        yield conn


# queries


def test_findings_for_control__any_finding__carries_no_text_or_benchmark_details(kb_conn):
    findings = queries.findings_for_control(kb_conn, "AC-2", [("TEST_STIG", "1")])
    assert findings
    # via is the row's internal record of the enhancements a rule came through; the answer
    # strips it from findings, as the next test pins.
    assert all(set(f) == _LIST_FINDING_KEYS | {"via"} for f in findings)


def test_findings_for_control__severity_filter__keeps_only_those_cats(mixed_kb):
    conn = open_db_for_test(mixed_kb.path)
    scope = [("MIXED_SEVERITY_STIG", "1")]
    assert [f["severity"]["cat"] for f in queries.findings_for_control(conn, "AC-2(1)", scope, ("I", "III"))] == [
        "I",
        "III",
    ]


def test_finding_details__rule_id__returns_the_text_and_benchmark_details(kb_conn):
    (listed, *_) = queries.findings_for_control(kb_conn, "AC-2", [("TEST_STIG", "1")])
    (detail,) = queries.finding_details(kb_conn, [listed["rule_id"]])
    assert detail["check_text"] and detail["fix_text"]
    assert (detail["stig_release"], detail["origin"]) == ("V1R1", "library")
    assert detail["rule_id"] == listed["rule_id"]


def test_finding_details__v_id_carried_by_two_benchmarks__returns_each_labeled(two_benchmark_rules_db):
    details = queries.finding_details(two_benchmark_rules_db, ["V-251008"])
    assert [(d["stig_id"], d["stig_release"]) for d in details] == [
        ("NEW_NAME_STIG", "V1R1"),
        ("OLD_NAME_STIG", "V3R1"),
    ]


def test_finding_details__lower_case_and_padded_ids__still_match(two_benchmark_rules_db):
    details = queries.finding_details(two_benchmark_rules_db, ["  sv-251008r1_rule "])
    assert [d["rule_id"] for d in details] == ["SV-251008r1_rule"]


# mitigations_for_technique


def test_mitigations_for_technique__any_answer__lists_each_finding_once_and_controls_by_rule_id(mixed_kb):
    result = tools.mitigations_for_technique(mixed_kb, "T1078", stig_ids=["RHEL_9_STIG", "MIXED_SEVERITY_STIG"])
    ac2_1 = next(c for c in result["controls"] if c["control_id"] == "AC-2(1)")
    assert "stig_findings" not in ac2_1
    assert set(ac2_1["rules"]) == set(result["findings"])
    assert all(set(f) == _LIST_FINDING_KEYS for f in result["findings"].values())
    assert all(key == f["rule_id"] for key, f in result["findings"].items())


def test_mitigations_for_technique__summary__comes_first_and_counts_by_cat(mixed_kb):
    result = tools.mitigations_for_technique(mixed_kb, "T1078", stig_ids=["RHEL_9_STIG", "MIXED_SEVERITY_STIG"])
    assert next(iter(result)) == "summary"
    assert list(result["summary"]) == ["findings", "by_cat", "control_counts", "cat_i", "controls_with_rules"]
    assert result["summary"] == {
        "findings": 4,
        "by_cat": {"I": 2, "II": 1, "III": 1},
        "control_counts": {"mapped": 3, "with_rules": 2},
        "cat_i": {"count": 2, "ids": ["V-770002", "V-100001"]},
        "controls_with_rules": ["AC-2", "AC-2(1)"],
    }


def test_mitigations_for_technique__severity_i__returns_only_cat_i_and_says_what_was_filtered(mixed_kb):
    result = tools.mitigations_for_technique(mixed_kb, "T1078", stig_ids=["MIXED_SEVERITY_STIG"], severity=["I"])
    assert [f["group_id"] for f in result["findings"].values()] == ["V-770002"]
    assert (
        "Control AC-6 has no CAT I rules, at the control or any of its enhancements, in the resolved STIG(s)."
        in result["notes"]
    )


@pytest.mark.parametrize("severity", [[], ["IV"], ["high"], ["i"]])
def test_mitigations_for_technique__severity_not_a_cat_list__refuses_and_names_the_values(kb_path, severity):
    with pytest.raises(tools.CallerError, match=r"severity must list CAT values drawn from 'I', 'II' and 'III'"):
        tools.mitigations_for_technique(app_module.KnowledgeBase(kb_path), "T1078", severity=severity)


# techniques_for_actor


def test_techniques_for_actor__overlapping_techniques__list_a_shared_finding_once(mixed_kb):
    kb = _with_second_technique(mixed_kb)
    result = tools.techniques_for_actor(kb, "APT29", stig_ids=["RHEL_9_STIG"], include_mitigations=True)
    assert list(result["findings"]) == ["SV-100001r1_rule"]
    assert result["controls"]["AC-2(1)"]["rules"] == ["SV-100001r1_rule"]
    by_technique = {t["technique_id"]: t["controls"] for t in result["techniques"]}
    assert by_technique["T1078.001"] == {"override": ["AC-2(1)"]}
    assert "AC-2(1)" in by_technique["T1078"]["ctid"]
    assert all("mitigations" not in t for t in result["techniques"])


def test_mitigations_for_technique__rule_tagged_to_an_enhancement__counts_for_the_base_with_via(mixed_kb):
    # The fixture's RHEL 9 rule cites CCI-000015, which DISA maps to AC-2(1) only; CTID maps
    # T1078 to AC-2.
    result = tools.mitigations_for_technique(mixed_kb, "T1078", stig_ids=["RHEL_9_STIG"])
    by_id = {c["control_id"]: c for c in result["controls"]}
    assert by_id["AC-2"]["rules"] == ["SV-100001r1_rule"]
    assert by_id["AC-2"]["via"] == {"AC-2(1)": ["SV-100001r1_rule"]}
    assert "via" not in by_id["AC-2(1)"]
    assert list(result["findings"]) == ["SV-100001r1_rule"]
    assert all(set(f) == _LIST_FINDING_KEYS for f in result["findings"].values())


def test_techniques_for_actor__rule_tagged_to_an_enhancement__control_carries_via(mixed_kb):
    kb = _with_second_technique(mixed_kb)
    result = tools.techniques_for_actor(kb, "APT29", stig_ids=["RHEL_9_STIG"], include_mitigations=True)
    assert result["controls"]["AC-2"]["via"] == {"AC-2(1)": ["SV-100001r1_rule"]}
    assert "via" not in result["controls"]["AC-2(1)"]
    assert list(result["findings"]) == ["SV-100001r1_rule"]


@pytest.fixture
def rows_with_via(monkeypatch):
    """AC-2 rows reaching it through AC-2(10) and AC-2(3), with AC-2(10) met first, so both
    insertion order and a string sort put (10) first; plus a base-level rule that must stay
    out of via."""
    rows = [
        {**_finding("SV-1r1_rule", "I"), "via": []},
        {**_finding("SV-2r1_rule", "I"), "via": ["AC-2(10)"]},
        {**_finding("SV-3r1_rule", "II"), "via": ["AC-2(3)", "AC-2(10)"]},
    ]
    monkeypatch.setattr(queries, "findings_for_control", lambda conn, cid, *rest: rows if cid == "AC-2" else [])
    return rows


def test_mitigations_for_technique__via_keys__ordered_by_enhancement_number(kb_path, rows_with_via):
    result = tools.mitigations_for_technique(app_module.KnowledgeBase(kb_path), "T1078", stig_ids=["RHEL_9_STIG"])
    ac2 = next(c for c in result["controls"] if c["control_id"] == "AC-2")
    assert list(ac2["via"]) == ["AC-2(3)", "AC-2(10)"]
    assert ac2["via"] == {"AC-2(3)": ["SV-3r1_rule"], "AC-2(10)": ["SV-2r1_rule", "SV-3r1_rule"]}


def test_techniques_for_actor__rows_shared_across_techniques__are_not_mutated(kb_path, rows_with_via):
    # _ControlFindings hands the same row dicts to every technique mapping a control; stripping
    # via in place would empty it for the next one.
    tools.techniques_for_actor(
        app_module.KnowledgeBase(kb_path), "APT29", stig_ids=["RHEL_9_STIG"], include_mitigations=True
    )
    assert [row["via"] for row in rows_with_via] == [[], ["AC-2(10)"], ["AC-2(3)", "AC-2(10)"]]


def test_techniques_for_actor__include_mitigations__summary_comes_first(mixed_kb):
    result = tools.techniques_for_actor(mixed_kb, "APT29", stig_ids=["MIXED_SEVERITY_STIG"], include_mitigations=True)
    assert next(iter(result)) == "summary"
    assert result["summary"]["by_cat"] == {"I": 1, "II": 1, "III": 1}


def test_techniques_for_actor__scope_notes__appear_once_on_the_answer_not_per_technique(mixed_kb):
    kb = _with_second_technique(mixed_kb)
    result = tools.techniques_for_actor(kb, "APT29", stig_ids=["NO_SUCH_STIG"], include_mitigations=True)
    unknown = [n for n in result["notes"] if "NO_SUCH_STIG" in n]
    assert len(unknown) == 1
    assert not any("NO_SUCH_STIG" in n for t in result["techniques"] for n in t["notes"])


def test_techniques_for_actor__each_control__is_queried_once_however_many_techniques_share_it(mixed_kb, monkeypatch):
    kb = _with_second_technique(mixed_kb)
    asked = []
    real = queries.findings_for_control
    monkeypatch.setattr(
        queries, "findings_for_control", lambda conn, cid, *rest: asked.append(cid) or real(conn, cid, *rest)
    )
    tools.techniques_for_actor(kb, "APT29", stig_ids=["RHEL_9_STIG"], include_mitigations=True)
    assert sorted(asked) == sorted(set(asked))
    assert "AC-2(1)" in asked


def test_techniques_for_actor__controls_without_rules__are_named_in_one_note(mixed_kb):
    kb = _with_second_technique(mixed_kb)
    result = tools.techniques_for_actor(kb, "APT29", stig_ids=["RHEL_9_STIG"], include_mitigations=True)
    assert (
        "Control AC-6 has no rules, at the control or any of its enhancements, in the resolved STIG(s)."
        in result["notes"]
    )
    assert not any("has no" in n or "have no" in n for t in result["techniques"] for n in t["notes"])


def test_mitigations_for_technique__control_without_rules__keeps_its_own_note(mixed_kb):
    result = tools.mitigations_for_technique(mixed_kb, "T1078", stig_ids=["RHEL_9_STIG"])
    assert (
        "Control AC-6 has no rules, at the control or any of its enhancements, in the resolved STIG(s)."
        in result["notes"]
    )
    assert not any("AC-2 " in note for note in result["notes"])


def test_techniques_for_actor__severity_filter__applies_to_every_technique(mixed_kb):
    result = tools.techniques_for_actor(
        mixed_kb, "APT29", stig_ids=["MIXED_SEVERITY_STIG"], include_mitigations=True, severity=["III"]
    )
    assert [f["group_id"] for f in result["findings"].values()] == ["V-770003"]


def test_techniques_for_actor__without_mitigations__opens_with_the_technique_count(kb_path):
    result = tools.techniques_for_actor(app_module.KnowledgeBase(kb_path), "APT29")
    assert list(result) == ["summary", "actor", "techniques", "sources"]
    assert result["summary"] == {"techniques": len(result["techniques"])}
    assert result["summary"]["techniques"] == 1


def test_techniques_for_actor__include_mitigations__counts_techniques_and_distinct_controls(mixed_kb):
    kb = _with_second_technique(mixed_kb)
    result = tools.techniques_for_actor(kb, "APT29", stig_ids=["RHEL_9_STIG"], include_mitigations=True)
    summary = result["summary"]
    assert list(summary)[:2] == ["techniques", "findings"]
    assert summary["techniques"] == 2
    assert summary["control_counts"] == {"mapped": len(result["controls"]), "with_rules": 2}
    assert summary["control_counts"]["mapped"] == 3
    assert summary["controls_with_rules"] == ["AC-2", "AC-2(1)"]


# finding_details


def test_finding_details__known_and_unknown_ids__returns_the_known_and_names_the_rest(kb_path):
    listed = tools.mitigations_for_technique(app_module.KnowledgeBase(kb_path), "T1078", stig_ids=["RHEL_9_STIG"])
    rule_id = next(iter(listed["findings"]))
    result = tools.finding_details(app_module.KnowledgeBase(kb_path), [rule_id, "V-999999"])
    assert [f["rule_id"] for f in result["findings"]] == [rule_id]
    assert result["findings"][0]["fix_text"]
    assert result["not_found"] == ["V-999999"]
    assert result["sources"]["kb_sha256"]


def test_finding_details__nothing_matches__refuses_and_says_where_ids_come_from(kb_path):
    with pytest.raises(tools.CallerError, match="No finding in this knowledge base has the id 'V-999999'"):
        tools.finding_details(app_module.KnowledgeBase(kb_path), ["V-999999"])


@pytest.mark.parametrize(
    ("ids", "message"),
    [
        ([], "ids must name at least one finding"),
        ([f"V-{n}" for n in range(51)], "ids names 51 findings, over the limit of 50"),
    ],
)
def test_finding_details__empty_or_over_the_cap__refuses(kb_path, ids, message):
    with pytest.raises(tools.CallerError, match=message):
        tools.finding_details(app_module.KnowledgeBase(kb_path), ids)


def test_finding_details__no_knowledge_base__returns_not_ready(tmp_path):
    result = tools.finding_details(app_module.KnowledgeBase(tmp_path / "absent.sqlite"), ["V-1"])
    assert result["status"] == "not_ready"


# over MCP


def test_build_server__finding_details_tool__is_registered_and_answers(kb_path):
    server = app_module.build_server(kb_path)
    listed = server.call_tool("mitigations_for_technique", {"technique_id": "T1078", "stig_ids": ["RHEL_9_STIG"]})
    payload = json.loads(asyncio.run(listed).content[0].text)
    assert next(iter(payload)) == "summary"
    rule_id = next(iter(payload["findings"]))
    detail = json.loads(asyncio.run(server.call_tool("finding_details", {"ids": [rule_id]})).content[0].text)
    assert detail["findings"][0]["check_text"]


# ordering, summary and edge cases


def _finding(rule_id, cat, stig_id="A_STIG", group_id=None):
    return {
        "stig_id": stig_id,
        "stig_version": "1",
        "rule_id": rule_id,
        "group_id": group_id,
        "severity": {"cat": cat, "level": "x"},
        "title": rule_id,
        "ccis": [],
        "via": [],
    }


@pytest.fixture
def cat_ii_before_cat_i(monkeypatch):
    """The first control mapped to T1078 holds only a CAT II finding and a later one only a
    CAT I, so the findings arrive in the wrong order unless the answer re-sorts them. The CAT I
    rule also has the higher rule id, so rule-id order cannot pass for CAT order."""
    by_control = {"AC-2": [_finding("SV-2r1_rule", "II", group_id="V-2")]}

    def rows(conn, control_id, scope, severities=None):
        return by_control.get(control_id, [_finding("SV-9r1_rule", "I", group_id="V-9")])

    monkeypatch.setattr(queries, "findings_for_control", rows)


@pytest.mark.usefixtures("cat_ii_before_cat_i")
def test_mitigations_for_technique__findings_arriving_cat_ii_first__are_listed_cat_i_first(kb_path):
    result = tools.mitigations_for_technique(app_module.KnowledgeBase(kb_path), "T1078", stig_ids=["RHEL_9_STIG"])
    assert list(result["findings"]) == ["SV-9r1_rule", "SV-2r1_rule"]


@pytest.mark.usefixtures("cat_ii_before_cat_i")
def test_techniques_for_actor__findings_arriving_cat_ii_first__are_listed_cat_i_first(kb_path):
    result = tools.techniques_for_actor(
        app_module.KnowledgeBase(kb_path), "APT29", stig_ids=["RHEL_9_STIG"], include_mitigations=True
    )
    assert list(result["findings"]) == ["SV-9r1_rule", "SV-2r1_rule"]


def test_cat_ordered__an_unknown_cat__ranks_with_iii_as_the_sql_order_does():
    findings = {"B": _finding("B", "III", stig_id="B_STIG"), "A": _finding("A", "?", stig_id="A_STIG")}
    assert list(tools._cat_ordered(findings)) == ["A", "B"]


def test_summary__v_id_shared_by_two_rules_and_a_missing_v_id__lists_each_once_falling_back_to_the_rule():
    findings = {
        "SV-1r1_rule": _finding("SV-1r1_rule", "I", stig_id="A_STIG", group_id="V-1"),
        "SV-1r2_rule": _finding("SV-1r2_rule", "I", stig_id="B_STIG", group_id="V-1"),
        "SV-9r1_rule": _finding("SV-9r1_rule", "I"),
    }
    rules_by_control = {"AC-1": [], "AC-2": ["SV-1r1_rule"], "AC-3": ["SV-1r2_rule", "SV-9r1_rule"]}
    assert tools._summary(findings, rules_by_control) == {
        "findings": 3,
        "by_cat": {"I": 3},
        "control_counts": {"mapped": 3, "with_rules": 2},
        "cat_i": {"count": 2, "ids": ["V-1", "SV-9r1_rule"]},
        "controls_with_rules": ["AC-2", "AC-3"],
    }


def test_techniques_for_actor__no_scope__carries_no_note_about_controls_without_rules(kb_path):
    result = tools.techniques_for_actor(app_module.KnowledgeBase(kb_path), "APT29", include_mitigations=True)
    assert not any("have no" in n or "has no" in n for n in result["notes"])


def test_mitigations_for_technique__severity_as_a_bare_string__refuses_rather_than_reading_characters(kb_path):
    with pytest.raises(tools.CallerError, match="severity must list CAT values"):
        tools.mitigations_for_technique(app_module.KnowledgeBase(kb_path), "T1078", severity="II")


def test_finding_details__lower_case_padded_v_id__matches_and_is_not_reported_missing(kb_path):
    result = tools.finding_details(app_module.KnowledgeBase(kb_path), [" v-100001 ", "V-999999"])
    assert [f["group_id"] for f in result["findings"]] == ["V-100001"]
    assert result["not_found"] == ["V-999999"]


def test_finding_details__lower_case_v_id__matches_in_the_query(two_benchmark_rules_db):
    assert len(queries.finding_details(two_benchmark_rules_db, ["v-251008"])) == 2


@pytest.mark.parametrize(
    ("name", "arguments", "first_key"),
    [
        ("mitigations_for_technique", {"technique_id": "T1078", "stig_ids": ["RHEL_9_STIG"]}, "summary"),
        (
            "techniques_for_actor",
            {"actor": "APT29", "stig_ids": ["RHEL_9_STIG"], "include_mitigations": True},
            "summary",
        ),
        ("finding_details", {"ids": ["V-100001"]}, "findings"),
    ],
)
def test_build_server__answer_tools__return_one_line_of_json(kb_path, name, arguments, first_key):
    result = asyncio.run(app_module.build_server(kb_path).call_tool(name, arguments))
    (block,) = result.content
    assert "\n" not in block.text
    assert block.text.startswith(f'{{"{first_key}":')


def test_finding_details__a_blank_id__is_reported_missing_even_beside_a_rule_with_no_v_id(kb_path, monkeypatch):
    row = {**_finding("SV-1r1_rule", "I"), "check_text": "c", "fix_text": "f"}
    monkeypatch.setattr(queries, "finding_details", lambda conn, ids: [row])
    result = tools.finding_details(app_module.KnowledgeBase(kb_path), ["SV-1r1_rule", " "])
    assert result["not_found"] == [" "]


def test_build_server__finding_details_description__asks_to_quote_disa_and_label_additions(kb_path):
    listed = asyncio.run(app_module.build_server(kb_path).list_tools())
    description = next(t.description for t in listed if t.name == "finding_details")
    assert "Quote check_text and fix_text as DISA wrote them" in description
    assert "label anything you add" in description
