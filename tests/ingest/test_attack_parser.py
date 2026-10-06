import json
import logging
from pathlib import Path

import pytest

from stig_mcp.ingest.attack_parser import AttackDefensesMissing, parse_attack, require_defenses
from tests.conftest import defense_edges_to_an_intrusion_set

FIXTURE = Path(__file__).parent.parent / "fixtures" / "attack_bundle.json"


def test_parse_attack__bundle__extracts_techniques_and_tactics():
    data = parse_attack(FIXTURE)
    by_id = {t.technique_id: t for t in data.techniques}
    assert set(by_id) == {"T1078", "T1078.001", "T9000"}  # revoked skipped
    assert by_id["T1078"].tactics == ["defense-evasion", "persistence"]
    assert by_id["T1078.001"].is_subtechnique is True
    assert by_id["T1078.001"].parent_id == "T1078"


def test_parse_attack__intrusion_set__links_actor_to_techniques():
    data = parse_attack(FIXTURE)
    actor = next(a for a in data.actors if a.actor_id == "G0016")
    assert actor.name == "APT29"
    assert "Cozy Bear" in actor.aliases
    assert actor.technique_ids == ["T1078"]


def test_parse_attack__collection_version__is_captured():
    assert parse_attack(FIXTURE).version == "15.1"


def test_parse_attack__deprecated_intrusion_set__is_skipped():
    data = parse_attack(FIXTURE)
    actor_ids = {a.actor_id for a in data.actors}
    assert "G9999" not in actor_ids
    assert "G0016" in actor_ids


def test_parse_attack__revoked_technique__resolves_to_its_replacement():
    attack = parse_attack(FIXTURE)
    by_revoked = {r.revoked_id: r for r in attack.revocations}
    assert by_revoked["T8001"].replacement_id == "T9000"
    assert by_revoked["T8001"].revoked_name == "Old One Hop"


def test_parse_attack__chain_of_revocations__follows_to_the_live_technique():
    # T8002 was revoked by T8003, which was itself revoked by T9000. Stopping after one
    # hop would strand the mapping on T8003, which is not in the techniques table, and
    # the technique_control foreign key would then reject it.
    attack = parse_attack(FIXTURE)
    by_revoked = {r.revoked_id: r.replacement_id for r in attack.revocations}
    assert by_revoked["T8002"] == "T9000"
    assert by_revoked["T8003"] == "T9000"


def test_parse_attack__cycle_in_revocations__drops_the_entry_rather_than_looping():
    attack = parse_attack(FIXTURE)
    by_revoked = {r.revoked_id for r in attack.revocations}
    assert "T8004" not in by_revoked
    assert "T8005" not in by_revoked


def test_parse_attack__replacement_not_a_live_technique__drops_the_entry():
    # T8006 points at a deprecated technique, which parse_attack never keeps, so there
    # is nothing to remap onto.
    attack = parse_attack(FIXTURE)
    assert "T8006" not in {r.revoked_id for r in attack.revocations}


def test_parse_attack__revocations__are_sorted_and_exclude_live_techniques():
    # The fixture carries a revoked-by edge out of T1078, which the bundle still defines as
    # live. Honoring it would move T1078's mappings onto T9000 while T1078 kept answering
    # queries, with no redirect to explain the loss.
    attack = parse_attack(FIXTURE)
    revoked_ids = [r.revoked_id for r in attack.revocations]
    assert revoked_ids == sorted(revoked_ids)
    assert "T1078" not in revoked_ids


def test_parse_attack__revoked_by_edge_out_of_a_live_technique__warns_the_operator(caplog):
    # Dropping the edge is right, but silently dropping it is not: the bundle disagrees
    # with itself, and only the operator can decide whether the mappings need moving.
    with caplog.at_level(logging.WARNING):
        parse_attack(FIXTURE)
    assert any("defines as live" in rec.message for rec in caplog.records)


def test_parse_attack__revoked_techniques__still_absent_from_the_technique_list():
    # The revocation table is additive: revoked techniques must not start appearing as
    # techniques, or every query would begin returning ids ATT&CK retired.
    attack = parse_attack(FIXTURE)
    ids = {t.technique_id for t in attack.techniques}
    assert "T9000" in ids
    assert ids.isdisjoint({"T8001", "T8002", "T8003", "T8004", "T8005", "T8006", "T8007"})


def test_parse_attack__attack_pattern_with_created__records_the_date_part(tmp_path):
    bundle = {
        "objects": [
            {"type": "x-mitre-collection", "x_mitre_version": "19.1"},
            {
                "type": "attack-pattern",
                "id": "attack-pattern--1",
                "name": "Newer Thing",
                "created": "2025-04-15T12:00:00.000Z",
                "external_references": [{"source_name": "mitre-attack", "external_id": "T1999"}],
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--2",
                "name": "Undated Thing",
                "external_references": [{"source_name": "mitre-attack", "external_id": "T1998"}],
            },
        ]
    }
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps(bundle))
    created = {t.technique_id: t.created for t in parse_attack(path).techniques}
    assert created == {"T1999": "2025-04-15", "T1998": None}


@pytest.mark.parametrize(
    "created",
    [
        "not-a-date",
        "2025/01/14T00:00:00Z",
        "20250114T000000Z",
        "xxxxxxxxxx2025-01-14",
    ],
    ids=["prose", "slash-separated", "no-separators", "valid-date-buried-past-position-10"],
)
def test_parse_attack__attack_pattern_with_malformed_created__records_none(tmp_path, created):
    bundle = {
        "objects": [
            {"type": "x-mitre-collection", "x_mitre_version": "19.1"},
            {
                "type": "attack-pattern",
                "id": "attack-pattern--1",
                "name": "Malformed Thing",
                "created": created,
                "external_references": [{"source_name": "mitre-attack", "external_id": "T1997"}],
            },
        ]
    }
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps(bundle))
    technique = parse_attack(path).techniques[0]
    assert technique.created is None


def test_parse_attack__course_of_action__keeps_live_m_ids_and_skips_legacy_t_ids():
    data = parse_attack(FIXTURE)
    assert {m.mitigation_id: m.name for m in data.mitigations} == {
        "M1026": "Privileged Account Management",
        "M1027": "Password Policies",
    }


def test_parse_attack__mitigates_edges__carry_pair_text_and_follow_a_revoked_target_to_its_replacement():
    data = parse_attack(FIXTURE)
    assert len(data.technique_mitigations) == 3
    pairs = {(p.technique_id, p.mitigation_id): p.description for p in data.technique_mitigations}
    assert set(pairs) == {("T1078", "M1026"), ("T1078", "M1027"), ("T9000", "M1027")}
    assert pairs[("T1078", "M1026")].startswith("Audit domain and local accounts")
    assert pairs[("T9000", "M1027")] == "Reaches T9000 through the revocation."
    assert pairs[("T1078", "M1027")] == "Enforce strong password policies on valid accounts."
    assert "must not appear" not in pairs.values()
    assert "must not appear either" not in pairs.values()


def test_parse_attack__collection_spec_version__is_captured():
    assert parse_attack(FIXTURE).spec_version == "3.3.0"


def test_parse_attack__detection_strategies__attach_to_their_technique_through_detects_edges():
    data = parse_attack(FIXTURE)
    assert {s.detection_strategy_id: (s.technique_id, s.name) for s in data.detection_strategies} == {
        "DET0001": ("T1078", "Detect Valid Account Abuse"),
        "DET0002": ("T9000", "Detect Replacement Technique"),
    }


def test_parse_attack__analytics__keep_platforms_log_sources_and_mutable_elements():
    data = parse_attack(FIXTURE)
    by_id = {a.analytic_id: a for a in data.analytics}
    assert set(by_id) == {"AN0001", "AN0002", "AN0003"}  # AN0099 deprecated, --missing absent
    an0001 = by_id["AN0001"]
    assert an0001.detection_strategy_id == "DET0001"
    assert an0001.platforms == ["Windows"]
    assert [(s.name, s.channel, s.data_component_id) for s in an0001.log_sources] == [
        ("WinEventLog:Security", "EventCode=4624", "DC0001"),
        ("WinEventLog:Sysmon", "EventCode=1", "DC0002"),
    ]
    assert an0001.mutable_elements[0]["field"] == "TimeWindow"


def test_parse_attack__a_detects_edge_from_a_data_component__is_counted_and_ignored(caplog):
    with caplog.at_level(logging.DEBUG, logger="stig_mcp.ingest.attack_parser"):
        data = parse_attack(FIXTURE)
    assert [s.detection_strategy_id for s in data.detection_strategies if s.technique_id == "T1078"] == ["DET0001"]
    assert "1 detects relationship(s) from the pre-v18 data-component model" in caplog.text


def test_parse_attack__an_analytic_ref_that_is_deprecated_or_missing__is_skipped_with_a_warning(caplog):
    with caplog.at_level(logging.WARNING, logger="stig_mcp.ingest.attack_parser"):
        parse_attack(FIXTURE)
    assert "DET0001" in caplog.text
    assert "2 analytic reference(s)" in caplog.text


def test_parse_attack__data_components__are_kept_when_live():
    data = parse_attack(FIXTURE)
    assert {d.data_component_id: d.name for d in data.data_components} == {
        "DC0001": "Logon Session Creation",
        "DC0002": "Process Creation",
    }


def test_parse_attack__detects_edges_to_a_dead_technique_or_repeating_a_strategy__yield_one_strategy_each():
    data = parse_attack(FIXTURE)
    ids = [s.detection_strategy_id for s in data.detection_strategies]
    assert sorted(ids) == ["DET0001", "DET0002"]
    assert None not in {s.technique_id for s in data.detection_strategies}
    assert {s.detection_strategy_id: s.technique_id for s in data.detection_strategies}["DET0001"] == "T1078"
    analytic_ids = [a.analytic_id for a in data.analytics]
    assert sorted(analytic_ids) == ["AN0001", "AN0002", "AN0003"]


def test_parse_attack__a_log_source_with_null_channel_and_unknown_component__gets_empty_channel_and_no_component():
    data = parse_attack(FIXTURE)
    an0003 = next(a for a in data.analytics if a.analytic_id == "AN0003")
    assert [(s.name, s.channel, s.data_component_id) for s in an0003.log_sources] == [("auditd:SYSCALL", "", None)]


def _without(objects, otype):
    return {"objects": [o for o in objects if o.get("type") != otype]}


@pytest.mark.parametrize(
    ("dropped", "phrase"),
    [
        ("course-of-action", "0 live mitigations"),
        ("x-mitre-detection-strategy", "0 detection strategies attached"),
    ],
)
def test_require_defenses__a_bundle_missing_a_defensive_object_type__refuses_naming_the_count(
    tmp_path, dropped, phrase
):
    objects = json.loads(FIXTURE.read_text())["objects"]
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps(_without(objects, dropped)))
    with pytest.raises(AttackDefensesMissing) as excinfo:
        require_defenses(parse_attack(path), path)
    message = str(excinfo.value)
    assert phrase in message
    assert str(path) in message
    assert "attack.mitre.org/resources/updates/" in message


def test_require_defenses__strategies_present_but_no_detects_edge__refuses(tmp_path):
    objects = json.loads(FIXTURE.read_text())["objects"]
    kept = [o for o in objects if o.get("relationship_type") != "detects"]
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps({"objects": kept}))
    with pytest.raises(AttackDefensesMissing, match="0 detection strategies attached"):
        require_defenses(parse_attack(path), path)


def test_require_defenses__the_fixture__passes():
    require_defenses(parse_attack(FIXTURE), FIXTURE)


def test_require_defenses__a_spec_major_the_parser_does_not_know__warns_but_passes(tmp_path, caplog):
    objects = json.loads(FIXTURE.read_text())["objects"]
    for obj in objects:
        if obj["type"] == "x-mitre-collection":
            obj["x_mitre_attack_spec_version"] = "4.0.0"
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps({"objects": objects}))
    with caplog.at_level(logging.WARNING, logger="stig_mcp.ingest.attack_parser"):
        require_defenses(parse_attack(path), path)
    assert "spec version 4.0.0" in caplog.text


def test_parse_attack__a_log_source_name_and_channel_with_trailing_whitespace__are_stored_stripped():
    # ATT&CK 19.2 ships 'firmware:integrity ' (AN0916) and 'networkconfig ' (AN0876); a caller's
    # list is stripped, so an unstripped stored name could never be matched.
    an0002 = next(a for a in parse_attack(FIXTURE).analytics if a.analytic_id == "AN0002")
    assert [(s.name, s.channel) for s in an0002.log_sources] == [
        ("auditd:SYSCALL", "execve"),
        ("auditd:EXECVE", "execve"),
    ]


def _bundle_with_log_source_names(tmp_path, renames):
    """The fixture with analytics re-identified and their first log source renamed:
    renames maps a fixture analytic id to (new analytic id, new log source name)."""
    objects = json.loads(FIXTURE.read_text())["objects"]
    for obj in objects:
        refs = obj.get("external_references", [])
        if obj.get("type") == "x-mitre-analytic" and refs and refs[0]["external_id"] in renames:
            refs[0]["external_id"], obj["x_mitre_log_source_references"][0]["name"] = renames[refs[0]["external_id"]]
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps({"objects": objects}))
    return path


def _first_source_names(path):
    return {a.analytic_id: a.log_sources[0].name for a in parse_attack(path).analytics}


def test_parse_attack__the_two_misspelled_syslog_names_in_attack_19_2__are_stored_as_linux_syslog(tmp_path):
    path = _bundle_with_log_source_names(
        tmp_path, {"AN0001": ("AN0272", "linus:syslog"), "AN0002": ("AN0364", "linuxsyslog")}
    )
    names = _first_source_names(path)
    assert (names["AN0272"], names["AN0364"]) == ("linux:syslog", "linux:syslog")


def test_parse_attack__a_misspelling_on_an_analytic_the_correction_does_not_name__is_left_alone(tmp_path):
    path = _bundle_with_log_source_names(tmp_path, {"AN0001": ("AN0001", "linus:syslog")})
    assert _first_source_names(path)["AN0001"] == "linus:syslog"


def test_parse_attack__a_corrected_analytic_once_attack_fixes_the_name__keeps_every_name_as_attack_wrote_it(
    tmp_path,
):
    # The fixture's AN0002 has a second log source, which the correction must not touch either.
    path = _bundle_with_log_source_names(tmp_path, {"AN0002": ("AN0272", "linux:syslog")})
    an0272 = next(a for a in parse_attack(path).analytics if a.analytic_id == "AN0272")
    assert [s.name for s in an0272.log_sources] == ["linux:syslog", "auditd:EXECVE"]


def test_parse_attack__deprecated_or_non_m_course_of_action__is_skipped_and_counted_at_debug(caplog):
    with caplog.at_level(logging.DEBUG, logger="stig_mcp.ingest.attack_parser"):
        data = parse_attack(FIXTURE)
    assert {m.mitigation_id for m in data.mitigations} == {"M1026", "M1027"}
    assert "Skipped 2 course-of-action object(s)" in caplog.text


def _bundle_with_edges_to_an_intrusion_set(tmp_path):
    bundle = json.loads(FIXTURE.read_text())
    bundle["objects"] += defense_edges_to_an_intrusion_set()
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps(bundle))
    return path


def test_parse_attack__mitigates_and_detects_edges_targeting_an_intrusion_set__are_dropped(tmp_path):
    data = parse_attack(_bundle_with_edges_to_an_intrusion_set(tmp_path))
    assert "G0016" not in {p.technique_id for p in data.technique_mitigations}
    assert "DET0098" not in {s.detection_strategy_id for s in data.detection_strategies}
    assert "AN0098" not in {a.analytic_id for a in data.analytics}
