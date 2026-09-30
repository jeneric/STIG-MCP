import json
import logging
from pathlib import Path

import pytest

from stig_mcp.ingest.attack_parser import parse_attack

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
