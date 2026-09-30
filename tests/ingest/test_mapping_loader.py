import json
from pathlib import Path

from stig_mcp.ingest.mapping_loader import load_ctid_mappings, load_overrides

FIX = Path(__file__).parent.parent / "fixtures"


def test_load_ctid_mappings__csv__returns_ctid_pairs():
    pairs = load_ctid_mappings(FIX / "ctid_mappings.csv").pairs
    assert all(p.source == "ctid" and p.suppressed is False for p in pairs)
    assert {(p.technique_id, p.control_id) for p in pairs} == {
        ("T1078", "AC-2"),
        ("T1078", "AC-2(1)"),
        ("T1078", "AC-8"),
        ("T8001", "AC-3"),
        ("T8002", "AC-3"),
        ("T8001", "AC-7"),
        ("T9000", "AC-4"),
    }


def test_load_ctid_mappings__json__parses_mitigates_and_normalizes():
    pairs = load_ctid_mappings(FIX / "ctid_mappings.json").pairs
    got = {(p.technique_id, p.control_id) for p in pairs}
    assert got == {("T1078", "AC-2"), ("T1078", "CM-3")}  # zero-pad stripped, deduped
    assert all(p.source == "ctid" and p.suppressed is False for p in pairs)
    # non_mappable (T9999/AC-05) and non-"mitigates" (T1055/SI-04) rows are excluded
    assert ("T9999", "AC-5") not in got
    assert ("T1055", "SI-4") not in got


def test_load_ctid_mappings__json_missing_mapping_objects__returns_empty(tmp_path):
    path = tmp_path / "empty.json"
    path.write_text("{}")
    assert load_ctid_mappings(path).pairs == []


def test_load_overrides__override_tombstone__suppresses_ctid_pair():
    overrides = load_overrides(FIX / "overrides.yaml").pairs
    by_pair = {(o.technique_id, o.control_id): o for o in overrides}
    assert by_pair[("T1078", "AC-6")].suppressed is False
    assert by_pair[("T1078", "AC-8")].suppressed is True
    assert all(o.source == "override" for o in overrides)


def test_load_ctid_mappings__json_without_mapping_version__composes_version_from_metadata():
    # CTID publishes mapping_version empty, so the composed string is what actually
    # records which ATT&CK release the mapping set was authored against.
    mappings = load_ctid_mappings(FIX / "ctid_mappings.json")
    assert mappings.version == "attack-16.1/rev5@04/16/2025"


def test_load_ctid_mappings__json_with_mapping_version__prefers_it(tmp_path):
    path = tmp_path / "versioned.json"
    path.write_text('{"metadata": {"mapping_version": "1.4.0", "attack_version": "16.1"}, "mapping_objects": []}')
    assert load_ctid_mappings(path).version == "1.4.0"


def test_load_ctid_mappings__json_without_metadata__marks_the_missing_parts(tmp_path):
    path = tmp_path / "bare.json"
    path.write_text('{"mapping_objects": []}')
    assert load_ctid_mappings(path).version == "attack-?/?@?"


def test_load_ctid_mappings__csv__has_no_version():
    # A bare two-column CSV carries no provenance, and inventing one would be a lie.
    assert load_ctid_mappings(FIX / "ctid_mappings.csv").version == ""


def test_load_overrides__file_without_version_key__defaults_to_local():
    assert load_overrides(FIX / "overrides.yaml").version == "local"


def test_load_overrides__file_with_version_key__uses_it(tmp_path):
    path = tmp_path / "overrides.yaml"
    path.write_text("version: 2026-07-31\nadd:\n  - technique: T1078\n    control: AC-6\n")
    overrides = load_overrides(path)
    assert overrides.version == "2026-07-31"
    assert [(o.technique_id, o.control_id) for o in overrides.pairs] == [("T1078", "AC-6")]


def test_load_overrides__missing_file__returns_empty_set_marked_local(tmp_path):
    overrides = load_overrides(tmp_path / "absent.yaml")
    assert overrides.pairs == [] and overrides.version == "local"


def test_load_ctid_mappings__json_with_non_mappable_rows__records_them_apart_from_pairs(tmp_path):
    doc = {
        "metadata": {"attack_version": "16.1", "mapping_framework_version": "rev5", "last_update": "04/16/2025"},
        "mapping_objects": [
            {"attack_object_id": "T1001", "capability_id": "AC-2", "mapping_type": "mitigates", "status": "complete"},
            {"attack_object_id": "T1656", "capability_id": None, "mapping_type": None, "status": "non_mappable"},
        ],
    }
    path = tmp_path / "ctid.json"
    path.write_text(json.dumps(doc))
    mappings = load_ctid_mappings(path)
    assert mappings.attack_version == "16.1"
    assert mappings.non_mappable == frozenset({"T1656"})
    assert [p.technique_id for p in mappings.pairs] == ["T1001"]


def test_load_ctid_mappings__csv__has_no_attack_version_and_no_non_mappable():
    mappings = load_ctid_mappings(FIX / "ctid_mappings.csv")
    assert mappings.attack_version == ""
    assert mappings.non_mappable == frozenset()
