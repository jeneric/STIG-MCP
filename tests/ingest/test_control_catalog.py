import json
from pathlib import Path

from stig_mcp.ingest.control_catalog import catalog_version, parse_control_catalog

FIXTURE = Path(__file__).parent.parent / "fixtures" / "oscal_catalog.json"
FIX = Path(__file__).parent.parent / "fixtures"


def test_parse_control_catalog__base_control__has_name_family_no_parent():
    by_id = {c.control_id: c for c in parse_control_catalog(FIXTURE)}
    ac2 = by_id["AC-2"]
    assert ac2.name == "Account Management"
    assert ac2.family == "Access Control"
    assert ac2.is_enhancement is False
    assert ac2.parent_control_id is None


def test_parse_control_catalog__enhancement__canonical_id_parent_and_flag():
    by_id = {c.control_id: c for c in parse_control_catalog(FIXTURE)}
    ac2_1 = by_id["AC-2(1)"]  # ac-2.1 -> AC-2(1), matching normalize_control's form
    assert ac2_1.name == "Automated System Account Management"
    assert ac2_1.family == "Access Control"
    assert ac2_1.is_enhancement is True
    assert ac2_1.parent_control_id == "AC-2"


def test_parse_control_catalog__covers_both_families():
    by_id = {c.control_id: c for c in parse_control_catalog(FIXTURE)}
    assert by_id["CM-6"].family == "Configuration Management"
    assert set(by_id) == {"AC-1", "AC-2", "AC-2(1)", "AC-6", "AC-8", "CM-6"}


def test_parse_control_catalog__unmappable_base_id__skips_base_and_its_enhancements(tmp_path):
    # An unmappable base id must skip the base AND its nested enhancements, so an
    # enhancement can never be emitted (or later inserted) without its parent, the
    # invariant that keeps the parent_control_id self-FK safe.
    path = tmp_path / "cat.json"
    path.write_text(
        json.dumps(
            {
                "catalog": {
                    "groups": [
                        {
                            "id": "ac",
                            "title": "Access Control",
                            "controls": [
                                {
                                    "id": "not-a-control",
                                    "title": "Bogus",
                                    "controls": [{"id": "not-a-control.1", "title": "Bogus enhancement"}],
                                },
                                {"id": "ac-2", "title": "Account Management"},
                            ],
                        },
                    ]
                }
            }
        )
    )
    assert {c.control_id for c in parse_control_catalog(path)} == {"AC-2"}


def test_catalog_version__metadata_version_present__returns_it(tmp_path):
    path = tmp_path / "cat.json"
    path.write_text(json.dumps({"catalog": {"metadata": {"version": "5.2.0"}, "groups": []}}))
    assert catalog_version(path) == "5.2.0"


def test_catalog_version__repo_fixture_without_metadata__returns_none():
    assert catalog_version(FIX / "oscal_catalog.json") is None
