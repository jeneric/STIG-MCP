import logging
from pathlib import Path

import pytest

from stig_mcp.ingest.cci_parser import cci_list_version, parse_cci_list

FIXTURE = Path(__file__).parent.parent / "fixtures" / "cci_list.xml"
FIX = Path(__file__).parent.parent / "fixtures"


def test_parse_cci_list__cci_list__maps_cci_to_rev5_control():
    records = {r.cci_id: r for r in parse_cci_list(FIXTURE)}
    assert records["CCI-000015"].controls == ["AC-2(1)"]  # Rev4 ref ignored
    assert "CM-6" not in records["CCI-000015"].controls  # Rev4-only control must be excluded
    assert records["CCI-000048"].controls == ["AC-8"]
    assert "automated mechanisms" in records["CCI-000015"].definition


def test_parse_cci_list__file_without_cci_items__raises_naming_the_expected_source(tmp_path):
    # A wrong XML must name the expected file rather than fail with a TypeError from an
    # iteration over None, which tells the operator nothing about which file to replace.
    path = tmp_path / "wrong.xml"
    path.write_text("<some_other_root><thing/></some_other_root>")
    with pytest.raises(ValueError) as excinfo:
        parse_cci_list(path)
    message = str(excinfo.value)
    assert "cci_items" in message
    assert "U_CCI_List.xml" in message
    assert str(path) in message


def test_parse_cci_list__cci_item_without_id__skips_it_and_warns(tmp_path, caplog):
    # A NULL cci_id would become a NULL primary key, so the record is unusable.
    path = tmp_path / "partial.xml"
    path.write_text(
        "<cci_list><cci_items>"
        '<cci_item id="CCI-000015"><definition>real</definition></cci_item>'
        "<cci_item><definition>no id</definition></cci_item>"
        "</cci_items></cci_list>"
    )
    with caplog.at_level(logging.WARNING):
        records = parse_cci_list(path)
    assert [r.cci_id for r in records] == ["CCI-000015"]
    assert any("no @id" in rec.message for rec in caplog.records)


def test_parse_cci_list__not_a_cci_document__points_at_the_document_that_holds_the_section(tmp_path):
    # The section 'Build the knowledge base' is in docs/operations.md; README.md has no such
    # heading. orchestrator._require carries the same pointer in a separate string in another
    # module, so each has its own pin.
    not_cci = tmp_path / "wrong.xml"
    not_cci.write_text('<?xml version="1.0"?><something_else/>')
    with pytest.raises(ValueError) as excinfo:
        parse_cci_list(not_cci)
    message = str(excinfo.value)
    assert "docs/operations.md" in message
    assert "README.md" not in message


def test_cci_list_version__metadata_version_present__returns_it(tmp_path):
    path = tmp_path / "cci.xml"
    path.write_text(
        '<cci_list xmlns="http://iase.disa.mil/cci"><metadata><version>2025-01-23</version>'
        "<publishdate>2025-01-23</publishdate></metadata><cci_items/></cci_list>"
    )
    assert cci_list_version(path) == "2025-01-23"


def test_cci_list_version__repo_fixture_without_metadata__returns_none():
    assert cci_list_version(FIX / "cci_list.xml") is None
