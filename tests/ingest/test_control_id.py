import pytest

from stig_mcp.ingest.control_id import normalize_control


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("AC-2 a", "AC-2"),
        ("AC-2", "AC-2"),
        ("AC-2 (1)", "AC-2(1)"),
        ("AC-2(1)(a)", "AC-2(1)"),
        ("ac-17 (2)", "AC-17(2)"),
        ("no control here", None),
        ("CCI-000185 AC-2 a", "AC-2"),
        ("CCI-000185", None),
        ("AC-02", "AC-2"),  # CTID zero-padded base -> match CCI-derived "AC-2"
        ("CM-03", "CM-3"),
        ("AC-02 (01)", "AC-2(1)"),  # zero-padded enhancement too
    ],
)
def test_normalize_control__various_inputs__canonical_id(raw, expected):
    assert normalize_control(raw) == expected
