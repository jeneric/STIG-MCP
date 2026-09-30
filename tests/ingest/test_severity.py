import pytest

from stig_mcp.ingest.severity import is_known_level, severity_cat


@pytest.mark.parametrize(
    "level,expected",
    [
        ("high", "I"),
        ("medium", "II"),
        # `low` maps to III, which is also UNKNOWN_CAT, so no row here can detect its dict entry
        # being deleted. test_is_known_level__the_three_xccdf_levels... covers that by passing
        # " low ". These rows still catch a changed value such as "low": "II".
        ("low", "III"),
        ("unknown", "III"),
        ("", "III"),
        # The three normalizations severity_cat performs, each pinned by its own rows: .lower() by
        # the uppercase rows, .strip() by the padded ones, and `or ""` by None, which would
        # otherwise raise AttributeError rather than rank last.
        ("HIGH", "I"),
        ("Medium", "II"),
        (" medium ", "II"),  # not " low ", for the reason in the comment above
        ("\thigh\n", "I"),
        (None, "III"),
    ],
)
def test_severity_cat__each_level__maps_to_expected_cat(level, expected):
    assert severity_cat(level) == expected


def test_is_known_level__the_three_xccdf_levels_disa_ships__returns_true():
    assert all(is_known_level(level) for level in ("high", "MEDIUM", " low "))


def test_is_known_level__unrecognized_or_missing_level__returns_false():
    # XCCDF also permits "unknown" and "info"; DISA's benchmarks use none of them.
    assert not any(is_known_level(level) for level in ("critical", "unknown", "info", "", None))


def test_severity_cat__unrecognized_level__still_ranks_it_last_rather_than_dropping_it():
    assert severity_cat("critical") == "III"
