import pytest

from stig_mcp.ingest import id_corrections

DATABASE_DOC = "U_MS_SQL_Server_2012_Database_V1R18_Manual_STIG/U_SQL_Server_2012_Database_STIG_V1R18_Manual-xccdf.xml"
INSTANCE_DOC = "U_MS_SQL_Server_2012_Instance_V1R18_Manual_STIG/U_MS_SQL_Server_2012_STIG_V1R18_Manual-xccdf.xml"
PUBLISHED = "MS_SQL_Server_2012_Database_Instance_STIG"


def test_load_corrections__the_shipped_file__names_both_halves_of_the_ms_sql_2012_split():
    corrections = id_corrections.load_corrections()

    entry = corrections[PUBLISHED]
    assert {document.stig_id for document in entry.documents} == {
        "MS_SQL_Server_2012_Database_STIG",
        "MS_SQL_Server_2012_Instance_STIG",
    }
    # The map is a claim about a DISA document, so it must say which one.
    assert "Overview" in entry.source
    assert entry.verified_against


def test_correction_for__the_database_document__names_the_database_benchmark():
    corrections = id_corrections.load_corrections()

    correction = id_corrections.correction_for(PUBLISHED, DATABASE_DOC, corrections)

    assert correction.stig_id == "MS_SQL_Server_2012_Database_STIG"
    assert "Database" in correction.title
    assert "Instance" not in correction.title


def test_correction_for__the_instance_document__names_the_instance_benchmark():
    corrections = id_corrections.load_corrections()

    correction = id_corrections.correction_for(PUBLISHED, INSTANCE_DOC, corrections)

    assert correction.stig_id == "MS_SQL_Server_2012_Instance_STIG"


def test_correction_for__an_id_the_map_does_not_cover__returns_None():
    corrections = id_corrections.load_corrections()

    assert id_corrections.correction_for("RHEL_9_STIG", "anything.xml", corrections) is None


def test_correction_for__a_document_no_match_fragment_hits__returns_None():
    # Declining is the whole safety property: an unmatched document keeps its published id
    # rather than being renamed to a guess.
    corrections = id_corrections.load_corrections()

    assert id_corrections.correction_for(PUBLISHED, "U_Something_Else/x-xccdf.xml", corrections) is None


def test_correction_for__no_source_document_at_all__returns_None():
    corrections = id_corrections.load_corrections()

    assert id_corrections.correction_for(PUBLISHED, None, corrections) is None


def test_correction_for__two_fragments_both_matching_one_document__returns_None(tmp_path):
    # The realistic curation mistake: one fragment is a substring of another, e.g. '_STIG/'
    # alongside '_Database_V1R18_Manual_STIG/'. _unique only rejects two documents sharing an
    # identical match string, so an overlap like this is caught only by this guard.
    path = _write(
        tmp_path,
        "Some_STIG:\n  documents:\n"
        "    - match: '_STIG/'\n      stig_id: A_STIG\n      title: A\n"
        "    - match: '_Database_V1R18_Manual_STIG/'\n      stig_id: B_STIG\n      title: B\n",
    )
    corrections = id_corrections.load_corrections(path)

    correction = id_corrections.correction_for("Some_STIG", DATABASE_DOC, corrections)

    assert correction is None


def _write(tmp_path, body):
    path = tmp_path / "id_corrections.yaml"
    path.write_text(body)
    return path


def test_load_corrections__an_entry_with_one_document__raises_naming_the_entry(tmp_path):
    path = _write(
        tmp_path,
        "Some_STIG:\n  documents:\n    - match: 'a/'\n      stig_id: A_STIG\n      title: A\n",
    )

    with pytest.raises(ValueError, match="Some_STIG.*at least two"):
        id_corrections.load_corrections(path)


def test_load_corrections__two_documents_sharing_a_match__raises(tmp_path):
    path = _write(
        tmp_path,
        "Some_STIG:\n  documents:\n"
        "    - match: 'a/'\n      stig_id: A_STIG\n      title: A\n"
        "    - match: 'a/'\n      stig_id: B_STIG\n      title: B\n",
    )

    with pytest.raises(ValueError, match="match"):
        id_corrections.load_corrections(path)


def test_load_corrections__two_documents_mapping_to_one_stig_id__raises(tmp_path):
    # Correcting both halves to one id would re-create the collision this file exists to fix,
    # and the second document would then be discarded.
    path = _write(
        tmp_path,
        "Some_STIG:\n  documents:\n"
        "    - match: 'a/'\n      stig_id: A_STIG\n      title: A\n"
        "    - match: 'b/'\n      stig_id: A_STIG\n      title: B\n",
    )

    with pytest.raises(ValueError, match="stig_id"):
        id_corrections.load_corrections(path)


def test_load_corrections__a_document_missing_its_title__raises_naming_the_key(tmp_path):
    path = _write(
        tmp_path,
        "Some_STIG:\n  documents:\n"
        "    - match: 'a/'\n      stig_id: A_STIG\n"
        "    - match: 'b/'\n      stig_id: B_STIG\n      title: B\n",
    )

    with pytest.raises(ValueError, match="title"):
        id_corrections.load_corrections(path)


def test_load_corrections__a_document_row_that_is_not_a_mapping__raises(tmp_path):
    path = _write(tmp_path, "Some_STIG:\n  documents:\n    - just a string\n    - another\n")

    with pytest.raises(ValueError, match="Some_STIG.*not a mapping"):
        id_corrections.load_corrections(path)


def test_load_corrections__an_empty_file__returns_an_empty_map(tmp_path):
    assert dict(id_corrections.load_corrections(_write(tmp_path, ""))) == {}


def test_load_corrections__the_returned_map__cannot_be_written_to():
    # The map is cached, so a caller that mutated it would rewrite every later call's answer.
    corrections = id_corrections.load_corrections()

    with pytest.raises(TypeError):
        corrections["RHEL_9_STIG"] = None
