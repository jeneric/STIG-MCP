import logging
from pathlib import Path

from stig_mcp.ingest.stig_parser import ParsedStig, document_kind, parse_stig, parse_stig_bytes

FIXTURE = Path(__file__).parent.parent / "fixtures" / "rhel9_xccdf.xml"


def test_parse_stig__valid_xccdf__returns_rules_with_ccis_and_fixtext():
    parsed = parse_stig(FIXTURE)
    assert parsed.stig_id == "RHEL_9_STIG"
    assert "Red Hat Enterprise Linux 9" in parsed.title
    rule = next(r for r in parsed.rules if r.rule_id == "SV-100001r1_rule")
    assert rule.group_id == "V-100001"
    assert rule.ccis == ["CCI-000015"]
    assert rule.fix_text == "Configure automated account management."
    assert "automated account management is enabled" in rule.check_text


def test_parse_stig__severity_high__maps_to_cat_i():
    parsed = parse_stig(FIXTURE)
    rule = next(r for r in parsed.rules if r.rule_id == "SV-100001r1_rule")
    assert rule.severity_level == "high"
    assert rule.severity_cat == "I"


def test_parse_stig__malformed_rule__skips_and_logs(caplog):
    with caplog.at_level(logging.WARNING):
        parsed = parse_stig(FIXTURE)
    ids = {r.rule_id for r in parsed.rules}
    assert "SV-100003r1_rule" not in ids
    assert len(parsed.rules) == 2
    assert any("SV-100003r1_rule" in rec.message for rec in caplog.records)


def test_parse_stig__rule_with_unrecognized_severity__keeps_it_as_cat_iii_and_warns(tmp_path, caplog):
    # Keeping the rule is deliberate: XCCDF permits "unknown" and "info", and losing a
    # rule's fix and check text is worse for a compliance answer than ranking it last.
    path = tmp_path / "odd-xccdf.xml"
    path.write_text(
        '<Benchmark id="ODD_STIG"><title>Odd</title><version>1</version>'
        '<Group id="V-1"><Rule id="SV-1r1_rule" severity="critical">'
        "<title>Odd rule</title><description>d</description><fixtext>f</fixtext>"
        "<check><check-content>c</check-content></check>"
        "</Rule></Group></Benchmark>"
    )
    with caplog.at_level(logging.WARNING):
        parsed = parse_stig(path)
    assert [r.rule_id for r in parsed.rules] == ["SV-1r1_rule"]
    assert parsed.rules[0].severity_cat == "III"
    assert parsed.rules[0].severity_level == "critical"
    assert any("critical" in rec.getMessage() for rec in caplog.records)


def test_parse_stig__deprecated_status__is_captured_with_its_date(tmp_path):
    # U_MS_Windows_Server_2019_V3R9 and the library's own EPAS both carry this.
    path = tmp_path / "b-xccdf.xml"
    path.write_text(
        '<?xml version="1.0"?>'
        '<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1" id="Windows_Server_2019_STIG">'
        '<status date="2026-05-19">deprecated</status>'
        "<title>Windows Server 2019</title><version>3</version>"
        '<plain-text id="release-info">Release: 9 Benchmark Date: 01 Jul 2026</plain-text>'
        "</Benchmark>"
    )
    parsed = parse_stig(path)
    assert parsed.status == "deprecated"
    assert parsed.status_date == "2026-05-19"
    assert parsed.release_info == "Release: 9 Benchmark Date: 01 Jul 2026"


def test_parse_stig__accepted_status__is_captured_verbatim(tmp_path):
    path = tmp_path / "b-xccdf.xml"
    path.write_text(
        '<?xml version="1.0"?>'
        '<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1" id="RHEL_9_STIG">'
        '<status date="2026-06-01">accepted</status>'
        "<title>RHEL 9</title><version>2</version>"
        '<plain-text id="release-info">Release: 9 Benchmark Date: 01 Jul 2026</plain-text>'
        "</Benchmark>"
    )
    parsed = parse_stig(path)
    assert parsed.status == "accepted"
    assert parsed.status_date == "2026-06-01"
    assert parsed.release_info == "Release: 9 Benchmark Date: 01 Jul 2026"


def test_parse_stig__no_status_element__leaves_both_fields_none(tmp_path):
    path = tmp_path / "b-xccdf.xml"
    path.write_text(
        '<?xml version="1.0"?>'
        '<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1" id="Bare_STIG">'
        "<title>Bare</title><version>1</version>"
        '<plain-text id="release-info">Release: 1 Benchmark Date: 01 Jan 2026</plain-text>'
        "</Benchmark>"
    )
    parsed = parse_stig(path)
    assert parsed.status is None
    assert parsed.status_date is None


def test_parse_stig_bytes__same_document_as_parse_stig__returns_the_same_fields():
    data = FIXTURE.read_bytes()
    from_bytes = parse_stig_bytes(data)
    from_path = parse_stig(FIXTURE)
    assert (from_bytes.stig_id, from_bytes.title, from_bytes.version) == (
        from_path.stig_id,
        from_path.title,
        from_path.version,
    )
    assert len(from_bytes.rules) == len(from_path.rules)


def _doc(stig_id="X_STIG", title="A Title", status="accepted"):
    return ParsedStig(
        stig_id=stig_id,
        title=title,
        benchmark_id=stig_id,
        version="1",
        release_info="Release: 1 Benchmark Date: 02 Jul 2026",
        status=status,
    )


def test_document_kind__title_says_security_technical_implementation_guide__returns_stig():
    parsed = _doc(stig_id="RHEL_9", title="Red Hat Enterprise Linux 9 Security Technical Implementation Guide")
    assert document_kind(parsed) == "stig"


def test_document_kind__title_misspells_implementation__returns_stig():
    # U_Multifunction_Device_and_Network_Printers_V2R15_STIG.zip is titled
    # "... Security Technical Implemetation Guide" in DISA's own document. A literal
    # match on the correct spelling loses a benchmark that is in the corpus today.
    parsed = _doc(
        stig_id="MULTI-FUNCTION_DEVICE",
        title="Multifunction Device and Network Printers Security Technical Implemetation Guide",
    )
    assert document_kind(parsed) == "stig"


def test_document_kind__id_ends_in_STIG_and_title_is_bare__returns_stig():
    # Not \b: the regex word class includes the underscore, so
    # \bstig\b does not match zOS_BMC_CONTROL-D_for_RACF_STIG, and every DISA id is that
    # shape. With \b this passes only when the title carries the boilerplate, which is the
    # rule the id test exists to back up.
    parsed = _doc(stig_id="zOS_BMC_CONTROL-D_for_RACF_STIG", title="z/OS BMC CONTROL-D for RACF")
    assert document_kind(parsed) == "stig"


def test_document_kind__id_ends_in_SRG_and_title_is_bare__returns_srg():
    # Same underscore hazard on the SRG side, where getting it wrong is worse: an SRG
    # falling through to the STIG rule would be ingested.
    parsed = _doc(stig_id="AAA_Services_SRG", title="Authentication Authorization and Accounting Services")
    assert document_kind(parsed) == "srg"


def test_document_kind__title_says_security_requirements_guide__returns_srg():
    # The id carries no SRG marker, so this exercises _SRG_TITLE alone. With an id like
    # AAA_Services_SRG the token rule fires first, and _SRG_TITLE could then be deleted
    # outright with every test still passing.
    parsed = _doc(
        stig_id="AAA_Services",
        title="Authentication Authorization and Accounting Services Security Requirements Guide",
    )
    assert document_kind(parsed) == "srg"


def test_document_kind__status_is_draft_and_title_says_stig__returns_draft():
    # U_BIND_9-x_V3R0-1_IDraftSTIG.zip carries <status>draft</status> and Release: 0.1
    # while its title still says STIG, so the draft ruling has to be evaluated first.
    parsed = _doc(stig_id="BIND_9-x_STIG", title="BIND 9.x Security Technical Implementation Guide", status="draft")
    assert document_kind(parsed) == "draft"


def test_document_kind__document_carries_both_an_SRG_and_a_STIG_marker__srg_wins():
    # Pins the rule ORDER, which no other test does: every other SRG fixture carries an
    # SRG marker and no STIG marker, so the SRG and STIG blocks could be swapped with the
    # whole suite still green.
    parsed = _doc(
        stig_id="Application_Server_SRG",
        title="Application Server Security Technical Implementation Guide",
    )
    assert document_kind(parsed) == "srg"


def test_document_kind__title_names_a_product_with_no_marker__returns_neither():
    # Microsoft_Access_2010 in U_SRG-STIG_Library_2020_01v3.zip carries no marker at all.
    parsed = _doc(stig_id="Microsoft_Access_2010", title="Microsoft Access 2010")
    assert document_kind(parsed) == "neither"


def test_document_kind__title_and_status_are_missing__returns_neither():
    parsed = _doc(stig_id=None, title=None, status=None)
    assert document_kind(parsed) == "neither"


def test_document_kind__disas_secure_title_variant__classifies_stig():
    # U_Network_Infrastructure_L3_Switch_Cisco_STIG_V8R29_Manual-xccdf.xml, present in the
    # 2020_01 library vintages, titles itself "... Secure Technical Implementation Guide
    # ..." rather than "Security Technical Implementation Guide".
    parsed = _doc(
        stig_id="Network_-_Infrastructure_Layer_3_Switch_-_Cisco",
        title="Infrastructure L3 Switch Secure Technical Implementation Guide - Cisco",
    )
    assert document_kind(parsed) == "stig"


def test_document_kind__a_scap_benchmark_id_on_a_checklist__does_not_classify_stig():
    # The embedded .stig_ token must not make every document a stig once the prefix is
    # stripped.
    parsed = _doc(
        stig_id="xccdf_mil.disa.stig_benchmark_Traditional_Security_Checklist",
        title="Traditional Security Checklist",
    )
    assert document_kind(parsed) == "neither"
