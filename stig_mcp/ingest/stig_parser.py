import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

from defusedxml import ElementTree

from stig_mcp.ingest.severity import is_known_level, severity_cat

logger = logging.getLogger(__name__)


@dataclass
class StigRule:
    rule_id: str
    group_id: str
    severity_cat: str
    severity_level: str
    title: str
    discussion: str
    fix_text: str
    check_text: str
    ccis: list = field(default_factory=list)


@dataclass
class ParsedStig:
    stig_id: str
    title: str
    benchmark_id: str
    version: str
    release_info: str
    status: str | None = None
    status_date: str | None = None
    rules: list = field(default_factory=list)


def _local(tag):
    return tag.rsplit("}", 1)[-1]


def _first(element, name):
    for child in element.iter():
        if _local(child.tag) == name:
            return child
    return None


def _direct(element, name):
    for child in element:
        if _local(child.tag) == name:
            return child
    return None


def _text(element):
    return (element.text or "").strip() if element is not None else ""


def _parse_rule(rule_el, group_id):
    rule_id = rule_el.get("id")
    level = rule_el.get("severity")
    if not level:
        raise ValueError(f"rule {rule_id} has no @severity")
    if not is_known_level(level):
        logger.warning(
            "Rule %s has @severity %r, which is not one of high/medium/low; ranking it "
            "CAT III. The rule is kept, so its fix and check text are still returned.",
            rule_id,
            level,
        )
    check_content = _first(rule_el, "check-content")
    ccis = [
        (ident.text or "").strip()
        for ident in rule_el
        if _local(ident.tag) == "ident" and (ident.text or "").startswith("CCI-")
    ]
    return StigRule(
        rule_id=rule_id,
        group_id=group_id,
        severity_cat=severity_cat(level),
        severity_level=level,
        title=_text(_direct(rule_el, "title")),
        discussion=_text(_direct(rule_el, "description")),
        fix_text=_text(_direct(rule_el, "fixtext")),
        check_text=_text(check_content),
        ccis=ccis,
    )


def _from_root(root):
    stig_id = root.get("id")
    title = _text(_direct(root, "title"))
    version = _text(_direct(root, "version"))
    # <status> precedes <plain-text id="release-info"> in DISA's documents, so this loop must
    # not share the status loop's `break` below: merged, the walk would stop before
    # release-info and leave release_info (which orchestrator._version_key reads) empty.
    release_info = ""
    for child in root:
        if _local(child.tag) == "plain-text" and child.get("id") == "release-info":
            release_info = _text(child)
    status, status_date = None, None
    for child in root:
        if _local(child.tag) == "status":
            # DISA marks the final release of a sunset STIG deprecated. It is a reliable
            # positive with no false positives across every benchmark examined, and it is
            # incomplete rather than absent: a sunset archive holds earlier releases,
            # published while the product was live, which all say accepted.
            status = _text(child) or None
            status_date = child.get("date")
            break
    rules = []
    for group in root:
        if _local(group.tag) != "Group":
            continue
        group_id = group.get("id")
        for rule_el in group:
            if _local(rule_el.tag) != "Rule":
                continue
            try:
                rules.append(_parse_rule(rule_el, group_id))
            except (ValueError, AttributeError) as exc:
                logger.warning("Skipping rule %s: %s", rule_el.get("id"), exc)
    return ParsedStig(
        stig_id=stig_id,
        title=title,
        benchmark_id=stig_id,
        version=version,
        release_info=release_info,
        status=status,
        status_date=status_date,
        rules=rules,
    )


def parse_stig(path):
    return _from_root(ElementTree.parse(Path(path)).getroot())


def parse_stig_bytes(data):
    """Parse a benchmark already held in memory, for callers walking a zip-of-zips who
    would otherwise write the file out only to read it back."""
    return _from_root(ElementTree.fromstring(data))


# "Implemetation" is DISA's typo, not ours: U_Multifunction_Device_and_Network_Printers_V2R15_STIG.zip
# ships that spelling, and a literal match on the correct one silently loses the benchmark.
# `secur\w*` rather than the literal "security" for the same reason: the 2020_01 library
# vintages title U_Network_Infrastructure_L3_Switch_Cisco_STIG_V8R29_Manual-xccdf.xml "...
# Secure Technical Implementation Guide ...", and a literal "security" match silently loses it.
_SRG_TITLE = re.compile(r"security requirements guide", re.IGNORECASE)
_STIG_TITLE = re.compile(r"secur\w* technical implem\w*ation guide", re.IGNORECASE)


def _marker(word):
    """Match `word` delimited by anything that is not alphanumeric.

    NOT \\b: the regex word class includes the underscore, so \\bstig\\b does not match
    zOS_BMC_CONTROL-D_for_RACF_STIG, which is exactly the shape every DISA benchmark id
    uses. That spelling would leave the title boilerplate as the only working rule."""
    return re.compile(rf"(?:^|[^a-z0-9]){word}(?:[^a-z0-9]|$)", re.IGNORECASE)


_SRG_TOKEN = _marker("srg")
_STIG_TOKEN = _marker("stig")


def document_kind(parsed):
    """What DISA's document says it is, in priority order.

    The filename is deliberately not an input. DISA ships STIG benchmarks in archives named
    for neither their contents nor their kind (U_zOS_RACF_Y26M07_Products.zip holds several),
    so a name-based test misses real content while an id-and-title test does not.

    Draft is checked first because a draft STIG says both "draft" and "STIG", and the draft
    ruling must win. SRG is checked before STIG because an SRG's id can end in _SRG while
    its title mentions neither phrase."""
    if (parsed.status or "").strip().lower() == "draft":
        return "draft"
    haystack = f"{parsed.stig_id or ''} {parsed.title or ''}"
    if _SRG_TITLE.search(haystack) or _SRG_TOKEN.search(haystack):
        return "srg"
    # Stripped before the STIG check only: a SCAP data-stream's benchmark id carries the
    # literal prefix "xccdf_mil.disa.stig_benchmark_", whose embedded ".stig_" would satisfy
    # _STIG_TOKEN and misclassify every such checklist as a STIG. The SRG check above already
    # ran on the unstripped haystack, so scoping the strip to this branch cannot change an SRG
    # ruling; it only closes the STIG-side false positive.
    stig_id = (parsed.stig_id or "").removeprefix("xccdf_mil.disa.stig_benchmark_")
    haystack = f"{stig_id} {parsed.title or ''}"
    if _STIG_TITLE.search(haystack) or _STIG_TOKEN.search(haystack):
        return "stig"
    return "neither"
