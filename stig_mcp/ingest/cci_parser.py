import logging
from dataclasses import dataclass, field
from pathlib import Path

from defusedxml import ElementTree

from stig_mcp.ingest.control_id import normalize_control

logger = logging.getLogger(__name__)


@dataclass
class CciRecord:
    cci_id: str
    definition: str
    controls: list = field(default_factory=list)


def _local(tag):
    return tag.rsplit("}", 1)[-1]


def _find_child(element, name):
    for child in element:
        if _local(child.tag) == name:
            return child
    return None


def cci_list_version(path):
    """The CCI list's <metadata><version>, or None when it carries none."""
    metadata = _find_child(ElementTree.parse(Path(path)).getroot(), "metadata")
    version = _find_child(metadata, "version") if metadata is not None else None
    text = (version.text or "").strip() if version is not None else ""
    return text or None


def parse_cci_list(path):
    path = Path(path)
    root = ElementTree.parse(path).getroot()
    items_container = _find_child(root, "cci_items")
    if items_container is None:
        raise ValueError(
            f"{path} has no <cci_items> element, so it is not a DISA CCI list. Pass the "
            f"U_CCI_List.xml downloaded from cyber.mil; docs/operations.md, section 'Build "
            f"the knowledge base', names the file and where to get it."
        )
    records = []
    for item in items_container:
        if _local(item.tag) != "cci_item":
            continue
        cci_id = item.get("id")
        if not cci_id:
            logger.warning("Skipping a <cci_item> with no @id in %s; it cannot be keyed or joined.", path)
            continue
        definition_el = _find_child(item, "definition")
        definition = (definition_el.text or "").strip() if definition_el is not None else ""
        controls = []
        references = _find_child(item, "references")
        for ref in references if references is not None else []:
            if "Revision 5" not in (ref.get("title") or "") and ref.get("version") != "5":
                continue
            control = normalize_control(ref.get("index"))
            if control and control not in controls:
                controls.append(control)
        records.append(CciRecord(cci_id=cci_id, definition=definition, controls=controls))
    return records
