"""Parse the NIST SP 800-53 Revision 5 OSCAL control catalog.

Source: usnistgov/oscal-content, `NIST_SP-800-53_rev5_catalog[-min].json`.
Structure: `catalog.groups[]` are families (id "ac", title "Access Control"); each
group's `controls[]` are base controls (id "ac-2"); control enhancements are nested
as a `controls[]` array inside a control (id "ac-2.1"). This yields the display
name, family, and base↔enhancement link that the derived-id `controls` rows lack.
"""

import json
import re
from dataclasses import dataclass
from pathlib import Path

# ac-2 -> AC-2 ; ac-2.1 -> AC-2(1) ; matches normalize_control's canonical output.
_ID_RE = re.compile(r"^([a-z]{2})-(\d+)(?:\.(\d+))?$")


@dataclass
class CatalogControl:
    control_id: str
    name: str
    family: str
    is_enhancement: bool
    parent_control_id: str | None


def _canonical(oscal_id):
    match = _ID_RE.match(oscal_id or "")
    if not match:
        return None
    family, number, enhancement = match.groups()
    base = f"{family.upper()}-{int(number)}"
    return f"{base}({int(enhancement)})" if enhancement else base


def catalog_version(path):
    """The catalog's own metadata.version (e.g. 5.2.0), or None when it carries none."""
    metadata = json.loads(Path(path).read_text())["catalog"].get("metadata") or {}
    version = metadata.get("version")
    return version.strip() if isinstance(version, str) and version.strip() else None


def parse_control_catalog(path):
    """Return the flat list of CatalogControl rows (base controls + enhancements)."""
    catalog = json.loads(Path(path).read_text())["catalog"]
    records = []
    for group in catalog.get("groups", []):
        family = group.get("title") or (group.get("id") or "").upper()
        for control in group.get("controls", []):
            base_id = _canonical(control.get("id"))
            if not base_id:
                continue
            records.append(CatalogControl(base_id, control.get("title", ""), family, False, None))
            for enhancement in control.get("controls", []):
                enh_id = _canonical(enhancement.get("id"))
                if enh_id:
                    records.append(CatalogControl(enh_id, enhancement.get("title", ""), family, True, base_id))
    return records
