import csv
import json
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from stig_mcp.ingest.control_id import normalize_control


@dataclass
class TechniqueControl:
    technique_id: str
    control_id: str
    source: str
    suppressed: bool = False


OVERRIDE_VERSION_DEFAULT = "local"


@dataclass
class MappingSet:
    """A set of technique-to-control pairs plus the provenance of the file they came
    from, so technique_control rows can record which release each pair belongs to."""

    version: str
    pairs: list = field(default_factory=list)
    attack_version: str = ""
    non_mappable: frozenset = frozenset()


def _ctid_version(metadata):
    """CTID ships mapping_version empty in the published file, so fall back to the
    metadata it does populate. Recording the ATT&CK release the set was authored
    against is what makes a stale mapping set visible once ATT&CK moves on."""
    explicit = (metadata.get("mapping_version") or "").strip()
    if explicit:
        return explicit
    attack = (metadata.get("attack_version") or "?").strip()
    framework = (metadata.get("mapping_framework_version") or "?").strip()
    updated = (metadata.get("last_update") or "?").strip()
    return f"attack-{attack}/{framework}@{updated}"


def load_ctid_mappings(path):
    """Load CTID ATT&CK->800-53 pairs from a CSV (technique_id,control_id) or the
    CTID mappings-explorer JSON (mapping_objects with attack_object_id/capability_id)."""
    path = Path(path)
    if path.suffix.lower() == ".json":
        return _load_ctid_json(path)
    return _load_ctid_csv(path)


def _load_ctid_csv(path):
    pairs = []
    with open(path, newline="") as handle:
        for row in csv.DictReader(handle):
            technique = (row.get("technique_id") or "").strip()
            control = normalize_control(row.get("control_id"))
            if technique and control:
                pairs.append(TechniqueControl(technique, control, "ctid", False))
    return MappingSet("", pairs)


def _load_ctid_json(path):
    doc = json.loads(path.read_text())
    pairs = []
    seen = set()
    non_mappable = set()
    for obj in doc.get("mapping_objects", []):
        technique = (obj.get("attack_object_id") or "").strip()
        if obj.get("status") == "non_mappable":
            if technique:
                non_mappable.add(technique)
            continue
        if obj.get("mapping_type") != "mitigates":
            continue
        control = normalize_control(obj.get("capability_id"))
        if technique and control and (technique, control) not in seen:
            seen.add((technique, control))
            pairs.append(TechniqueControl(technique, control, "ctid", False))
    metadata = doc.get("metadata") or {}
    return MappingSet(
        _ctid_version(metadata),
        pairs,
        attack_version=(metadata.get("attack_version") or "").strip(),
        non_mappable=frozenset(non_mappable),
    )


def _override_entries(doc, key, suppressed):
    entries = []
    for item in (doc or {}).get(key, []) or []:
        control = normalize_control(item.get("control"))
        technique = (item.get("technique") or "").strip()
        if technique and control:
            entries.append(TechniqueControl(technique, control, "override", suppressed))
    return entries


def load_overrides(path):
    path = Path(path)
    if not path.exists():
        return MappingSet(OVERRIDE_VERSION_DEFAULT, [])
    doc = yaml.safe_load(path.read_text()) or {}
    version = str(doc.get("version") or OVERRIDE_VERSION_DEFAULT).strip()
    pairs = _override_entries(doc, "add", False) + _override_entries(doc, "suppress", True)
    return MappingSet(version, pairs)
