"""Objects merged onto attack_bundle.json so APT29 uses eight techniques whose defensive shapes
make every coverage count distinct. With platforms=["Windows"],
log_sources=["WinEventLog:Security", "WinEventLog:Sysmon"] and RHEL 9 in scope:

    technique  mitigation         rules  analytics (platform; sources)            detect class
    T1078      M1026, M1027       yes    AN0001 (Win; Security+Sysmon), AN0002 (Linux; auditd x2)  detectable
    T9000      M1027 (redirect)   no     AN0003 (Linux)                           without_applicable_analytic
    T9001      M1026              no     AN0004 (Win; Security)                   detectable
    T9002      none               no     AN0005 (Win; Application)                undetectable
    T9003      M1027              no     AN0006 (Win; no log sources)             undetectable
    T9004      none               no     AN0007 (Win; Security+Application)       undetectable
    T9005      none               no     AN0008 (Win,Linux; auditd)               undetectable
    T9006      M1026              no     AN0009 (Linux; auditd), AN0010 (Win; App) undetectable

    techniques 8, without_mitigation 3, mitigated_without_rules 4,
    without_applicable_analytic 1, detectable 2, undetectable 5
"""


def _technique(tid):
    return {
        "type": "attack-pattern",
        "id": f"attack-pattern--{tid.lower()}",
        "name": f"Technique {tid}",
        "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "persistence"}],
        "external_references": [{"source_name": "mitre-attack", "external_id": tid}],
    }


# attack_bundle.json defines T9000 under a STIX id that does not follow the f"attack-pattern--{tid}" scheme.
_STIX_ID_OF_BUNDLE_TECHNIQUE = {"T9000": "attack-pattern--live-9000"}


def _uses(tid):
    return {
        "type": "relationship",
        "relationship_type": "uses",
        "source_ref": "intrusion-set--g0016",
        "target_ref": _STIX_ID_OF_BUNDLE_TECHNIQUE.get(tid, f"attack-pattern--{tid.lower()}"),
    }


def _mitigates(mid, tid):
    return {
        "type": "relationship",
        "relationship_type": "mitigates",
        "source_ref": f"course-of-action--{mid.lower()}",
        "target_ref": f"attack-pattern--{tid.lower()}",
        "description": f"{mid} on {tid}",
    }


def _analytic(aid, platforms, sources):
    return {
        "type": "x-mitre-analytic",
        "id": f"x-mitre-analytic--{aid.lower()}",
        "name": f"Analytic {aid}",
        "description": f"fixture {aid}",
        "x_mitre_platforms": platforms,
        "x_mitre_log_source_references": [{"name": name, "channel": channel} for name, channel in sources],
        "x_mitre_mutable_elements": [],
        "external_references": [{"source_name": "mitre-attack", "external_id": aid}],
    }


def _strategy(did, tid, analytic_ids):
    return [
        {
            "type": "x-mitre-detection-strategy",
            "id": f"x-mitre-detection-strategy--{did.lower()}",
            "name": f"Strategy {did}",
            "x_mitre_analytic_refs": [f"x-mitre-analytic--{aid.lower()}" for aid in analytic_ids],
            "external_references": [{"source_name": "mitre-attack", "external_id": did}],
        },
        {
            "type": "relationship",
            "relationship_type": "detects",
            "source_ref": f"x-mitre-detection-strategy--{did.lower()}",
            "target_ref": f"attack-pattern--{tid.lower()}",
        },
    ]


SECURITY = ("WinEventLog:Security", "EventCode=4624")
SYSMON = ("WinEventLog:Sysmon", "EventCode=1")
APPLICATION = ("WinEventLog:Application", "EventCode=1000")
AUDITD = ("auditd:SYSCALL", "execve")

EXTRA_OBJECTS = [
    *(_technique(tid) for tid in ("T9001", "T9002", "T9003", "T9004", "T9005", "T9006")),
    *(_uses(tid) for tid in ("T9000", "T9001", "T9002", "T9003", "T9004", "T9005", "T9006")),
    _mitigates("M1026", "T9001"),
    _mitigates("M1027", "T9003"),
    _mitigates("M1026", "T9006"),
    _analytic("AN0004", ["Windows"], [SECURITY]),
    *_strategy("DET0003", "T9001", ["AN0004"]),
    _analytic("AN0005", ["Windows"], [APPLICATION]),
    *_strategy("DET0004", "T9002", ["AN0005"]),
    _analytic("AN0006", ["Windows"], []),
    *_strategy("DET0005", "T9003", ["AN0006"]),
    _analytic("AN0007", ["Windows"], [SECURITY, APPLICATION]),
    *_strategy("DET0006", "T9004", ["AN0007"]),
    _analytic("AN0008", ["Windows", "Linux"], [AUDITD]),
    *_strategy("DET0007", "T9005", ["AN0008"]),
    _analytic("AN0009", ["Linux"], [AUDITD]),
    _analytic("AN0010", ["Windows"], [APPLICATION]),
    *_strategy("DET0008", "T9006", ["AN0009", "AN0010"]),
]
