_CAT_BY_LEVEL = {"high": "I", "medium": "II", "low": "III"}
UNKNOWN_CAT = "III"


def is_known_level(level):
    return (level or "").strip().lower() in _CAT_BY_LEVEL


def severity_cat(level):
    return _CAT_BY_LEVEL.get((level or "").strip().lower(), UNKNOWN_CAT)
