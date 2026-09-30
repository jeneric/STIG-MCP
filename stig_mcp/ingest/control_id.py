import re

_CONTROL_RE = re.compile(r"\b([A-Za-z]{2})-(\d+)(?:\s*\((\d+)\))?")


def normalize_control(raw: str | None) -> str | None:
    if not raw:
        return None
    match = _CONTROL_RE.search(raw)
    if not match:
        return None
    family, number, enhancement = match.groups()
    base = f"{family.upper()}-{int(number)}"
    return f"{base}({int(enhancement)})" if enhancement else base
