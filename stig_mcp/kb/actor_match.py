"""Match a typed threat-actor name to ATT&CK groups.

Misspellings are suggested, never resolved: real names sit one character apart (APT28 and
APT29, APT3 and APT30), and a guess would answer for the wrong adversary. A loose form
(spacing, punctuation, a trailing Group or Team) resolves only when it names one group, and a
typo that happens to be another group's exact label resolves to that group.
"""

import difflib
import re
import unicodedata
from typing import NamedTuple

SUGGESTION_LIMIT = 5
# ATT&CK 19.2, one random letter substituted in each label: at 0.75 the intended group is in the
# top three for 748 of 754 typos; at 0.80, for 726.
_SIMILARITY_CUTOFF = 0.75
# Real labels are under 40 characters; scoring cost grows with the product of the lengths.
_SUGGESTION_INPUT_LIMIT = 100
# Not [^a-z0-9], which would read "APT29é" as APT29. Combining marks are still dropped, which is
# safe only while every ATT&CK label is ASCII (true of 19.1).
_NON_ALNUM = re.compile(r"[\W_]+")
_GROUP_SUFFIX = re.compile(r" (?:group|team)$")


class ActorMatch(NamedTuple):
    """One group in `groups` resolves, several are ambiguous, none leaves only `suggestions`.
    `also_matches` exists because one label can name two groups: "LUMINOUS MOTH" is Mustang
    Panda's alias and, loosely, the name of LuminousMoth."""

    groups: list
    matched_as: str | None
    suggestions: list
    also_matches: list


class Actor(NamedTuple):
    id: str
    name: str
    aliases: list

    def labels(self):
        return [self.name, *self.aliases]

    def public(self):
        return {"id": self.id, "name": self.name, "aliases": list(self.aliases)}


def match(actors, typed):
    needle = _fold(typed).strip()
    by_name = [a for a in actors if needle in (_fold(a.id), _fold(a.name))]
    by_alias = [a for a in actors if needle in (_fold(alias) for alias in a.aliases)]
    loose = _loose_matches(actors, typed)
    for exact in (by_name, by_alias):
        if exact:
            groups = _public(exact)
            also = [] if len(groups) > 1 else _others(loose, groups[0]["id"])
            return ActorMatch(groups, None, [], also)
    groups = _public(actor for actor, _ in loose)
    if groups:
        matched_as = loose[0][1] if len(groups) == 1 else None
        return ActorMatch(groups, matched_as, [], [])
    return ActorMatch([], None, _suggestions(actors, typed), [])


def _loose_matches(actors, typed):
    key = _loose_key(typed)
    return [(actor, label) for actor in actors for label in (actor.id, *actor.labels()) if _loose_key(label) == key]


def _others(loose, resolved_id):
    first_label = {}
    for actor, label in loose:
        if actor.id != resolved_id:
            first_label.setdefault(actor.id, (actor, label))
    return [_labeled(actor, label) for actor, label in (first_label[i] for i in sorted(first_label))]


def _labeled(actor, label):
    return {"id": actor.id, "name": actor.name, "via": None if label == actor.name else label}


def _public(actors):
    distinct = {actor.id: actor for actor in actors}
    return [distinct[actor_id].public() for actor_id in sorted(distinct)]


def _fold(text):
    """NFKC, so a fullwidth "APT3０" reads as APT30, not APT3 plus punctuation."""
    return unicodedata.normalize("NFKC", text).casefold()


def _words(text):
    return _NON_ALNUM.sub(" ", _fold(text)).strip()


def _loose_key(text):
    words = _words(text)
    return _GROUP_SUFFIX.sub("", words).replace(" ", "")


def _suggestions(actors, typed):
    words = _words(typed)
    if not words or len(words) > _SUGGESTION_INPUT_LIMIT:
        return []
    scored = []
    for actor in actors:
        qualifying = [(ratio, label) for label in actor.labels() if (ratio := _closeness(words, label)) is not None]
        if qualifying:
            ratio, label = max(qualifying, key=lambda pair: pair[0])
            scored.append((ratio, actor, label))
    scored.sort(key=lambda entry: (-entry[0], entry[1].id))
    return [_labeled(actor, label) for _, actor, label in scored[:SUGGESTION_LIMIT]]


def _closeness(words, label):
    """Similarity, or None unless it clears the cutoff or `words` is a whole-word subset
    ("Bear" of "Cozy Bear", which scores low). A trailing Group or Team is scored both ways,
    since "Lazurus" against "lazarus group" falls below the cutoff."""
    label_words = _words(label)
    forms = {label_words, _GROUP_SUFFIX.sub("", label_words)}
    ratio = max(difflib.SequenceMatcher(None, words, form).ratio() for form in forms)
    if ratio >= _SIMILARITY_CUTOFF or set(words.split()) <= set(label_words.split()):
        return ratio
    return None
