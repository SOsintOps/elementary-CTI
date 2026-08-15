# "It is a capital mistake to theorise before one has data." — Sherlock Holmes
"""Name to `Group`, deterministically, without the model ever seeing an id.

Roadmap criterion 3, and the reason behind it is worth stating plainly: a model
that picks a primary key can pick the wrong one in a way that reads perfectly.
A merge of two adversaries is indistinguishable from a true row when you look at
the row. So `AdversarySketchOutput` returns **names as the article wrote them**,
and this module resolves them, in code, by rules anyone can rerun.

Four steps, in order, each narrower than the next:

1. Exact match on `group_name`, case and whitespace insensitive.
2. Exact match against an already-approved alias.
3. Fuzzy match on `group_name` above `fuzzy_threshold`, defaulting to the 85
   that `matching.py` has used since the watchlist scanner.
4. Nothing matched: create.

**Two existing `Group.id` are never merged, on any path.** That is not an
emergent property of the four steps, it is a rule enforced on top of them: a
fuzzy hit that is ambiguous between two groups resolves to neither. Merging is
the one mistake here that cannot be undone by rewriting a field, because the
rows that were folded together no longer exist to be separated.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from sqlalchemy import func, select
from sqlalchemy.orm import Session
from thefuzz import fuzz

from pestilentia.config import get_settings
from pestilentia.models.tables import Group, GroupAliasProposal


class Resolution(StrEnum):
    """How the name was resolved. Recorded so the path can be argued with."""

    EXACT = "exact"
    ALIAS = "alias"
    FUZZY = "fuzzy"
    CREATED = "created"
    #: Two or more groups matched equally well. Deliberately not a match.
    AMBIGUOUS = "ambiguous"
    #: The name was empty or unusable.
    REFUSED = "refused"


@dataclass(frozen=True)
class Resolved:
    """A name, what it resolved to, and by which rule."""

    name: str
    group: Group | None
    how: Resolution
    score: int | None = None
    #: Set only for AMBIGUOUS: the groups that tied, so a reviewer can pick.
    candidates: tuple[str, ...] = ()

    @property
    def matched(self) -> bool:
        return self.group is not None


def _normalise(name: str) -> str:
    return " ".join(name.split()).casefold()


def resolve(
    session: Session,
    name: str,
    *,
    threshold: int | None = None,
    create: bool = True,
) -> Resolved:
    """Resolve one actor name to a `Group`, or make one.

    `create=False` answers the question without acting on it, which is what the
    caller wants when it is deciding whether a finding is worth enriching at all.
    """
    if not name or not name.strip():
        return Resolved(name, None, Resolution.REFUSED)

    wanted = _normalise(name)
    cutoff = threshold if threshold is not None else get_settings().fuzzy_threshold

    # All matches, not the first. `group_name` is unique as stored, which does
    # not stop "DarkSide" and "DarkSide " from both existing, and a LIMIT 1 here
    # would pick between them by whatever order the database felt like. That is
    # the accidental merge, arrived at through the step nobody suspects, because
    # "exact match" sounds like it cannot be ambiguous.
    exact = list(
        session.scalars(select(Group).where(func.lower(func.trim(Group.group_name)) == wanted))
    )
    if len(exact) > 1:
        return Resolved(
            name, None, Resolution.AMBIGUOUS, 100, tuple(sorted(g.group_name for g in exact))
        )
    if exact:
        return Resolved(name, exact[0], Resolution.EXACT, 100)

    # Approved aliases only. A pending proposal is a suggestion nobody has
    # accepted, and resolving through one would let the AI's own unreviewed
    # guess become the route by which its next guess is attached to a group.
    alias_hits = list(
        session.scalars(
            select(Group)
            .join(GroupAliasProposal, GroupAliasProposal.group_id == Group.id)
            .where(
                GroupAliasProposal.status == "approved",
                func.lower(func.trim(GroupAliasProposal.proposed_alias)) == wanted,
            )
            .distinct()
        )
    )
    if len(alias_hits) > 1:
        # One alias approved onto two groups is a curation error, and resolving
        # it either way would launder that error into the adversary tables.
        return Resolved(
            name, None, Resolution.AMBIGUOUS, 100, tuple(sorted(g.group_name for g in alias_hits))
        )
    if alias_hits:
        return Resolved(name, alias_hits[0], Resolution.ALIAS, 100)

    scored = [
        (fuzz.ratio(wanted, _normalise(group.group_name)), group)
        for group in session.scalars(select(Group))
        if group.group_name
    ]
    above = sorted((pair for pair in scored if pair[0] >= cutoff), key=lambda p: -p[0])

    if above:
        best = above[0][0]
        tied = [group for score, group in above if score == best]
        if len(tied) > 1:
            # Not a match. Choosing one of two equally good candidates is how a
            # merge gets made by accident, and the row that results looks true.
            return Resolved(
                name,
                None,
                Resolution.AMBIGUOUS,
                best,
                tuple(sorted(group.group_name for group in tied)),
            )
        return Resolved(name, tied[0], Resolution.FUZZY, best)

    if not create:
        return Resolved(name, None, Resolution.REFUSED)

    created = Group(group_name=name.strip())
    session.add(created)
    session.flush()
    return Resolved(name, created, Resolution.CREATED)
