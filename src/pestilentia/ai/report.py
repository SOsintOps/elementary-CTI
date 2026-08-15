# "You see, but you do not observe." — Sherlock Holmes
"""The report: the shape the sources give, filled from what the states produced.

The house style document said for weeks what a sentence may not contain and
never said what a report **is**. The sources do say, and precisely: a title of
its own, the bottom line first, the body ordered from what is known to what is
concluded, and a closing that names the gaps and the possibility of deception
before it names anything else. What this module does is impose that order on
material the pipeline already holds.

**A projection, not a second author.** Nothing here calls a model. Every
sentence in the output was written by a state, checked by the grounding, and
scored by the gate; the report arranges them. If reading a report could change
its text, the report would be a writer nobody validated, and two readings of one
article would disagree for no reason a reader could see.

**What it refuses to fake.** The form wants a title of the report's own, a noun
phrase naming the subject with a short elaboration. No state produces one. Until
one does, the report carries the publisher's headline *and says whose it is*,
because a borrowed title presented as ours is exactly the kind of quiet
misattribution the rest of this pipeline exists to prevent.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from pestilentia.ai.enrichment.identity import IdentityCatalog, NameKind

#: The manual's ceiling for a paragraph, in lines. Kept here rather than in the
#: checker because it is a property of the form, and the checker measures the
#: form rather than defining it.
MAX_PARAGRAPH_LINES = 6


@dataclass(frozen=True)
class Section:
    """One headed block of the report, in the order the form fixes."""

    heading: str
    body: str

    def __bool__(self) -> bool:
        return bool(self.body.strip())


@dataclass
class Report:
    """One article's analysis, in the shape the sources prescribe.

    `level` is the report's own attribute and deliberately not
    `AdversarySketchOutput.attribution_level`, which carries the same three
    words for a different question: how deep the attribution reached, not who
    the report is written for. The values coincide and the meanings do not,
    which is the quietest kind of mistake available here.
    """

    title: str
    title_is_ours: bool
    bottom_line: str
    confidence: str
    sections: list[Section] = field(default_factory=list)
    level: str = ""

    def to_markdown(self) -> str:
        """The report as a reader receives it.

        The bottom line is not a heading and not a summary: the sources are
        explicit that it states the conclusion rather than describing what
        follows, so it sits above the first heading with nothing between.
        """
        lines = [f"# {self.title}"]
        if not self.title_is_ours:
            lines.append("*Title as published by the source; this report has none of its own.*")
        lines.append("")
        if self.bottom_line:
            confidence = f" ({self.confidence})" if self.confidence else ""
            lines.append(f"**Bottom line.** {self.bottom_line}{confidence}")
            lines.append("")
        for section in self.sections:
            if not section:
                continue
            lines.append(f"## {section.heading}")
            lines.append("")
            lines.append(section.body.strip())
            lines.append("")
        return "\n".join(lines).strip() + "\n"


def _actor_line(entry: object, catalog: IdentityCatalog | None) -> str:
    """One named actor, with whoever vouches for the name.

    This is where the identity work stops being infrastructure and becomes
    something a reader sees: *Handala Hack Team, which MITRE ATT&CK lists among
    the names of VOID MANTICORE* tells them what a bare name cannot. A name no
    catalogue knows is reported as unrecognised rather than dressed up, because
    the reader's next decision depends on which of the two it is.
    """
    name = entry if isinstance(entry, str) else (entry or {}).get("name", "")
    if not name:
        return ""
    if catalog is None:
        return f"- {name}"

    resolution = catalog.resolve(name)
    if resolution.kind is NameKind.KNOWN_ACTOR:
        others = [alias for alias in resolution.aliases if alias.casefold() != name.casefold()]
        also = f", also known as {', '.join(others[:4])}" if others else ""
        return f"- **{name}**{also} ({resolution.authority})"
    if resolution.kind in (NameKind.MALWARE, NameKind.TOOL):
        return f"- {name} — {resolution.kind.value}, not an actor ({resolution.authority})"
    if resolution.kind is NameKind.CLUSTER_DESIGNATOR:
        return f"- {name} — a cluster {resolution.authority} has not named"
    if resolution.kind is NameKind.VENDOR_NAMED:
        return f"- {name} — {resolution.evidence}"
    return f"- {name} — recognised by no catalogue held here"


def build(
    *,
    article_title: str,
    narrative: dict,
    sketch: dict | None = None,
    source_name: str = "",
    source_url: str = "",
    published: str = "",
    catalog: IdentityCatalog | None = None,
    level: str = "",
) -> Report:
    """Assemble one report from one article's stored analysis.

    Takes plain dictionaries rather than models because the material comes off
    `raw_output_json`, which is where the reconciled output lives: reading the
    row rather than the model is what guarantees the report shows what was
    stored and not what a schema default would supply.
    """
    narrative = narrative or {}
    sketch = sketch or {}

    sections: list[Section] = []

    sections.append(Section("What the reporting establishes", narrative.get("summary_md", "")))

    actor_lines = [_actor_line(entry, catalog) for entry in sketch.get("named_actors") or []]
    adversary = "\n".join(line for line in actor_lines if line)
    cluster = (sketch.get("cluster_summary") or "").strip()
    if cluster:
        adversary = f"{cluster}\n\n{adversary}".strip()
    likelihood = (sketch.get("likelihood") or "").strip()
    if likelihood and adversary:
        adversary = f"{adversary}\n\nAssessed likelihood: {likelihood}."
    sections.append(Section("The adversary", adversary))

    # The form puts this before the closing comments and before anything
    # actionable, which is a judgement about what a reader most needs and not a
    # layout preference: a recommendation read without the gaps beside it is a
    # recommendation read as more certain than it is.
    caveats = [
        (sketch.get("false_flag_note") or "").strip(),
        (sketch.get("shared_infrastructure_note") or "").strip(),
    ]
    sections.append(Section("Gaps and deception", "\n\n".join(c for c in caveats if c)))

    sections.append(Section("Recommended action", narrative.get("recommendations_md", "")))

    source_bits = [bit for bit in (source_name, published, source_url) if bit]
    sections.append(Section("Source", " · ".join(source_bits)))

    return Report(
        title=article_title or "Untitled report",
        title_is_ours=False,
        bottom_line=(narrative.get("key_judgement") or "").strip(),
        confidence=(narrative.get("confidence") or "").strip(),
        sections=sections,
        level=level,
    )
