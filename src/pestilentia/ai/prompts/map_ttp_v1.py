# "It is a mistake to confound strangeness with mystery." — Sherlock Holmes
"""MapTTP — behaviour the article describes, named in ATT&CK.

Every id returned is resolved against the ATT&CK catalogue and every quote is
anchored in the body (`extraction/ttps.py`); what neither vouches for is
discarded. The failure this prompt is written against is not invention of ids —
those get caught — but *recall from training*: mapping the techniques a group is
famous for rather than the ones this article describes. Both produce valid ids
with plausible quotes, and only the anchor tells them apart.
"""

from __future__ import annotations

from pestilentia.ai.prompts.base import ATTACK_RULES, DATA_RULES, Prompt, system_prompt

VERSION = "map_ttp_v1"

_THIS_ARTICLE = """\
## This article, not this group

You know a great deal about these groups. None of it is evidence here.

Map a technique only where the article describes the behaviour taking place in \
the activity it reports. "The group is known for exploiting VPN appliances" in a \
background paragraph is not the same claim as "the intruder authenticated to the \
VPN with valid credentials", and only the second maps.

The quote you attach is the test: if you cannot copy a clause from the body that \
shows the behaviour, the mapping does not belong in the output."""

_TASK = """\
Map the behaviours this article reports to ATT&CK techniques, quoting the body \
for each one."""

PROMPT = Prompt(
    state="map_ttp",
    version=VERSION,
    system=system_prompt("map_ttp", VERSION, DATA_RULES, ATTACK_RULES, _THIS_ARTICLE),
    task=_TASK,
    max_output_tokens=2500,
)
