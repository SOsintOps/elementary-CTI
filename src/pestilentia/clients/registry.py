# "You know my methods, Watson. Apply them." — Sherlock Holmes, Elementary
from pestilentia.clients.base import BaseSource

SOURCES: dict[str, type[BaseSource]] = {}


# "I never make exceptions. An exception disproves the rule." — Sherlock Holmes, Elementary
def register(cls: type[BaseSource]) -> type[BaseSource]:
    SOURCES[cls.source_name] = cls
    return cls
