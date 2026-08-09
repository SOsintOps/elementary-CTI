# "It is a capital mistake to theorize before one has data." — Sherlock Holmes
"""Provider-agnostic LLM routing (ADR-006 section 2, roadmap phase 3).

Every model call in the system goes through `Router.choose`, which answers one
question — *which model may serve this task, if any* — by consulting two gates
in a fixed order:

1. **TLP.** Content above the configured cloud ceiling never reaches a
   third-party provider. If no local provider can take it, the answer is a
   refusal, never a downgrade.
2. **Budget.** A pre-call token estimate against the daily and monthly caps.

The router returns a decision, it does not make the call. That split is what
keeps this testable at zero LLM spend: the tests exercise every branch through
a mock provider, and no code path here imports a vendor SDK.
"""

from __future__ import annotations

from pestilentia.ai.router.decisions import (
    Decision,
    ModelChoice,
    Refusal,
    RefusalReason,
    Tier,
    TlpOverride,
)
from pestilentia.ai.router.providers import (
    PROVIDERS,
    MockProvider,
    Provider,
    ProviderSpec,
    available_providers,
)
from pestilentia.ai.router.router import Router

__all__ = [
    "PROVIDERS",
    "Decision",
    "MockProvider",
    "ModelChoice",
    "Provider",
    "ProviderSpec",
    "Refusal",
    "RefusalReason",
    "Router",
    "Tier",
    "TlpOverride",
    "available_providers",
]
