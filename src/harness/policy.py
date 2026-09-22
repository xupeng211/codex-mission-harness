from __future__ import annotations

from enum import StrEnum


class Decision(StrEnum):
    AUTO_CONTINUE = "AUTO_CONTINUE"
    OWNER_APPROVAL_REQUIRED = "OWNER_APPROVAL_REQUIRED"


SENSITIVE = {"live_provider_request", "quota_consumption", "protected_production_mutation",
             "credential_action", "delete_unknown_resource", "merge"}


def decide(action: str, merge_policy: str = "owner_approval") -> Decision:
    if action == "merge":
        return Decision.AUTO_CONTINUE if merge_policy == "auto" else Decision.OWNER_APPROVAL_REQUIRED
    return Decision.OWNER_APPROVAL_REQUIRED if action in SENSITIVE else Decision.AUTO_CONTINUE


def permitted(action: str, forbidden_actions: tuple[str, ...], approved: bool = False) -> bool:
    """Deny explicitly forbidden actions and every sensitive action without a persisted approval."""
    if action in forbidden_actions:
        return False
    return approved or decide(action) == Decision.AUTO_CONTINUE
