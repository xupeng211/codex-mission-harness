from __future__ import annotations

from enum import StrEnum


class Decision(StrEnum):
    AUTO_CONTINUE = "AUTO_CONTINUE"
    OWNER_APPROVAL_REQUIRED = "OWNER_APPROVAL_REQUIRED"
    DENY = "DENY"


SENSITIVE = {"live_provider_request", "quota_consumption", "protected_production_mutation",
             "credential_action", "delete_unknown_resource", "merge"}


def decide(action: str, merge_policy: str = "owner_approval") -> Decision:
    if not isinstance(action, str) or not action:
        return Decision.DENY
    if action == "merge":
        if merge_policy == "auto":
            return Decision.AUTO_CONTINUE
        if merge_policy == "owner_approval":
            return Decision.OWNER_APPROVAL_REQUIRED
        return Decision.DENY
    if action in SENSITIVE:
        return Decision.OWNER_APPROVAL_REQUIRED
    if action == "source_edit" or (action.startswith("gate:") and len(action) > 5):
        return Decision.AUTO_CONTINUE
    return Decision.DENY


def permitted(action: str, forbidden_actions: tuple[str, ...], approved: bool = False,
              merge_policy: str = "owner_approval") -> bool:
    """Deny explicitly forbidden actions and every sensitive action without a persisted approval."""
    if type(approved) is not bool:
        return False
    if action in forbidden_actions:
        return False
    decision = decide(action, merge_policy)
    if decision == Decision.DENY:
        return False
    return approved is True or decision == Decision.AUTO_CONTINUE
