"""The delivery bridge is a draft, never an execution authorization."""
import copy
import hashlib
import json
import unittest

from harness.delivery_bridge import BridgeRejected, validate_draft


def sha(value):
    return hashlib.sha256(value).hexdigest()


class DeliveryBridgeTests(unittest.TestCase):
    def setUp(self):
        self.row = {"number": 334, "mission_id": "HARNESS_AUTONOMOUS_PRE_MERGE_DELIVERY",
                    "status": "FAILED", "reported_usage": "UNKNOWN",
                    "usage_accounting": "USAGE_UNVERIFIED_BLOCK_FUTURE_CALLS",
                    "provider": "deepseek", "cost_reservation_microunits": 400000}
        self.ledger = json.dumps({"requests": [{"number": i} for i in range(1, 334)] + [self.row]}).encode()
        self.draft = {"version": "cmh-current-delivery-bridge-draft/v1",
                      "old_mission_id": self.row["mission_id"],
                      "old_ledger_sha256": sha(self.ledger),
                      "request_334_sha256": sha(json.dumps(self.row, sort_keys=True, separators=(",", ":")).encode()),
                      "old_acceptance": "INCOMPLETE", "old_model_requests_frozen": True,
                      "new_mission_id": "CURRENT_VERSION_DELIVERY_PROPOSED",
                      "scope": ["PR2_HARNESS_V0_1_1", "PR4_REVIEWER_V2"],
                      "main_sha": "a" * 40, "pr2_head": "b" * 40, "pr4_head": "c" * 40,
                      "runtime_sha256": "d" * 64, "registry_sha256": "e" * 64,
                      "source_binding_version": "exact-unique-utf8-quote/v1",
                      "models": {"deepseek": "deepseek-flash", "openai": "gpt-5.6-sol/high"},
                      "shared_account_evidence_sha256": None,
                      "old_deepseek_cost_reserved_microusd": 28800000,
                      "new_authorization_status": "PENDING_USER_APPROVAL",
                      "new_mission_executable": False,
                      "new_model_requests_allowed": False}
        self.current = {key: self.draft[key] for key in
                        ("main_sha", "pr2_head", "pr4_head", "runtime_sha256", "registry_sha256")}

    def check(self, draft=None, ledger=None):
        return validate_draft(self.draft if draft is None else draft,
                              self.ledger if ledger is None else ledger, self.current)

    def test_valid_draft_is_still_not_executable(self):
        result = self.check()
        self.assertFalse(result["new_mission_executable"])
        self.assertFalse(result["new_model_requests_allowed"])

    def test_modified_ledger_rejected(self):
        with self.assertRaises(BridgeRejected): self.check(ledger=self.ledger + b" ")

    def test_334_verified_rejected(self):
        changed = json.loads(self.ledger)
        changed["requests"][-1]["reported_usage"] = {"input": 0}
        candidate = copy.deepcopy(self.draft)
        raw = json.dumps(changed).encode()
        candidate["old_ledger_sha256"] = sha(raw)
        candidate["request_334_sha256"] = sha(json.dumps(changed["requests"][-1], sort_keys=True, separators=(",", ":")).encode())
        with self.assertRaises(BridgeRejected): self.check(candidate, raw)

    def test_missing_old_anchor_rejected(self):
        candidate = copy.deepcopy(self.draft); candidate.pop("old_ledger_sha256")
        with self.assertRaises(BridgeRejected): self.check(candidate)

    def test_empty_history_rejected(self):
        candidate = copy.deepcopy(self.draft); raw = b'{"requests":[]}'
        candidate["old_ledger_sha256"] = sha(raw)
        with self.assertRaises(BridgeRejected): self.check(candidate, raw)

    def test_missing_authorization_cannot_become_executable(self):
        for key, value in (("new_authorization_status", "APPROVED"),
                           ("new_mission_executable", True), ("new_model_requests_allowed", True)):
            candidate = copy.deepcopy(self.draft); candidate[key] = value
            with self.assertRaises(BridgeRejected): self.check(candidate)

    def test_identity_drift_rejected(self):
        for key in ("pr2_head", "pr4_head", "runtime_sha256", "registry_sha256"):
            candidate = copy.deepcopy(self.draft); candidate[key] = "f" * len(candidate[key])
            with self.assertRaises(BridgeRejected): self.check(candidate)

    def test_old_cost_reservation_cannot_disappear(self):
        candidate = copy.deepcopy(self.draft); candidate["old_deepseek_cost_reserved_microusd"] = 0
        with self.assertRaises(BridgeRejected): self.check(candidate)

    def test_shared_evidence_does_not_activate_draft(self):
        candidate = copy.deepcopy(self.draft); candidate["shared_account_evidence_sha256"] = "f" * 64
        self.assertFalse(self.check(candidate)["new_model_requests_allowed"])

    def test_missing_shared_evidence_keeps_execution_denied(self):
        self.assertIsNone(self.draft["shared_account_evidence_sha256"])
        self.assertFalse(self.check()["new_mission_executable"])

    def test_old_qualification_cannot_be_claimed_by_draft(self):
        candidate = copy.deepcopy(self.draft); candidate["qualification_receipt"] = "old-runtime"
        with self.assertRaises(BridgeRejected): self.check(candidate)

    def test_draft_cannot_contain_formal_review_receipt(self):
        candidate = copy.deepcopy(self.draft); candidate["full_review_receipt"] = "PASS"
        with self.assertRaises(BridgeRejected): self.check(candidate)

    def test_source_binding_contract_change_rejected(self):
        candidate = copy.deepcopy(self.draft); candidate["source_binding_version"] = "fuzzy"
        with self.assertRaises(BridgeRejected): self.check(candidate)


if __name__ == "__main__": unittest.main()
