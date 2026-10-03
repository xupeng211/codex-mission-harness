"""Offline security probes for the formally versioned Group quote locator."""
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from harness.resource_gate import canonical as auth_canonical, sign_authorization
from harness.reviewer_v2_contract import (
    FORMAL_MISSION_ID, SourceBindingError, contract_authorization_identity,
    parse_synthesis, sha256, validate_source_binding,
)


class ExactBindingTests(unittest.TestCase):
    def setUp(self):
        self.source = b"diff --git a/a.py b/a.py\n+exact evidence statement\n"
        self.decision = {"finding_id": "C000F000", "decision": "DISPUTED",
                         "rationale": "This source makes the stated blocker inapplicable.",
                         "source_quote": "exact evidence statement",
                         "source_id": sha256(self.source)}

    def reject(self, subclass, *, source=None, **changes):
        with self.assertRaises(SourceBindingError) as caught:
            validate_source_binding(dict(self.decision, **changes),
                                    self.source if source is None else source)
        self.assertEqual(caught.exception.details["error_subclass"], subclass)

    def test_01_unique_ascii(self):
        bound = validate_source_binding(self.decision, self.source)
        self.assertEqual(self.source[bound["quote_start"]:bound["quote_end"]],
                         self.decision["source_quote"].encode())
        self.assertEqual(bound["validation"], "EXACT_UNIQUE_UTF8")

    def test_02_unique_multibyte_utf8(self):
        source = "header\n+证据明确存在\n".encode()
        bound = validate_source_binding(dict(self.decision, source_id=sha256(source),
                                             source_quote="证据明确存在"), source)
        self.assertEqual((bound["quote_start"], bound["quote_end"]),
                         (len("header\n+".encode()), len("header\n+证据明确存在".encode())))

    def test_03_repeated_quote(self):
        source = b"exact evidence statement|exact evidence statement"
        self.reject("QUOTE_AMBIGUOUS", source=source, source_id=sha256(source))

    def test_04_empty_quote(self): self.reject("QUOTE_TOO_SHORT", source_quote="")
    def test_05_wrong_source_id(self): self.reject("SOURCE_ID_MISMATCH", source_id="0" * 64)

    def test_06_cross_group(self):
        other = b"another group's exact evidence statement"
        self.reject("SOURCE_ID_MISMATCH", source=other)

    def test_07_cross_source_id(self): self.reject("SOURCE_ID_MISMATCH", source_id=sha256(b"other"))

    def test_08_crlf_lf(self): self.reject("QUOTE_NOT_EXACT", source_quote="exact evidence\r\nstatement")
    def test_09_rewritten_quote(self): self.reject("QUOTE_NOT_EXACT", source_quote="exact evidence statements")

    def test_10_source_hash_changed(self): self.reject("SOURCE_ID_MISMATCH", source=self.source+b"x")

    def test_11_original_source_absent(self):
        with self.assertRaises(SourceBindingError) as caught:
            validate_source_binding(self.decision, None)
        self.assertEqual(caught.exception.details["error_subclass"], "SOURCE_UNAVAILABLE")

    def test_12_old_model_offset_is_rejected(self): self.reject("INVALID_REFERENCE_FIELDS", quote_start=42634, quote_end=42689)

    def test_13_request_286_reconstructed_hash_only(self):
        quote = b'if not allow_disputes and item["decision"] != "UPHELD":'
        self.assertEqual(hashlib.sha256(quote).hexdigest(),
                         "5f90d110781789b4767978f94c10b9ab9f2c11b23e17de5e00b3271c61536022")
        source = b"x" * 40947 + quote + b"z" * 1700
        bound = validate_source_binding(dict(self.decision, source_quote=quote.decode(),
                                             source_id=sha256(source)), source)
        self.assertEqual((bound["quote_start"], bound["quote_end"]), (40947, 41002))
        self.assertNotEqual((bound["quote_start"], bound["quote_end"]), (42634, 42689))

    def test_14_request_324_reconstructed_hash_only(self):
        quote = b'item["finding_sha256"] != digest(canon(source))'
        self.assertEqual(hashlib.sha256(quote).hexdigest(),
                         "006c2a49cf281a6b53ed7f0bee41706548b5f16c35bb83f18863a6bdefe57deb")
        source = b"x" * 40450 + quote + b"z" * 1700
        bound = validate_source_binding(dict(self.decision, source_quote=quote.decode(),
                                             source_id=sha256(source)), source)
        self.assertEqual((bound["quote_start"], bound["quote_end"]), (40450, 40497))
        self.assertNotEqual((bound["quote_start"], bound["quote_end"]), (41660, 41708))

    def test_15_unknown_finding_rejected(self):
        expected = [{"finding_id": "C000F000", "severity": "P1",
                     "finding": {"severity": "P1", "title": "issue", "evidence": "a.py:2"}}]
        raw = json.dumps({"findings": [], "decisions": [dict(self.decision, finding_id="C999F999")],
                          "summary": "A sufficiently specific source review summary is present."})
        with self.assertRaisesRegex(ValueError, "unknown disposition"):
            parse_synthesis(raw, expected, source=self.source, structured_evidence=True)

    def test_16_different_finding_cannot_reuse_quote(self):
        expected = [{"finding_id": name, "severity": "P1",
                     "finding": {"severity": "P1", "title": "issue", "evidence": "a.py:2"}}
                    for name in ("C000F000", "C000F001")]
        raw = json.dumps({"findings": [], "decisions": [self.decision,
                          dict(self.decision, finding_id="C000F001")],
                          "summary": "A sufficiently specific source review summary is present."})
        with self.assertRaises(SourceBindingError) as caught:
            parse_synthesis(raw, expected, source=self.source, structured_evidence=True)
        self.assertEqual(caught.exception.details["error_subclass"], "EVIDENCE_REUSED")

    def test_17_signed_contract_required_for_formal_mission(self):
        with patch.dict(os.environ, {}, clear=True), self.assertRaisesRegex(ValueError, "required"):
            contract_authorization_identity(FORMAL_MISSION_ID)

    def test_18_contract_signature_and_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            key = root / "key"; key.write_bytes(b"test-signing-key"); key.chmod(0o600)
            payload = {"version": "cmh-source-binding-contract-authorization/v1",
                       "mission_id": FORMAL_MISSION_ID,
                       "new_contract": "model_submitted_verbatim_quote_and_source_id; machine_derived_unique_exact_utf8_range",
                       "resource_limits_unchanged": True,
                       "chunk_cross_identity_migration_authorized": False,
                       "historical_requests_286_324_unchanged": True,
                       "historical_failures_not_pass": True}
            approval = root / "approval.json"
            approval.write_bytes(auth_canonical(sign_authorization(payload, key.read_bytes())))
            approval.chmod(0o600)
            env = {"CMH_SOURCE_BINDING_AUTHORIZATION": str(approval),
                   "CMH_RESOURCE_GATE_KEY_FILE": str(key),
                   "CMH_SOURCE_BINDING_AUTH_SHA256": sha256(approval.read_bytes())}
            with patch.dict(os.environ, env):
                self.assertEqual(contract_authorization_identity(FORMAL_MISSION_ID),
                                 env["CMH_SOURCE_BINDING_AUTH_SHA256"])
                approval.write_bytes(approval.read_bytes()+b"x")
                with self.assertRaises(ValueError):
                    contract_authorization_identity(FORMAL_MISSION_ID)


if __name__ == "__main__": unittest.main()
