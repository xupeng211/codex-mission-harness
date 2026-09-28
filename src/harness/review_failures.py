"""Shared, fail-closed reviewer failure classifications and diagnostics."""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Iterable


class ReviewFailureClassification(str, Enum):
    """Semantic failure classes shared by all independent reviewer lanes."""

    TRANSIENT_TRANSPORT = "TRANSIENT_TRANSPORT"
    TRANSIENT_CAPACITY = "TRANSIENT_CAPACITY"
    AUTHENTICATION_FAILURE = "AUTHENTICATION_FAILURE"
    PAYMENT_OR_BILLING_FAILURE = "PAYMENT_OR_BILLING_FAILURE"
    MODEL_UNAVAILABLE_OR_UNSUPPORTED = "MODEL_UNAVAILABLE_OR_UNSUPPORTED"
    POLICY_OR_CONTRACT_FAILURE = "POLICY_OR_CONTRACT_FAILURE"
    INVALID_REVIEWER_OUTPUT = "INVALID_REVIEWER_OUTPUT"
    UNKNOWN_EXTERNAL_FAILURE = "UNKNOWN_EXTERNAL_FAILURE"

    @property
    def retryable(self) -> bool:
        return self in {
            ReviewFailureClassification.TRANSIENT_TRANSPORT,
            ReviewFailureClassification.TRANSIENT_CAPACITY,
        }


@dataclass(frozen=True)
class ReviewFailureDetails:
    classification: ReviewFailureClassification
    reason_code: str
    sanitized_diagnostic: str
    http_status: int | None = None
    provider_error_code: str | None = None

    @property
    def retryable(self) -> bool:
        return self.classification.retryable


_STATUS_PATTERNS = (
    re.compile(r"(?i)\bHTTP(?:/\d(?:\.\d)?)?\s+([1-5]\d\d)\b"),
    re.compile(r"(?i)\b(?:http_?status|status(?:_code)?|statusCode)\s*[:=]\s*([1-5]\d\d)\b"),
)
_SAFE_PROVIDER_CODES = (
    "token_revoked", "authentication_error", "invalid_api_key", "invalid_authentication",
    "payment_required", "billing_error", "insufficient_quota", "rate_limit_error",
    "overloaded_error", "model_not_found", "unsupported_model", "model_unavailable",
    "invalid_request_error", "etimedout", "econnreset", "econnrefused", "econnaborted",
    "websocket_error", "service_unavailable",
)


def _http_status(text: str) -> int | None:
    for pattern in _STATUS_PATTERNS:
        match = pattern.search(text)
        if match:
            return int(match.group(1))
    # Common structured JSON spelling: {"status": 429}.
    match = re.search(r'(?i)["\'](?:status|status_code|http_status)["\']\s*:\s*([1-5]\d\d)\b', text)
    status = int(match.group(1)) if match else None
    return status if status is not None and 100 <= status <= 599 else None


def _provider_code(text: str) -> str | None:
    folded = text.casefold()
    for code in _SAFE_PROVIDER_CODES:
        if re.search(rf"(?<![a-z0-9_]){re.escape(code)}(?![a-z0-9_])", folded):
            return code
    return None


def classify_review_failure(values: Iterable[str]) -> ReviewFailureDetails:
    """Classify only known signals and emit a bounded, non-echoing diagnostic.

    The input may contain untrusted provider output. It is inspected in memory,
    but none of it is returned. Diagnostics and provider codes are normalized
    from allowlisted categories.
    """
    text = "\n".join(value for value in values if isinstance(value, str))
    folded = text.casefold()
    status = _http_status(text)
    provider_code = _provider_code(text)

    if status in {401, 403} or provider_code in {
            "token_revoked", "authentication_error", "invalid_api_key", "invalid_authentication"} \
            or any(marker in folded for marker in (
                "unauthorized", "authentication failed", "invalid api key", "invalid authentication",
                "token revoked", "token_revoked", "authentication file missing",
                "authentication file must", "canonical codex auth file", "codex authentication",
                "reviewer was not authenticated", "canonical reviewer 未建立")) \
            or folded.strip() == "401":
        classification = ReviewFailureClassification.AUTHENTICATION_FAILURE
        reason, diagnostic = "authentication_rejected", "provider rejected reviewer authentication"
    elif status == 402 or provider_code in {
            "payment_required", "billing_error", "insufficient_quota"} \
            or any(marker in folded for marker in (
                "payment required", "billing error", "billing failure", "payment required",
                "insufficient_quota", "payment method", "billing issue")):
        classification = ReviewFailureClassification.PAYMENT_OR_BILLING_FAILURE
        reason, diagnostic = "payment_or_billing_required", "provider requires payment or billing recovery"
    elif provider_code in {"model_not_found", "unsupported_model", "model_unavailable"} \
            or any(marker in folded for marker in (
                "unsupported model", "unrecognized model", "unknown model", "model not found",
                "model_not_found", "model not supported", "model unsupported", "model does not exist",
                "model is not supported", "not supported for model", "model unavailable",
                "model_unavailable")):
        classification = ReviewFailureClassification.MODEL_UNAVAILABLE_OR_UNSUPPORTED
        reason, diagnostic = "model_unavailable", "requested reviewer model is unavailable or unsupported"
    elif status in {429, 529} or provider_code in {"rate_limit_error", "overloaded_error"} \
            or any(marker in folded for marker in (
                "selected model is at capacity", "model at capacity", "at capacity", "overloaded",
                "rate_limit", "rate limit", "too many requests")):
        classification = ReviewFailureClassification.TRANSIENT_CAPACITY
        reason, diagnostic = "provider_capacity", "provider capacity is temporarily unavailable"
    elif status == 408 or (status is not None and 500 <= status <= 599) or provider_code in {
            "etimedout", "econnreset", "econnrefused", "econnaborted", "websocket_error",
            "service_unavailable"} \
            or any(marker in folded for marker in (
                "request timeout", "timed out", "timeout", "etimedout", "connection reset",
                "econnreset", "connection refused", "econnrefused", "connection closed",
                "websocket", "tls handshake", "ssl error", "https transport", "reconnect",
                "service unavailable", "server disconnected", "socket hang up", "network error")):
        classification = ReviewFailureClassification.TRANSIENT_TRANSPORT
        reason, diagnostic = "transport_interrupted", "reviewer provider transport was interrupted"
    elif status == 400 or any(marker in folded for marker in (
            "invalid_request", "review contract", "receipt missing", "receipt validation",
            "challenge mismatch", "policy refusal", "policy failure",
            "unrecognized argument", "unrecognized option", "unknown argument", "unknown option",
            "unexpected argument", "invalid command-line", "invalid cli argument",
            "configuration error", "failed to parse configuration", "failed to load configuration",
            "unknown configuration key", "invalid configuration")):
        classification = ReviewFailureClassification.POLICY_OR_CONTRACT_FAILURE
        reason, diagnostic = "review_contract_rejected", "review request or receipt contract was rejected"
    elif any(marker in folded for marker in (
            "invalid reviewer output", "invalid json", "malformed json", "output schema",
            "schema validation", "structured output")):
        classification = ReviewFailureClassification.INVALID_REVIEWER_OUTPUT
        reason, diagnostic = "invalid_reviewer_output", "reviewer response did not match the required output schema"
    else:
        classification = ReviewFailureClassification.UNKNOWN_EXTERNAL_FAILURE
        reason, diagnostic = "unclassified_external_failure", "reviewer failure did not match a known safe diagnostic"

    if status is not None:
        diagnostic = f"provider returned HTTP {status}; {diagnostic}"
    return ReviewFailureDetails(classification, reason, diagnostic, status, provider_code)
