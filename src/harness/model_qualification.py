"""Reusable semantic qualification contract for a configured reviewer model.

Local contract tests and actual provider qualification are deliberately distinct.
Only responses from ``qualify_live`` can yield a live qualification certificate.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import subprocess
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .model_registry import ModelSpec
from .openai_invocation import invoke_openai, InvocationFailure, InvocationResult
from .resource_gate import ResourceGateDenied, FundingPause, model_request
from .reviewer_v2_contract import bind_findings, parse_synthesis, FINDING_GUIDANCE, SUPPLIED_CLAIM_GUIDANCE

QUALIFICATION_VERSION = "cmh-model-qualification/v5"


@dataclass(frozen=True)
class QualificationCase:
    name: str
    source: str
    findings: tuple[dict[str, str], ...]
    expected: dict[str, str]


CASES = (
    QualificationCase("clean", "def total(a, b):\n    return a + b\n", (), {}),
    QualificationCase("single_blocker", "def total(a, b):\n    return a - b\n",
                      ({"severity": "P1",
                        "title": "Subtraction violates total contract",
                        "evidence": "line 2 returns a - b"},), {"F1": "UPHELD"}),
    QualificationCase("source_based_dispute", "def total(a, b):\n    return a + b\n",
                      ({"severity": "P1",
                        "title": "Function subtracts", "evidence": "claimed line 2"},),
                      {"F1": "DISPUTED"}),
    QualificationCase("multiple_blockers", "def total(a, b):\n    return a - b\n\ndef always_true():\n    return False\n",
                      ({"severity": "P1", "title": "Wrong operator",
                        "evidence": "line 2 subtracts"},
                       {"severity": "P2", "title": "Always true returns false",
                        "evidence": "line 5 returns False"}),
                      {"F1": "UPHELD", "F2": "UPHELD"}),
)


def expected_findings(case: QualificationCase) -> list[dict]:
    return bind_findings(list(case.findings), "F", 0)


def qualification_prompt(case: QualificationCase) -> str:
    return (FINDING_GUIDANCE + SUPPLIED_CLAIM_GUIDANCE
            + "In this isolated Qualification, the review context supplies the behavioral "
            "contract asserted by each supplied finding's title and evidence for checking "
            "the fixture. That context establishes applicability of the stated contract, "
            "not truth of the claimed defect: independently verify the actual source behavior. "
            "Do not demand another declaration of that contract inside the source. This "
            "context does not authorize inventing additional external requirements. "
            + "Review this isolated qualification fixture. Treat each supplied finding's title and "
            "evidence as the claimed contract to check against the source; do not require a "
            "separate prose contract. Return only JSON with key decisions: "
            "an array of {finding_id, decision, rationale, source_quote}, plus findings "
            "(an array of newly discovered severity/title/evidence objects), and summary "
            "(at least 32 characters). Decide UPHELD or DISPUTED "
            "from the source. For DISPUTED, source_quote must be an exact source substring "
            "of at least 12 characters; for UPHELD use an empty source_quote. "
            "Include every finding exactly once. Do not use tools.\n"
            f"SOURCE:\n{case.source}\nFINDINGS:\n"
            f"{json.dumps(expected_findings(case), sort_keys=True)}")


class QualificationEvidence:
    """Private, append-only raw evidence; never grants a qualification receipt."""

    def __init__(self, directory: Path, *, resume: bool = False):
        self.directory = Path(directory)
        if not self.directory.is_absolute() or self.directory.is_symlink():
            raise ValueError("qualification diagnostics require an absolute non-symlink path")
        parent = self.directory.parent.stat()
        if parent.st_uid != os.getuid() or stat.S_IMODE(parent.st_mode) & 0o077:
            raise ValueError("qualification diagnostic parent must be private")
        self.directory.mkdir(mode=0o700, exist_ok=resume)
        info = self.directory.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or
                stat.S_IMODE(info.st_mode) != 0o700):
            raise ValueError("qualification diagnostics require a private directory")

    def _write(self, name: str, data: bytes):
        if name.split(".")[0] not in {case.name for case in CASES} or len(data) > 262_144:
            raise ValueError("qualification diagnostic name or size invalid")
        path = self.directory / name
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
        except BaseException:
            path.unlink(missing_ok=True)
            raise

    def capture_transport(self, case_name: str, stdout: bytes, stderr: bytes, returncode: int):
        self._write(case_name + ".stdout", stdout)
        self._write(case_name + ".stderr", stderr)
        self._write(case_name + ".transport.json", json.dumps({
            "returncode": returncode, "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
            "stderr_sha256": hashlib.sha256(stderr).hexdigest()}, sort_keys=True).encode())

    def record_case(self, case_name: str, record: dict):
        reservation = self.directory / (case_name + ".reservation.json")
        if reservation.exists():
            details = json.loads(reservation.read_bytes())
            record["resource_request_id"] = details["request_id"]
            ledger_path = os.environ.get("CMH_RESOURCE_LEDGER")
            if ledger_path:
                rows = json.loads(Path(ledger_path).read_bytes()).get("requests", [])
                matching = [row for row in rows if row.get("request_id") == details["request_id"]]
                if len(matching) == 1:
                    record["resource_request_number"] = matching[0]["number"]
                    record["invocation_usage"] = matching[0].get("reported_usage")
                    record["resource_status"] = matching[0].get("status")
        self._write(case_name + ".json", json.dumps(record, sort_keys=True,
                                                     ensure_ascii=False).encode() + b"\n")
        files = sorted(path for path in self.directory.iterdir()
                       if path.is_file() and path.name != "checkpoint.json")
        checkpoint = {"version": "cmh-qualification-diagnostics/v1",
                      "files": {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                                for path in files}, "last_case": case_name,
                      "last_verdict": record["verdict"]}
        pending = self.directory / ".checkpoint.pending"
        descriptor = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(json.dumps(checkpoint, sort_keys=True).encode() + b"\n")
            stream.flush(); os.fsync(stream.fileno())
        os.replace(pending, self.directory / "checkpoint.json")
        directory_fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)

    def capture_reservation(self, case_name: str, request_id: str):
        previous = self.directory / (case_name + ".reservation.json")
        if previous.exists():
            from .resource_gate import _private
            from . import formal_delivery_gate as gate
            old_id = json.loads(_private(previous))['request_id']
            auth = gate.load_authorization()
            ledger = gate._verify_child(Path(auth['ledger_path']),
                _private(Path(os.environ['CMH_RESOURCE_GATE_KEY_FILE'])), auth)
            old = next((r for r in ledger['requests'] if r['request_id'] == old_id), {})
            if not gate._capacity_paused_request(old) or old_id == request_id:
                raise ResourceGateDenied('only accounted subscription-pause evidence permits a new case attempt')
            # Keep failed attempt evidence; never overwrite it or completed cases.
            for suffix in ('reservation.json', 'stdout', 'stderr', 'transport.json'):
                source = self.directory / (case_name + '.' + suffix)
                if source.exists():
                    _private(source)
                    archive = self.directory / (case_name + '.capacity-pause-' + old_id + '.' + suffix)
                    os.link(source, archive, follow_symlinks=False)
                    source.unlink()
        self._write(case_name + ".reservation.json",
                    json.dumps({"request_id": request_id}, sort_keys=True).encode() + b"\n")

    def capture_prompt(self, case_name: str, prompt: str):
        path = self.directory / (case_name + ".prompt")
        if path.exists():
            from .resource_gate import _private
            if _private(path) != prompt.encode("utf-8"):
                raise ResourceGateDenied("qualification prompt changed on funding resume")
        else:
            self._write(case_name + ".prompt", prompt.encode("utf-8"))

    def delivery_progress(self, spec, record=None):
        """Authenticate reuse against the existing signed resource checkpoint."""
        from . import formal_delivery_gate as gate
        from .resource_gate import _locked, _private, digest, canonical
        auth = gate.load_authorization()
        key = _private(Path(os.environ['CMH_RESOURCE_GATE_KEY_FILE']))
        path = Path(auth['ledger_path'])
        run_id = os.environ['CMH_RESOURCE_RUN_ID']
        if spec.identity() != auth['runtime']['models'][spec.provider]:
            raise ResourceGateDenied('qualification progress model differs from signed runtime')
        name = spec.provider + '/' + run_id
        with _locked(path.with_name(path.name + '.lock')):
            ledger = gate._verify_child(path, key, auth)
            identity = dict(gate.qualification_binding(auth), model=spec.identity(),
                            evidence_directory=str(self.directory), run_id=run_id)
            entry = ledger.get('qualification_progress', {}).get(name, {'identity': identity, 'cases': []})
            if entry['identity'] != identity:
                raise ResourceGateDenied('qualification resume execution identity changed')
            rows = [r for r in ledger['requests'] if r['provider'] == spec.provider and
                    r['stage'] == 'qualification-case' and r['authorization_sha256'] == auth['_authorization_sha256']]
            if any(r['run_id'] != run_id for r in rows):
                raise ResourceGateDenied('qualification capacity pause belongs to a different run')
            if spec.provider == 'openai':
                rows = [r for r in rows if not gate._capacity_paused_request(r)]
            if any(r['run_id'] != run_id or r.get('status') != 'RETURNED' or
                   r.get('usage_accounting') != 'FULL_RESERVATION_RETAINED' for r in rows):
                raise ResourceGateDenied('qualification resume cannot reuse failed, unknown or other-run requests')
            result = []
            for i, item in enumerate(entry['cases']):
                raw = _private(self.directory / (CASES[i].name + '.json'))
                value = json.loads(raw)
                if (digest(raw) != item['sha256'] or value['resource_request_id'] != rows[i]['request_id']
                        or value['model_identity'] != spec.identity() or value['verdict'] != 'PASS'):
                    raise ResourceGateDenied('qualification progress artifact or reservation changed')
                result.append(value)
            if record is not None:
                i = len(result)
                if (i >= len(CASES) or record['case_id'] != CASES[i].name or record['verdict'] != 'PASS'
                        or len(rows) != i + 1 or record['resource_request_id'] != rows[i]['request_id']):
                    raise ResourceGateDenied('qualification progress must commit exactly the next successful call')
                entry['cases'].append({'sha256': digest(_private(self.directory / (CASES[i].name + '.json')))})
                ledger.setdefault('qualification_progress', {})[name] = entry
                gate._write_child(path, ledger, key)
            elif len(rows) != len(result):
                raise ResourceGateDenied('uncommitted qualification request cannot be replayed')
            return result


@dataclass(frozen=True)
class QualificationResult:
    identity: dict[str, str | None]
    mode: str
    cases_passed: tuple[str, ...]
    cases_failed: tuple[str, ...]
    response_sha256: tuple[str, ...]

    @property
    def passed(self) -> bool:
        return self.mode == "real_provider" and not self.cases_failed \
            and len(self.cases_passed) == len(CASES)


def _evaluate_cases(spec: ModelSpec, invoke: Callable[[ModelSpec, str], str], *,
                    mode: str, evidence: QualificationEvidence | None = None) -> QualificationResult:
    """Evaluate responses from an invoker; injected invokers cannot certify a model.

    This function does not retry or substitute a model. A provider failure or
    missing/invalid response fails that case and preserves the model identity.
    """
    passed, failed, hashes = [], [], []
    from .formal_delivery_gate import NEW_MISSION, is_delivery_mission
    resumable = mode == "real_provider" and is_delivery_mission(os.environ.get('CMH_RESOURCE_MISSION_ID'))
    if resumable and evidence is None:
        raise ResourceGateDenied('delivery qualification requires durable evidence')
    completed = evidence.delivery_progress(spec) if resumable else []
    result_mode = mode
    if resumable:
        from .formal_delivery_gate import load_authorization
        if load_authorization()['evidence_domain'] != 'FORMAL':
            result_mode = 'offline_delivery_fixture'
    for index, case in enumerate(CASES):
        prompt = qualification_prompt(case)
        if evidence is not None:
            evidence.capture_prompt(case.name, prompt)
        reused = index < len(completed)
        paused = False
        record = {"case_id": case.name, "model_identity": spec.identity(), "mode": mode,
                  "prompt": prompt, "prompt_sha256": hashlib.sha256(prompt.encode()).hexdigest(),
                  "source": case.source, "expected_findings": expected_findings(case),
                  "expected_decisions": case.expected, "structured_output_raw": None,
                  "structured_output_sha256": None, "parsed_result": None,
                  "resource_request_id": None, "invocation_usage": None,
                  "parser_result": "UNKNOWN", "source_binding_result": "UNKNOWN",
                  "failure_phase": None,
                  "exact_failure_reason": None, "verdict": "FAIL"}
        try:
            record["failure_phase"] = "INVOCATION"
            raw = completed[index]["structured_output_raw"] if reused else invoke(spec, prompt)
            if isinstance(raw, InvocationResult):
                record["resource_request_id"] = raw.evidence.get("resource_request_id")
                record["invocation_usage"] = raw.evidence.get("usage")
                raw = raw.response
            record["structured_output_raw"] = raw
            record["structured_output_sha256"] = hashlib.sha256(raw.encode()).hexdigest()
            record["failure_phase"] = "PARSER_OR_SOURCE_BINDING"
            if mode == "real_provider" and spec.provider == "deepseek":
                from .deepseek_direct import validate_envelope
                validate_envelope(raw, schema=_SCHEMA, prompt=prompt)
            bound = parse_synthesis(raw, expected_findings(case), source=case.source.encode())
            record["parsed_result"] = bound
            record["parser_result"] = "PASS"
            record["source_binding_result"] = "PASS"
            record["failure_phase"] = "QUALIFICATION_VERDICT"
            decisions = {item["finding_id"]: item["decision"] for item in bound["decisions"]}
            expected = {expected_findings(case)[int(key[1:])-1]["finding_id"]: value
                        for key, value in case.expected.items()}
            if decisions != expected or bound["new_findings"]:
                raise ValueError("semantic decision mismatch")
        except InvocationFailure as exc:
            record["exact_failure_reason"] = str(exc)
            # One failed provider invocation already invalidates the whole
            # certificate. Do not repeat an auth failure or stalled turn for
            # every remaining fixture.
            failed.append(case.name)
            break
        except FundingPause:
            paused = True
            raise
        except ResourceGateDenied:
            raise
        except (ValueError, RuntimeError, TimeoutError, subprocess.TimeoutExpired) as exc:
            record["exact_failure_reason"] = str(exc)
            record["error_class"] = type(exc).__name__
            failed.append(case.name)
            if mode == "real_provider":
                break
        except (KeyboardInterrupt, SystemExit) as exc:
            record["failure_phase"] = "INTERRUPTED"
            record["error_class"] = type(exc).__name__
            record["exact_failure_reason"] = "qualification interrupted"
            raise
        else:
            record["failure_phase"] = None
            record["verdict"] = "PASS"
            passed.append(case.name)
            hashes.append(hashlib.sha256(raw.encode("utf-8")).hexdigest())
        finally:
            if evidence is not None and not reused and not paused:
                evidence.record_case(case.name, record)
                if resumable and record['verdict'] == 'PASS':
                    evidence.delivery_progress(spec, record)
    return QualificationResult(spec.identity(), result_mode, tuple(passed),
                               tuple(failed), tuple(hashes))


def evaluate_cases(spec: ModelSpec, invoke: Callable[[ModelSpec, str], str], *,
                   evidence: QualificationEvidence | None = None) -> QualificationResult:
    """Exercise deterministic fixtures; this result can never certify a provider."""
    return _evaluate_cases(spec, invoke, mode="deterministic_fixture", evidence=evidence)


_SCHEMA = {"type": "object", "properties": {"decisions": {"type": "array", "items": {
    "type": "object", "properties": {
        "finding_id": {"type": "string"},
        "decision": {"type": "string", "enum": ["UPHELD", "DISPUTED"]},
        "rationale": {"type": "string"}, "source_quote": {"type": "string"}},
    "required": ["finding_id", "decision", "rationale", "source_quote"],
    "additionalProperties": False}}, "findings": {"type": "array", "items": {"type": "object",
    "properties": {"severity": {"type": "string", "enum": ["P0", "P1", "P2", "P3"]},
                   "title": {"type": "string"}, "evidence": {"type": "string"}},
    "required": ["severity", "title", "evidence"], "additionalProperties": False}},
    "summary": {"type": "string"}},
    "required": ["decisions", "findings", "summary"], "additionalProperties": False}


def _actual_provider_invoke_unmetered(spec: ModelSpec, prompt: str, *, token: str | None,
                            timeout: int, transport_sink=None) -> str | InvocationResult:
    """One bounded, noninteractive call to the exact configured model."""
    from .formal_delivery_gate import require_active_transport
    require_active_transport(spec.provider, spec.model)
    from .formal_delivery_gate import bounded_delivery_timeout
    timeout = bounded_delivery_timeout(timeout)
    if spec.provider == "deepseek":
        from .formal_delivery_gate import require_provider_credential
        require_provider_credential("deepseek", token.encode() if isinstance(token, str) else b"")
    if spec.provider == "openai":
        return invoke_openai(prompt, spec, _SCHEMA, timeout=timeout)
    if spec.provider == "deepseek":
        from . import deepseek_direct as direct
        if token is None:
            raise ValueError("DeepSeek qualification token missing")
        try:
            raw = direct.invoke(prompt, token, _SCHEMA, timeout=timeout)
        except direct.DirectFailure as exc:
            if transport_sink is not None:
                transport_sink(b"", exc.code.encode(), 1)
            raise RuntimeError("DeepSeek qualification Direct invocation failed") from None
        if transport_sink is not None:
            transport_sink(raw, b"", 0)
        envelope = direct.validate_envelope(raw, schema=_SCHEMA, prompt=prompt)
        return InvocationResult(raw.decode(), {"usage": envelope["direct_completion"]["usage"],
                                "provider_route": "DIRECT_DEEPSEEK_API"})

    raise ValueError("unsupported provider")


def _actual_provider_invoke(spec: ModelSpec, prompt: str, *, token: str | None,
                            timeout: int, transport_sink=None,
                            reservation_sink=None) -> str | InvocationResult:
    from .formal_delivery_gate import require_invocation_spec
    require_invocation_spec(spec)
    # Codex's lower-level invocation sees the active reservation and does not
    # append a second logical call for the same qualification case.
    with model_request(provider=spec.provider, model=spec.model, prompt=prompt.encode(),
                       stage="qualification-case") as reservation:
        if reservation_sink is not None:
            reservation_sink(reservation.request_id)
        result = _actual_provider_invoke_unmetered(spec, prompt, token=token, timeout=timeout,
                                                   transport_sink=transport_sink)
        if isinstance(result, InvocationResult):
            usage = result.evidence.get("usage")
            if isinstance(usage, dict):
                from .resource_gate import normalize_deepseek_usage, normalize_direct_deepseek_usage
                reservation.observe(usage if spec.provider == "openai" else
                    normalize_direct_deepseek_usage(usage)
                    if result.evidence.get("provider_route") == "DIRECT_DEEPSEEK_API" else
                    normalize_deepseek_usage(usage, result.evidence.get("cli_reported_cost_usd")))
            return InvocationResult(result.response, dict(result.evidence,
                                                         resource_request_id=reservation.request_id))
        return result


def qualify_live(spec: ModelSpec, *, token_file: str | Path | None = None,
                 timeout: int = 120, evidence_dir: Path | None = None) -> QualificationResult:
    """Run actual provider calls after noninteractive auth validation."""
    from .model_registry import preflight, read_private_token

    from .formal_delivery_gate import NEW_MISSION, is_delivery_mission, load_authorization, qualification_binding
    if is_delivery_mission(os.environ.get('CMH_RESOURCE_MISSION_ID')):
        from .resource_gate import digest, canonical
        auth = load_authorization()
        if auth.get('fresh_task'):
            from .fresh_task import qualification_evidence_path
            if evidence_dir != qualification_evidence_path(auth, spec.provider):
                raise ResourceGateDenied('fresh qualification needs its own evidence namespace')
        if evidence_dir is None or not Path(evidence_dir).is_absolute():
            raise ResourceGateDenied('delivery qualification requires a fixed private evidence directory')
        # The CLI normally chooses a fresh UUID. Funding continuation instead
        # retains this exact execution+directory identity, without CLI changes.
        os.environ['CMH_RESOURCE_RUN_ID'] = digest(canonical(dict(
            qualification_binding(auth), model=spec.identity(), directory=str(evidence_dir))))
    preflight(spec, token_file=token_file)
    token = read_private_token(Path(token_file)) if token_file else None
    from .formal_delivery_gate import NEW_MISSION, is_delivery_mission
    evidence = QualificationEvidence(evidence_dir, resume=is_delivery_mission(os.environ.get('CMH_RESOURCE_MISSION_ID'))) \
        if evidence_dir is not None else None
    return _evaluate_cases(spec,
                           lambda actual, prompt: _actual_provider_invoke(
                               actual, prompt, token=token, timeout=timeout,
                               transport_sink=(lambda stdout, stderr, code:
                                   evidence.capture_transport(next(case.name for case in CASES
                                       if qualification_prompt(case) == prompt), stdout, stderr, code))
                               if evidence is not None and actual.provider == "deepseek" else None,
                               reservation_sink=(lambda request_id:
                                   evidence.capture_reservation(next(case.name for case in CASES
                                       if qualification_prompt(case) == prompt), request_id))
                               if evidence is not None else None),
                           mode="real_provider", evidence=evidence)


def qualification_receipt(result: QualificationResult, *, auth_key: str,
                          role: str, registry_path: str | Path | None = None) -> dict:
    """Build an integrity-bound record without storing model responses."""
    from .model_registry import load_registry
    from . import reviewer_v2_contract, openai_invocation, model_registry, codex, full_diff_manifest, deepseek_direct

    if not result.passed or not isinstance(auth_key, str) or not auth_key:
        raise ValueError("only a complete real-provider qualification can produce a receipt")
    code = Path(__file__).resolve()
    registry = load_registry(registry_path)
    if result.identity != registry.role(role).identity():
        raise ValueError("qualification identity is absent from selected registry")
    cli = code.parents[2] / "scripts" / "model_qualification.py"
    review_runner = code.parents[2] / 'scripts' / (
        'reviewer_v2_deepseek.py' if role == 'independent_reviewer' else
        'reviewer_v2_openai.py' if role == 'final_reviewer' else 'model_qualification.py')
    receipt = {"version": QUALIFICATION_VERSION, "role": role,
               "mode": result.mode, "identity": result.identity,
               "cases_passed": list(result.cases_passed),
               "response_sha256": list(result.response_sha256),
               "registry_sha256": hashlib.sha256(registry.path.read_bytes()).hexdigest(),
               "contract_sha256": hashlib.sha256(Path(reviewer_v2_contract.__file__).read_bytes()).hexdigest(),
               "runner_sha256": hashlib.sha256(code.read_bytes()).hexdigest(),
               "cli_runner_sha256": hashlib.sha256(cli.read_bytes()).hexdigest(),
               "invocation_sha256": hashlib.sha256((Path(deepseek_direct.__file__) if result.identity["provider"] == "deepseek" else Path(openai_invocation.__file__)).read_bytes()).hexdigest(),
               "builder_runtime_sha256": hashlib.sha256(Path(codex.__file__).read_bytes()).hexdigest(),
               "qualification_schema_sha256": hashlib.sha256(json.dumps(
                   _SCHEMA, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
               "registry_code_sha256": hashlib.sha256(Path(model_registry.__file__).read_bytes()).hexdigest(),
               "review_runner_sha256": hashlib.sha256(review_runner.read_bytes()).hexdigest(),
               "full_scope_contract_sha256": hashlib.sha256(Path(full_diff_manifest.__file__).read_bytes()).hexdigest(),
               "case_manifest_sha256": hashlib.sha256(json.dumps([
                   {'name': c.name, 'source': c.source, 'findings': c.findings, 'expected': c.expected}
                   for c in CASES], sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
               "authentication_identity": hmac.new(auth_key.encode(), b'cmh-qualification-auth/v1', hashlib.sha256).hexdigest()}
    from .formal_delivery_gate import NEW_MISSION, is_delivery_mission, load_authorization, qualification_binding
    if is_delivery_mission(os.environ.get("CMH_RESOURCE_MISSION_ID")):
        if result.mode != "real_provider" or role not in {"independent_reviewer", "final_reviewer"}:
            raise ValueError("offline qualification cannot issue a formal delivery receipt")
        receipt["delivery_binding"] = qualification_binding(load_authorization())
    receipt["integrity_sha256"] = hmac.new(auth_key.encode(),
        json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode(), hashlib.sha256).hexdigest()
    return receipt


def validate_qualification_receipt(path: str | Path, spec: ModelSpec, *, auth_key: str,
                                   role: str, registry_path: str | Path | None = None) -> dict:
    """Reject stale, incomplete, altered, or different-model qualification."""
    from .artifact_lineage import artifact_code_hash, qualification_history
    from .model_registry import load_registry
    from . import reviewer_v2_contract, openai_invocation, model_registry, codex, full_diff_manifest, deepseek_direct

    receipt_path = Path(path)
    if not receipt_path.is_absolute():
        raise ValueError("qualification receipt must use an absolute private path")
    descriptor = os.open(receipt_path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or not 0 < info.st_size <= 65_536):
            raise ValueError("qualification receipt must be private and bounded")
        payload = os.read(descriptor, info.st_size + 1)
        if len(payload) != info.st_size:
            raise ValueError("qualification receipt changed while reading")
    finally:
        os.close(descriptor)
    receipt = json.loads(payload)
    expected_keys = {"version", "role", "mode", "identity", "cases_passed", "response_sha256",
                     "registry_sha256", "contract_sha256", "runner_sha256", "cli_runner_sha256",
                     "invocation_sha256", "builder_runtime_sha256",
                     "qualification_schema_sha256", "registry_code_sha256", "full_scope_contract_sha256", "review_runner_sha256", "case_manifest_sha256", "authentication_identity", "integrity_sha256"}
    from .formal_delivery_gate import (NEW_MISSION, is_delivery_mission, load_authorization,
                                      validate_qualification_binding)
    if is_delivery_mission(os.environ.get("CMH_RESOURCE_MISSION_ID")):
        expected_keys.add("delivery_binding")
        validate_qualification_binding(receipt.get("delivery_binding"), load_authorization())
    if not isinstance(receipt, dict) or set(receipt) != expected_keys \
            or receipt["version"] != QUALIFICATION_VERSION \
            or receipt["role"] != role \
            or receipt["mode"] != "real_provider" or receipt["identity"] != spec.identity() \
            or receipt["cases_passed"] != [case.name for case in CASES] \
            or not isinstance(receipt["response_sha256"], list) \
            or len(receipt["response_sha256"]) != len(CASES) \
            or any(not isinstance(item, str) or len(item) != 64
                   or any(char not in "0123456789abcdef" for char in item)
                   for item in receipt["response_sha256"]):
        raise ValueError("invalid or mismatched model qualification receipt")
    registry = load_registry(registry_path)
    if spec.identity() != registry.role(role).identity():
        raise ValueError("qualification model is absent from selected registry")
    review_runner = Path(__file__).resolve().parents[2] / 'scripts' / (
        'reviewer_v2_deepseek.py' if role == 'independent_reviewer' else
        'reviewer_v2_openai.py' if role == 'final_reviewer' else 'model_qualification.py')
    hashes = {"full_scope_contract_sha256": Path(full_diff_manifest.__file__), "review_runner_sha256": review_runner, "registry_sha256": registry.path,
              "contract_sha256": Path(reviewer_v2_contract.__file__),
              "runner_sha256": Path(__file__),
              "cli_runner_sha256": Path(__file__).resolve().parents[2] / "scripts" / "model_qualification.py",
              "invocation_sha256": Path(deepseek_direct.__file__) if spec.provider == "deepseek" else Path(openai_invocation.__file__),
              "builder_runtime_sha256": Path(codex.__file__),
              "registry_code_sha256": Path(model_registry.__file__)}
    formal = is_delivery_mission(os.environ.get('CMH_RESOURCE_MISSION_ID'))
    if formal:
        qualification_history(receipt, load_authorization())
    if any(receipt[key] != (artifact_code_hash(file, receipt['delivery_binding']['authorization_sha256'])
                            if formal else hashlib.sha256(file.read_bytes()).hexdigest())
           for key, file in hashes.items()):
        raise ValueError("model qualification code or registry changed")
    if receipt["qualification_schema_sha256"] != hashlib.sha256(json.dumps(
            _SCHEMA, sort_keys=True, separators=(",", ":")).encode()).hexdigest():
        raise ValueError("model qualification schema changed")
    expected_cases = hashlib.sha256(json.dumps([
        {'name': c.name, 'source': c.source, 'findings': c.findings, 'expected': c.expected}
        for c in CASES], sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    if (receipt['case_manifest_sha256'] != expected_cases or receipt['authentication_identity'] !=
            hmac.new(auth_key.encode(), b'cmh-qualification-auth/v1', hashlib.sha256).hexdigest()):
        raise ValueError('qualification cases or authentication identity changed')
    unsigned = {key: value for key, value in receipt.items() if key != "integrity_sha256"}
    if not isinstance(auth_key, str) or not auth_key or not hmac.compare_digest(
            receipt["integrity_sha256"], hmac.new(auth_key.encode(),
            json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode(),
            hashlib.sha256).hexdigest()):
        raise ValueError("model qualification receipt integrity mismatch")
    return receipt


def require_builder_qualification(receipt_path: str | Path | None,
                                  auth_key_file: str | Path | None) -> dict:
    """Fail before any builder model process starts without its own certificate."""
    from .model_registry import load_registry, read_private_token
    if receipt_path is None or auth_key_file is None:
        raise ValueError("builder execution requires a builder qualification and auth key file")
    registry = load_registry()
    return validate_qualification_receipt(receipt_path, registry.role("builder"),
                                          auth_key=read_private_token(Path(auth_key_file)),
                                          role="builder")
