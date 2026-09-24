#!/usr/bin/env python3
"""Durable, exact-diff DeepSeek review for this repository only.

The caller supplies a token-file path at execution time; no credential is ever
stored in the mission, journal, receipt, or repository.  Receipt publication is
commit-last: an incomplete run has no receipt and is never an approval.
"""
from __future__ import annotations

import argparse, base64, hashlib, json, os, shutil, subprocess, sys, tempfile, time, uuid
from pathlib import Path

VERSION = "cmh-deepseek-review/v1"
MODEL = "deepseek-flash"
ENDPOINT = "https://api.deepseek.com/anthropic"
CHUNK_BYTES = 32000

SCHEMA = {"type":"object","additionalProperties":False,"required":["review_result","findings"],"properties":{"review_result":{"enum":["PASS","FAIL"]},"findings":{"type":"array","items":{"type":"object","additionalProperties":False,"required":["severity","title","evidence"],"properties":{"severity":{"enum":["P0","P1","P2","P3"]},"title":{"type":"string"},"evidence":{"type":"string"}}}}}}

def canon(value): return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
def digest(value): return hashlib.sha256(value).hexdigest()
def sha(path): return digest(Path(path).read_bytes())
def finding(value):
    return (isinstance(value,dict) and set(value)=={"severity","title","evidence"}
            and value.get("severity") in {"P0","P1","P2","P3"}
            and isinstance(value.get("title"),str) and bool(value["title"])
            and isinstance(value.get("evidence"),str) and bool(value["evidence"]))
def reviewer_result(raw):
    value=json.loads(raw); result=value.get("structured_output") or value.get("result") or value
    if (not isinstance(result,dict) or set(result)!={"review_result","findings"}
            or result.get("review_result") not in {"PASS","FAIL"}
            or not isinstance(result.get("findings"),list)
            or not all(finding(item) for item in result["findings"])): raise ValueError("invalid reviewer output")
    blocking=any(item["severity"] in {"P0","P1","P2"} for item in result["findings"])
    if (result["review_result"] == "PASS") != (not blocking): raise ValueError("reviewer verdict mismatch")
    return result
def git(root, *args): return subprocess.check_output(["git", "-C", str(root), *args])
def full_sha(value):
    if len(value) != 40 or any(c not in "0123456789abcdef" for c in value.lower()): raise ValueError("full SHA required")
    return value.lower()
def chunks(diff):
    if not diff: raise ValueError("empty diff is not reviewable")
    out=[]; start=0
    while start < len(diff):
        end=min(len(diff),start+CHUNK_BYTES); cut=diff.rfind(b"\n",start+1,end+1)
        if cut > start: end=cut+1
        source=diff[start:end]; out.append({"index":len(out),"start":start,"end":end,"sha256":digest(source)}) ; start=end
    return out
def validate(receipt, base, head, root=None, receipt_path=None, mission_id=None, repository=None):
    required={"version","repository","mission_id","base_sha","head_sha","diff_sha256","manifest_sha256","chunks","provider","model","command_sha256","review_result","findings","integrity_sha256"}
    optional={"started_at","completed_at"}
    if not isinstance(receipt,dict) or not required <= set(receipt) or set(receipt)-required-optional: raise ValueError("incomplete or unknown receipt fields")
    if receipt["version"] != VERSION or receipt["base_sha"] != base or receipt["head_sha"] != head: raise ValueError("receipt exact-head binding mismatch")
    if not isinstance(receipt["repository"],str) or not receipt["repository"] or not isinstance(receipt["mission_id"],str) or not receipt["mission_id"]: raise ValueError("invalid receipt identity")
    if mission_id is not None and receipt["mission_id"] != mission_id: raise ValueError("receipt mission binding mismatch")
    if repository is not None and receipt["repository"] != repository: raise ValueError("receipt repository binding mismatch")
    copy=dict(receipt); observed=copy.pop("integrity_sha256")
    if digest(canon(copy)) != observed: raise ValueError("receipt integrity mismatch")
    if (receipt["provider"] != "deepseek" or receipt["model"] != MODEL
            or not isinstance(receipt["command_sha256"],str) or len(receipt["command_sha256"])!=64): raise ValueError("reviewer provenance mismatch")
    chunks_=receipt["chunks"]
    if not isinstance(chunks_,list) or not chunks_ or [c.get("index") for c in chunks_ if isinstance(c,dict)] != list(range(len(chunks_))): raise ValueError("missing or duplicate chunks")
    position=0; aggregate=[]; descriptors=[]
    for chunk in chunks_:
        start,end=chunk.get("start"),chunk.get("end"); result=chunk.get("result")
        if not isinstance(start,int) or not isinstance(end,int) or start!=position or end<=start: raise ValueError("invalid chunk coverage")
        if not isinstance(chunk.get("sha256"),str) or len(chunk["sha256"])!=64: raise ValueError("invalid chunk identity")
        if not isinstance(chunk.get("output_sha256"),str) or len(chunk["output_sha256"])!=64: raise ValueError("invalid chunk output identity")
        reviewer_result(json.dumps(result))
        descriptors.append({"index":chunk["index"],"start":start,"end":end,"sha256":chunk["sha256"]})
        aggregate.extend(result["findings"]); position=end
    if aggregate != receipt["findings"]: raise ValueError("aggregate findings mismatch")
    if root is not None:
        diff=git(Path(root).resolve(),"diff","--no-ext-diff","--binary",f"{base}..{head}")
        if position!=len(diff) or digest(diff)!=receipt["diff_sha256"]: raise ValueError("receipt diff coverage mismatch")
        if descriptors!=chunks(diff): raise ValueError("chunk manifest does not match exact diff")
        manifest={"version":"cmh-deepseek-chunks/v1","base_sha":base,"head_sha":head,"diff_sha256":digest(diff),"chunks":descriptors}
        if digest(canon(manifest))!=receipt["manifest_sha256"]: raise ValueError("chunk manifest hash mismatch")
        if receipt_path is not None:
            evidence=Path(receipt_path).resolve().parent
            for chunk in chunks_:
                artifact=evidence/f"chunk-{chunk['index']:03d}.json"
                if not artifact.is_file() or sha(artifact)!=chunk["output_sha256"]: raise ValueError("chunk artifact mismatch")
                if reviewer_result(artifact.read_text())!=chunk["result"]: raise ValueError("chunk result does not match durable artifact")
    if receipt["review_result"] not in {"PASS", "FAIL"}:
        raise ValueError("invalid aggregate verdict")
    blocking=any(f.get("severity") in {"P0","P1","P2"} for f in aggregate)
    if (receipt["review_result"] == "PASS") != (not blocking): raise ValueError("aggregate verdict mismatch")
    return receipt
def prompt(base, head, diff_hash, manifest_hash, chunk, source):
    try: rendered="UTF-8 DIFF:\n"+source.decode("utf-8")
    except UnicodeDecodeError: rendered="BASE64-ENCODED EXACT DIFF BYTES:\n"+base64.b64encode(source).decode("ascii")
    return ("You are an independent restricted code reviewer. Do not use tools or filesystem. Return only JSON matching the schema. "
            "PASS only when P0/P1/P2 are absent.\n"
            f"Base={base}\nHead={head}\nDiffSHA256={diff_hash}\nManifestSHA256={manifest_hash}\n"
            f"Chunk={chunk['index']} range={chunk['start']}:{chunk['end']} SHA256={chunk['sha256']}\n"+rendered)

def invoke_reviewer(command, prompt_text, env, timeout):
    return subprocess.run(command+[prompt_text],env=env,capture_output=True,text=True,timeout=timeout)

def resolve_claude_launcher(root, path_value):
    """Resolve the owner-installed CLI without searching the reviewed tree or CWD."""
    repository=Path(root).resolve()
    safe_entries=[]
    for entry in path_value.split(os.pathsep):
        if not entry:
            continue
        candidate=Path(entry)
        if not candidate.is_absolute():
            continue
        try:
            directory=candidate.resolve(strict=True)
        except OSError:
            continue
        if (not directory.is_dir() or directory==repository or directory in repository.parents
                or repository in directory.parents):
            continue
        rendered=str(directory)
        if rendered not in safe_entries:
            safe_entries.append(rendered)
    safe_path=os.pathsep.join(safe_entries)
    if not safe_entries:
        raise ValueError("trusted absolute Claude Code launcher is unavailable")
    executable=shutil.which("claude",path=safe_path)
    if not executable or not Path(executable).is_absolute():
        raise ValueError("trusted absolute Claude Code launcher is unavailable")
    try:
        resolved=Path(executable).resolve(strict=True)
    except OSError as exc:
        raise ValueError("trusted absolute Claude Code launcher is unavailable") from exc
    if (not resolved.is_file() or not os.access(resolved,os.X_OK)
            or resolved==repository or repository in resolved.parents):
        raise ValueError("Claude Code launcher is not outside the reviewed repository")
    return str(resolved),safe_path

def run(args):
    root=Path(args.repo).resolve(); base=full_sha(args.base); head=full_sha(args.head)
    if git(root,"rev-parse","HEAD").decode().strip().lower()!=head: raise ValueError("worktree HEAD differs from requested HEAD")
    diff=git(root,"diff","--no-ext-diff","--binary",f"{base}..{head}"); plan=chunks(diff); diff_hash=digest(diff)
    claude_executable,safe_path=resolve_claude_launcher(root,os.environ.get("PATH",""))
    manifest={"version":"cmh-deepseek-chunks/v1","base_sha":base,"head_sha":head,"diff_sha256":diff_hash,"chunks":[dict(chunk) for chunk in plan]}; manifest_hash=digest(canon(manifest))
    evidence_root=Path(args.evidence).resolve(); evidence_root.mkdir(parents=True,exist_ok=True); os.chmod(evidence_root,0o700)
    run_id=uuid.uuid4().hex; evidence=evidence_root/run_id; evidence.mkdir(mode=0o700)
    token=Path(args.token_file).read_text().strip()
    if not token: raise ValueError("empty DeepSeek token file")
    settings=tempfile.NamedTemporaryFile(mode="w",delete=False); settings.write('{"permissions":{"allow":[],"deny":["Bash","Edit","Write","Read","Glob","Grep","WebFetch","WebSearch"]}}'); settings.close()
    results=[]; command=[claude_executable,"--bare","--restricted","--print","--model",MODEL,"--settings",settings.name,"--tools","","--disallowed-tools","Bash,Edit,Write,Read,Glob,Grep,WebFetch,WebSearch","--output-format","json","--json-schema",json.dumps(SCHEMA,separators=(",",":"))]
    try:
        env={"HOME":"/nonexistent","PATH":safe_path,"LANG":"C.UTF-8","ANTHROPIC_API_KEY":token,"ANTHROPIC_AUTH_TOKEN":token,"ANTHROPIC_BASE_URL":ENDPOINT,"CLAUDE_CODE_SIMPLE":"1"}
        for chunk in plan:
            source=diff[chunk["start"]:chunk["end"]]
            completed=invoke_reviewer(command,prompt(base,head,diff_hash,manifest_hash,chunk,source),env,args.timeout)
            if completed.returncode: raise RuntimeError(f"DeepSeek reviewer infrastructure failure: exit={completed.returncode}")
            raw=completed.stdout.encode(); (evidence/f"chunk-{chunk['index']:03d}.json").write_bytes(raw)
            result=reviewer_result(completed.stdout)
            chunk["result"]=result; chunk["output_sha256"]=digest(raw); results.extend(result.get("findings",[]))
    finally:
        Path(settings.name).unlink(missing_ok=True)
    verdict="FAIL" if any(f.get("severity") in {"P0","P1","P2"} for f in results) else "PASS"
    receipt={"version":VERSION,"repository":git(root,"config","--get","remote.origin.url").decode().strip(),"mission_id":args.mission_id,"base_sha":base,"head_sha":head,"diff_sha256":diff_hash,"manifest_sha256":manifest_hash,"chunks":plan,"provider":"deepseek","model":MODEL,"command_sha256":digest(canon(command)),"started_at":int(time.time()),"completed_at":int(time.time()),"review_result":verdict,"findings":results}
    receipt["integrity_sha256"]=digest(canon(receipt)); path=evidence/f"deepseek-receipt-{head[:12]}-{uuid.uuid4().hex}.json"; path.write_bytes(canon(receipt)); os.chmod(path,0o600)
    print(json.dumps({"status":verdict,"receipt":str(path),"review_receipt":str(path),"head_sha":head}))
def main():
    p=argparse.ArgumentParser(); sub=p.add_subparsers(dest="cmd",required=True)
    r=sub.add_parser("run"); r.add_argument("--repo",default="."); r.add_argument("--mission-id",default="codex-mission-harness"); r.add_argument("--base",required=True); r.add_argument("--head",required=True); r.add_argument("--evidence",required=True); r.add_argument("--token-file",required=True); r.add_argument("--timeout",type=int,default=900)
    c=sub.add_parser("validate"); c.add_argument("--receipt",required=True); c.add_argument("--base",required=True); c.add_argument("--head",required=True); c.add_argument("--repo",default="."); c.add_argument("--mission-id",default="codex-mission-harness")
    a=p.parse_args()
    try:
        if a.cmd=="run": run(a)
        else:
            repository=git(Path(a.repo).resolve(),"config","--get","remote.origin.url").decode().strip()
            print(json.dumps({"status":validate(json.loads(Path(a.receipt).read_text()),full_sha(a.base),full_sha(a.head),a.repo,a.receipt,a.mission_id,repository)["review_result"]}))
    except Exception as exc: print(json.dumps({"status":"BLOCKED_EXTERNAL","error":str(exc)})); return 1
    return 0
if __name__=="__main__": raise SystemExit(main())
