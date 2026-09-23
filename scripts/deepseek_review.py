#!/usr/bin/env python3
"""Durable, exact-diff DeepSeek review for this repository only.

The caller supplies a token-file path at execution time; no credential is ever
stored in the mission, journal, receipt, or repository.  Receipt publication is
commit-last: an incomplete run has no receipt and is never an approval.
"""
from __future__ import annotations

import argparse, hashlib, json, os, subprocess, sys, tempfile, time, uuid
from pathlib import Path

VERSION = "cmh-deepseek-review/v1"
MODEL = "deepseek-flash"
ENDPOINT = "https://api.deepseek.com/anthropic"
CHUNK_BYTES = 32000

SCHEMA = {"type":"object","additionalProperties":False,"required":["review_result","findings"],"properties":{"review_result":{"enum":["PASS","FAIL"]},"findings":{"type":"array","items":{"type":"object","additionalProperties":False,"required":["severity","title","evidence"],"properties":{"severity":{"enum":["P0","P1","P2","P3"]},"title":{"type":"string"},"evidence":{"type":"string"}}}}}}

def canon(value): return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
def digest(value): return hashlib.sha256(value).hexdigest()
def sha(path): return digest(Path(path).read_bytes())
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
def validate(receipt, base, head):
    required={"version","repository","mission_id","base_sha","head_sha","diff_sha256","manifest_sha256","chunks","provider","model","command_sha256","review_result","findings","integrity_sha256"}
    if not required <= set(receipt): raise ValueError("incomplete receipt")
    if receipt["version"] != VERSION or receipt["base_sha"] != base or receipt["head_sha"] != head: raise ValueError("receipt exact-head binding mismatch")
    copy=dict(receipt); observed=copy.pop("integrity_sha256")
    if digest(canon(copy)) != observed: raise ValueError("receipt integrity mismatch")
    if receipt["provider"] != "deepseek" or receipt["model"] != MODEL: raise ValueError("reviewer provenance mismatch")
    chunks_=receipt["chunks"]
    if not chunks_ or [c.get("index") for c in chunks_] != list(range(len(chunks_))): raise ValueError("missing or duplicate chunks")
    if any(c.get("result",{}).get("review_result") not in {"PASS","FAIL"} for c in chunks_): raise ValueError("invalid chunk result")
    blocking=any(f.get("severity") in {"P0","P1","P2"} for f in receipt["findings"])
    if (receipt["review_result"] == "PASS") != (not blocking): raise ValueError("aggregate verdict mismatch")
    return receipt
def prompt(base, head, diff_hash, manifest_hash, chunk, source):
    return ("You are an independent restricted code reviewer. Do not use tools or filesystem. Return only JSON matching the schema. "
            "PASS only when P0/P1/P2 are absent.\n"
            f"Base={base}\nHead={head}\nDiffSHA256={diff_hash}\nManifestSHA256={manifest_hash}\n"
            f"Chunk={chunk['index']} range={chunk['start']}:{chunk['end']} SHA256={chunk['sha256']}\nDIFF:\n"+source.decode("utf-8","replace"))
def run(args):
    root=Path(args.repo).resolve(); base=full_sha(args.base); head=full_sha(args.head)
    if git(root,"rev-parse","HEAD").decode().strip().lower()!=head: raise ValueError("worktree HEAD differs from requested HEAD")
    diff=git(root,"diff","--no-ext-diff","--binary",f"{base}..{head}"); plan=chunks(diff); diff_hash=digest(diff)
    manifest={"version":"cmh-deepseek-chunks/v1","base_sha":base,"head_sha":head,"diff_sha256":diff_hash,"chunks":[dict(chunk) for chunk in plan]}; manifest_hash=digest(canon(manifest))
    evidence=Path(args.evidence).resolve(); evidence.mkdir(parents=True,exist_ok=True); os.chmod(evidence,0o700)
    token=Path(args.token_file).read_text().strip()
    if not token: raise ValueError("empty DeepSeek token file")
    settings=tempfile.NamedTemporaryFile(mode="w",delete=False); settings.write('{"permissions":{"allow":[],"deny":["Bash","Edit","Write","Read","Glob","Grep","WebFetch","WebSearch"]}}'); settings.close()
    results=[]; command=["claude","--bare","--restricted","--print","--model",MODEL,"--settings",settings.name,"--tools","","--disallowed-tools","Bash,Edit,Write,Read,Glob,Grep,WebFetch,WebSearch","--output-format","json","--json-schema",json.dumps(SCHEMA,separators=(",",":"))]
    try:
        env={"HOME":"/nonexistent","PATH":os.environ.get("PATH","")+":/usr/bin:/bin","LANG":"C.UTF-8","ANTHROPIC_API_KEY":token,"ANTHROPIC_AUTH_TOKEN":token,"ANTHROPIC_BASE_URL":ENDPOINT,"CLAUDE_CODE_SIMPLE":"1"}
        for chunk in plan:
            source=diff[chunk["start"]:chunk["end"]]; completed=subprocess.run(command+[prompt(base,head,diff_hash,manifest_hash,chunk,source)],env=env,capture_output=True,text=True,timeout=args.timeout)
            if completed.returncode: raise RuntimeError(f"DeepSeek reviewer infrastructure failure: exit={completed.returncode}")
            raw=completed.stdout.encode(); (evidence/f"chunk-{chunk['index']:03d}.json").write_bytes(raw)
            value=json.loads(completed.stdout); result=value.get("structured_output") or value.get("result") or value
            if not isinstance(result,dict) or result.get("review_result") not in {"PASS","FAIL"}: raise ValueError("invalid reviewer output")
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
    c=sub.add_parser("validate"); c.add_argument("--receipt",required=True); c.add_argument("--base",required=True); c.add_argument("--head",required=True)
    a=p.parse_args()
    try:
        if a.cmd=="run": run(a)
        else: print(json.dumps({"status":validate(json.loads(Path(a.receipt).read_text()),full_sha(a.base),full_sha(a.head))["review_result"]}))
    except Exception as exc: print(json.dumps({"status":"BLOCKED_EXTERNAL","error":str(exc)})); return 1
    return 0
if __name__=="__main__": raise SystemExit(main())
