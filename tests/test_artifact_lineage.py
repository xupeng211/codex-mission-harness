"""Offline signed lineage proofs; no provider calls or production mutations."""
import copy
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from harness import artifact_lineage as reuse, formal_delivery_gate as gate
from harness.resource_gate import canonical, digest, sign_authorization


class ArtifactLineageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name); self.key = self.root/'key'
        self.key.write_bytes(b'OFFLINE-LINEAGE-ONLY'); self.key.chmod(0o600)
        self.env = patch.dict(os.environ, CMH_RESOURCE_GATE_KEY_FILE=str(self.key))
        self.env.start(); self.addCleanup(self.env.stop)
        self.rows = [{'request_id':'historic-unknown','reported_usage':'UNKNOWN','status':'FAILED',
                      'cost_reservation_microunits':100,'token_reservation':{'input':100}}]
        self.base = {'mission_id':gate.NEW_MISSION,'targets':{'PR2':{'base':'a'*40,'head':'b'*40}},
                     'runtime':{'semantic':'original'},'credential_identities':{'openai':'pinned'},
                     'account_ids':{'openai':'pinned'},'ledger_path':str(self.root/'ledger0.json')}
        gate._write_child(Path(self.base['ledger_path']), {'requests':copy.deepcopy(self.rows)}, self.key.read_bytes())
        self.base_path, self.base_sha = self.seal('origin.json',self.base)
        self.auth = self.successor(self.base,self.base_path,self.base_sha,'one')
        self.auth['_lineage_sha256'] = {self.base_sha,self.auth['_authorization_sha256']}
        self.current_rows = copy.deepcopy(self.rows)
        self.mocks = [patch.object(gate,'load_authorization',side_effect=lambda:self.auth),
                      patch.object(gate,'_verify_child',side_effect=lambda *x:{'requests':self.current_rows}),
                      patch.object(gate,'continuation_ledger_path',side_effect=lambda c:Path(c['predecessor_ledger_path']).with_suffix('.next.json')),
                      patch.object(reuse,'semantic_runtime',side_effect=lambda r:r)]
        for m in self.mocks:m.start();self.addCleanup(m.stop)

    def seal(self,name,value):
        p=self.root/name;p.write_bytes(canonical(sign_authorization(value,self.key.read_bytes()))+b'\n');p.chmod(0o600)
        return str(p),digest(p.read_bytes())

    def successor(self,prior,path,sha,name):
        c={'predecessor_authorization_sha256':sha,'predecessor_ledger_path':prior['ledger_path'],
           'predecessor_ledger_sha256':digest(gate._read(prior['ledger_path'])),
           'predecessor_checkpoint_sha256':digest(gate._read(gate._checkpoint_path(Path(prior['ledger_path'])))),
           'requests_sha256':digest(canonical(self.rows))}
        a=copy.deepcopy(prior);a.update(previous_authorization_path=path,previous_authorization_sha256=sha,
           continuation=c,ledger_path=str(Path(prior['ledger_path']).with_suffix('.next.json')))
        gate._write_child(Path(a['ledger_path']), {'requests':copy.deepcopy(self.rows)}, self.key.read_bytes())
        ap,ash=self.seal(name+'.json',a);a['_authorization_sha256']=ash
        return a

    def test_direct_continuation_retains_unrelated_unknown(self):
        before=copy.deepcopy(self.current_rows)
        self.assertEqual(reuse.origin_authority(self.base_sha)[0],self.base)
        self.assertEqual(before,self.current_rows)

    def test_multi_generation(self):
        prior={k:v for k,v in self.auth.items() if not k.startswith('_')}
        p,s=self.seal('signed-one.json',prior)
        self.auth=self.successor(prior,p,s,'two')
        self.auth['_lineage_sha256']={self.base_sha,s,self.auth['_authorization_sha256']}
        self.assertEqual(reuse.origin_authority(self.base_sha)[0],self.base)

    def test_reject_semantic_target_account_changes(self):
        for key, value in [('runtime',{'semantic':'changed'}),('targets',{'PR2':{'base':'a'*40,'head':'c'*40}}),
                          ('targets',{'PR2':{'base':'c'*40,'head':'b'*40}}),('credential_identities',{'openai':'other'})]:
            with self.subTest(key=key):
                old=self.auth[key];self.auth[key]=value
                with self.assertRaises(ValueError):reuse.origin_authority(self.base_sha)
                self.auth[key]=old

    def test_reject_authority_hash_skipped_predecessor_and_fork(self):
        for key in ['predecessor_authorization_sha256','predecessor_ledger_sha256','predecessor_checkpoint_sha256','requests_sha256','predecessor_ledger_path']:
            with self.subTest(key=key):
                old=self.auth['continuation'][key];self.auth['continuation'][key]='tampered'
                with self.assertRaises(ValueError):reuse.origin_authority(self.base_sha)
                self.auth['continuation'][key]=old
        self.auth['ledger_path']=str(self.root/'fork.json')
        with self.assertRaises(ValueError):reuse.origin_authority(self.base_sha)

    def test_reject_missing_origin_or_altered_full_reservation(self):
        with self.assertRaises(ValueError):reuse.origin_authority('unrelated')
        self.current_rows[0]['cost_reservation_microunits']=0
        with self.assertRaises(ValueError):reuse.origin_authority(self.base_sha)

    def test_signed_authority_tampering_rejected(self):
        p=Path(self.base_path);v=json.loads(p.read_text());v['runtime']={'semantic':'tampered'};p.write_text(json.dumps(v))
        with self.assertRaises(Exception):reuse.origin_authority(self.base_sha)

    def test_semantic_projection_preserves_prompts_schema_fixtures_and_parser(self):
        baseline=b"SCHEMA={'minLength':24}\nFIXTURE='clean'\ndef prompt():return 'risk based review'\ndef validate():return 'old provenance'\n"
        excluded=('validate',)
        self.assertEqual(reuse.semantic_code(baseline,excluded),reuse.semantic_code(baseline.replace(b'old provenance',b'new provenance'),excluded))
        for old,new in [(b'24',b'1'),(b'clean',b'wrong'),(b'risk based review',b'uphold everything')]:
            with self.subTest(change=old):self.assertNotEqual(reuse.semantic_code(baseline,excluded),reuse.semantic_code(baseline.replace(old,new),excluded))

    def test_review_identity_only_provenance_may_change(self):
        p={'provider':'openai','runner_hash':'old','invocation_hash':'transport','manifest_implementation_sha256':'manifest',
           'source_binding_contract_authorization_sha256':self.base_sha,'base_sha':'a','head_sha':'b',
           'schema_manifest_hash':'schema','registry_hash':'registry','model_configuration':{'reasoning':'high'},
           'qualification_receipt_identity':'qualified','input_manifest_identity':'source','diff_hash':'diff'}
        p['review_execution_identity']=digest(canonical(p));cur=copy.deepcopy(p);cur['runner_hash']='current';cur['source_binding_contract_authorization_sha256']=self.auth['_authorization_sha256']
        cur['review_execution_identity']='new'
        hashes={'runner_hash':'old','invocation_hash':'transport','manifest_implementation_sha256':'manifest'}
        def oldhash(path,sha):return hashes['runner_hash' if path.name.startswith('reviewer_v2') else 'invocation_hash' if path.name=='openai_invocation.py' else 'manifest_implementation_sha256']
        def newhash(raw):return 'current' if b'"""' in raw and b'OpenAI' in raw else digest(raw)
        # Current real code hashes are explicit, while synthetic origin hashes are mocked.
        paths={'runner_hash':'scripts/reviewer_v2_openai.py','invocation_hash':'src/harness/openai_invocation.py','manifest_implementation_sha256':'src/harness/full_diff_manifest.py'}
        root=Path(reuse.__file__).resolve().parents[2]
        for key,name in paths.items():cur[key]=digest((root/name).read_bytes())
        p['invocation_hash']=cur['invocation_hash'];p['manifest_implementation_sha256']=cur['manifest_implementation_sha256']
        hashes.update(invocation_hash=p['invocation_hash'],manifest_implementation_sha256=p['manifest_implementation_sha256'])
        p['review_execution_identity']=digest(canonical({k:v for k,v in p.items() if k!='review_execution_identity'}))
        with patch.object(reuse,'artifact_code_hash',side_effect=oldhash):
            self.assertTrue(reuse.reusable_review_identity(p,cur))
            for key in ['head_sha','base_sha','schema_manifest_hash','registry_hash','model_configuration','qualification_receipt_identity','input_manifest_identity','diff_hash']:
                bad=copy.deepcopy(cur);bad[key]='changed'
                with self.subTest(key=key),self.assertRaises(ValueError):reuse.reusable_review_identity(p,bad)

    def test_partial_openai_output_requires_original_verified_request(self):
        raw=b'{"findings":[]}'
        state={'identity':{'provider':'openai','source_binding_contract_authorization_sha256':self.base_sha},
               'review_run_id':'run','completed':{'chunk-000':{'artifact_path':'chunk-000.json','artifact_sha256':digest(raw),'output_hash':digest(raw),'input_hash':'prompt'}}}
        row={'run_id':'run','stage':'chunk-000','status':'RETURNED','prompt_sha256':'prompt',
             'authorization_sha256':self.base_sha,'provider':'openai','reported_usage':{'response_sha256':digest(raw)},'usage_accounting':'FULL_RESERVATION_RETAINED'}
        self.current_rows.append(row)
        with patch('harness.openai_invocation.verify_openai_usage',return_value=True) as verify:
            reuse.review_history(state,lambda name:raw);self.assertEqual(verify.call_count,1)
            for key,value in [('status','FAILED'),('reported_usage','UNKNOWN'),('prompt_sha256','wrong'),('usage_accounting','REFUNDED')]:
                old=row[key];row[key]=value
                with self.subTest(key=key),self.assertRaises(ValueError):reuse.review_history(state,lambda name:raw)
                row[key]=old
            with self.assertRaises(ValueError):reuse.review_history(state,lambda name:raw+b' ')
            self.current_rows.pop()
            with self.assertRaises(ValueError):reuse.review_history(state,lambda name:raw)

    def test_qualification_requires_bound_cases_and_accounting(self):
        from harness.model_qualification import CASES, qualification_prompt
        receipt={'delivery_binding':{'authorization_sha256':self.base_sha},'identity':{'provider':'deepseek'}}
        rows=[{'authorization_sha256':self.base_sha,'provider':'deepseek','stage':'qualification-case',
               'status':'RETURNED','prompt_sha256':digest(qualification_prompt(c).encode()),
               'reported_usage':{'verified':'synthetic'},'usage_accounting':'FULL_RESERVATION_RETAINED'} for c in CASES]
        self.current_rows.extend(rows)
        reuse.qualification_history(receipt,self.auth)
        for key,value in [('prompt_sha256','changed-fixture'),('reported_usage','UNKNOWN'),('usage_accounting','REFUNDED')]:
            old=rows[0][key];rows[0][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):reuse.qualification_history(receipt,self.auth)
            rows[0][key]=old
        self.current_rows.remove(rows[-1])
        with self.assertRaises(ValueError):reuse.qualification_history(receipt,self.auth)

    def test_deepseek_output_must_equal_original_accounted_transport(self):
        import base64
        envelope={'direct_completion':{'usage':{'tokens':10},'prompt_sha256':'prompt'},'structured_output':{'findings':[]}}
        raw=canonical(envelope)
        row={'run_id':'run','stage':'chunk-000.json','status':'RETURNED','prompt_sha256':'prompt',
             'authorization_sha256':self.base_sha,'provider':'deepseek',
             'request_id':'verified-ds','reported_usage':{'raw_usage_fields':{'tokens':10}},'usage_accounting':'FULL_RESERVATION_RETAINED'}
        self.current_rows.append(row)
        transport={'resource_request':{'request_id':'verified-ds'},'stdout_base64':base64.b64encode(raw).decode()}
        state={'identity':{'provider':'deepseek','source_binding_contract_authorization_sha256':self.base_sha},
               'review_run_id':'run','completed':{'chunk-000':{'artifact_path':'chunk-000.json','artifact_sha256':digest(raw),'output_hash':digest(raw),'input_hash':'prompt'}},
               'diagnostic_artifacts':[{'path':'chunk-000-transport-test.json'}, {'path':'chunk-000-transport-no-request.json'}]}
        read=lambda name:raw if name=='chunk-000.json' else canonical({'resource_request':None}) if name.endswith('no-request.json') else canonical(transport)
        reuse.review_history(state,read)
        transport['stdout_base64']=base64.b64encode(raw+b' ').decode()
        with self.assertRaises(Exception):reuse.review_history(state,read)
        transport['stdout_base64']=base64.b64encode(raw).decode();row['reported_usage']['raw_usage_fields']['tokens']=0
        with self.assertRaises(ValueError):reuse.review_history(state,read)

    def test_source_binding_and_transport_are_semantic(self):
        for name in ('src/harness/reviewer_v2_contract.py','src/harness/openai_invocation.py','src/harness/deepseek_direct.py'):
            self.assertEqual(reuse.SEMANTIC_FILES[name],())
            self.assertNotEqual(reuse.semantic_code(b"def validate():return True"),reuse.semantic_code(b"def validate():return False"))

    def test_legacy_direct_proof_must_bind_every_identity(self):
        schema={'type':'object','properties':{'findings':{'type':'array'}},'required':['findings']}
        response={'id':'provider-id','usage':{'tokens':10},'choices':[{'message':{'content':'{"findings":[]}'}}]}
        raw=canonical(response);rawpath=self.root/'raw';rawpath.write_bytes(raw);rawpath.chmod(0o600)
        envelope={'direct_completion':{'provider_id':'provider-id','usage':response['usage'],'schema_sha256':digest(canonical(schema))},'structured_output':{'findings':[]}}
        artifact=canonical(envelope)
        row={'request_id':'accounted','authorization_sha256':self.base_sha,'prompt_sha256':'prompt','model':'deepseek-flash'}
        proof={'request_id':'accounted','authorization_sha256':self.base_sha,'runtime_sha256':digest(canonical(self.base['runtime'])),
               'prompt_sha256':'prompt','model':'deepseek-flash','route':'DIRECT_DEEPSEEK_API','transport_retry':0,'http_status':200,
               'raw_response_path':str(rawpath),'raw_response_sha256':digest(raw),'provider_id':'provider-id',
               'schema_sha256':digest(canonical(schema)),'schema':schema}
        def publish(proof):
            path=self.root/'proof.json';path.write_bytes(canonical(sign_authorization(proof,self.key.read_bytes()))+b'\n');path.chmod(0o600)
            index={'version':'cmh-legacy-direct-binding-index/v1','authorization_sha256':self.auth['_authorization_sha256'],
                   'bindings':{'accounted':{'path':str(path),'sha256':digest(path.read_bytes()),'artifact_sha256':digest(artifact)}}}
            ip=self.root/'index.json';ip.write_bytes(canonical(sign_authorization(index,self.key.read_bytes()))+b'\n');ip.chmod(0o600)
            return {'CMH_ARTIFACT_RAW_BINDINGS':str(ip),'CMH_ARTIFACT_RAW_BINDINGS_SHA256':digest(ip.read_bytes())}
        with patch('harness.deepseek_direct.validate_envelope') as validate:
            with patch.dict(os.environ,publish(proof)):reuse.verify_legacy_direct_binding(row,artifact,self.base,self.key.read_bytes())
            self.assertEqual(validate.call_count,1)
            for key in ['request_id','authorization_sha256','runtime_sha256','prompt_sha256','model','route','raw_response_sha256','provider_id','schema_sha256']:
                bad=copy.deepcopy(proof);bad[key]='tampered'
                with self.subTest(key=key),patch.dict(os.environ,publish(bad)),self.assertRaises(ValueError):reuse.verify_legacy_direct_binding(row,artifact,self.base,self.key.read_bytes())
            with patch.dict(os.environ,publish(proof)),self.assertRaises(ValueError):reuse.verify_legacy_direct_binding(row,artifact+b' ',self.base,self.key.read_bytes())
