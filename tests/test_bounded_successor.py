"""One fixed failed parent; synthetic signatures only, no Provider transport."""
import copy
import json
import multiprocessing
import os
import unittest
from pathlib import Path
from unittest.mock import patch
from harness import fresh_task as fresh, formal_delivery_gate as gate
from harness.resource_gate import ResourceGateDenied, canonical, digest, sign_authorization
from harness.model_qualification import CASES, qualification_prompt
import test_fresh_task as fixtures
import test_fresh_task_e2e as e2e

REAL_FAILURE = Path('/home/xupeng/mission-evidence/HARNESS_PR2_FRESH_APPROVED_GPT_THEN_DEEPSEEK_DUAL_REVIEW_EXECUTION-20261011')


def prepare_successor(f):
    """Adapt the real failed facts into an explicitly signed OFFLINE_TEST chain.

    Production parent/anchor keys are never read. Original real evidence is read
    only and hash checked; fixture identity/time are necessarily independent.
    """
    f.activate(); parent_auth = f.load()
    prompt = qualification_prompt(CASES[0]).encode()
    reservation = f.reserve_stage('openai', 'qualification-case', prompt)
    with patch.object(gate, 'load_authorization', return_value=parent_auth):
        fresh.claim_transport(parent_auth, reservation, prompt)
    with patch('harness.resource_gate.time.time', return_value=1201):
        f.settle(reservation, known=False, status='FAILED')
    f.failed_ledger = f.ledger; f.failed_authority = f.auth
    f.failed_ledger_bytes = f.failed_ledger.read_bytes()
    f.failed_checkpoint_bytes = gate._checkpoint_path(f.failed_ledger).read_bytes()
    f.failed_authority_bytes = f.failed_authority.read_bytes()
    row = gate._checked_child(f.failed_ledger, f.key.read_bytes())['requests'][0]
    refs = {}
    for name, sha in fresh.FAILED_EVIDENCE.items():
        raw = (REAL_FAILURE / name).read_bytes(); assert digest(raw) == sha
        path = f.root / ('real-failure-' + name.replace('/', '-'))
        path.write_bytes(raw); path.chmod(0o600)
        refs[name] = dict(path=str(path), sha256=sha)
    real = json.loads((REAL_FAILURE/'final-fresh-ledger.json').read_bytes())['requests'][0]
    assert real['status'] == row['status'] == 'FAILED'
    assert real['reported_usage'] == row['reported_usage'] == 'UNKNOWN'
    assert digest(canonical(real)) == fresh.FAILED_ROW_SHA
    s = dict(mission_id=parent_auth['mission_id'], authorization_path=str(f.failed_authority),
             authorization_sha256=digest(f.failed_authority_bytes), ledger_path=str(f.failed_ledger),
             ledger_sha256=digest(f.failed_ledger_bytes), checkpoint_sha256=digest(f.failed_checkpoint_bytes),
             unknown_row_sha256=digest(canonical(row)), failure_evidence=refs,
             retain_unknown=True, refund=0, abandon_failed_execution_approved=True,
             accepted_risks=list(fresh.SUCCESSOR_RISKS),
             read_only_get_limits=dict(logical=9, physical=10, automatic_retries=0))
    f.payload = copy.deepcopy(f.payload)
    f.payload['fresh_task'].update(version=fresh.SUCCESSOR_VERSION, successor=s)
    f.payload.update(authorization_id='OFFLINE_ONE_SUCCESSOR', approved_at_epoch=1210,
                     started_epoch=1211, expires_epoch=1361)
    f.account_path = f.root/'successor-account.json'
    f.payload['account_evidence_path'] = str(f.account_path)
    f.now = 1220; f.accounts.update(observed_epoch=1210, expires_epoch=1361,
                                    successor_parent_ledger_sha256=s['ledger_sha256'])
    f.approval = f.root/'successor-approval.json'; f.auth = f.root/'successor-auth.json'
    f.ledger = fresh.authorization_ledger_path(f.payload)
    f.payload['ledger_path'] = str(f.ledger)
    f.env.update(CMH_RESOURCE_AUTHORIZATION=str(f.auth), CMH_RESOURCE_LEDGER=str(f.ledger))
    f.approve()


class BoundedSuccessorTests(unittest.TestCase):
    def setUp(self):
        self.f = fixtures.FreshTaskTests(); self.f.setUp(); self.addCleanup(self.f.doCleanups)
        prepare_successor(self.f)

    def assert_parent_unchanged(self):
        f = self.f
        self.assertEqual(f.failed_ledger.read_bytes(), f.failed_ledger_bytes)
        self.assertEqual(gate._checkpoint_path(f.failed_ledger).read_bytes(), f.failed_checkpoint_bytes)
        self.assertEqual(f.failed_authority.read_bytes(), f.failed_authority_bytes)
        self.assertEqual(f.predecessor.read_bytes(), f.old_bytes)

    def test_approved_independent_task_retains_full_chain_accounting(self):
        f=self.f; a=f.load(); f.activate()
        self.assertEqual(a['_history']['global_calls'],455)
        self.assertEqual(len(a['_fresh_history']['requests']),121)
        self.assertEqual(sum(r['reported_usage']=='UNKNOWN' for r in a['_fresh_history']['requests']),9)
        parent=json.loads(f.failed_authority_bytes)
        self.assertNotEqual(a['execution_id'],parent['execution_id'])
        self.assertNotEqual(a['mission_id'],parent['mission_id'])
        self.assertNotEqual(a['ledger_path'],parent['ledger_path'])
        self.assertNotEqual(a['started_epoch'],parent['started_epoch'])
        self.assertEqual(gate._verify_child(f.ledger,f.key.read_bytes(),a)['requests'],[])
        self.assert_parent_unchanged()

    def test_parent_failure_cannot_resume_or_replay(self):
        f=self.f; env=dict(f.env,CMH_RESOURCE_AUTHORIZATION=str(f.failed_authority),
            CMH_RESOURCE_AUTH_SHA256=digest(f.failed_authority_bytes),
            CMH_RESOURCE_MISSION_ID=json.loads(f.failed_authority_bytes)['mission_id'],CMH_RESOURCE_LEDGER=str(f.failed_ledger))
        parent=gate._load(env,f.anchor,json.loads(f.failed_authority_bytes)['runtime'],1220,offline=True)
        with self.assertRaises(ResourceGateDenied):
            gate._reserve_validated(parent,env,'openai','gpt-5.6-sol',qualification_prompt(CASES[0]).encode(),'qualification-case',1220,offline=True)
        self.assert_parent_unchanged()

    def test_no_approval_and_wrong_approval_version_denied(self):
        f=self.f
        for change in ('explicit_paid_execution_approval','version'):
            f.approve(); obj=json.loads(f.approval.read_bytes())
            obj[change]=False if change=='explicit_paid_execution_approval' else fresh.APPROVAL_VERSION
            f.write(f.approval,obj);f.payload['user_approval_sha256']=digest(f.approval.read_bytes());f.write_auth()
            with self.assertRaises(ResourceGateDenied):f.load()

    def test_parent_substitution_nested_disposition_and_unknown_rewrite_denied(self):
        f=self.f; original=copy.deepcopy(f.payload)
        for field,value in [('mission_id','OTHER'),('ledger_sha256','0'*64),('checkpoint_sha256','0'*64),
              ('authorization_sha256','0'*64),('unknown_row_sha256','0'*64),('retain_unknown',False),
              ('refund',1),('abandon_failed_execution_approved',False)]:
            f.payload=copy.deepcopy(original);f.payload['fresh_task']['successor'][field]=value;f.approve()
            with self.subTest(field=field),self.assertRaises(ResourceGateDenied):f.load()
        f.payload=original;f.approve();a=f.load()
        s=f.payload['fresh_task']['successor'];s.update(mission_id=a['mission_id'],authorization_path=str(f.auth),authorization_sha256=a['_authorization_sha256'])
        f.approve()
        with self.assertRaises(ResourceGateDenied):f.load()
        self.assert_parent_unchanged()

    def test_risks_and_get_permission_cannot_be_omitted_or_expanded(self):
        f=self.f;original=copy.deepcopy(f.payload)
        for field,value in [('accepted_risks',[]),('read_only_get_limits',dict(logical=10,physical=11,automatic_retries=0)),
                ('read_only_get_limits',dict(logical=9,physical=10,automatic_retries=1))]:
            f.payload=copy.deepcopy(original);f.payload['fresh_task']['successor'][field]=value;f.approve()
            with self.subTest(field=field),self.assertRaises(ResourceGateDenied):f.load()

    def test_production_rejects_arbitrary_parent_even_with_fixture_signature(self):
        f=self.f;a=f.load()
        with self.assertRaisesRegex(ResourceGateDenied,'fixed real GPT authentication failure'):
            fresh.validate_failed_parent(a,f.env,f.key.read_bytes(),f.now,offline=False)

    def test_native_funds_reserve_and_budget_cannot_skip_parent_binding(self):
        f=self.f;a=f.load();hist=copy.deepcopy(a['_fresh_history'])
        for row in hist['requests']:
            if row['provider']=='deepseek' and row.get('reported_usage')=='UNKNOWN':row['wallet_exposure_microcny']=2637152
        a=dict(a,_fresh_history=hist,deepseek_funding_policy={'safety_margin_microcny':263716})
        sha=a['fresh_task']['history']['predecessor_ledger_sha256'];parent=a['fresh_task']['successor']['ledger_sha256']
        source=f.root/'successor-settlement.json';f.write(source,dict(fresh_history_sha256=sha,successor_parent_ledger_sha256=parent))
        snapshot=dict(fresh_history_sha256=sha,successor_parent_ledger_sha256=parent,settlement_source_path=str(source))
        retained=sum(r.get('wallet_exposure_microcny',0) for r in hist['requests'])
        self.assertEqual(fresh.native_funding_check(a,{'requests':[]},snapshot,2637152,10000000),10000000-retained)
        with self.assertRaises(ResourceGateDenied):fresh.native_funding_check(a,{'requests':[]},dict(snapshot,successor_parent_ledger_sha256='0'*64),2637152,10000000)
        a['fresh_task']['budget_microcny']=2637152
        with self.assertRaises(ResourceGateDenied):fresh.native_funding_check(a,{'requests':[]},snapshot,2637152,10000000)
        with patch.object(gate,'_current_funds',side_effect=ResourceGateDenied('stale or missing funds')):
            with self.assertRaises(ResourceGateDenied):gate._funding_check(a,{'requests':[]},f.key.read_bytes(),'qualification-case',f.now)

    def test_original_failure_evidence_hash_required(self):
        f=self.f;ref=next(iter(f.payload['fresh_task']['successor']['failure_evidence'].values()))
        Path(ref['path']).write_bytes(b'fake authentication diagnosis')
        with self.assertRaises(ResourceGateDenied):f.load()

    def test_same_or_new_approval_name_path_and_resign_cannot_fork(self):
        f=self.f;f.activate();claim=fresh.activation_claim_path(f.load()).read_bytes()
        for mode in ('same','new-name','new-path','new-execution','descriptor-name'):
            original=copy.deepcopy(f.payload)
            if mode=='new-name':f.payload['authorization_id']='another';f.approve()
            if mode=='new-path':f.payload['ledger_path']=str(f.root/'copy.json');f.approve()
            if mode=='new-execution':f.payload['execution_id']='0'*64;f.write_auth()
            if mode=='descriptor-name':f.payload['another_successor']=f.payload['fresh_task']['successor'];f.approve()
            with self.subTest(mode=mode),self.assertRaises(ResourceGateDenied):f.activate()
            f.payload=original;f.approve()
        self.assertEqual(fresh.activation_claim_path(f.load()).read_bytes(),claim)
        self.assert_parent_unchanged()

    def test_cross_process_concurrent_activation_has_exactly_one_winner(self):
        f=self.f;a=f.load();ctx=multiprocessing.get_context('fork');q=ctx.Queue()
        def worker():
            try:gate._activate_validated(a,f.env,offline=True);q.put('accepted')
            except ResourceGateDenied:q.put('denied')
        jobs=[ctx.Process(target=worker) for _ in range(3)]
        for job in jobs:job.start()
        for job in jobs:job.join(10);self.assertFalse(job.is_alive());self.assertEqual(job.exitcode,0)
        self.assertEqual(sorted(q.get(timeout=2) for _ in jobs),['accepted','denied','denied'])
        gate._verify_child(f.ledger,f.key.read_bytes(),a);q.close()

    def test_crash_after_claim_or_checkpoint_cannot_reinitialize(self):
        f=self.f;a=f.load()
        with patch.object(gate,'_write_child',side_effect=RuntimeError('simulated crash')):
            with self.assertRaises(RuntimeError):f.activate()
        self.assertTrue(fresh.activation_claim_path(a).exists())
        self.assertFalse(f.ledger.exists())
        with self.assertRaises(ResourceGateDenied):f.activate()
        with self.assertRaises(ResourceGateDenied):gate._verify_child(f.ledger,f.key.read_bytes(),a)

    def test_restart_claim_loss_or_ledger_copy_does_not_authorize_transport(self):
        f=self.f;f.activate();a=f.load();claim=fresh.activation_claim_path(a)
        claim.unlink()  # isolated attacker fixture only
        with self.assertRaises(ResourceGateDenied):gate._verify_child(f.ledger,f.key.read_bytes(),a)
        with self.assertRaises(ResourceGateDenied):f.activate()

    def test_process_death_after_durable_claim_and_fresh_process_restart(self):
        f=self.f;a=f.load();ctx=multiprocessing.get_context('fork')
        def interrupted():
            with patch.object(gate,'_write_child',side_effect=lambda *args:os._exit(31)):
                gate._activate_validated(a,f.env,offline=True)
        process=ctx.Process(target=interrupted);process.start();process.join(10)
        self.assertFalse(process.is_alive());self.assertEqual(process.exitcode,31)
        self.assertTrue(fresh.activation_claim_path(a).exists());self.assertFalse(f.ledger.exists())
        def restarted():
            try:f.activate()
            except ResourceGateDenied:os._exit(0)
            os._exit(99)
        process=ctx.Process(target=restarted);process.start();process.join(10)
        self.assertFalse(process.is_alive());self.assertEqual(process.exitcode,0)
        self.assert_parent_unchanged()

    def test_successor_unknown_blocks_all_new_slots_and_second_activation(self):
        f=self.f;f.activate();r=f.reserve_stage('openai','qualification-case',qualification_prompt(CASES[0]).encode())
        f.settle(r,known=False,status='FAILED')
        for p in ('openai','deepseek'):
            with self.assertRaises(ResourceGateDenied):f.reserve_stage(p,'qualification-case',qualification_prompt(CASES[0]).encode())
        with self.assertRaises(ResourceGateDenied):f.activate()
        self.assert_parent_unchanged()

    def test_target_models_scope_runtime_budget_expiry_drift_fail_closed(self):
        f=self.f;original=copy.deepcopy(f.payload)
        for field in ('head','tree','scope','plan','model','effort','registry','runtime','budget','expiry','tokens','calls'):
            f.payload=copy.deepcopy(original)
            if field=='head':f.payload['targets']['PR2']['head']='0'*40
            elif field=='tree':f.payload['fresh_task']['scope']['tree']='0'*40
            elif field=='scope':f.payload['fresh_task']['scope']['manifest_sha256']='0'*64
            elif field=='plan':f.payload['fresh_task']['request_plan']['maximum_calls']['openai']=8
            elif field=='model':f.payload['runtime']['models']['openai']['model']='gpt-6-astra'
            elif field=='effort':f.payload['runtime']['models']['openai']['reasoning_effort']='low'
            elif field=='registry':f.payload['runtime']['registry_sha256']='0'*64
            elif field=='runtime':f.payload['runtime']['files']={}
            elif field=='budget':f.payload['providers']['openai']['cost_limit_microunits']=1
            elif field=='expiry':f.payload['expires_epoch']=2000
            elif field=='tokens':f.payload['providers']['openai']['token_limit']['input']=1
            else:f.payload['providers']['openai']['max_new_calls']=8
            f.approve()
            with self.subTest(field=field),self.assertRaises(ResourceGateDenied):f.load()

    def test_shared_limits_include_failed_parent_and_new_budget(self):
        f=self.f;a=f.load();f.payload['shared_max_calls']=a['_history']['global_calls']+13;f.approve()
        with self.assertRaises(ResourceGateDenied):f.load()
        self.assert_parent_unchanged()

    def test_parent_capacity_binding_is_mandatory(self):
        f=self.f;f.accounts.pop('successor_parent_ledger_sha256');f.approve()
        with self.assertRaises(ResourceGateDenied):f.load()
        a=dict(f.payload)
        with self.assertRaises(ResourceGateDenied):fresh.require_parent_capacity_binding(a,{})

    def test_expiry_and_new_slot_single_send(self):
        f=self.f;f.activate();a=f.load()
        with self.assertRaises(ResourceGateDenied):gate._reserve_validated(a,f.env,'openai','gpt-5.6-sol',b'x','qualification-case',1361,offline=True)
        prompt=qualification_prompt(CASES[0]).encode();r=f.reserve_stage('openai','qualification-case',prompt)
        with patch.object(gate,'load_authorization',return_value=a):
            with self.assertRaises(ResourceGateDenied):fresh.claim_transport(a,r,b'wrong')
            fresh.claim_transport(a,r,prompt)
            with self.assertRaises(ResourceGateDenied):fresh.claim_transport(a,r,prompt)
        self.assert_parent_unchanged()

    def test_no_formal_sender_permission_for_offline_or_unapproved_authority(self):
        f=self.f;f.activate();r=f.reserve_stage('openai','qualification-case',qualification_prompt(CASES[0]).encode())
        from harness.resource_gate import _active_reservation
        token=_active_reservation.set(r)
        try:
            with patch.dict(os.environ,f.env),self.assertRaises(ResourceGateDenied):gate.require_active_transport('openai','gpt-5.6-sol',prompt=b'x',claim_send=True)
        finally:_active_reservation.reset(token)
        with self.assertRaises(ResourceGateDenied):gate.load_authorization(f.env)

    def test_parent_qualification_never_inherited(self):
        f=self.f;a=f.load();parent=json.loads(f.failed_authority_bytes)
        parent['_authorization_sha256']=digest(f.failed_authority_bytes)
        with self.assertRaises(ResourceGateDenied):gate.validate_qualification_binding(gate.qualification_binding(parent),dict(a,evidence_domain='FORMAL'))


class BoundedSuccessorEndToEndTests(e2e.FreshTaskEndToEndTests):
    def prepare_fixture(self,f):
        prepare_successor(f)
        output=os.environ.get('CMH_OFFLINE_E2E_EVIDENCE_DIR')
        if output:
            destination=Path(output).parent/'successor';destination.mkdir(parents=True,exist_ok=True)
            self.enterContext(patch.dict(os.environ,CMH_OFFLINE_E2E_EVIDENCE_DIR=str(destination)))
            f.write(destination/'readonly-real-failure-source.json',dict(ledger_sha256=fresh.FAILED_LEDGER_SHA,
                row_sha256=fresh.FAILED_ROW_SHA,source=str(REAL_FAILURE),fixture_identity_and_time_adapted=True))
            for name,path in [('parent-ledger',f.failed_ledger),('parent-checkpoint',gate._checkpoint_path(f.failed_ledger)),('parent-authorization',f.failed_authority)]:
                (destination/('OFFLINE_ONLY-'+name+'.json')).write_bytes(path.read_bytes())

