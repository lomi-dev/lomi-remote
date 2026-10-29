import base64
import importlib.util
import json
import sys
from pathlib import Path
import unittest

spec=importlib.util.spec_from_file_location('login_lifecycle',Path(__file__).with_name('lifecycle.py'))
lifecycle=importlib.util.module_from_spec(spec);spec.loader.exec_module(lifecycle)

sys.path.insert(0,str(Path(__file__).parent))
recovery_spec=importlib.util.spec_from_file_location('login_recovery',Path(__file__).with_name('lifecycle-recover.py'))
recovery=importlib.util.module_from_spec(recovery_spec);recovery_spec.loader.exec_module(recovery)

class LifecycleAcceptance(unittest.TestCase):
    def preflight(self):return {'sid':lifecycle.SID,'enabled':True,'administrator':False,'session':2}
    def test_requires_exact_ordinary_active_session(self):
        lifecycle.require_preflight(self.preflight())
        for key,value in [('sid','S-1-5-18'),('enabled',False),('administrator',True),('session',0),('session',True)]:
            changed=self.preflight();changed[key]=value
            with self.assertRaises(RuntimeError):lifecycle.require_preflight(changed)
    def report(self):
        checks=['two-real-ipc-clients-same-runtime-sharing-disabled','actual-managed-helper-ordinary-interactive-session','stopped-restart-new-runtime-same-host-two-clients','running-restart-new-runtime-same-host-two-clients','initial-single-owned-host-and-task','stopped-restart-single-owned-host-and-task','running-restart-single-owned-host-and-task','private-owned-task-folder-and-profile-acls','uninstall-exact-folder-absent-data-preserved-no-hosts']
        inventories=[{'label':label,'cimExactHosts':1,'nativeExactHosts':1,'nativeUnreadableLiveCandidates':0,'folderTasks':1,'folderSubfolders':0,'schedulerInstances':0,'schedulerState':4,'markerProcessBirthMatched':True,'ownerSidMatched':True} for label in ['initial','stopped-restart','running-restart']]
        return {'hostInventories':inventories,'fixtureDiagnostics':False,'restartRuntimes':['runtime-a','runtime-b','runtime-c'],'restartRuns':['run-a','run-b','run-c'],'operations':[{'arguments':['service','restart'],'exitCode':0} for _ in range(2)],'runId':'run','sid':lifecycle.SID,'session':2,'administratorGroup':False,'passed':True,'complete':True,'ordinaryInteractiveLifecycleQualified':True,'productTaskAbsent':True,'dataPreserved':True,'logonTriggerQualified':False,'visibleConsoleQualified':False,'ownedHostsRemaining':0,'checks':[{'name':name,'passed':True} for name in checks]}
    def test_rejects_false_qualification_and_incomplete_cleanup(self):
        lifecycle.require_result(self.report(),'run',2)
        for key,value in [('sid','S-1-5-18'),('session',0),('administratorGroup',True),('passed',False),('productTaskAbsent',False),('ownedHostsRemaining',True),('logonTriggerQualified',True),('visibleConsoleQualified',True),('checks',[])]:
            changed=self.report();changed[key]=value
            with self.assertRaises(RuntimeError):lifecycle.require_result(changed,'run',2)
    def test_singleton_proof_uses_native_and_cim_identity_with_scheduler_observations(self):
        for count in (0,1):
            value=self.report()
            for row in value['hostInventories']:row['schedulerInstances']=count;row['schedulerState']=3
            lifecycle.require_result(value,'run',2)
        for field,replacement in [('cimExactHosts',0),('cimExactHosts',2),('nativeExactHosts',0),('nativeExactHosts',2),('nativeUnreadableLiveCandidates',1),('folderTasks',2),('folderSubfolders',1),('schedulerInstances',2),('schedulerInstances',True),('markerProcessBirthMatched',False),('ownerSidMatched',False)]:
            value=self.report();value['hostInventories'][0][field]=replacement
            with self.assertRaises(RuntimeError):lifecycle.require_result(value,'run',2)
        value=self.report();value['hostInventories'].pop()
        with self.assertRaises(RuntimeError):lifecycle.require_result(value,'run',2)
    def test_cleanup_requires_all_independent_absence_proofs(self):
        value={key:True for key in ['helperTaskAbsent','ordinaryRootAbsent','stageAbsent','freshAbsenceAudit']}
        lifecycle.require_cleanup(value)
        for key in value:
            changed=value.copy();changed[key]=False
            with self.assertRaises(RuntimeError):lifecycle.require_cleanup(changed)
    def test_both_restart_paths_require_distinct_runtimes_and_generations(self):
        for field in ['restartRuntimes','restartRuns']:
            for values in [[],['a','b'],['a','b','b']]:
                changed=self.report();changed[field]=values
                with self.assertRaises(RuntimeError):lifecycle.require_result(changed,'run',2)
        for label in ['stopped-restart','running-restart']:
            changed=self.report();changed['checks']=[row for row in changed['checks'] if not row['name'].startswith(label)]
            with self.assertRaises(RuntimeError):lifecycle.require_result(changed,'run',2)
        changed=self.report();changed['operations'].pop()
        with self.assertRaises(RuntimeError):lifecycle.require_result(changed,'run',2)
    def test_new_active_session_id_is_allowed_but_must_match_result(self):
        fresh=self.preflight();fresh['session']=7;lifecycle.require_preflight(fresh)
        value=self.report();value['session']=7;lifecycle.require_result(value,'run',7)
        with self.assertRaises(RuntimeError):lifecycle.require_result(value,'run',2)
    def test_closed_fixture_diagnostics_never_accept_private_fields_or_unknown_stages(self):
        value=self.report();value['fixtureDiagnostics']=True
        value['operations'][0]['launchDiagnostics']=[{'stage':'Admission','category':'LOGIN_HOST_NOT_READY'}]
        lifecycle.require_result(value,'run',2,True)
        with self.assertRaises(RuntimeError):lifecycle.require_result(value,'run',2,False)
        for diagnostic in [{'stage':'Environment','category':'LOGIN_HOST_NOT_READY'},{'stage':'Admission','category':'OPERATOR_PRIVATE_SENTINEL'},{'stage':'Admission','category':'LOGIN_HOST_NOT_READY','payload':'OPERATOR_PRIVATE_SENTINEL'}]:
            value['operations'][0]['launchDiagnostics']=[diagnostic]
            with self.assertRaises(RuntimeError):lifecycle.require_result(value,'run',2,True)
    def test_closed_native_parser_sanitizes_before_saving_operation(self):
        script=Path(__file__).with_name('lifecycle.ps1').read_text()
        self.assertIn('$errorSummary=Closed-CliError $child.error.Result',script)
        self.assertIn('launchDiagnostics=$errorSummary.diagnostics',script)
        self.assertNotIn('stderr=$child.error.Result',script)
        native=Path(__file__).with_name('lifecycle-tests.ps1').read_text()
        self.assertIn("'closed-admission-stage-retains-canonical-error'",native)
        self.assertIn('OPERATOR_PRIVATE_SENTINEL',native)
    def test_transport_scripts_fit_windows_command_budget(self):
        case=self
        class FakeEvidence:
            path=Path('/tmp/login-receipt.json')
            report={'runId':'00000000-0000-4000-8000-000000000001','inputs':{'files':{'tests/product-login-windows/'+name:{'sha256':'a'*64} for name in ['lifecycle.ps1','lifecycle-admin.ps1','lifecycle-identity.ps1']}}}
            def save(self):pass
            def transfer(self,*args):pass
            def ps(self,name,script):
                case.assertLess(len(base64.b64encode(script.encode('utf-16-le')))+150,7600,name)
                if name=='readonly-ordinary-interactive-preflight':return json.dumps(case.preflight())
                if name=='ordinary-launch':return json.dumps({'identity':{'beforeLastRunTime':'1999-11-30T00:00:00'}})
                if name=='ordinary-poll':return json.dumps({'state':3,'instances':0,'last':0,'lastRunTime':'2026-10-19T12:00:00'})
                value=case.report();value['runId']=self.report['runId'];value['root']='C:\\Users\\test-user\\AppData\\Local\\LomiLoginProof-'+value['runId'];value['installation']=self.report['runId']
                if name in ['ordinary-collect','ordinary-inventory']:return json.dumps(value)
                return json.dumps({key:True for key in ['helperTaskAbsent','ordinaryRootAbsent','stageAbsent','freshAbsenceAudit']})
        lifecycle.execute(FakeEvidence(),'C:\\Users\\woro-server\\lomi-windows-login-00000000-0000-4000-8000-000000000001',[{'name':name,'sha256':'b'*64} for name in ['lomiremote.exe','lomiremote-host.exe']])
        FakeEvidence.path.with_name(FakeEvidence.report['runId']+'.ordinary-inventory.json').unlink()
    def test_failed_completed_helper_receipt_is_retained_without_cleanup(self):
        case=self
        class FakeEvidence:
            report={'runId':'00000000-0000-4000-8000-000000000002','fixtureDiagnostics':True,'inputs':{'files':{'tests/product-login-windows/'+name:{'sha256':'a'*64} for name in ['lifecycle.ps1','lifecycle-admin.ps1','lifecycle-identity.ps1']}}}
            calls=[]
            def save(self):pass
            def transfer(self,*args):case.fail('No cleanup inventory transfer after failed lifecycle')
            def ps(self,name,script):
                self.calls.append(name)
                if name=='readonly-ordinary-interactive-preflight':return json.dumps(case.preflight())
                if name=='ordinary-launch':return json.dumps({'identity':{'beforeLastRunTime':'1999-11-30T00:00:00'}})
                if name=='ordinary-poll':return json.dumps({'state':3,'instances':0,'last':1,'lastRunTime':'2026-10-19T12:00:00'})
                if name=='ordinary-collect':
                    value=case.report();value.update(runId=self.report['runId'],passed=False,complete=False,fixtureDiagnostics=True)
                    value['operations']=[{'arguments':['service','restart'],'exitCode':4,'launchDiagnostics':[{'stage':'Admission','category':'LOGIN_HOST_NOT_READY'}]}]
                    return json.dumps(value)
                return '{}'
        evidence=FakeEvidence()
        with self.assertRaises(RuntimeError):lifecycle.execute(evidence,'C:\\Users\\test\\lomi-windows-login-'+evidence.report['runId'],[{'name':name,'sha256':'b'*64} for name in ['lomiremote.exe','lomiremote-host.exe']])
        self.assertEqual(evidence.report['ordinaryHelperCompletion']['last'],1)
        self.assertFalse(evidence.report['ordinaryLifecycle']['passed'])
        self.assertEqual(evidence.report['ordinaryLifecycle']['operations'][0]['launchDiagnostics'][0]['stage'],'Admission')
        self.assertFalse(any(name in evidence.calls for name in ['ordinary-inventory','ordinary-delete-helper','ordinary-delete-root','ordinary-delete-stage']))
        script=Path(__file__).with_name('lifecycle-admin.ps1').read_text()
        self.assertIn("if($Phase -eq 'collect'){Assert-Completed $task $pin.beforeLastRunTime;",script)
    def test_wrapper_admission_waits_through_never_run_queued_and_running(self):
        before='1999-11-30T00:00:00';fresh='2026-10-19T12:00:00'
        observations=iter([
            {'state':3,'instances':0,'last':0,'lastRunTime':before},
            {'state':3,'instances':0,'last':0x41303,'lastRunTime':before},
            {'state':2,'instances':1,'last':0x41303,'lastRunTime':before},
            {'state':4,'instances':1,'last':0x41301,'lastRunTime':fresh},
            {'state':3,'instances':0,'last':1,'lastRunTime':fresh},
        ])
        clock=[0]
        def sleep(seconds):clock[0]+=seconds
        completed=lifecycle.wait_for_wrapper(lambda:next(observations),before,20,lambda:clock[0],sleep)
        self.assertEqual(completed['last'],1)
        self.assertEqual(clock[0],8)
    def test_never_run_ready_observation_cannot_reset_wrapper_deadline(self):
        before='1999-11-30T00:00:00';clock=[0];polls=[]
        def poll():polls.append(clock[0]);return {'state':3,'instances':0,'last':0,'lastRunTime':before}
        def sleep(seconds):clock[0]+=seconds
        with self.assertRaisesRegex(RuntimeError,'completion unknown'):
            lifecycle.wait_for_wrapper(poll,before,5,lambda:clock[0],sleep)
        self.assertEqual(polls,[0,2,4])
    def test_admin_cleanup_binds_native_identity_and_exact_task(self):
        script=Path(__file__).with_name('lifecycle-admin.ps1').read_text()
        for required in ['xmlSha256','sddlSha256','$d.Actions.Count -ne 1','$d.Actions.Item(1).Path -cne $program','$d.Actions.Item(1).WorkingDirectory -cne $stage','$d.Triggers.Count -ne 0','$d.Principal.RunLevel -ne 0','$task.LastTaskResult -ne 0','Win32_UserProfile','rootIdentity','[LomiLoginFileIdentity]::Read($item.FullName)',"'volume','fileId','finalPath','links'",'Assert-Absent $scheduler']:
            self.assertIn(required,script)
    def test_never_run_recovery_rejects_any_prior_execution_or_uncertainty(self):
        import copy
        value={'passed':False,'complete':False,'runId':'00000000-0000-4000-8000-000000000001','kind':'native-windows-ordinary-login-lifecycle','taskSchedulerMutationsAttempted':True,'failure':'ordinary-launch: command failed','ordinaryInteractiveLifecycleQualified':False,'operations':[{'name':'ordinary-launch','passed':False,'completionKnown':True,'exitCode':1}],'neverRunHelperSnapshot':{'state':3,'instances':0,'last':267011,'lastRunTime':'1999-11-30T00:00:00.0000000','sid':lifecycle.SID,'xml':'<Task/>','sddl':'fixed'}}
        recovery.prepare_intent(value)
        for key,changed in [('state',4),('instances',1),('last',0),('lastRunTime','2026-10-19T12:00:00.0000000'),('sid','S-1-5-18')]:
            candidate=copy.deepcopy(value);candidate['neverRunHelperSnapshot'][key]=changed
            with self.assertRaises(RuntimeError):recovery.prepare_intent(candidate)
        for key,changed in [('passed',True),('completionKnown',False),('exitCode',255)]:
            candidate=copy.deepcopy(value);candidate['operations'][0][key]=changed
            with self.assertRaises(RuntimeError):recovery.prepare_intent(candidate)
    def test_actual_runner_has_no_account_policy_or_process_termination_operations(self):
        script=Path(__file__).with_name('lifecycle.ps1').read_text()
        for forbidden in ['Stop-Process','taskkill','Set-LocalUser','net.exe','Set-ItemProperty','TerminateProcess']:
            self.assertNotIn(forbidden,script)
        self.assertIn("$identity.Groups.Value -contains 'S-1-5-32-544'",script)
        self.assertIn("$session -ne $ExpectedSession",script)

if __name__=='__main__':unittest.main()
