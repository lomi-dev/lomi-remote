import copy
import importlib.util
from pathlib import Path
import unittest
spec=importlib.util.spec_from_file_location('dpapi_native',Path(__file__).with_name('run_native.py'))
native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
class Acceptance(unittest.TestCase):
    def proof(self):
        crypto={key:True for key in ['same_account_before','same_account_after','provider_kind_windows_dpapi','provider_available_after','transport_acl_verified','ciphertext_readable','ciphertext_unchanged','wrong_sid_rejected']}
        crypto.update(provider_error='SECRET_STORAGE_UNAVAILABLE',local_service_sid='S-1-5-19',ciphertext_sha256='a'*64,ciphertext_bytes=256)
        return dict(runId="test-uuid",created=dict(created=True,started=False,manualLocalService=True,intentBeforeCreate=True,service="LomiProductServiceProbe-test-uuid"),passed=True,fixtureRootAbsent=True,ownedProcessesRemaining=0,taskSchedulerMutations=0,accountChanges=0,syntheticPayloadOnly=True,export=dict(operatorSameAccountBefore=True,operatorSid='S-1-5-21-1-2-3-1000',ciphertextSha256='a'*64,ciphertextBytes=256),run=dict(proof=crypto,processExitCode=0,serviceStoppedExitCode=0,ownerSession=0,processHandleRetained=True,localServiceProfileAbsent=True),finish=dict(operatorSameAccountAfter=True,originalCiphertextUnchanged=True,operatorProfileAbsent=True),deleted=dict(serviceAbsent=True,nativeAbsenceError=1060))
    def test_requires_all_controls_and_exact_provider_error(self):
        native.require_proof(self.proof())
        for key,value in self.proof()['run']['proof'].items():
            changed=self.proof();changed['run']['proof'][key]=False if isinstance(value,bool) else 'different'
            with self.assertRaises(RuntimeError):native.require_proof(changed)
    def test_rejects_missing_cleanup_process_or_positive_controls(self):
        for group in ['created','export','run','finish','deleted']:
            for key,value in self.proof()[group].items():
                if key=='proof':continue
                changed=self.proof();changed[group][key]=not value if isinstance(value,bool) else 'different'
                with self.assertRaises(RuntimeError):native.require_proof(changed)
        for key in ['fixtureRootAbsent','syntheticPayloadOnly','ownedProcessesRemaining','taskSchedulerMutations','accountChanges']:
            changed=self.proof();changed[key]=False if isinstance(changed[key],bool) else 1
            with self.assertRaises(RuntimeError):native.require_proof(changed)
    def test_requires_frozen_build_units_and_cleanup(self):
        report={key:dict(exitCode=0) for key in ['fixture-build','dpapi-unit-tests','fixture-clippy','platform-tests-clippy']};report['dpapi-unit-tests']['verifiedPassedTests']=4
        native.require_build_pass(report)
        for key in report:
            changed=copy.deepcopy(report);changed[key]['exitCode']=1
            with self.assertRaises(RuntimeError):native.require_build_pass(changed)
        clean=dict(ownedSourceAbsent=True,ownedArchiveAbsent=True,ownedProcessesRemaining=0);native.require_cleanup(clean)
        for key in clean:
            changed=clean.copy();changed[key]=False if isinstance(changed[key],bool) else 1
            with self.assertRaises(RuntimeError):native.require_cleanup(changed)
if __name__=='__main__':unittest.main()
