import importlib.util
from pathlib import Path
import unittest
import tempfile
import tomllib
import inspect
from unittest import mock
spec=importlib.util.spec_from_file_location('login_native',Path(__file__).with_name('run_native.py'))
native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
class Acceptance(unittest.TestCase):
    def report(self):
        report={'taskSchedulerMutations':0,'ordinaryInteractiveLifecycleQualified':False,'freshBuildDirectoryVerified':True,'nativeBuildTools':{**{name:True for name in ['msvcCompilerDiscovered','msvcLinkerDiscovered','windowsSdkDiscovered','nativeCBuildRequired']},'compilerExecuted':False},'inputs':{'files':{name:{'sha256':'a'*64} for name in native.LAUNCH_SOURCES}},'peSubsystems':{'lomiremote.exe':3,'lomiremote-host.exe':2},**{name:{'exitCode':0} for name,_,_ in native.native_checks()}}
        for name,_,count in native.native_checks():
            if count is not None:report[name]['verifiedPassedTests']=count
        return report
    def test_requires_all_build_checks_and_gui_helper(self):
        native.require_build_pass(self.report())
        for name,_,_ in native.native_checks():
            value=self.report();value[name]['exitCode']=1
            with self.assertRaises(RuntimeError):native.require_build_pass(value)
        value=self.report();value['peSubsystems']['lomiremote-host.exe']=3
        with self.assertRaises(RuntimeError):native.require_build_pass(value)
    def test_rejects_task_mutation_or_unproved_lifecycle_claim(self):
        for key,value in [('taskSchedulerMutations',1),('ordinaryInteractiveLifecycleQualified',True)]:
            report=self.report();report[key]=value
            with self.assertRaises(RuntimeError):native.require_build_pass(report)
    def test_cleanup_requires_both_artifacts_absent_and_zero_owned_workers(self):
        value={'ownedSourceAbsent':True,'ownedArchiveAbsent':True,'ownedProcessesRemaining':0}
        native.require_cleanup(value)
        for key,replacement in [('ownedSourceAbsent',False),('ownedArchiveAbsent',False),('ownedProcessesRemaining',1)]:
            changed=value.copy();changed[key]=replacement
            with self.assertRaises(RuntimeError):native.require_cleanup(changed)
    def test_rejects_stale_build_and_missing_current_launch_sources(self):
        report=self.report();report['freshBuildDirectoryVerified']=False
        with self.assertRaises(RuntimeError):native.require_build_pass(report)
        for source in native.LAUNCH_SOURCES:
            report=self.report();del report['inputs']['files'][source]
            with self.assertRaises(RuntimeError):native.require_build_pass(report)
        report=self.report();report['login-unit-tests']['verifiedPassedTests']=14
        with self.assertRaises(RuntimeError):native.require_build_pass(report)
    def test_fixture_feature_is_explicit_and_policy_tests_execute_on_native_target(self):
        normal=dict((name,args) for name,args,_ in native.native_checks())
        fixture=dict((name,args) for name,args,_ in native.native_checks(True))
        self.assertNotIn('service-fixture',normal['product-binaries-build'])
        self.assertIn("'--features','service-fixture'",fixture['product-binaries-build'])
        self.assertIn("'test'",normal['policy-unit-tests'])
        self.assertNotIn('--no-run',normal['policy-unit-tests'])
    def test_public_source_inventory_rejects_private_sentinels_and_links(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);(root/'src').mkdir();safe=root/'src/lib.rs';safe.write_text('// synthetic public input')
            self.assertEqual(list(native.selected_crate_sources(root)),[safe])
            for name in ['.env','operator.env.rs','secret.key']:
                private=root/'src'/name;private.write_text('OPERATOR_PRIVATE_SENTINEL')
                with self.assertRaises(RuntimeError):list(native.selected_crate_sources(root))
                private.unlink()
            link=root/'src/link.rs';link.symlink_to(safe)
            with self.assertRaises(RuntimeError):list(native.selected_crate_sources(root))
    def test_current_path_dependency_closure_includes_host_http_auth_crypto_and_external_targets(self):
        files,packages=native.public_dependency_closure(native.ROOT)
        for name in ['crates/lomi-host-auth','crates/lomi-host-http','crates/lomi-remote-crypto','crates/lomi-remote-crypto/vendor/snow','vendor/alacritty_terminal','vendor/vte']:
            self.assertIn(name,packages)
            self.assertIn(name+'/Cargo.toml',files)
        for name in ['crates/lomi-host-auth/src/channel.rs','tests/grant-v3/proof.rs','tests/grant-v3/vectors.json','contracts/terminal-profile-experimental.json','crates/lomi-remote-crypto/vendor/snow/build.rs','tests/terminal-state-native/qualification.rs',*native.LAUNCH_SOURCES]:
            self.assertIn(name,files)
        manifest=tomllib.loads(native.workspace_manifest(native.ROOT,packages))
        self.assertEqual(native.workspace_manifest(native.ROOT,packages),(native.ROOT/'Cargo.toml').read_text())
        self.assertEqual(manifest['workspace']['members'],['crates/*'])
        self.assertIn('crates/lomi-remote-crypto/vendor/snow',manifest['workspace']['exclude'])
    def test_nested_tmpdir_guard_retains_original_manifest_after_staging_removal(self):
        # The owned controller deliberately keeps TMPDIR under the repository.
        # A copied temporary manifest must never become a live-source binding.
        class CapturedGuard(Exception):pass
        captured={}
        original_temporary_directory=tempfile.TemporaryDirectory
        with original_temporary_directory(dir=native.ROOT/'artifacts') as outer:
            outer=Path(outer)
            def nested_staging(*args,**kwargs):
                return original_temporary_directory(*args,dir=outer,**kwargs)
            def capture(files):
                captured.update(inspect.currentframe().f_back.f_locals['source_guard'])
                self.assertEqual(files['Cargo.toml'],native.ROOT/'Cargo.toml')
                raise CapturedGuard
            evidence=mock.Mock();evidence.return_value.save.return_value=None
            with mock.patch.object(native,'ART',outer/'receipts'),mock.patch.object(native,'Evidence',evidence),mock.patch.object(native,'initialize_process_ownership'),mock.patch.object(native.tempfile,'TemporaryDirectory',side_effect=nested_staging),mock.patch.object(native,'require_launch_sources',new=capture),mock.patch('sys.argv',['run_native.py']):
                with self.assertRaises(CapturedGuard):native.main()
            self.assertIn('Cargo.toml',captured)
            self.assertTrue(all((native.ROOT/name).is_file() for name in captured))
            self.assertFalse(any(Path(name).is_relative_to(outer.relative_to(native.ROOT)) for name in captured))
            self.assertEqual(captured['Cargo.toml'],native.digest(native.ROOT/'Cargo.toml'))
            self.assertEqual(captured,{name:native.digest(native.ROOT/name) for name in captured})
    def test_subset_lock_verifies_all_four_dependency_identity_fields(self):
        original='version = 4\n[[package]]\nname = "public"\nversion = "1.0.0"\nsource = "registry+https://example.invalid/index"\nchecksum = "aaa"\n'
        native.verify_subset_lock(original,original)
        for before,after in [('public','other'),('1.0.0','1.0.1'),('example.invalid','other.invalid'),('aaa','bbb')]:
            with self.assertRaises(RuntimeError):native.verify_subset_lock(original,original.replace(before,after))
    def test_closed_native_build_preflight_requires_msvc_and_sdk_without_executing_compiler(self):
        value=self.report()['nativeBuildTools'];native.require_native_build_tools(value)
        for name in value:
            changed=value.copy();changed[name]=not changed[name]
            with self.assertRaises(RuntimeError):native.require_native_build_tools(changed)
        changed=value.copy();changed['compilerPath']='OPERATOR_PRIVATE_SENTINEL'
        with self.assertRaises(RuntimeError):native.require_native_build_tools(changed)
    def test_external_feature_gated_include_closure_rejects_private_files_and_links(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);crate=root/'crates/app';(crate/'src').mkdir(parents=True);(root/'tests').mkdir()
            (root/'Cargo.toml').write_text('[workspace]\nmembers=["crates/app"]\n')
            (crate/'Cargo.toml').write_text('[package]\nname="app"\nversion="0.1.0"\n[[test]]\nname="proof"\npath="../../tests/proof.rs"\nrequired-features=["fixtures"]\n')
            (crate/'src/lib.rs').write_text('// public synthetic source')
            proof=root/'tests/proof.rs';proof.write_text('const DATA: &str = include_str!("vector.json");')
            vector=root/'tests/vector.json';vector.write_text('{}')
            files,_=native.public_dependency_closure(root,('crates/app',))
            self.assertIn('tests/proof.rs',files);self.assertIn('tests/vector.json',files)
            vector.unlink();vector.symlink_to(proof)
            with self.assertRaises(RuntimeError):native.public_dependency_closure(root,('crates/app',))
            vector.unlink();proof.write_text('const DATA: &str = include_str!(".env");');(root/'tests/.env').write_text('OPERATOR_PRIVATE_SENTINEL')
            with self.assertRaises(RuntimeError):native.public_dependency_closure(root,('crates/app',))
    def test_workspace_inherited_path_dependencies_use_original_root_base(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            (root/'Cargo.toml').write_text('[workspace]\nmembers=["crates/app","crates/shared"]\n[workspace.package]\nversion="1.2.3"\n[workspace.dependencies]\nshared={path="crates/shared"}\n')
            for name in ['app','shared']:
                directory=root/'crates'/name;(directory/'src').mkdir(parents=True)
                manifest='[package]\nname="'+name+'"\nversion.workspace=true\n'
                if name=='app':manifest+='[dependencies]\nshared.workspace=true\n'
                (directory/'Cargo.toml').write_text(manifest);(directory/'src/lib.rs').write_text('// public source')
            files,packages=native.public_dependency_closure(root,('crates/app',))
            self.assertIn('crates/shared/Cargo.toml',files)
            self.assertIn('crates/shared/src/lib.rs',files)
            recipe=tomllib.loads(native.workspace_manifest(root,packages))
            self.assertEqual(recipe['workspace']['package']['version'],'1.2.3')
            self.assertEqual(recipe['workspace']['dependencies']['shared']['path'],'crates/shared')
if __name__=='__main__':unittest.main()
