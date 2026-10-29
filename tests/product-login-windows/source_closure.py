"""Public local Cargo path dependencies and literal compile-input closure."""
from pathlib import Path
import os
import re
import tomllib

SOURCE_SUFFIXES={'.rs','.c','.h','.txt','.py'}
PUBLIC_SUFFIXES=SOURCE_SUFFIXES|{'.json','.toml','.md'}

def public_file(root,path):
    path=Path(os.path.abspath(path))
    relative=path.relative_to(root)
    current=root
    for part in relative.parts:
        current=current/part
        if current.is_symlink():raise RuntimeError('Symlink in public dependency closure')
        if part.startswith('.') or part in {'target','artifacts','node_modules'} or '.env' in part.lower():
            raise RuntimeError('Private/cache path in public dependency closure')
    if path.suffix not in PUBLIC_SUFFIXES or not path.is_file():raise RuntimeError('Unexpected public compile-input type')
    return path

def dependency_paths(document,workspace_dependencies):
    for name,table in document.items():
        if not isinstance(table,dict):continue
        if name in {'dependencies','dev-dependencies','build-dependencies'}:
            for alias,dependency in table.items():
                if isinstance(dependency,dict) and dependency.get('workspace') is True:
                    if alias not in workspace_dependencies:raise RuntimeError('Inherited workspace dependency missing')
                    inherited=workspace_dependencies[alias]
                    if isinstance(inherited,dict) and 'path' in inherited:yield inherited['path'],True
                elif isinstance(dependency,dict) and 'path' in dependency:yield dependency['path'],False
        else:
            yield from dependency_paths(table,workspace_dependencies)

def package_source_files(directory):
    for source in sorted(directory.rglob('*')):
        relative=source.relative_to(directory)
        if source.is_symlink():raise RuntimeError('Symlink in public source closure')
        if any(part in {'target','artifacts','.git','.venv','node_modules'} for part in relative.parts):
            if source.is_file():raise RuntimeError('Unexpected cache in public source closure')
            continue
        if '.env' in source.name.lower() or source.suffix.lower() in {'.pem','.key'}:
            raise RuntimeError('Private filename in public source closure')
        if source.is_file() and source.suffix in SOURCE_SUFFIXES:yield source

def public_dependency_closure(root,seeds=('crates/lomiremote','crates/lomi-platform')):
    root=Path(os.path.abspath(root))
    root_manifest=public_file(root,root/'Cargo.toml')
    workspace=tomllib.loads(root_manifest.read_text())
    pending=[root/seed for seed in seeds]
    for registry in workspace.get('patch',{}).values():
        for patch in registry.values():
            if isinstance(patch,dict) and 'path' in patch:pending.append(root/patch['path'])
    packages={};files={'Cargo.toml':root_manifest}
    def add(path):
        path=public_file(root,path);files[path.relative_to(root).as_posix()]=path
        return path
    while pending:
        directory=Path(os.path.abspath(pending.pop()))
        manifest=public_file(root,directory/'Cargo.toml')
        name=directory.relative_to(root).as_posix()
        if name in packages:continue
        document=tomllib.loads(manifest.read_text());packages[name]=document
        add(manifest)
        for dependency,inherited in dependency_paths(document,workspace.get('workspace',{}).get('dependencies',{})):
            pending.append((root if inherited else directory)/dependency)
        for source in package_source_files(directory):add(source)
        readme=document.get('package',{}).get('readme','README.md')
        if isinstance(readme,str) and (directory/readme).exists():add(directory/readme)
        build=document.get('package',{}).get('build')
        if isinstance(build,str):add(directory/build)
        targets=[document.get('lib',{})]
        for kind in ['bin','test','example','bench']:targets.extend(document.get(kind,[]))
        for target in targets:
            if 'path' in target:add(directory/target['path'])
    # Explicit external test/module paths and data includes remain required
    # even when their Cargo targets are gated by required-features.
    scanned=set()
    while True:
        pending=[p for p in files.values() if p.suffix=='.rs' and p not in scanned]
        if not pending:break
        for source in pending:
            scanned.add(source);text=source.read_text()
            for include in re.findall(r'include_(?:str|bytes)!\s*\(\s*"([^"]+)"',text):add(source.parent/include)
            for module in re.findall(r'#\[path\s*=\s*"([^"]+)"\]',text):add(source.parent/module)
    return files,packages

def workspace_manifest(root,packages):
    original=(root/'Cargo.toml').read_text()
    workspace=tomllib.loads(original)['workspace']
    # Pinned Cargo 1.98.1 lets an explicit parent member override a nested
    # exclude via starts_with; preserving the original glob keeps Snow out.
    # cargo 797e8a9b/src/cargo/core/workspace.rs:1985 (is_excluded).
    # Only the selected public package directories are copied into staging.
    for member in workspace['members']:
        if not any(character in member for character in '*?[') and member not in packages:
            raise RuntimeError('Literal workspace member outside selected closure')
    return original

def verify_subset_lock(original,subset):
    identity=lambda package:tuple(package.get(key) for key in ['name','version','source','checksum'])
    frozen={identity(package) for package in tomllib.loads(original)['package']}
    if any(identity(package) not in frozen for package in tomllib.loads(subset)['package']):
        raise RuntimeError('Harness dependency differs from frozen workspace lock')
