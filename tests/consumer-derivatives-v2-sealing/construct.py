"""Pure deterministic NULL-token constructor. Imports start no children."""
from pathlib import Path
import argparse
import copy
import hashlib
import importlib.util
import json
import os
import stat
import uuid

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
LOCK_SHA = 'd2b246e4c681688c31a3339030887160b2c735ffd20ea345fd90e2baab7b8fd6'
ACCEPTED_MANIFEST_SHA = 'cae4ab3af16fd593daeb023197bcf38866a58640b7fa2d9cd9d03b5140070053'
FILES = ('helper-seal.pending.json', 'catalog-contract.pending.json',
         'operator-seal-auth-helpers.candidate.sql', 'operator-three-roots.candidate.sql')
BASE = 'staging/consumer-derivatives-v2/'
OUTPUT_PARENT = ROOT/'artifacts/consumer-derivatives-v2-sealing-derived'
PREREQUISITE_CANDIDATES = (
    'staging/consumer-derivatives-v2/authority-core.candidate.sql',
    'staging/consumer-derivatives-v2/012-derivative-authority.candidate.sql',
    'staging/consumer-derivatives-v2/typed-entrypoints.candidate.sql',
    'staging/consumer-derivatives-v2/approval-intent.candidate.sql',
)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def require(ok, message):
    if not ok:
        raise ValueError(message)


def read_exact(path, pin):
    path=Path(os.path.abspath(os.fspath(path)))
    require(not any(x.is_symlink() for x in (path,*path.parents)), 'symlink input')
    parent_fd=_open_directory_chain(path.parent)
    try:
        fd=os.open(path.name,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0),dir_fd=parent_fd)
        try:
            with os.fdopen(fd,'rb') as stream:
                fd=-1;data=stream.read()
        finally:
            if fd>=0:os.close(fd)
    finally:
        os.close(parent_fd)
    require(sha(data) == pin, 'input identity mismatch: ' + str(path))
    return data


def validate_frozen_evidence(manifest, receipt, outer, root, manifest_raw,
                             receipt_raw, outer_raw):
    manifest_sha=sha(manifest_raw);receipt_sha=sha(receipt_raw);outer_sha=sha(outer_raw)
    require(manifest_sha==ACCEPTED_MANIFEST_SHA,'accepted manifest identity')
    fixture_id=manifest.get('runId')
    require(isinstance(fixture_id,str) and str(uuid.UUID(fixture_id))==fixture_id,
            'fixture run id')
    require(receipt.get('runId')==fixture_id==outer.get('fixtureRunId')
            ==root.get('fixtureRunId'), 'fixture run id chain')
    require(root.get('manifestSha256')==manifest_sha==receipt.get('manifestSha256')
            ==outer.get('transitionManifestSha256'), 'manifest chain')
    require(root.get('completionReceiptSha256')==receipt_sha
            ==outer.get('completionReceiptSha256'), 'completion chain')
    require(root.get('outerToolResultSha256')==outer_sha, 'outer identity')
    require(manifest.get('targetOldEquality')=={'catalog':True,'metadata':True}
            and root.get('targetOldEquality')=={'catalog':True,'metadata':True},
            'target old equality')
    require(manifest.get('derivedCopies')==[] and manifest.get('derivedCopyDeltas')==[],
            'frozen evidence already has derived copies')
    require(root.get('status') == 'BOUNDED_S0_S4_REFERENCE_RESULT_ACCEPTED'
            and root.get('S5RuntimeAdmitted') is False, 'root scope')
    require(outer.get('actualOuterToolExitCode') == 0
            and outer.get('withinOriginalDeadline') is True
            and 0 <= outer.get('conservativeActualOuterElapsedUpperBoundSeconds',900) < 900,
            'independent exit/deadline')


def validate_output_path(path, expected_parent=OUTPUT_PARENT):
    path=Path(os.path.abspath(os.fspath(path)))
    expected_parent=Path(os.path.abspath(os.fspath(expected_parent)))
    require(path.parent == expected_parent, 'output parent must be dedicated artifacts directory')
    current=path
    while current.parent!=current:
        require(not current.is_symlink(),'symlink output alias')
        current=current.parent
    try:
        parsed=uuid.UUID(path.name)
    except (ValueError,AttributeError):
        raise ValueError('output basename must be a UUID')
    require(str(parsed)==path.name, 'output basename must be canonical UUID')
    return path


def _open_directory_chain(path, create=False, private_leaf=False):
    """Open each absolute path component with O_NOFOLLOW, anchored by dir_fd."""
    path=Path(os.path.abspath(os.fspath(path)))
    flags=os.O_RDONLY|getattr(os,'O_DIRECTORY',0)|getattr(os,'O_NOFOLLOW',0)
    fd=os.open(path.anchor,flags)
    try:
        components=path.parts[1:]
        if private_leaf:require(bool(components),'dedicated output parent cannot be filesystem root')
        for index,component in enumerate(components):
            is_private=private_leaf and index==len(components)-1
            mode=0o700 if is_private else 0o755
            if is_private:
                try:os.stat(component,dir_fd=fd,follow_symlinks=False)
                except FileNotFoundError:
                    if not create:raise
                    try:os.mkdir(component,mode,dir_fd=fd)
                    except FileExistsError:pass
                details=os.stat(component,dir_fd=fd,follow_symlinks=False)
                require(stat.S_ISDIR(details.st_mode),'dedicated output parent is not a directory')
                require(details.st_uid==os.getuid(),'dedicated output parent owner mismatch')
                os.chmod(component,0o700,dir_fd=fd,follow_symlinks=False)
                child=os.open(component,flags,dir_fd=fd)
            else:
                try:
                    child=os.open(component,flags,dir_fd=fd)
                except FileNotFoundError:
                    if not create:raise
                    try:os.mkdir(component,mode,dir_fd=fd)
                    except FileExistsError:pass
                    child=os.open(component,flags,dir_fd=fd)
            os.close(fd);fd=child
        if private_leaf:
            details=os.fstat(fd)
            require(stat.S_ISDIR(details.st_mode),'dedicated output parent is not a directory')
            require(details.st_uid==os.getuid(),'dedicated output parent owner mismatch')
            os.fchmod(fd,0o700)
        result=fd;fd=-1
        return result
    finally:
        if fd>=0:os.close(fd)


def private_mkdir(path):
    path=Path(path)
    parent_fd=_open_directory_chain(path.parent,create=True,private_leaf=True)
    try:
        os.mkdir(path.name,0o700,dir_fd=parent_fd)
        os.chmod(path.name,0o700,dir_fd=parent_fd,follow_symlinks=False)
        output_fd=os.open(path.name,os.O_RDONLY|getattr(os,'O_DIRECTORY',0)
                          |getattr(os,'O_NOFOLLOW',0),dir_fd=parent_fd)
        os.fchmod(output_fd,0o700)
        return output_fd
    finally:
        os.close(parent_fd)


def write_private(name, data, dir_fd):
    fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL
               |getattr(os,'O_NOFOLLOW',0),0o600,dir_fd=dir_fd)
    try:
        os.fchmod(fd,0o600)
        with os.fdopen(fd,'wb') as stream:
            fd=-1
            stream.write(data)
    finally:
        if fd >= 0: os.close(fd)


def load_admitted():
    lock = json.loads(read_exact(HERE/'inputs.lock.json', LOCK_SHA))
    data = {name: read_exact(ROOT/name, pin) for name, pin in lock['sourceAndEvidenceSha256'].items()}
    manifest, receipt, outer, root = [json.loads(data[p]) for p in lock['proofs']]
    validate_frozen_evidence(manifest,receipt,outer,root,data[lock['proofs'][0]],
                             data[lock['proofs'][1]],data[lock['proofs'][2]])
    require(manifest['runId']==Path(lock['proofs'][0]).parent.name,
            'fixture run id differs from frozen evidence directory')
    require(outer['controllerRunId']==Path(lock['proofs'][2]).parent.name,
            'controller run id differs from frozen evidence directory')
    require(manifest['originalInputsUnchanged'] and manifest['cleanup']['completed']
            and manifest['toolchainSha256Before'] == manifest['toolchainSha256After']
            and len(manifest['toolchainSha256Before']) == 49, 'S4 closure')
    require(manifest['stages'] == {s:'PASS' for s in ('S0','S1','S2','S3','S4')}, 'S4 incomplete')
    require(not manifest['pinsFilled'] and not manifest['measuredOperatorsExecuted'], 'wrong source generation')
    spec = importlib.util.spec_from_file_location('sealing_pinned_s4', ROOT/lock['driver'])
    base = importlib.util.module_from_spec(spec); spec.loader.exec_module(base)
    # No process invocation: re-admit exact original archive/28/candidate14/prep8,
    # original NULL contracts, source constructor, authority JSONs and49 tools.
    base.admit_sources()
    prefix = lock['fixtureEvidenceRoot'] + '/'
    refs = {}
    for state in ('old','new'):
        refs[state] = {}
        for kind in ('catalog','metadata'):
            name = prefix + 'lomi_derivative_reference_' + state + '-' + kind + '.json'
            refs[state][kind] = json.loads(data[name])
    contract = json.loads(data[BASE+'catalog-contract.pending.json'])
    helper = json.loads(data[BASE+'helper-seal.pending.json'])
    validate_root_source_correlations(data,lock,manifest,contract)
    validate_references(base, refs, contract, helper)
    return lock, data, manifest, refs, contract, helper


def function_map(rows, signatures):
    result = {}
    for row in rows:
        if row.get('kind') != 'function':
            continue
        require(row['signature'] not in result, 'duplicate function')
        require(sha(bytes.fromhex(row['definitionUtf8Hex'])) == row['catalogSha256'], 'raw definition mismatch')
        require(isinstance(row['acl'], list) and len({json.dumps(a,sort_keys=True) for a in row['acl']}) == len(row['acl']), 'duplicate/invalid ACL')
        result[row['signature']] = row
    require(set(result) == signatures and len(result) == 27, 'missing/extra function closure')
    return result


def extract_candidate_function(raw, name):
    """Return exact candidate DDL bytes and its dollar quote tag, source only."""
    import re
    starts=list(re.finditer(rb'(?m)^CREATE(?: OR REPLACE)? FUNCTION public\.'
                            +re.escape(name.encode())+rb'\s*\(',raw))
    require(len(starts)==1,'candidate function definition is not unique: '+name)
    start=starts[0].start()
    opening=re.search(rb'\bAS\s+(\$[A-Za-z_][A-Za-z_0-9]*\$|\$\$)',raw[starts[0].end():])
    require(opening is not None,'candidate function dollar tag missing: '+name)
    tag=opening.group(1);body_start=starts[0].end()+opening.end()
    end=raw.find(tag,body_start)
    require(end>=0,'candidate function closing dollar tag missing: '+name)
    semicolon=end+len(tag)
    while semicolon<len(raw) and raw[semicolon] in b' \t\r\n':semicolon+=1
    require(semicolon<len(raw) and raw[semicolon:semicolon+1]==b';',
            'candidate function terminator missing: '+name)
    ddl=raw[start:semicolon+1]
    require(ddl.count(tag)==2,'candidate function dollar tag is ambiguous: '+name)
    arguments_start=starts[0].end()-1
    arguments_end=matching_paren(raw,arguments_start)
    argument_types=[candidate_argument_type(part)
                    for part in split_sql_args(raw[arguments_start+1:arguments_end].decode('utf8'))]
    return ddl,tag.decode('ascii'),argument_types


def matching_paren(text, opening):
    depth=0;quote=None;i=opening
    while i<len(text):
        char=text[i]
        if quote:
            if char==quote:
                if i+1<len(text) and text[i+1]==quote:i+=1
                else:quote=None
        elif char in (39,34):quote=char
        elif char==40:depth+=1
        elif char==41:
            depth-=1
            if depth==0:return i
        i+=1
    raise ValueError('unclosed candidate function argument list')


def split_sql_args(text):
    if not text.strip():return []
    args=[];start=0;depth=0;quote=None;i=0
    while i<len(text):
        char=text[i]
        if quote:
            if char==quote:
                if i+1<len(text) and text[i+1]==quote:i+=1
                else:quote=None
        elif char in "'\"":quote=char
        elif char=='(':depth+=1
        elif char==')':depth-=1
        elif char==',' and depth==0:
            args.append(text[start:i].strip());start=i+1
        i+=1
    args.append(text[start:].strip())
    return args


def candidate_argument_type(declaration):
    import re
    declaration=re.split(r'\s+(?:DEFAULT)\s+|\s*=\s*',declaration,
                         maxsplit=1,flags=re.I)[0].strip()
    tokens=declaration.split(None,1)
    require(len(tokens)==2,'candidate argument must declare a name and type')
    if tokens[0].upper() in ('IN','OUT','INOUT','VARIADIC'):
        tokens=tokens[1].split(None,1)
        require(len(tokens)==2,'candidate argument mode lacks name/type')
    return ' '.join(tokens[1].lower().split())


def signature_argument_types(signature):
    opening=signature.find('(');require(opening>=0 and signature.endswith(')'),
                                           'malformed prerequisite signature')
    return [' '.join(arg.lower().split()) for arg in split_sql_args(signature[opening+1:-1])]


def prerequisite_source_correlations(data, lock, contract, new_map):
    source_rows={}
    for path in PREREQUISITE_CANDIDATES:
        source_rows[path]=data[path]
    result={}
    prerequisites=contract['prerequisites']
    require(len(prerequisites)==24,'prerequisite source closure')
    for pin in prerequisites:
        signature=pin['signature'];name=signature.split('(',1)[0].split('.',1)[1]
        matches=[]
        for path,raw in source_rows.items():
            import re
            matches.extend((path,raw) for _ in re.finditer(
                rb'(?m)^CREATE(?: OR REPLACE)? FUNCTION public\.'+re.escape(name.encode())+rb'\s*\(',raw))
        require(len(matches)==1,'prerequisite source definition missing/duplicate: '+signature)
        path,raw=matches[0]
        require(signature in new_map,'prerequisite signature absent from captured catalog: '+signature)
        ddl,tag,source_argument_types=extract_candidate_function(raw,name)
        require(source_argument_types==signature_argument_types(signature),
                'candidate declared argument types differ from contract signature: '+signature)
        catalog=new_map[signature]
        require(catalog['owner']==pin['owner'],'prerequisite source/catalog owner mismatch: '+signature)
        require(tag.startswith('$') and tag.endswith('$'),'candidate dollar tag invalid: '+signature)
        result[signature]={
            'candidatePath':path,
            'candidateFileSha256':lock['sourceAndEvidenceSha256'][path],
            'candidateFunctionSourceSha256':sha(ddl),
            'catalogSignature':signature,
            'catalogDefinitionSha256':catalog['catalogSha256'],
            'contractOwner':pin['owner'],
            'catalogOwner':catalog['owner'],
            'ownerMatch':True,
            'dollarQuoteTag':tag,
            'correlationBasis':'unique CREATE FUNCTION name in pinned candidate source; declared input type list equals contract signature; contract owner equals captured catalog owner; source and catalog hashes are separate and are not asserted equal',
            'declaredInputTypes':source_argument_types,
        }
    return result


def validate_root_source_correlations(data, lock, manifest, contract):
    """Bind frozen old sources and operator literals to the accepted S4 record."""
    correlations=manifest.get('sourceCorrelations')
    require(isinstance(correlations,dict),'missing frozen source correlations')
    predecessors=correlations.get('predecessor')
    literals=correlations.get('rootLiterals')
    require(isinstance(predecessors,list) and len(predecessors)==3,
            'frozen predecessor source closure')
    require(isinstance(literals,list) and len(literals)==3,
            'frozen root literal closure')
    roots={row['signature']:row for row in contract['roots']}
    require(len(roots)==3,'candidate root contract closure')
    predecessor_by_signature={row.get('signature'):row for row in predecessors}
    literal_by_signature={row.get('signature'):row for row in literals}
    require(set(predecessor_by_signature)==set(roots)
            and set(literal_by_signature)==set(roots),
            'S4 source/candidate root signatures differ')

    operator=data[BASE+'operator-three-roots.candidate.sql']
    blocks=[]
    for index in range(3):
        tag=f'$literal{index}$'.encode('ascii')
        require(operator.count(tag)==2,'ambiguous operator literal block')
        start=operator.index(tag)+len(tag)
        end=operator.index(tag,start)
        blocks.append(operator[start:end])

    result={}
    for signature,pin in roots.items():
        name=signature.split('(',1)[0].split('.',1)[1]
        predecessor=predecessor_by_signature[signature]
        require(isinstance(predecessor.get('source'),str)
                and predecessor['source'].startswith('prisma/migrations/'),
                'predecessor migration is not pinned: '+signature)
        require(predecessor.get('sourceSha256')==pin.get('old_source_sha256'),
                'predecessor hash differs from root source contract: '+signature)
        old_source=data[BASE+name+'.old-source.sql']
        require(old_source.endswith(b'\n')
                and sha(old_source[:-1])==predecessor.get('sourceSha256'),
                'old-source differs from frozen S4 predecessor: '+signature)

        record=literal_by_signature[signature]
        require(record.get('name')==name,'root literal name mismatch: '+signature)
        require(record.get('migration')==predecessor.get('source'),
                'predecessor and root literal migration differ: '+signature)
        require(record.get('manifestCreateFormSha256')==pin.get('new_source_sha256'),
                'root literal hash differs from candidate source contract: '+signature)
        matches=[ddl for ddl in blocks
                 if sha(ddl)==record.get('literalSha256')]
        require(len(matches)==1,
                'operator literal differs from frozen S4 source: '+signature)
        ddl=matches[0]
        create_form=b'CREATE OR REPLACE FUNCTION'
        require(ddl.startswith(create_form),
                'operator root literal prefix changed: '+signature)
        manifest_form=b'CREATE FUNCTION'+ddl[len(create_form):]
        require(sha(manifest_form)==record.get('manifestCreateFormSha256'),
                'operator root literal differs from S4 manifest create form: '+signature)
        _,_,types=extract_candidate_function(ddl,name)
        require(types==signature_argument_types(signature),
                'operator root declared argument types differ from S4 signature: '+signature)
        result[signature]={
            'predecessorSource':predecessor['source'],
            'predecessorSourceSha256':predecessor['sourceSha256'],
            'oldSourceFileSha256':sha(old_source),
            'operatorLiteralSha256':record['literalSha256'],
            'manifestCreateFormSha256':record['manifestCreateFormSha256'],
            'declaredInputTypes':types,
        }
    return result


def validate_references(base, refs, contract, helper):
    signatures = {r['signature'] for r in contract['roots']+contract['prerequisites']}
    require(len(signatures)==27 and len(contract['roots'])==3 and len(helper['helpers'])==2, 'unexpected contract shape')
    maps = {s:function_map(refs[s]['catalog'],signatures) for s in ('old','new')}
    roots={r['signature'] for r in contract['roots']}; helpers={r['signature'] for r in helper['helpers']}
    for s in ('old','new'):
        base.reject_authority_drift(refs[s]['catalog']); base.reject_authority_drift(refs[s]['metadata'])
        base.protected_relation_map(refs[s]['metadata'])
    require(base.canonical(refs['old']['metadata']) == base.canonical(refs['new']['metadata']), 'reference metadata drift')
    for sig in signatures:
        old,new=maps['old'][sig],maps['new'][sig]
        if sig in helpers:
            require(old['owner']=='lomi_migrator' and new['owner']=='lomi_consumer_auth_body_owner', 'helper owner')
            require({k:v for k,v in old.items() if k not in ('owner','acl')} == {k:v for k,v in new.items() if k not in ('owner','acl')}, 'helper body/config drift')
        elif sig in roots:
            require(old['owner']==new['owner']=='lomi_remote_inventory_owner', 'root owner')
            require({k:v for k,v in old.items() if k not in ('definitionUtf8Hex','catalogSha256')} == {k:v for k,v in new.items() if k not in ('definitionUtf8Hex','catalogSha256')}, 'root authority drift')
            require(old['catalogSha256'] != new['catalogSha256'], 'root transition absent')
        else:
            require(old==new, 'unrelated function drift')
            prereq=next((r for r in contract['prerequisites'] if r['signature']==sig),None)
            if prereq is not None:
                require(new['owner']==prereq['owner'],'prerequisite contract/catalog owner drift')
    for s in ('old','new'):
        others=[r for r in refs[s]['catalog'] if r.get('kind')!='function']
        refs_map=base.protected_relation_map(refs[s]['metadata'])
        if s=='old': expected=base.canonical(others,refs_map)
        else: require(base.canonical(others,refs_map)==expected,'reference role/default/column/type ACL drift')
    return maps


def null_spans(text):
    """A JSON parser with exact value spans; no SQL/body text replacement."""
    decoder=json.JSONDecoder(); spans={}
    def ws(i):
        while i<len(text) and text[i].isspace(): i+=1
        return i
    def parse(i,path):
        i=ws(i)
        if text[i]=='{':
            i=ws(i+1); seen=set()
            if text[i]=='}': return i+1
            while True:
                key,j=decoder.raw_decode(text,i); require(isinstance(key,str) and key not in seen,'duplicate JSON key');seen.add(key)
                i=ws(j);require(text[i]==':','JSON colon');i=ws(parse(i+1,(*path,key)))
                if text[i]=='}':return i+1
                require(text[i]==',','JSON comma');i=ws(i+1)
        if text[i]=='[':
            i=ws(i+1);n=0
            if text[i]==']':return i+1
            while True:
                i=ws(parse(i,(*path,n)));n+=1
                if text[i]==']':return i+1
                require(text[i]==',','JSON comma');i=ws(i+1)
        value,j=decoder.raw_decode(text,i)
        if value is None:spans[path]=(i,j)
        return j
    end=parse(0,());require(ws(end)==len(text),'extra JSON input')
    return spans


def fill_json(raw, values, correlations):
    text=raw.decode('utf8'); spans=null_spans(text)
    require(set(spans)==set(values), 'NULL allowlist differs; no missing/extra pins')
    edits=[]
    for path,(start,end) in spans.items():
        value=values[path];require(value is not None,'unfilled pin')
        edits.append((len(text[:start].encode()),len(text[:end].encode()),json.dumps(value,ensure_ascii=True,separators=(',',':')).encode(),path))
    output=bytearray(); previous=0; deltas=[]
    for start,end,replacement,path in sorted(edits):
        output.extend(raw[previous:start]);newstart=len(output);output.extend(replacement)
        deltas.append(dict(path=list(path),originalStart=start,originalEnd=end,derivedStart=newstart,derivedEnd=len(output),oldHex=raw[start:end].hex(),newHex=replacement.hex(),correlation=correlations[path]))
        previous=end
    output.extend(raw[previous:]);return bytes(output),deltas


def construct():
    lock,data,manifest,refs,contract,helper=load_admitted()
    root_source_correlations=validate_root_source_correlations(data,lock,manifest,contract)
    signatures={r['signature'] for r in contract['roots']+contract['prerequisites']}
    maps={s:function_map(refs[s]['catalog'],signatures) for s in ('old','new')}
    values={}; correlations={}
    for filename, groups in [('helper-seal.pending.json',[('helpers',helper['helpers'])]),('catalog-contract.pending.json',[('roots',contract['roots']),('prerequisites',contract['prerequisites'])])]:
        vs={}; cs={}
        for group,rows in groups:
            for i,pin in enumerate(rows):
                states=('new',) if group=='prerequisites' else ('old','new')
                for state in states:
                    row=maps[state][pin['signature']]
                    for field,catalogfield in [('catalog_sha256','catalogSha256'),('acl','acl')]:
                        key=field if group=='prerequisites' else state+'_'+field
                        path=(group,i,key);require(pin[key] is None,'original pin already filled')
                        vs[path]=copy.deepcopy(row[catalogfield])
                        cs[path]={'referenceState':state,'referenceFile':'lomi_derivative_reference_'+state+'-catalog.json','referenceSha256':lock['sourceAndEvidenceSha256'][lock['fixtureEvidenceRoot']+'/lomi_derivative_reference_'+state+'-catalog.json'],'signature':pin['signature'],'catalogField':catalogfield,'sourceConstructionTranscriptSha256':lock['sourceAndEvidenceSha256'][lock['fixtureEvidenceRoot']+'/reference-transcripts.json'],'rawDefinitionSha256':row['catalogSha256'],'unchangedSourceCorrelation':{k:v for k,v in pin.items() if 'source_sha256' in k}}
        values[filename]=vs;correlations[filename]=cs
    output={};delta={}
    prerequisite_correlations=prerequisite_source_correlations(
        data,lock,contract,maps['new'])
    for filename in FILES[:2]:output[filename],delta[filename]=fill_json(data[BASE+filename],values[filename],correlations[filename])
    for filename,blocks in [('operator-seal-auth-helpers.candidate.sql',[('$helper_pins$','helper-seal.pending.json','helpers')]),('operator-three-roots.candidate.sql',[('$pins$','catalog-contract.pending.json','roots'),('$deps$','catalog-contract.pending.json','prerequisites')])]:
        raw=data[BASE+filename]; out=bytearray();pos=0;delta[filename]=[]
        for marker,source,group in blocks:
            tag=marker.encode();require(raw.count(tag)==2,'ambiguous JSON delimiter')
            a=raw.index(tag)+len(tag);b=raw.index(tag,a)
            require(json.loads(raw[a:b])==json.loads(data[BASE+source])[group],'embedded JSON differs from contract')
            vs={(i,k):v for (g,i,k),v in values[source].items() if g==group};cs={(i,k):v for (g,i,k),v in correlations[source].items() if g==group}
            filled,changes=fill_json(raw[a:b],vs,cs);out.extend(raw[pos:a]);offset=len(out)
            for change in changes:
                change['originalStart']+=a;change['originalEnd']+=a;change['derivedStart']+=offset;change['derivedEnd']+=offset;change['jsonBlock']=marker
            delta[filename].extend(changes);out.extend(filled);pos=b
        out.extend(raw[pos:]);output[filename]=bytes(out)
    report={'status':'DERIVED_FIXTURE_SOURCE_ONLY_RUNTIME_NOT_RUN','admittedManifestSha256':sha(data[lock['proofs'][0]]),'rootReviewSha256':sha(data[lock['proofs'][3]]),'sourceLockSha256':LOCK_SHA,'files':{n:{'sourceSha256':sha(data[BASE+n]),'derivedSha256':sha(output[n]),'deltas':delta[n]} for n in FILES},'sourceCorrelations':manifest['sourceCorrelations'],'rootSourceCorrelations':root_source_correlations,'prerequisiteSourceCorrelations':prerequisite_correlations,'originalPinsModified':False,'S5':'NOT_RUN'}
    return output,report


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',required=True,type=Path);args=parser.parse_args()
    output_path=validate_output_path(args.output)
    output,report=construct();output_fd=private_mkdir(output_path)
    try:
        for name,raw in output.items(): write_private(name,raw,output_fd)
        write_private('derived-manifest.json',(json.dumps(report,indent=2)+'\n').encode(),output_fd)
    finally:os.close(output_fd)
    print(json.dumps({'status':report['status'],'output':str(output_path),'files':{n:sha(b) for n,b in output.items()}}))

if __name__=='__main__':main()
