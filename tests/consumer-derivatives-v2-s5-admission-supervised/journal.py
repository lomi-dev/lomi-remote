"""Staged five-only lossless command journals; no runner or native entrypoint."""
import hashlib
import json
from pathlib import Path
import re

VERSION='supervised-five-command-journal-v1'
COMMAND_KEYS={'id','label','argv','returncode','stdout','stderr'}
HEX=re.compile(r'[0-9a-f]{64}')

def encoded(value):return (json.dumps(value,indent=2)+'\n').encode()
def sha(raw):return hashlib.sha256(raw).hexdigest()
def same(left,right):return encoded(left)==encoded(right)

def frozen_json(value, fail):
    def forbidden(*args,**kwargs):
        fail('prior command history mutation');raise ValueError('immutable journal history')
    if type(value) is dict:
        class FrozenDict(dict):
            __setitem__=__delitem__=clear=pop=popitem=setdefault=update=__ior__=forbidden
        return FrozenDict({k:frozen_json(v,fail) for k,v in value.items()})
    if type(value) is list:
        class FrozenList(list):
            __setitem__=__delitem__=append=extend=insert=pop=remove=clear=reverse=sort=__iadd__=__imul__=forbidden
        return FrozenList(frozen_json(v,fail) for v in value)
    return value


def journal_fixture_class(parent_factory,helper,base,recorder):
    """Layer on the unchanged public five factory; CTAS never selects this."""
    parent=parent_factory(helper,base,recorder)
    class JournalFixture(parent):
        def __init__(self,*args,**kwargs):
            super().__init__(*args,**kwargs)
            self.journal_failed=False;self.journal_finalized=False
            self.journals=[];self.journal_children=[];self.journal_attestations=[]
            owner=self
            class Events(recorder.RecordedEvents):
                def append(events,entry):
                    if owner.journal_failed:raise ValueError('journal already failed')
                    if type(entry) is not dict or set(entry)!=COMMAND_KEYS or type(entry['id']) is not int or entry['id']!=len(events)+1:
                        owner.journal_fail('noncontiguous command append');raise ValueError('invalid command append')
                    super().append(entry)
                    if set(events[-1])!=COMMAND_KEYS:
                        owner.journal_fail('incomplete recorded event');raise ValueError('incomplete recorded event')
                    list.__setitem__(events,-1,frozen_json(events[-1],owner.journal_fail))
                def forbidden(events,*args,**kwargs):
                    owner.journal_fail('command history mutation');raise ValueError('immutable command history')
                __setitem__=__delitem__=extend=insert=pop=remove=clear=reverse=sort=__iadd__=__imul__=forbidden
            self.events=Events(self.recording_store,self.recording_scope)

        def journal_fail(self,message):
            self.journal_failed=True
            self.recording_store.fail(ValueError(message))
            if len(self.evidence_errors)<16:self.evidence_errors.append('command journal: '+message)

        def journal_binding(self):
            child=self.owned.last_child;result=self.owned.last_result
            if (child is None or result is None or not any(c is child for c in self.guardian.children)
                or child.foreground or child.retired or not child.reaped or not child.group_quiet
                or result.evidenceComplete is not True or tuple(result.argv)!=child.argv
                or result.pid!=child.handle.pid or result.returncode!=child.exit_code
                or type(result.returncode) is not int or any(type(x) is not str or HEX.fullmatch(x) is None for x in (result.stdoutSha256,result.stderrSha256))):
                raise ValueError('command Child/Result binding')
            return child,result

        def journal_streams(self,result):
            return [dict(stream='stdout',stdout=self.recording_store.compact(result.stdout),rawSha256=result.stdoutSha256),
                    dict(stream='stderr',stdout=self.recording_store.compact(result.stderr),rawSha256=result.stderrSha256)]

        def save(self,name,value):
            try:
                if name=='commands.json':
                    if self.journal_failed or self.journal_finalized:raise ValueError('journal closed or failed')
                    if value is not self.events or len(value)!=len(self.journals)+1 or self.sequence!=len(value):
                        raise ValueError('one new command required')
                    if any(value[i] is not pair[0] for i,pair in enumerate(self.journals)):
                        raise ValueError('prior command history changed')
                    child,result=self.journal_binding();entry=value[-1]
                    clean=lambda text:text.replace(str(self.work),'<owned>').replace(str(base.ROOT),'<repo>')
                    expected=dict(id=self.sequence,label=entry['label'],argv=[clean(str(a)) for a in result.argv],
                        returncode=result.returncode,stdout=entry['stdout'],stderr=clean(result.stderr))
                    text=clean(result.stdout);actual=entry['stdout']
                    if isinstance(actual,str):
                        if actual!=text:raise ValueError('legacy stdout mismatch')
                    elif (not isinstance(actual,dict) or actual.get('encoding')!='gzip-utf8-v1'
                        or actual.get('logicalSha256')!=sha(text.encode()) or actual.get('logicalBytes')!=len(text.encode())):
                        raise ValueError('legacy compact stdout mismatch')
                    if not same(entry,expected):raise ValueError('legacy command/result mismatch')
                    streams=self.journal_streams(result)
                    record=[dict(entry,version=VERSION,kind='command'),*streams]
                    digest=super().save('owned-result-'+str(self.sequence)+'.json',record)
                    self.journals.append((entry,digest,record));self.journal_children.append(child)
                    self.journal_attestations.append(dict(sequence=self.sequence,pid=result.pid,argv=list(result.argv),
                        returncode=result.returncode,stdoutRawSha256=result.stdoutSha256,stderrRawSha256=result.stderrSha256,
                        stdoutLegacyTextSha256=sha(clean(result.stdout).encode()),stderrLegacyTextSha256=sha(clean(result.stderr).encode()),helperVerified=False,evidenceComplete=True))
                    return digest
                match=re.fullmatch(r'owned-result-([1-9][0-9]*)\.json',name)
                if match:
                    if self.journal_failed:raise ValueError('latched journal failure blocks retirement')
                    seq=int(match[1]);child,result=self.journal_binding()
                    if seq!=self.sequence or seq!=len(self.journals) or child is not self.journal_children[-1]:
                        raise ValueError('owned-result sequence/Child mismatch')
                    if not same(value,self.journals[-1][2][1:]) or not same(value,self.journal_streams(result)):
                        raise ValueError('owned-result differs from committed journal')
                    raw=self.recording_store._verify((self.recording_scope+'/' if self.recording_scope else '')+name)
                    if sha(raw)!=self.journals[-1][1] or raw!=encoded(self.journals[-1][2]):raise ValueError('committed journal changed before retirement')
                    if self.journal_attestations[-1]['helperVerified']:raise ValueError('duplicate helper result save')
                    self.journal_attestations[-1]['helperVerified']=True
                    return self.journals[-1][1]
                return super().save(name,value)
            except (OSError,ValueError,UnicodeError) as exc:
                if name=='commands.json' or re.fullmatch(r'owned-result-[0-9]+\.json',name):self.journal_fail(type(exc).__name__+': '+str(exc))
                raise

        def _materialize_commands(self):
            if self.journal_failed or self.journal_finalized:raise ValueError('journal failed or already materialized')
            if self.guardian.cleanup_result is None or self.guardian.cleanup_result.get('completed') is not True or self.guardian.handlers_installed is not False:
                raise ValueError('materialization requires finished owner cleanup')
            if len(self.journals)!=len(self.events) or len(self.journal_children)!=self.sequence:raise ValueError('journal history length')
            committed=[];visited=[];logical=0
            names=tuple((self.recording_scope+'/' if self.recording_scope else '')+'owned-result-'+str(index)+'.json'
                        for index in range(1,len(self.journals)+1))
            expected_events=encoded(self.events)
            if len(expected_events)>self.recording_store.max_item:raise ValueError('final history item limit exceeded')
            bindings=lambda:sha(encoded([(digest,sha(encoded(record))) for entry,digest,record in self.journals]))
            expected_bindings=bindings()
            def collect(name,raw):
                nonlocal logical
                index=len(visited)+1
                if index>len(names) or name!=names[index-1]:raise ValueError('journal batch order changed')
                entry,digest,record=self.journals[index-1]
                if sha(raw)!=digest or raw!=encoded(record):raise ValueError('committed journal changed')
                legacy=dict(json.loads(raw)[0]);legacy.pop('version');legacy.pop('kind')
                logical+=len(encoded([legacy]))  # Conservative final-array logical bound.
                if logical>self.recording_store.max_item:raise ValueError('final history item limit exceeded')
                if not self.journal_children[index-1].retired or not self.journal_attestations[index-1]['helperVerified']:
                    raise ValueError('command retirement incomplete')
                committed.append(legacy);visited.append(name)
            self.recording_store._verified_read_batch(names,collect)
            if tuple(visited)!=names or bindings()!=expected_bindings or encoded(self.events)!=expected_events:
                raise ValueError('journal history changed during batch')
            if encoded(committed)!=expected_events:raise ValueError('final stored history differs from events')
            result=super().save('commands.json',committed)
            self.journal_finalized=True
            return result
        def materialize_commands(self):
            try:return self._materialize_commands()
            except (OSError,ValueError,UnicodeError) as exc:
                self.journal_fail(type(exc).__name__+': '+str(exc));raise

        def command_journal_metadata(self):
            if not self.journal_finalized or self.journal_failed:raise ValueError('journal not finalized')
            rows=[]
            for child,attestation in zip(self.journal_children,self.journal_attestations,strict=True):
                if (not any(c is child for c in self.guardian.children) or not child.retired or not child.reaped
                    or not child.group_quiet or child.foreground or child.handle.pid!=attestation['pid']
                    or list(child.argv)!=attestation['argv'] or child.exit_code!=attestation['returncode']):
                    self.journal_fail('postfinish retained Child mismatch');raise ValueError('postfinish retained Child mismatch')
                rows.append(dict(attestation,retired=child.retired,reaped=child.reaped,groupQuiet=child.group_quiet,foreground=child.foreground))
            return dict(version=VERSION,work=str(self.work),repository=str(base.ROOT),commands=rows)
    return JournalFixture


def strict_json(raw):
    def pairs(items):
        value={}
        for key,item in items:
            if key in value:raise ValueError('duplicate journal JSON key')
            value[key]=item
        return value
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda x:(_ for _ in ()).throw(ValueError('nonfinite journal JSON')))


def verify_command_journals(reader,scope,metadata,*,repository,databases):
    """Independent stored evidence join; hashes never imply future PID ownership."""
    if reader.validate() is not True:raise ValueError('journal reader incomplete')
    if type(metadata) is not dict or set(metadata)!={'version','work','repository','commands'} or metadata['version']!=VERSION:
        raise ValueError('closed journal metadata')
    if metadata['repository']!=str(repository) or type(metadata['work']) is not str:
        raise ValueError('journal normalization paths')
    work=metadata['work'];repo=metadata['repository']
    if not Path(work).is_absolute() or str(Path(work))!=work or '..' in Path(work).parts:
        raise ValueError('canonical journal work')
    if not same(reader.read(scope+'/case-cleanup.json')['commandJournal'],metadata):raise ValueError('stored metadata binding')
    rows=metadata['commands']
    if type(rows) is not list or not rows:raise ValueError('nonempty journal attestations')
    history=strict_json(reader.raw(scope+'/commands.json'))
    if type(history) is not list or len(history)!=len(rows):raise ValueError('command history count')
    expected={scope+'/owned-result-'+str(i)+'.json' for i in range(1,len(rows)+1)}
    actual={n for n in reader.index['files'] if n.startswith(scope+'/owned-result-')}
    if actual!=expected:raise ValueError('contiguous journal namespace')
    legacy=[];sql_sequences=set()
    clean=lambda text:text.replace(work,'<owned>').replace(repo,'<repo>')
    fields={'sequence','pid','argv','returncode','stdoutRawSha256','stderrRawSha256',
        'stdoutLegacyTextSha256','stderrLegacyTextSha256','helperVerified','evidenceComplete',
        'retired','reaped','groupQuiet','foreground'}
    for sequence,attestation in enumerate(rows,1):
        if type(attestation) is not dict or set(attestation)!=fields:raise ValueError('closed Guardian attestation')
        a=attestation
        if (type(a['sequence']) is not int or a['sequence']!=sequence or type(a['pid']) is not int or a['pid']<=1
            or type(a['returncode']) is not int or a['returncode']!=0 or type(a['argv']) is not list or not a['argv']
            or any(type(v) is not str for v in a['argv'])
            or any(a[k] is not True for k in ('helperVerified','evidenceComplete','retired','reaped','groupQuiet'))
            or a['foreground'] is not False):raise ValueError('Guardian attestation values')
        if any(type(a[k]) is not str or HEX.fullmatch(a[k]) is None for k in ('stdoutRawSha256','stderrRawSha256','stdoutLegacyTextSha256','stderrLegacyTextSha256')):
            raise ValueError('attested hash type')
        journal=reader.read(scope+'/owned-result-'+str(sequence)+'.json')
        if type(journal) is not list or len(journal)!=3:raise ValueError('three-entry command journal')
        command=journal[0]
        if (type(command) is not dict or set(command)!=COMMAND_KEYS|{'version','kind'}
            or command['version']!=VERSION or command['kind']!='command' or type(command['id']) is not int or command['id']!=sequence
            or type(command['label']) is not str or type(command['argv']) is not list
            or any(type(v) is not str for v in command['argv']) or type(command['returncode']) is not int
            or command['returncode']!=a['returncode'] or type(command['stderr']) is not str):raise ValueError('closed legacy command entry')
        expanded=reader.stdout(command['stdout']);streams=[]
        for index,stream in enumerate(('stdout','stderr'),1):
            row=journal[index]
            if type(row) is not dict or set(row)!={'stream','stdout','rawSha256'} or row['stream']!=stream or row['rawSha256']!=a[stream+'RawSha256']:
                raise ValueError('journal raw Guardian SHA binding')
            text=reader.stdout(row['stdout']);streams.append(text)
            normalized=clean(text)
            if sha(normalized.encode())!=a[stream+'LegacyTextSha256']:raise ValueError('normalized legacy text SHA binding')
            if normalized!=(expanded if stream=='stdout' else command['stderr']):raise ValueError('legacy/owned stream mismatch')
        if command['argv']!=[clean(arg) for arg in a['argv']]:raise ValueError('command argv binding')
        item=dict(command);item.pop('version');item.pop('kind');legacy.append(item)
        argv=a['argv'];tool=Path(argv[0]).name
        if tool in ('postgres','pg_ctl','initdb','psql') and argv[1:]==['--version']:pass
        elif tool=='psql':
            sql_sequences.add(sequence)
            sql=reader.read(scope+'/sql-'+str(sequence)+'.json');raw=reader.raw(scope+'/source-sql-'+str(sequence)+'.sql')
            if (type(sql) is not dict or set(sql)!={'database','label','sql','sqlSha256','stdout'}
                or sql['database'] not in databases or sql['label']!=command['label'] or type(sql['sql']) is not str
                or raw!=sql['sql'].encode() or sql['sqlSha256']!=sha(raw) or sql['stdout']!=streams[0]):raise ValueError('SQL journal binding')
            expected_args=['-X','--no-password','-qAt','-h',work+'/socket','-p','55439','-U','e2_owner','-v','ON_ERROR_STOP=1','-v','VERBOSITY=verbose','-d',sql['database'],'-f',work+'/sql-'+str(sequence)+'.sql']
            if argv[1:]!=expected_args:raise ValueError('SQL database/argv/sequence binding')
        elif tool in ('postgres','pg_ctl','initdb') and argv[1:]==['--version']:pass
        elif tool=='initdb' and argv[1:]==['-D',work+'/data','-U','e2_owner','--auth=trust','--no-locale','-E','UTF8']:pass
        elif tool=='node' and argv[1:]==[repo+'/tests/consumer-derivatives-v2/pg-s0-s4-bridge.mjs',work+'/constructor-input.json',work+'/reference-transcripts.json']:pass
        else:raise ValueError('original tool command schedule')
    if encoded(legacy)!=reader.raw(scope+'/commands.json') or not same(legacy,history):raise ValueError('exact final legacy command history')
    for prefix,suffix in (('sql-','.json'),('source-sql-','.sql')):
        names={n for n in reader.index['files'] if re.fullmatch(re.escape(scope+'/'+prefix)+r'[0-9]+'+re.escape(suffix),n)}
        if names!={scope+'/'+prefix+str(n)+suffix for n in sql_sequences}:raise ValueError('complete SQL journal sequence join')
    if reader.validate() is not True:raise ValueError('journal reader changed')
    return True
