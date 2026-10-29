"""Pure phases over unchanged actual capture rows. Never fills/accepts pins."""
import copy
import hashlib
import json

UNKNOWN='fixture_unexpected'
CASES=(
 {'id':'unknown-role','phase':'ROLE','message':'unknown fixture role','category':'UNKNOWN_ROLE','unknown':True,'default':False,'column':False},
 {'id':'unknown-default','phase':'DEFAULT_ACL','message':'unknown default privilege','category':'UNKNOWN_DEFAULT_PRINCIPAL','unknown':True,'default':True,'column':False},
 {'id':'unknown-column','phase':'COLUMN_ACL','message':'unknown object privilege','category':'UNKNOWN_COLUMN_PRINCIPAL','unknown':True,'default':False,'column':True},
 {'id':'known-default','phase':'REFERENCE','message':'metadata differs from admitted independent reference','category':'KNOWN_DEFAULT_REFERENCE_DRIFT','unknown':False,'default':True,'column':False},
 {'id':'known-column','phase':'REFERENCE','message':'metadata differs from admitted independent reference','category':'KNOWN_COLUMN_REFERENCE_DRIFT','unknown':False,'default':False,'column':True})
NEW_TABLES=('consumer_approval_intent','consumer_approval_consumed_proof','consumer_derivative_consent')


def setup_before(case):
    sql=[]
    if case['unknown']:sql.append('CREATE ROLE fixture_unexpected NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;')
    if case['default']:
        grantee=UNKNOWN if case['unknown'] else 'lomi_migrator'
        sql.append('ALTER DEFAULT PRIVILEGES FOR ROLE e2_owner IN SCHEMA public GRANT SELECT ON TABLES TO '+grantee+';')
    return '\n'.join(sql)


def setup_after(case):
    if not case['column']:return ''
    return 'GRANT UPDATE("originId") ON public.consumer_authorization TO '+(UNKNOWN if case['unknown'] else 'lomi_remote_api')+';'


def phase_indices(rows,phase):
    kinds={'DEFAULT_ACL':{'defaultAcl'},'COLUMN_ACL':{'columnAcl'},'ROLE':{'role'}}
    if phase not in kinds:raise ValueError('unknown phase')
    return [i for i,row in enumerate(rows) if row.get('kind') in kinds[phase]]


def run_guard(base,rows):
    try:base.reject_authority_drift(rows)
    except ValueError as exc:return {'passed':False,'exceptionType':'ValueError','message':str(exc)}
    return {'passed':True,'exceptionType':None,'message':None}


def classify(base,compare,catalog_bytes,metadata_bytes,expected,case):
    catalog=json.loads(catalog_bytes);metadata=json.loads(metadata_bytes)
    before_catalog=copy.deepcopy(catalog);before_metadata=copy.deepcopy(metadata)
    full={'catalog':run_guard(base,catalog),'metadata':run_guard(base,metadata)}
    records=[];failure=None
    # Phased checks preserve ALL raw captures. Indices and exact SHA identify
    # selected actual rows; no principal, ACL, function or OID value is changed.
    for phase in ('DEFAULT_ACL','COLUMN_ACL','ROLE'):
        indices=phase_indices(metadata,phase);result=run_guard(base,[metadata[i] for i in indices])
        records.append(dict(phase=phase,fullCaptureSha256=hashlib.sha256(metadata_bytes).hexdigest(),indices=indices,**result))
        if failure is None and not result['passed']:failure=(phase,result)
    full_pass=full['catalog']['passed'] and full['metadata']['passed']
    reference=None
    if failure is None and full_pass:
        try:compare(base,catalog,metadata,expected)
        except ValueError as exc:reference={'passed':False,'exceptionType':'ValueError','message':str(exc)}
        else:reference={'passed':True,'exceptionType':None,'message':None}
        if not reference['passed']:failure=('REFERENCE',reference)
    if failure is None:raise ValueError('fault snapshot unexpectedly admitted')
    if failure[0]!=case['phase'] or failure[1]['exceptionType']!='ValueError' or failure[1]['message']!=case['message']:
        raise ValueError('wrong admission phase/category: '+repr(failure))
    if case['phase']=='REFERENCE' and not full_pass:raise ValueError('known-role drift masked by original guard')
    if case['unknown'] and (full['catalog']['message']!='unknown fixture role' or full['metadata']['message']!=('unknown object privilege' if case['default'] or case['column'] else 'unknown fixture role')):
        raise ValueError('full original-order role diagnostic missing')
    if catalog!=before_catalog or metadata!=before_metadata:raise ValueError('capture mutated during admission')
    return dict(status='PASS',id=case['id'],category=case['category'],phase=case['phase'],
        exceptionType='ValueError',message=case['message'],phaseEvidence=records,
        fullOriginalOrderGuard=full,referenceComparison=reference,pinsAccepted=False,
        derivationAttempted=False,operatorInvoked=False,sqlstate=None)


def canonical_oid(value):
    if type(value) is not str or not value or not value.isascii() or not value.isdecimal() or value[0]=='0':
        raise ValueError('namespace OID must be a canonical positive ASCII decimal string')
    return value


def pristine_public_namespace_oid(raw):
    sections=[r for r in raw if r.get('section')=='schemas']
    if len(sections)!=1 or len(sections[0]['rows'])!=1:raise ValueError('pristine public schema identity closure')
    catalog=sections[0]['rows'][0]['catalog']
    if catalog.get('nspname')!='public':raise ValueError('pristine public schema identity name')
    return canonical_oid(catalog['oid'])


def validate_declared_delta(base,compare,catalog,metadata,expected,case):
    """Reject every delta except source-declared extra synthetic ACL rows.

    Expected authority starts from pristine independent reference. Fault rows
    never provide expected definitions, owners, privilege values or pin values.
    """
    allowed_meta=[];allowed_catalog=[]
    if case['unknown']:
        role=dict(kind='role',name=UNKNOWN,login=False,inherit=False,super=False,createRole=False,createDb=False,replication=False,bypassRls=False,config=None)
        allowed_meta.append(role);allowed_catalog.append(role)
        # Every public schema has PUBLIC USAGE in this frozen baseline. No
        # schema CREATE is granted to the newly introduced role.
        allowed_meta.append(dict(kind='schemaAuthority',role=UNKNOWN,create=False,usage=True))
    grantee=UNKNOWN if case['unknown'] else ('lomi_migrator' if case['default'] else 'lomi_remote_api')
    if case['default']:
        allowed_meta.append(dict(kind='defaultAcl',owner='e2_owner',namespace='public',objectType='r',grantor='e2_owner',grantee=grantee,privilege='SELECT',grantable=False))
        # Discovery preserves the raw OID JSON string. Use independent
        # pristine public schema identity; never coerce/infer it from a fault ACL.
        namespace=canonical_oid(case['publicNamespaceOid'])
        allowed_catalog.append(dict(kind='defaultAcl',owner='e2_owner',namespace=namespace,objectType='r',grantor='e2_owner',grantee=grantee,privilege='SELECT',grantable=False))
        for name in NEW_TABLES:allowed_meta.append(dict(kind='objectAcl',relation=name,owner='e2_owner',grantor='e2_owner',grantee=grantee,privilege='SELECT',grantable=False))
    if case['column']:
        allowed_meta.append(dict(kind='columnAcl',relation='consumer_authorization',column='originId',grantor='e2_owner',grantee=grantee,privilege='UPDATE',grantable=False))
    # Build exact expected raw row lists from pristine authority plus fixed
    # declared records. Compare row collections using the reviewed comparator;
    # raw captured definitions and ACL arrays remain untouched.
    expected_meta=[*copy.deepcopy(expected['metadata']),*allowed_meta]
    expected_catalog=[*copy.deepcopy(expected['catalog']),*allowed_catalog]
    for row in expected_catalog:
        if row.get('kind')!='protectedAcl':continue
        if case['default'] and row['relation'] in NEW_TABLES:
            if not row['tableAcl'] or row['tableAcl'][0]!='e2_owner=arwdDxtm/e2_owner':raise ValueError('owner ACL source shape')
            row['tableAcl']=[row['tableAcl'][0],grantee+'=r/e2_owner',*row['tableAcl'][1:]]
        if case['column'] and row['relation']=='consumer_authorization' and row['column']=='originId':
            row['columnAcl']=[*(row['columnAcl'] or []),grantee+'=w/e2_owner']
    catalog_view=catalog
    base.require(base.canonical(metadata)==base.canonical(expected_meta),'undeclared metadata privilege delta')
    relation_map=base.protected_relation_map(expected['metadata'])
    base.require(base.canonical(catalog_view,base.protected_relation_map(metadata))==base.canonical(expected_catalog,relation_map),'undeclared catalog authority delta')
