"""Pure preparation AST/allowlist/recipe checks; no SQL parsing or execution."""
from pathlib import Path
import ast
import hashlib
import json
import re
import prepare

HERE=Path(__file__).resolve().parent
checks=[]
def check(label,value):
    if not value: raise AssertionError(label)
    checks.append(label)

lock,public,candidate=prepare.inspect_inputs()
source=(HERE/'prepare.py').read_text()
tree=ast.parse(source)
imports={n.names[0].name.split('.')[0] for n in ast.walk(tree) if isinstance(n,ast.Import)}
imports|={n.module.split('.')[0] for n in ast.walk(tree) if isinstance(n,ast.ImportFrom)}
check('preparer imports only static standard library',imports=={'pathlib','argparse','hashlib','json','re','tarfile','uuid'})
check('no child or shell execution APIs',not any(isinstance(n,ast.Call) and ((isinstance(n.func,ast.Name) and n.func.id in {'exec','eval','compile','__import__'}) or (isinstance(n.func,ast.Attribute) and n.func.attr in {'Popen','run','system','spawn','check_call','check_output'})) for n in ast.walk(tree)))
check('no environment or operator config access',not any(x in source for x in ['os.environ','getenv(','dotenv','PGSERVICEFILE).read']))
check('no database client imports',not imports.intersection({'psycopg','asyncpg','subprocess','socket','os'}))
check('only current safe input flag',source.count('parser.add_argument(')==1 and "parser.add_argument('--check-inputs'" in source)
check('new artifact plan path never evidence destination',"ROOT/'artifacts/consumer-derivatives-plan'/run_id" in source and 'exist_ok=False' in source)
check('named archive member reads, no extraction glob',"archive.getmember(name)" in source and 'extractall' not in source and '.glob(' not in source)
check('no source symlink acceptance',"path.is_symlink()" in source and 'member.islnk()' in source)
check('all28 frozen members public and named',len(public)==28 and all(n.startswith('prisma/migrations/') or n in ['ops/database-permissions.sql','ops/remote-database-permissions.sql','ops/push-database-permissions.sql','test/run_host_credentials_runtime.py'] for n in public))
check('exact24 ordered migrations',len([n for n in public if n.endswith('/migration.sql')])==24)
check('reviewed14 candidate source inputs frozen',len(candidate)==14 and lock['candidateManifest']['sha256']=='3bac7eb5c3c221d05f9e5638792f361ee363ad2f69359233c52e0e37237a0b11')
check('39core and8initdb source identities',len(lock['toolchainCoreSha256'])==39 and len(lock['toolchainInitdbSha256'])==8)
check('preparer preserves zero-PG and absent admission',"'pgAdmission':None,'postgresInvocations':0,'sqlExecution':False" in source)
check('private fixture environment allowlist specified',all(x in source for x in ["'HOME':'<private-root>/home'","'TMPDIR':'<private-root>/tmp'","'LANG':'C'","'LC_ALL':'C'"]))
check('original frozen aggregate harness is not invoked','test/run_host_credentials_runtime.py' not in re.sub(r'""".*?"""','',source,flags=re.S))
recipe=json.loads((HERE/'acceptance.json').read_text())
check('staged recipe explicitly unexecuted',recipe['status']=='PREPARED_NOT_EXECUTED' and [x['id'] for x in recipe['stages']]==['S'+str(i) for i in range(9)])
check('all14 required cases remain recipe-only',len(recipe['cases'])==14 and all(x['implementation']=='recipe-not-yet-executed' for x in recipe['cases']))
text=json.dumps(recipe)
for token in ['owner-denials','mixed-and-drift','default-unknown','grants-twice','web-mobile-approval','partial-and-rollback','ttl-and-secret','bindings-and-pkce','legacy-upgrade-remint','approval-renew-race','mobile-access-vs-principal','revokes-cascades','race-commit-cleanup','ordinary-plans']:
    check('acceptance case '+token,any(x['id']==token for x in recipe['cases']))
check('root admission before any PG version/process',recipe['stages'][1]['gate'].startswith('explicit root appointment admission'))
check('reference equality before measured pins',all(x in text for x in ['independent','arbitrary target discovery never','no pg_get_functiondef normalization','private derived fixture copies','transition manifest']))
ops=(HERE/'fixture-ops.sql').read_text()
bootstrap=(HERE/'fixture-ownership-bootstrap.sql').read_text()
catalog=(HERE/'catalog-discovery.sql').read_text()
manifest=json.loads((prepare.ROOT/'staging/consumer-derivatives/catalog-contract.pending.json').read_text())
check('bootstrap touches exactly24 known prerequisites',re.findall(r'ALTER FUNCTION (.*?) OWNER TO',bootstrap)==[x['signature'] for x in manifest['prerequisites']])
check('bootstrap is once-only and temporary CREATE revoked','exactly once' in bootstrap and 'REVOKE CREATE ON SCHEMA public FROM lomi_migrator,lomi_remote_inventory_owner,lomi_remote_pairing_write_owner;' in bootstrap)
check('no bootstrap owner membership','GRANT lomi_' not in bootstrap and 'CREATE ROLE' not in bootstrap)
check('ten exact scalar API surfaces retired',len(re.findall(r'REVOKE ALL ON FUNCTION public\.lomi_',ops))==10)
check('ten typed API wrappers granted',len(re.findall(r'GRANT EXECUTE ON FUNCTION public\.lomi_\w+_v2\(.* TO lomi_remote_api;',ops))==10)
check('no broad all-table or membership grant',all(x not in ops for x in ['ALL TABLES','GRANT ALL','GRANT CREATE','CREATE ROLE','GRANT lomi_']))
check('catalog preserves raw definition bytes and exact digest',"encode(convert_to(pg_get_functiondef(f.oid),'UTF8'),'hex')" in catalog and "sha256(convert_to(pg_get_functiondef(f.oid),'UTF8'))" in catalog and 'replace(pg_get_functiondef' not in catalog)
check('catalog only selected public metadata',all(x not in catalog.lower() for x in ['pg_authid','pg_shadow','rolpassword','from public."session"','from public."user"']))
check('catalog includes role/default/column/type privilege evidence',all(x in catalog for x in ['pg_roles','pg_auth_members','pg_default_acl','attacl','typacl']))
check('all27 expected function catalog identities named',all("('"+x['signature']+"')" in catalog for x in manifest['roots']+manifest['prerequisites']))
readme=(HERE/'README.md').read_text()
for token in ['no PostgreSQL runner','SQLSTATE42501','reference-new','short source retention','EXPLAIN (ANALYZE, BUFFERS, VERBOSE)','not query executable versions','S6/S7 SQL driver','No test bootstrap change','Do not patch reviewed bodies']:
    check('explicit recipe limit '+token,token.lower() in ' '.join(readme.lower().split()))
for path in HERE.iterdir():
    if path.suffix=='.py': ast.parse(path.read_text())
check('preparation Python AST parses',True)
print(f'PASS: {len(checks)} static input/AST/allowlist/recipe checks; no PG/version/process/SQL execution.')
