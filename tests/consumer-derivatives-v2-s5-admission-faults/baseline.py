"""Explicit baseline-only runner, stopping BEFORE old[30] candidate creation."""
import json

def execute(base,f,inputs):
    encoded=f.work/'constructor-input.json';encoded.write_text(json.dumps(base.encode_inputs(inputs)))
    output=f.work/'reference-transcripts.json'
    f.command('pinned-pure-reference-constructor',[f.node,base.HERE/'pg-s0-s4-bridge.mjs',encoded,output])
    built=json.loads(output.read_bytes());f.save('reference-transcripts.json',built)
    base.require(built['pinsFilled'] is False and built['catalogInputAccepted'] is False,'constructor boundary')
    old=built['referenceOld']['steps']
    base.require(len(old)==36 and old[30]['id'].endswith('approval-intent.candidate.sql'),'prefix schedule')
    for step in old:
        base.require(step['role']=='e2_owner' and base.digest(step['sql'].encode())==step['emittedSha256'],'transcript drift')
    for binary in ('postgres','initdb','pg_ctl','psql'):
        base.require(f.command(binary+'-version',[f.pg/binary,'--version']).strip()==binary+' (PostgreSQL) 18.6 (Postgres.app)','PG version')
    f.command('owned-initdb',[f.pg/'initdb','-D',f.work/'data','-U','e2_owner','--auth=trust','--no-locale','-E','UTF8'])
    f.start_attempted=True
    options=("-h '' -k "+str(f.work/'socket')+' -p 55439 -c max_connections=2 '
        '-c superuser_reserved_connections=0 -c reserved_connections=0 '
        '-c unix_socket_permissions=0700 -c statement_timeout=55000 -c lock_timeout=10000 '
        '-c idle_in_transaction_session_timeout=55000')
    f.command('owned-cluster-start',[f.pg/'pg_ctl','-D',f.work/'data','-l',f.work/'postgres.log','-o',options,'-w','-t','30','start'])
    base.require(f.pid_identity() is not None,'postmaster identity')
    settings=json.loads(f.sql('postgres','socket-only-settings',"SELECT json_build_object('listen',current_setting('listen_addresses'),'socket',current_setting('unix_socket_directories'),'data',current_setting('data_directory'),'max',current_setting('max_connections'),'port',current_setting('port'));"))
    base.require(settings==dict(listen='',socket=str(f.work/'socket'),data=str(f.work/'data'),max='2',port='55439'),'socket bounds')
    f.sql('postgres','frozen-four-synthetic-roles',base.ROLE_SQL)
    ledger=base.checked(base.HERE/'pg-s0-s4-ledger-fixture.sql',base.LEDGER_FIXTURE_HASH).decode()
    steps=base.baseline_steps_with_ledger(old,ledger)
    f.save('baseline-only-schedule.json',dict(steps=steps,prismaLedgerQualified=False,stoppedBeforeOld30=True))
    for database in base.DATABASES:
        f.sql('postgres','create-'+database,'CREATE DATABASE '+database+' TEMPLATE template0;')
        for step in steps:
            result=f.sql(database,database+':'+step['id'],step['sql'])
            if step['id']=='fixture-only:empty-prisma-ledger:ONCE':base.require(result.strip()=='0','nonempty ledger')
    return built
