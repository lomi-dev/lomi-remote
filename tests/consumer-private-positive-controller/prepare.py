"""Pinned Python source preparation only; immutable SQL reuse, no fresh Node."""
from pathlib import Path
import hashlib
import importlib.util
import json
import shutil
import sys

HERE = Path(__file__).resolve().parent
PROJECT = Path("/Users/woro/Documents/Lomi/lomi-remote")
TRANSCRIPT = "artifacts/consumer-derivatives-v2-s0-s4/c98ddbfa-5495-4a40-851f-72ccd3361e92/reference-transcripts.json"
TRANSCRIPT_SHA = "df12fac4ab1e0a156c47354f7d33e3203f058e5c975b278953aaf060abe943a5"
CONSTRUCT = "tests/consumer-derivatives-v2-sealing/construct.py"
CONSTRUCT_SHA = "7edfc912fbc079812ac2e35ace9cd2d56505d12c4ffd7f399e22be676759a3fd"
ADAPTER_FREEZE = "artifacts/consumer-private-guardian-staging/2026-10-19-bootstrap-stdout-correction"
DERIVED = "artifacts/consumer-derivatives-v2-sealing-preparation/d1fb0ffc-4d09-4e1b-b0f0-cae7aecb9546/derived"


def sha(raw):return hashlib.sha256(raw).hexdigest()


def write_json(path, data):path.write_text(json.dumps(data,sort_keys=True,indent=2)+"\n")


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module)
    return module


def prepare():
    assert sha((PROJECT/CONSTRUCT).read_bytes())==CONSTRUCT_SHA
    constructor=load("private_positive_source_constructor",PROJECT/CONSTRUCT)
    lock,data,manifest,refs,contract,helper=constructor.load_admitted()
    base=load("private_positive_admitted_source_base",PROJECT/lock["driver"])
    _,inputs,tools,_=base.admit_sources()
    built=json.loads((PROJECT/TRANSCRIPT).read_bytes())
    assert sha((PROJECT/TRANSCRIPT).read_bytes())==TRANSCRIPT_SHA
    assert built["pinsFilled"] is False and built["catalogInputAccepted"] is False
    old,new=built["referenceOld"]["steps"],built["referenceNew"]["steps"]
    assert len(old)==36 and len(new)==37 and new[:36]==old
    for step in old:
        assert step["role"]=="e2_owner" and sha(step["sql"].encode())==step["emittedSha256"]
        source=step["source"]
        key={"baseline":"baselineFiles","candidate":"candidateFiles","preparation":"preparationFiles"}[source["kind"]]
        assert inputs[key][source["name"]]==step["sql"].encode()
        assert source["sourceSha256"]==step["emittedSha256"]
    transition=new[-1]
    assert all(transition[k] is True for k in ("singleScript","sameSession","noInterleaving","onAnyErrorRollbackAndStop"))
    assert transition["sql"]=="\n".join(fragment["sql"] for fragment in transition["fragments"])
    for fragment in [transition,*transition["fragments"]]:assert sha(fragment["sql"].encode())==fragment["emittedSha256"]
    derived,report=constructor.construct()
    for name,raw in derived.items():assert (PROJECT/DERIVED/name).read_bytes()==raw
    assert json.loads((PROJECT/DERIVED/"derived-manifest.json").read_bytes())==report
    (HERE/"sql").mkdir(exist_ok=True)
    registry={}
    def add(name,raw):
        assert name not in registry and type(raw) is bytes
        (HERE/"sql"/name).write_bytes(raw);registry[name]=sha(raw)
        return name
    role=add("cluster-roles.sql",base.ROLE_SQL.encode())
    create={database:add("create-"+database+".sql",("CREATE DATABASE "+database+" TEMPLATE template0;\n").encode()) for database in base.DATABASES}
    steps=[add(f"schema-{i:02d}.sql",step["sql"].encode()) for i,step in enumerate(old)]
    ledger=add("empty-prisma-ledger.sql",(PROJECT/"tests/consumer-derivatives-v2/pg-s0-s4-ledger-fixture.sql").read_bytes())
    transition_name=add("reference-new-transition.sql",transition["sql"].encode())
    helper_name=add("derived-helper-seal.sql",derived["operator-seal-auth-helpers.candidate.sql"])
    root_name=add("derived-root-seal.sql",derived["operator-three-roots.candidate.sql"])
    catalog_name=add("public-catalog.sql",inputs["preparationFiles"]["catalog-discovery.sql"])
    metadata_name=add("public-metadata.sql",(PROJECT/"tests/consumer-derivatives-v2/pg-s0-s4-metadata.sql").read_bytes())
    schedule=[]
    def run(database,name,kind="schema",state=None):
        schedule.append({"database":database,"script":name,"kind":kind,"referenceState":state})
    run("postgres",role)
    for database in base.DATABASES:run("postgres",create[database])
    for database in base.DATABASES:
        for name in [*steps[:24],ledger,*steps[24:]]:run(database,name)
    run(base.DATABASES[2],transition_name)
    def capture(database,state):
        run(database,catalog_name,"catalog",state);run(database,metadata_name,"metadata",state)
    for database,state in zip(base.DATABASES,("old","old","new")):capture(database,state)
    run(base.DATABASES[0],helper_name);run(base.DATABASES[0],root_name)
    for _ in range(2):
        for name in [*steps[24:27],steps[35]]:run(base.DATABASES[0],name)
    capture(base.DATABASES[0],"new")
    write_json(HERE/"public-registry.json",{"schemaVersion":1,"sqlSha256":registry,"orderedSchedule":schedule})
    for state in ("old","new"):
        for kind in ("catalog","metadata"):write_json(HERE/f"reference-{state}-{kind}.json",refs[state][kind])
    snapshots=load("private_positive_snapshots",HERE/"snapshots.py")
    (HERE/"private-positive-driver.sql").write_bytes(snapshots.private_wrapper(inputs["preparationFiles"]["catalog-discovery.sql"],(PROJECT/"tests/consumer-derivatives-v2/pg-s0-s4-metadata.sql").read_bytes()))
    (HERE/"positive-auth.sql").write_bytes((PROJECT/"tests/consumer-derivatives-v2-s5-positive-auth/positive-auth.sql").read_bytes())
    (HERE/"closed_dependencies").mkdir(exist_ok=True)
    shutil.copyfile(PROJECT/lock["driver"],HERE/"closed_dependencies/authority.py")
    shutil.copyfile(PROJECT/"tests/consumer-derivatives-v2-s5-pre012-supervised/resource_policy.py",HERE/"closed_dependencies/resource_policy.py")
    shutil.copyfile(PROJECT/"tests/consumer-private-native-probes/tools.json",HERE/"tools.json")
    # Exact eleven reviewed production sources, copied without any delta.
    source=PROJECT/"tests/consumer-private-guardian-staging"
    assert sha((PROJECT/ADAPTER_FREEZE/"freeze-sha256.json").read_bytes())=="23412ec852b2112c2c0f074e1254471b0ff5e9617ba6593cacd728c497dbb6d3"
    approved=json.loads((PROJECT/ADAPTER_FREEZE/"freeze-sha256.json").read_text())["sha256"]
    for name,pin in approved.items():assert sha((PROJECT/ADAPTER_FREEZE/name).read_bytes())==pin
    adapter_sources={str(p.relative_to(source)):p for p in source.rglob("*") if p.is_file()}
    assert len(adapter_sources)==11
    for name,path in adapter_sources.items():
        assert sha(path.read_bytes())==approved["qualification-source/tests/consumer-private-guardian-staging/"+name]
        target=HERE/"closed_dependencies/private_guardian_staging"/name
        before=HERE/"source-original/private_guardian_staging"/name
        target.parent.mkdir(parents=True,exist_ok=True);before.parent.mkdir(parents=True,exist_ok=True)
        if before.exists():assert before.read_bytes()==path.read_bytes()
        else:shutil.copyfile(path,before)
        shutil.copyfile(path,target)
    source_pins={**lock["sourceAndEvidenceSha256"],CONSTRUCT:CONSTRUCT_SHA,TRANSCRIPT:TRANSCRIPT_SHA}
    source_pins.update({"tests/consumer-private-guardian-staging/"+name:sha(path.read_bytes()) for name,path in adapter_sources.items()})
    source_pins[ADAPTER_FREEZE+"/freeze-sha256.json"]="23412ec852b2112c2c0f074e1254471b0ff5e9617ba6593cacd728c497dbb6d3"
    source_pins.update({
        "tests/consumer-pg-guardian/guardian.py":"24e3963ce7af07b6708ac7bd315e7f1d681186acb002bf934faa618d2f5caa47",
        "tests/consumer-private-diagnostics/diagnostics.py":"4c4248088591e64f95008758682967b6e1e39c645609a769497f06b613d53328",
        "tests/consumer-private-streams/streams.py":"af0646f267f6e0d91b2a21c60e02d8edc9566da165df13581acb2656bbaa44e4",
        "tests/consumer-derivatives-v2-s5-pre012-supervised/resource_policy.py":"1d631ec27f30f7b969ed32ab4504300a8932123401b0d5713a65b3a84a53cb3e"})
    positive_manifest="artifacts/consumer-derivatives-v2-s5-positive-auth-preparation/b303aa4a-8c5d-4171-84b2-31857f1c238a/source-inputs.json"
    assert sha((PROJECT/positive_manifest).read_bytes())=="46f5eeb2f03de99be1d1f3827d3f57904be8fb540250b175cd79804a4f2eb230"
    positive_pins=json.loads((PROJECT/positive_manifest).read_bytes())["sha256"]
    assert len(positive_pins)==17
    source_pins.update(positive_pins)
    source_pins[positive_manifest]=sha((PROJECT/positive_manifest).read_bytes())
    source_pins["tests/consumer-derivatives-v2-s5-positive-auth/positive-auth.sql"]="1fe715e2245f05b372cb2dd8904d3dee08aeed893ae75f8f367a996df1c375c8"
    source_pins["tests/consumer-derivatives-v2-s5-positive-auth/case-plan.json"]="c11a562d388fbe36016743b6b4b105e49ed447efeba3a2f852033175195fbea7"
    for name in derived:source_pins[DERIVED+"/"+name]=sha(derived[name])
    source_pins[DERIVED+"/derived-manifest.json"]=sha((PROJECT/DERIVED/"derived-manifest.json").read_bytes())
    source_pins["tests/consumer-derivatives-v2-sealing/inputs.lock.json"]=constructor.LOCK_SHA
    write_json(HERE/"source-inputs.json",{"schemaVersion":1,"sha256":source_pins})
    for name,pin in source_pins.items():assert sha((PROJECT/name).read_bytes())==pin
    write_json(HERE/"preparation-provenance.json",{"scope":"IMMUTABLE_SQL_SOURCE_REUSE_ONLY","freshNodeConstructorExecuted":False,"postgresExecuted":False,"sqlParsedOrExecuted":False,"transcriptSha256":TRANSCRIPT_SHA,"oldSteps":36,"newSteps":37,"allEmittedSha256Verified":True,"originalConstructorSha256":base.CONSTRUCTOR_HASH,"constructorInputsArchive28Candidate14Preparation8And49ToolsReadmitted":True,"derivedFourFilesAndFullManifestReconstructedExactly":True,"allOriginal17PositiveInputsReverified":True,"sourcePins":len(source_pins),"scheduledPublicOperations":len(schedule),"original31AdapterBytesChanged":False})
    return len(registry),len(schedule)


if __name__=="__main__":
    def audit(event,args):
        if event in ("subprocess.Popen","os.system","os.fork","os.posix_spawn","os.kill","os.killpg","ctypes.dlopen") or event.startswith("socket."):
            raise RuntimeError("source preparation child/network forbidden")
    sys.addaudithook(audit)
    print(json.dumps({"preparedRegistryScriptsAndOperations":prepare(),"native":"NOT_RUN"}))
