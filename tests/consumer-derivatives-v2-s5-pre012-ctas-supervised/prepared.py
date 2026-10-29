"""Compile all expected fields before faults; bind only ten declared OID slots."""
import copy
OID_FIELDS={'oid','reltype','attrelid','typrelid','typarray','typelem','conindid','conrelid','confrelid','indexrelid','indrelid','tgconstraint','tgconstrindid','tgrelid','tgconstrrelid'}

def at(tree,path):
    for key in path:tree=tree[key]
    return tree

def put(tree,path,value):at(tree,path[:-1])[path[-1]]=value

def sort_expected(model,rows):
    s=model.sections(rows)
    for name in ('objects','types','constraints','triggers'):s[name].sort(key=lambda r:int(r['catalog']['oid'] if 'catalog' in r else r['oid']))
    s['columns'].sort(key=lambda r:(int(r['catalog']['attrelid']),r['catalog']['attnum']))
    s['indexes'].sort(key=lambda r:int(r['catalog']['indexrelid']))
    for name in ('expandedRelationAcl','expandedTypeAcl'):s[name].sort(key=lambda r:(int(r['oid']),int(r['grantor']),int(r['grantee']),r['privilege_type'],r['is_grantable']))
    s['selected'].sort(key=lambda r:r['name'])

class Prepared:
    def __init__(self,model,case,baseline,builtins):
        self.model=model;self.case=copy.deepcopy(case);self.baseline=copy.deepcopy(baseline);self.builtins=dict(builtins)
        self.slots=dict(zip(model.OID_KEYS,map(str,range(4294967200,4294967210)),strict=True))
        model.fresh_identities(self.slots,baseline,builtins)
        self.template=model.expected_setup(case,baseline,self.slots,builtins)
        self.scalar_paths=[];self.trigger_paths=[];reverse={value:key for key,value in self.slots.items()}
        def walk(value,path):
            if isinstance(value,dict):
                for key,item in value.items():walk(item,path+[key])
            elif isinstance(value,list):
                for key,item in enumerate(value):walk(item,path+[key])
            elif type(value)==str and value in reverse:
                if path[-1] not in OID_FIELDS:raise ValueError('undeclared scalar OID field')
                self.scalar_paths.append(dict(path=path,slot=reverse[value]))
        walk(self.template,[])
        section=next(i for i,r in enumerate(self.template) if r['section']=='triggers')
        for i,row in enumerate(self.template[section]['rows']):
            oid=row['catalog']['oid']
            if oid not in reverse:continue
            slot=reverse[oid]
            if slot not in ('action_delete','action_update','check_insert','check_update'):raise ValueError('undeclared trigger OID')
            old=row['catalog']['tgname'];prefix='RI_ConstraintTrigger_'+('a' if slot.startswith('action') else 'c')+'_'
            if old!=prefix+oid or row['definition'].count('"'+old+'"')!=1:raise ValueError('exact known trigger name formatter')
            left,right=row['definition'].split('"'+old+'"')
            self.trigger_paths.append(dict(slot=slot,namePath=[section,'rows',i,'catalog','tgname'],definitionPath=[section,'rows',i,'definition'],prefix=prefix,left=left,right=right))
        if len(self.trigger_paths)!=4 or {r['slot'] for r in self.scalar_paths}!=set(model.OID_KEYS):raise ValueError('compiled ten-slot/four-trigger closure')
    def evidence(self):return dict(case=self.case,slots=self.slots,template=self.template,scalarPaths=self.scalar_paths,triggerPaths=self.trigger_paths,compiledBeforeFault=True)
    def instantiate(self,ids):
        ids=self.model.fresh_identities(ids,self.baseline,self.builtins);result=copy.deepcopy(self.template)
        for row in self.scalar_paths:put(result,row['path'],ids[row['slot']])
        for row in self.trigger_paths:
            name=row['prefix']+ids[row['slot']];put(result,row['namePath'],name);put(result,row['definitionPath'],row['left']+'"'+name+'"'+row['right'])
        sort_expected(self.model,result);return result
