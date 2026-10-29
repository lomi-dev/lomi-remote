"""Import frozen case code unchanged; isolate only the baseline load seam."""
import ast
from types import FunctionType, SimpleNamespace


def baseline_tree(raw):
    tree=ast.parse(raw)
    execute=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='execute')
    index=next(i for i,n in enumerate(execute.body) if isinstance(n,ast.Assign)
        and any(isinstance(t,ast.Name) and t.id=='options' for t in n.targets))
    removed=execute.body[index:index+3]
    if len(removed)!=3 or not all(isinstance(n,ast.Expr) for n in removed[1:]):
        raise ValueError('frozen baseline start seam shape')
    if not any(isinstance(n,ast.Constant) and n.value=='owned-cluster-start' for n in ast.walk(removed[1])):
        raise ValueError('frozen start command identity')
    if not any(isinstance(n,ast.Attribute) and n.attr=='pid_identity' for n in ast.walk(removed[2])):
        raise ValueError('frozen PID check identity')
    execute.body[index:index+3]=[ast.parse('f.start_foreground_postgres()').body[0]]
    return ast.fix_missing_locations(tree)


def case_runner(frozen, baseline_path):
    original=frozen.load
    tree=baseline_tree(baseline_path.read_bytes())
    namespace={'__name__':'admission_supervised_baseline'}
    exec(compile(tree,str(baseline_path),'exec'),namespace)
    baseline=SimpleNamespace(execute=namespace['execute'])
    def scoped_load(name,path):
        if name=='admission_baseline' and path==baseline_path:return baseline
        return original(name,path)
    # A new globals dictionary; never replace any original module global.
    context=dict(frozen.__dict__,load=scoped_load)
    return FunctionType(frozen.run_case.__code__,context,frozen.run_case.__name__,
        frozen.run_case.__defaults__,frozen.run_case.__closure__)
