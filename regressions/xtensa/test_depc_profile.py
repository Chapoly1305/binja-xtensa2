"""Native RFDE return dependencies under explicit per-view DEPC settings."""
import importlib,json,sys
from pathlib import Path
import binaryninja as bn
bn.set_worker_thread_count(2)
a=bn.Architecture['xtensa']
p=next(m for n,m in sys.modules.items() if n.endswith('.binja_xtensa') and hasattr(m,'XtensaLE'))
w=importlib.import_module(p.__name__+'.loop_workflow')
v=importlib.import_module(p.__name__+'.vector_profile')
rows=[]
for mode in ['unknown','present','absent']:
    view=bn.BinaryView.new(bytes.fromhex('003200'));view.platform=a.standalone_platform
    assert bn.Settings().set_string('analysis.workflows.functionWorkflow',w.NAME,view)
    assert bn.Settings().set_string(v.DEPC_KEY,mode,view)
    view.add_function(0);view.update_analysis_and_wait()
    f=view.get_function_at(0)
    returns={str(i.dest) for i in f.llil.instructions if i.operation.name=='LLIL_RET'}
    expected={'depc','epc1'} if mode=='unknown' else {'depc'} if mode=='present' else {'epc1'}
    # LLIL may retain unreachable arms after constant replacement. Execute
    # actual edges instead of requiring textual dead-code elimination.
    def value(expr, config):
        op=expr.operation.name
        if op=='LLIL_CONST':return expr.constant
        if op=='LLIL_REG':
            assert str(expr.src)=='config_ndepc'
            return config
        if op=='LLIL_CMP_NE':return value(expr.left,config)!=value(expr.right,config)
        raise AssertionError(str(expr))
    reached=set()
    for config in [0,1]:
        pc=0
        for step in range(20):
            ins=f.llil[pc]
            if ins.operation.name=='LLIL_IF':pc=int(ins.true if value(ins.condition,config) else ins.false)
            elif ins.operation.name=='LLIL_GOTO':pc=int(ins.dest)
            elif ins.operation.name=='LLIL_RET':reached.add(str(ins.dest));break
            else:raise AssertionError(str(ins))
    assert reached==expected,(mode,reached)
    assert f.mlil.ssa_form is not None and f.hlil is not None
    rows.append({'depc_setting':mode,'reachable_return_registers':sorted(reached),'syntactic_return_registers':sorted(returns)})
    view.file.close()
Path('/port/depc_profile_results.json').write_text(json.dumps(rows,indent=2)+'\n',encoding='utf-8')
print('PASS: three native DEPC profile return dependencies')
