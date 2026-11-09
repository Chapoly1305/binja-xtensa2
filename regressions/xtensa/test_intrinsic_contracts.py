"""Check declared intrinsic types against native lifted input/output operands."""
import ast, json, sys
from pathlib import Path
from types import SimpleNamespace
import binaryninja as bn
bn.set_worker_thread_count(2)
a = bn.Architecture['xtensa']
lifter = next(v for k,v in sys.modules.items() if k.endswith('.binja_xtensa.lifter'))
rows=[]
source=Path('/port/plugin/binja_xtensa/lifter.py').read_text(encoding='utf-8')
for node in ast.parse(source).body:
    if not isinstance(node,ast.Assign) or not isinstance(node.value,ast.Lambda): continue
    call=node.value.body
    if not isinstance(call,ast.Call) or not isinstance(call.func,ast.Name): continue
    if not call.func.id.startswith(('_lift_intrinsic_', '_lift_cache_intrinsic_')): continue
    name=node.targets[0].id
    il=bn.LowLevelILFunction(a)
    getattr(lifter,name)(SimpleNamespace(s=3,t=2,imm8=7,imm4=5,length=3),0,il)
    il.finalize()
    inst=il[0]
    intrinsic_name=str(inst.intrinsic)
    declaration=a.intrinsics[intrinsic_name]
    assert len(inst.params)==len(declaration.inputs), (name,str(inst))
    assert len(inst.output)==len(declaration.outputs), (name,str(inst))
    if inst.output: assert str(inst.output[0])=='a2', (name,str(inst))
    rows.append({'handler':name,'llil':str(inst)})
# Cache tag/word reads must survive full analysis as definitions of a2.
for data in [bytes.fromhex('2003f1'), bytes.fromhex('2023f1'), bytes.fromhex('2083f1')]:
    view=bn.BinaryView.new(data+bytes.fromhex('0df0'))
    view.platform=a.standalone_platform
    view.add_function(0); view.update_analysis_and_wait()
    f=view.get_function_at(0)
    statements=[i for b in f.mlil for i in b]
    intrinsics=[i for i in statements if i.operation.name=='MLIL_INTRINSIC']
    assert len(intrinsics)==1 and len(intrinsics[0].output)==1, [str(i) for i in statements]
    assert f.mlil.ssa_form is not None and f.hlil is not None
    rows.append({'bytes':data.hex(),'mlil':[str(i) for i in statements]})
    view.file.close()
Path('/port/intrinsic_contract_results.json').write_text(json.dumps(rows,indent=2)+'\n',encoding='utf-8')
print('PASS:', len(rows), 'intrinsic contract/native analysis cases')
