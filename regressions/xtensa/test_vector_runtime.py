"""Execute workflow-produced IL after WSR/XSR VECBASE for all six vectors."""
import importlib,json,sys
from pathlib import Path
import binaryninja as bn
from semantic_probe import evaluate,regname
bn.set_worker_thread_count(2)
a=bn.Architecture['xtensa']
p=next(m for n,m in sys.modules.items() if n.endswith('.binja_xtensa') and hasattr(m,'XtensaLE'))
w=importlib.import_module(p.__name__+'.loop_workflow')
v=importlib.import_module(p.__name__+'.vector_profile')
rows=[]
for operation,encoded in [('WSR','20e713'),('XSR','20e761')]:
 for kind,code in [('overflow','3641000df0'),('underflow','1df0')]:
    view=bn.BinaryView.new(bytes.fromhex(encoded+code));view.platform=a.standalone_platform
    assert bn.Settings().set_string('analysis.workflows.functionWorkflow',w.NAME,view)
    assert bn.Settings().set_string(v.KEY,'esp32-esp32s3',view)
    view.add_function(0);view.update_analysis_and_wait()
    f=view.get_function_at(0);il=f.llil
    assert a.get_instruction_text(bytes.fromhex(encoded),0)[0][0].text.strip().startswith(operation)
    for base in [0x40080000,0x40374000,0x40100000]:
     for increment in [1,2,3]:
        state={f'ar{i}':0x100000+i for i in range(64)}
        state.update({f'a{i}':0x200000+i for i in range(16)})
        # Overflow collides at WB+1. Subsequent bits select 4, 8, or 12.
        occupancy={1:7,2:11,3:3}[increment] if kind=='overflow' else 1
        state.update(a0=(increment<<30)|0x1234,a1=0x1000,a2=base,
                     vecbase=0xdead0000,ps=0x50000,windowbase=0,windowstart=occupancy)
        pc=0;target=None
        for step in range(1500):
            ins=il[pc];op=ins.operation.name
            if op=='LLIL_SET_REG':state[regname(ins.dest)]=evaluate(ins.src,state)
            elif op=='LLIL_IF':pc=int(ins.true if evaluate(ins.condition,state) else ins.false);continue
            elif op=='LLIL_GOTO':pc=int(ins.dest);continue
            elif op=='LLIL_JUMP':target=evaluate(ins.dest,state);break
            elif op=='LLIL_NOP':pass
            else:raise AssertionError((op,str(ins)))
            pc+=1
        offset=(increment-1)*128+(64 if kind=='underflow' else 0)
        assert target==base+offset,(operation,kind,base,increment,target)
        assert state['vecbase']==base
        rows.append({'write':operation,'kind':kind,'base':base,'window_increment':increment,'target':target})
    view.file.close()
Path('/port/vector_runtime_results.json').write_text(json.dumps(rows,indent=2)+'\n',encoding='utf-8')
print('PASS: 36 full-workflow vector executions after WSR/XSR VECBASE')
