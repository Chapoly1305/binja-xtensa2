"""Exception at a loop-ending branch must not execute branch or loop decrement."""
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
for name,r in [('LOOP',8),('LOOPNEZ',9),('LOOPGTZ',10)]:
 for profile in ['generic','esp32-esp32s3']:
    view=bn.BinaryView.new(bytes([0x76,(r<<4)|2,5])+bytes.fromhex('32c3015714ff0df0'))
    view.platform=a.standalone_platform
    assert bn.Settings().set_string('analysis.workflows.functionWorkflow',w.NAME,view)
    assert bn.Settings().set_string(v.KEY,profile,view)
    view.add_function(0);view.update_analysis_and_wait()
    il=view.get_function_at(0).llil
    for count in [1,3]:
     for equal in [True,False]:
        state={f'ar{i}':0x100000+i for i in range(64)}
        state.update({f'a{i}':0x200000+i for i in range(16)})
        state.update(a2=count,a3=0,a4=4,a5=4 if equal else 5,
                     ps=0x40000,windowbase=15,windowstart=(1<<15)|1,
                     vecbase=0x40374000,windowoverflow12=0x50000100)
        pc=0;target=None
        for step in range(1500):
            x=il[pc];op=x.operation.name
            if op=='LLIL_SET_REG':state[regname(x.dest)]=evaluate(x.src,state)
            elif op=='LLIL_IF':pc=int(x.true if evaluate(x.condition,state) else x.false);continue
            elif op=='LLIL_GOTO':pc=int(x.dest);continue
            elif op=='LLIL_JUMP':target=evaluate(x.dest,state);break
            elif op=='LLIL_NOP':pass
            else:raise AssertionError(str(x))
            pc+=1
        expected=0x40374100 if profile!='generic' else 0x50000100
        assert target==expected,(name,profile,target)
        assert state['epc1']==6 and state['lcount']==count-1
        assert state['ps']&16 and state['windowbase']==0
        # Pre-rotation a3 is saved in physical AR63; exactly one body increment.
        assert state['ar63']==1
        rows.append({'loop':name,'profile':profile,'count':count,'branch_equal':equal,'exception_target':target,'lcount':state['lcount']})
    view.file.close()
Path('/port/loop_overflow_results.json').write_text(json.dumps(rows,indent=2)+'\n',encoding='utf-8')
print('PASS: 24 loop-end window overflow cases preserve retry PC and loop count')
