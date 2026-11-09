"""Execute the relevant subset of BN-generated LLIL for real-byte loop fixtures.
This interpreter is a targeted regression oracle, not an Xtensa emulator.
"""
import importlib,json,sys
from pathlib import Path
import binaryninja as bn
import semantic_probe as probe
arch=bn.Architecture['xtensa']
plugin=next(m for n,m in sys.modules.items() if n.endswith('.binja_xtensa') and hasattr(m,'XtensaLE'))
workflow=importlib.import_module(plugin.__name__+'.loop_workflow')
base=probe.evaluate

def evaluate(node,state):
    op=node.operation.name
    if op in ('LLIL_CMP_NE','LLIL_CMP_SLE'):
        a,b=evaluate(node.left,state),evaluate(node.right,state)
        if op=='LLIL_CMP_NE':return a!=b
        signed=lambda x:(x&0x7fffffff)-(x&0x80000000)
        return signed(a)<=signed(b)
    return base(node,state)
probe.evaluate=evaluate
rows=[]
for mode,begin,end in [(m,b,e) for m in ['WSR','XSR'] for b,e in [(9,12),(9,15),(12,15)]]:
    name='LOOP'
    view=bn.BinaryView.new(bytes.fromhex('200213')+bytes([0x40,0,0x13 if mode=='WSR' else 0x61,0x50,1,0x13 if mode=='WSR' else 0x61])+bytes.fromhex('32c30162c6020df0'))
    view.platform=arch.standalone_platform
    settings=bn.Settings()
    assert settings.set_string('analysis.workflows.functionWorkflow',workflow.NAME,view)
    view.add_function(0);view.update_analysis_and_wait()
    il=view.get_function_at(0).llil
    instructions=[il[i] for i in range(len(il))]
    print(name, [str(x) for x in instructions], flush=True)
    addresses={}
    for i,x in enumerate(instructions):addresses.setdefault(x.address,i)
    for count in [1,3,5]:
        for ps in [0,16]:
            state={'a2':count-1,'a4':begin,'a5':end,'a6':0,'a3':0,'a0':0x100,'ps':ps};pc=0;finished=False
            for step in range(100):
                x=instructions[pc];op=x.operation.name
                if op=='LLIL_SET_REG':state[x.dest.name]=evaluate(x.src,state)
                elif op=='LLIL_IF':pc=int(x.true if evaluate(x.condition,state) else x.false);continue
                elif op=='LLIL_GOTO':pc=int(x.dest);continue
                elif op=='LLIL_JUMP_TO':pc=int(x.targets[evaluate(x.dest,state)]);continue
                elif op=='LLIL_JUMP':pc=addresses[evaluate(x.dest,state)];continue
                elif op=='LLIL_RET':finished=True;break
                else:raise AssertionError(op)
                pc+=1
            skip=(name=='LOOPNEZ' and count==0) or (name=='LOOPGTZ' and (count==0 or count>=0x80000000))
            expected=0 if skip else (1 if ps else count)
            if not skip and not ps and count in [0,0xffffffff]:
                assert not finished and state['a3']>1
            else:
                assert finished
                iterations=1 if ps else count
                assert state['a3']==(iterations if begin==9 else 1),state
                assert state['a6']==2*(iterations if end==15 else 1),state
            rows.append({'mode':mode,'begin':begin,'end':end,'input_count':count,'ps':ps,'body_executions_within_100_steps':state['a3'],'terminated':finished})
    del settings
Path('/port/dynamic_loop_results.json').write_text(json.dumps(rows,indent=2)+'\n')
print('PASS: 36 WSR/XSR dynamic-bound execution cases')
