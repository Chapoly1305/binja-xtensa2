"""MOVSP Alloca and RFDE optional-DEPC state transitions from native LLIL."""
import json
from pathlib import Path
import binaryninja as bn
from semantic_probe import evaluate,regname
arch=bn.Architecture['xtensa'];rows=[]
data=bytes.fromhex('101200')
assert arch.get_instruction_text(data,0)[0][0].text.strip()=='MOVSP'
il=bn.LowLevelILFunction(arch)
arch.get_instruction_low_level_il(data,0x40000100,il)
il.append(il.ret(il.const_pointer(4,0x40000103)));il.finalize()
def execute(il,state):
 pc=0
 for step in range(200):
    ins=il[pc];op=ins.operation.name
    if op=='LLIL_SET_REG':state[regname(ins.dest)]=evaluate(ins.src,state)
    elif op=='LLIL_IF':pc=int(ins.true if evaluate(ins.condition,state) else ins.false);continue
    elif op=='LLIL_GOTO':pc=int(ins.dest);continue
    elif op in ('LLIL_JUMP','LLIL_RET'):return op,evaluate(ins.dest,state)
    elif op=='LLIL_NOP':pass
    else:raise AssertionError(str(ins))
    pc+=1
 raise AssertionError('no terminal transfer')
for wb in range(16):
 for occupied in range(8):
  for ps in [0x40000,0x40020,0x40010,0x40030]:
   for ndep in [0,1]:
    ws=1<<wb
    for i in range(1,4):
     if occupied&(1<<(i-1)):ws|=1<<((wb-i)%16)
    state=dict(a1=0x2000,a2=0x1000,ps=ps,windowbase=wb,windowstart=ws,
               epc1=0x1111,depc=0x2222,exccause=0x3f,config_ndepc=ndep,
               userexception=0x40374340,kernelexception=0x40374300,doubleexception=0x403743c0)
    kind,target=execute(il,state)
    if occupied:
     assert kind=='LLIL_RET' and state['a1']==0x1000 and state['ps']==ps
     assert state['epc1']==0x1111 and state['depc']==0x2222 and state['exccause']==0x3f
    else:
     expected=state['doubleexception'] if ps&16 else state['userexception'] if ps&32 else state['kernelexception']
     assert kind=='LLIL_JUMP' and target==expected and state['a1']==0x2000
     assert state['exccause']==5 and state['ps']==ps|16
     reg='depc' if ps&16 and ndep else 'epc1'
     assert state[reg]==0x40000100
     other='epc1' if reg=='depc' else 'depc'
     assert state[other]==(0x1111 if other=='epc1' else 0x2222)
    assert state['windowbase']==wb and state['windowstart']==ws
    rows.append({'wb':wb,'occupied':occupied,'ps':ps,'ndepc':ndep,'target':target})
ret=bn.LowLevelILFunction(arch)
arch.get_instruction_low_level_il(bytes.fromhex('003200'),0,ret);ret.finalize()
for ndep in [0,1]:
 state=dict(config_ndepc=ndep,epc1=0x1111,depc=0x2222,ps=0x40030)
 assert execute(ret,state)==('LLIL_RET',0x2222 if ndep else 0x1111)
 assert state['ps']==0x40030
Path('/port/movsp_results.json').write_text(json.dumps({'movsp':rows,'rfde_configurations':2},indent=2)+'\n')
print('PASS:',len(rows),'MOVSP cases plus both RFDE DEPC configurations')
