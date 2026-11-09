import json
from pathlib import Path
import binaryninja as bn
from semantic_probe import evaluate,regname
arch=bn.Architecture['xtensa'];il=bn.LowLevelILFunction(arch)
arch.get_instruction_low_level_il(bytes.fromhex('1df0'),0x40000000,il);il.finalize()
rows=[]
for wb in range(16):
 for inc in range(4):
  for occupied in range(8):
   for ps in [0x40000,0,0x40010]:
    ws=1<<wb
    for d in range(1,4):
     if occupied&(1<<(d-1)):ws|=1<<((wb-d)%16)
    nearest=next((d for d in range(1,4) if occupied&(1<<(d-1))),None)
    invalid=inc==0 or ps!=0x40000 or (nearest is not None and nearest!=inc)
    state={f'ar{i}':0x100000+i for i in range(64)}
    state.update({f'a{i}':0x200000+i for i in range(16)})
    state.update(a0=(inc<<30)|0x1234,ps=ps,windowbase=wb,windowstart=ws)
    state.update({f'windowunderflow{i}':0x50000000+i for i in [4,8,12]})
    bank=[state[f'ar{i}'] for i in range(64)]
    for i in range(16):bank[(wb*4+i)%64]=state[f'a{i}']
    pc=0;kind=None;target=None
    for steps in range(1000):
     x=il[pc];op=x.operation.name
     if op=='LLIL_SET_REG':state[regname(x.dest)]=evaluate(x.src,state)
     elif op=='LLIL_IF':pc=int(x.true if evaluate(x.condition,state) else x.false);continue
     elif op=='LLIL_GOTO':pc=int(x.dest);continue
     elif op in ('LLIL_RET','LLIL_JUMP'):kind=op;target=evaluate(x.dest,state);break
     elif op=='LLIL_TRAP':kind=op;break
     elif op=='LLIL_NOP':pass
     else:raise AssertionError(op)
     pc+=1
    assert kind is not None
    if invalid:assert kind=='LLIL_TRAP'
    elif nearest is not None:
     assert kind=='LLIL_RET' and target==0x40001234
     assert state['windowbase']==(wb-inc)%16 and state['windowstart']==ws&~(1<<wb)
    else:
     new=(wb-inc)%16
     assert kind=='LLIL_JUMP' and target==0x50000000+inc*4
     assert state['epc1']==0x40000000 and state['ps']==ps|16|(wb<<8)
     assert state['windowstart']==ws and state['windowbase']==new
     assert all(state[f'ar{i}']==bank[i] for i in range(64))
     assert all(state[f'a{i}']==bank[(new*4+i)%64] for i in range(16))
    rows.append({'wb':wb,'inc':inc,'occupied':occupied,'ps':ps,'outcome':kind})
Path('/port/retw_underflow_results.json').write_text(json.dumps(rows,indent=2)+'\n')
print('PASS: 1536 RETW normal/underflow/undefined-state cases')
