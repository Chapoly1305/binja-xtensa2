import json
from pathlib import Path
import binaryninja as bn
from semantic_probe import evaluate,regname
arch=bn.Architecture['xtensa'];il=bn.LowLevelILFunction(arch)
assert arch.get_instruction_low_level_il(bytes.fromhex('364100'),0x40000000,il)==3
il.append(il.ret(il.const_pointer(4,0x40000100)));il.finalize()
instructions=[il[i] for i in range(len(il))];rows=[]
for wb in range(16):
 for inc in [1,2,3]:
  for occupied in range(32):
   ws=1<<wb
   for i in range(5):
    if occupied&(1<<i):ws|=1<<((wb+i+1)%16)
   state={f'ar{i}':0x100000+i for i in range(64)}
   state.update({f'a{i}':0x200000+i for i in range(16)})
   state.update(a1=0x1000,ps=0x40000|(inc<<16),windowbase=wb,windowstart=ws)
   state.update({f'windowoverflow{i}':0x50000000+i for i in [4,8,12]})
   expected=[state[f'ar{i}'] for i in range(64)]
   for i in range(16):expected[(wb*4+i)%64]=state[f'a{i}']
   collision=next((n for n in range(1,inc+1) if ws&(1<<((wb+n)%16))),None)
   pc=0;kind=None;target=None
   for step in range(1000):
    x=instructions[pc];op=x.operation.name
    if op=='LLIL_SET_REG':state[regname(x.dest)]=evaluate(x.src,state)
    elif op=='LLIL_IF':pc=int(x.true if evaluate(x.condition,state) else x.false);continue
    elif op=='LLIL_GOTO':pc=int(x.dest);continue
    elif op in ('LLIL_RET','LLIL_JUMP'):kind=op;target=evaluate(x.dest,state);break
    elif op=='LLIL_NOP':pass
    else:raise AssertionError(op)
    pc+=1
   assert kind is not None
   if collision is None:
    assert kind=='LLIL_RET' and target==0x40000100
    assert state['a1']==0xfe0 and state['windowbase']==(wb+inc)%16
    assert state['windowstart']==ws|(1<<((wb+inc)%16))
   else:
    new=(wb+collision)%16
    vector=4 if ws&(1<<((new+1)%16)) else 8 if ws&(1<<((new+2)%16)) else 12
    assert kind=='LLIL_JUMP' and target==0x50000000+vector
    assert state['ps']==0x40010|(inc<<16)|(wb<<8)
    assert state['epc1']==0x40000000 and state['windowbase']==new and state['windowstart']==ws
    assert all(state[f'ar{i}']==expected[i] for i in range(64))
    assert all(state[f'a{i}']==expected[(new*4+i)%64] for i in range(16))
   rows.append({'wb':wb,'inc':inc,'occupied':occupied,'overflow':collision is not None,'target':target})
Path('/port/entry_overflow_results.json').write_text(json.dumps(rows,indent=2)+'\n')
print('PASS: 1536 native ENTRY normal/overflow cases with physical bank and vector checks')
