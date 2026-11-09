"""Ordinary AR-access WindowCheck executions; no corpus accuracy claim."""
import json
from pathlib import Path
import binaryninja as bn
from semantic_probe import evaluate,regname
arch=bn.Architecture['xtensa'];rows=[]
for register in [0,4,8,12,15]:
 data=bytes([register<<4,0x23,0x80]) # ADD a2,a3,aT
 tokens,length=arch.get_instruction_text(data,0x40000000)
 assert tokens[0].text.strip()=='ADD'
 il=bn.LowLevelILFunction(arch)
 arch.get_instruction_low_level_il(data,0x40000000,il)
 il.append(il.ret(il.const_pointer(4,0x40000100)));il.finalize()
 for wb in [0,15]:
  for occupancy in range(8):
   for ps in [0,0x40000,0x40010]:
    ws=1<<wb
    for d in range(1,4):
     if occupancy&(1<<(d-1)):ws|=1<<((wb+d)%16)
    state={f'ar{i}':0x100000+i for i in range(64)}
    state.update({f'a{i}':0x200000+i for i in range(16)})
    expected_add=(state['a3']+state[f'a{register}'])&0xffffffff
    state.update(ps=ps,windowbase=wb,windowstart=ws)
    state.update({f'windowoverflow{i}':0x50000000+i for i in [4,8,12]})
    collision=next((d for d in range(1,(register>>2)+1) if ws&(1<<((wb+d)%16))),None) if ps==0x40000 else None
    pc=0;target=None;kind=None
    for step in range(1500):
     ins=il[pc];op=ins.operation.name
     if op=='LLIL_SET_REG':state[regname(ins.dest)]=evaluate(ins.src,state)
     elif op=='LLIL_IF':pc=int(ins.true if evaluate(ins.condition,state) else ins.false);continue
     elif op=='LLIL_GOTO':pc=int(ins.dest);continue
     elif op in ('LLIL_RET','LLIL_JUMP'):kind=op;target=evaluate(ins.dest,state);break
     elif op=='LLIL_NOP':pass
     else:raise AssertionError(str(ins))
     pc+=1
    if collision is None:
     assert kind=='LLIL_RET' and state['a2']==expected_add
    else:
     new=(wb+collision)%16
     vector=4 if ws&(1<<((new+1)%16)) else 8 if ws&(1<<((new+2)%16)) else 12
     assert kind=='LLIL_JUMP' and target==0x50000000+vector
     assert state['epc1']==0x40000000 and state['windowbase']==new
    rows.append({'register':register,'windowbase':wb,'occupancy':occupancy,'ps':ps,'overflow':collision is not None})
# FPU operand numbers must not accidentally become AR window references.
il=bn.LowLevelILFunction(arch)
arch.get_instruction_low_level_il(bytes.fromhex('10eefa'),0,il);il.finalize()
assert not any(il[i].operation.name=='LLIL_IF' for i in range(len(il)))
Path('/port/general_window_results.json').write_text(json.dumps(rows,indent=2)+'\n')
print('PASS:',len(rows),'ordinary AR window cases and FPU negative control')
