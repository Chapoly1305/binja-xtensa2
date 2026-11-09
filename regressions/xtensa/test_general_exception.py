"""Execute explicit Exception Option 2 triggers, checking restart PC and state.
ISA 8.3.123/124/325, RFUE architecture-2 illegal handling and 4.4.1.10.
"""
import json
from pathlib import Path
import binaryninja as bn
from semantic_probe import evaluate,regname
arch=bn.Architecture['xtensa'];rows=[]
for name,hexbytes,cause in [('ILL','000000',0),('ILL.N','6df0',0),('SYSCALL','005000',1),('RFUE','003100',0)]:
 data=bytes.fromhex(hexbytes)
 assert arch.get_instruction_text(data,0)[0][0].text.strip()==name
 assert [b.type for b in arch.get_instruction_info(data,0).branches]==[bn.BranchType.ExceptionBranch]
 for address in [0x40000100,0x40374120]:
  il=bn.LowLevelILFunction(arch);arch.get_instruction_low_level_il(data,address,il);il.finalize()
  for ps in [0,0x40020,0x40010,0x40030]:
   for ndep in [0,1]:
    state=dict(ps=ps,epc1=0x1111,depc=0x2222,exccause=63,config_ndepc=ndep,
     userexception=0x40374340,kernelexception=0x40374300,doubleexception=0x403743c0)
    before=dict(state);pc=0;target=None
    for _ in range(100):
     ins=il[pc];op=ins.operation.name
     if op=='LLIL_SET_REG':state[regname(ins.dest)]=evaluate(ins.src,state)
     elif op=='LLIL_IF':pc=int(ins.true if evaluate(ins.condition,state) else ins.false);continue
     elif op=='LLIL_GOTO':pc=int(ins.dest);continue
     elif op=='LLIL_JUMP':target=evaluate(ins.dest,state);break
     else:raise AssertionError(str(ins))
     pc+=1
    expected=before['doubleexception'] if ps&16 else before['userexception'] if ps&32 else before['kernelexception']
    assert target==expected and state['ps']==ps|16 and state['exccause']==cause
    saved='depc' if ps&16 and ndep else 'epc1'
    assert state[saved]==address  # Never advance PC at the throwing instruction.
    other='epc1' if saved=='depc' else 'depc'
    assert state[other]==before[other]
    rows.append(dict(instruction=name,pc=address,ps=ps,ndepc=ndep,cause=cause,target=target))
Path('/port/general_exception_results.json').write_text(json.dumps(rows,indent=2)+'\n')
print('PASS:',len(rows),'explicit exception-trigger cases; CFG terminates at exception')
