"""ACCHI Table 133: signed 8-to-32 reads, low-eight writes, old-value exchange."""
import json
from pathlib import Path
import binaryninja as bn
import semantic_probe as probe
arch=bn.Architecture['xtensa'];bn.set_worker_thread_count(2)
base=probe.evaluate
def evaluate(x,state):
 if x.operation.name=='LLIL_SX':
  value=evaluate(x.src,state);bits=x.src.size*8
  return (value-(1<<bits) if value&(1<<(bits-1)) else value)&((1<<(x.size*8))-1)
 return base(x,state)
probe.evaluate=evaluate
code=bytes.fromhex('201103301113401161')
il=bn.LowLevelILFunction(arch)
for i in range(0,9,3):assert arch.get_instruction_low_level_il(code[i:i+3],i,il)==3
il.append(il.ret(il.const_pointer(4,9)));il.finalize()
def sx(value):return (value-256 if value&128 else value)&0xffffffff
rows=[]
for old in [0,1,127,128,255]:
 for written in [0,127,128,255]:
  for exchanged in [0,255]:
   state=dict(ps=0,windowbase=0,windowstart=1,acchi=old,acclo=0x89abcdef,a2=0,a3=sx(written),a4=sx(exchanged));pc=0
   for _ in range(1000):
    x=il[pc];op=x.operation.name
    if op=='LLIL_SET_REG':state[probe.regname(x.dest)]=evaluate(x.src,state)
    elif op=='LLIL_IF':pc=int(x.true if evaluate(x.condition,state) else x.false);continue
    elif op=='LLIL_GOTO':pc=int(x.dest);continue
    elif op=='LLIL_RET':break
    elif op!='LLIL_NOP':raise AssertionError(str(x))
    pc+=1
   else:raise AssertionError('no return')
   assert state['a2']==sx(old) and state['a4']==sx(written) and state['acchi']==exchanged
   assert state['acclo']==0x89abcdef and state['a3']==sx(written)
   rows.append(dict(old=old,written=written,exchanged=exchanged,read=state['a2'],exchange_result=state['a4']))
view=bn.BinaryView.new(code+bytes.fromhex('0df0'));view.platform=arch.standalone_platform
view.create_user_function(0);view.update_analysis_and_wait();f=view.get_function_at(0)
for level in [f.llil,f.mlil,f.mlil.ssa_form,f.hlil]:
 assert level is not None and not any(x.operation.name.endswith('UNIMPL') for x in level.instructions)
Path('/port/acchi_access_results.json').write_text(json.dumps({'cases':rows,'mlil':[str(x) for x in f.mlil.instructions]},indent=2)+'\n')
view.file.close();print('PASS: 40 ACCHI read/write/exchange sequences and native full analysis')
