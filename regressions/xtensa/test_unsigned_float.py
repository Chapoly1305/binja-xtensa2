import json,re,struct
from pathlib import Path
import binaryninja as bn
arch=bn.Architecture['xtensa'];bn.set_worker_thread_count(2)
f32=lambda x:struct.unpack('<f',struct.pack('<f',x))[0]
def evaluate(x,state):
 op=x.operation.name
 if op=='LLIL_REG':return state[str(x.src)]
 if op=='LLIL_ZX':return evaluate(x.src,state)&((1<<(8*x.src.size))-1)
 if op=='LLIL_FLOAT_CONST':return x.constant
 if op=='LLIL_INT_TO_FLOAT':
  value=evaluate(x.src,state);bits=8*x.src.size
  if value&(1<<(bits-1)):value-=1<<bits
  return f32(value)
 if op=='LLIL_FMUL':return f32(evaluate(x.left,state)*evaluate(x.right,state))
 raise AssertionError(str(x))
rows=[]
view=bn.BinaryView.new(bytes.fromhex('0df0'));view.platform=arch.standalone_platform
view.create_user_function(0);view.update_analysis_and_wait();function=view.get_function_at(0)
for line in Path('/port/unsigned.dump').read_text().splitlines():
 match=re.search(r':\s+([0-9a-f]{6})\s+(u?float)\.s\s+f2, a3, (\d+)',line)
 if not match:continue
 encoded,mnemonic,scale=match.groups();scale=int(scale)
 il=bn.LowLevelILFunction(arch,source_func=function)
 assert arch.get_instruction_low_level_il(bytes.fromhex(encoded)[::-1],0,il)==3
 il.finalize();assignments=[i for i in il.instructions if i.operation.name=='LLIL_SET_REG' and str(i.dest)=='f2']
 assert len(assignments)==1
 for value in (0,1,0x7fffffff,0x80000000,0xffffffff):
  integer=value if mnemonic=='ufloat' or value<0x80000000 else value-(1<<32)
  expected=f32(f32(integer)*2.0**(-scale));actual=evaluate(assignments[0].src,{'a3':value})
  rows.append(dict(mnemonic=mnemonic,scale=scale,input=value,expected=expected,actual=actual,match=actual==expected))
Path('/port/unsigned_float_results.json').write_text(json.dumps(rows,indent=2)+'\n')
print('cases',len(rows),'failures',sum(not x['match'] for x in rows),flush=True)
assert len(rows)==160 and all(x['match'] for x in rows)
view.file.close()

for scale in (0,7,15):
 data=bytes([scale<<4,0x23,0xcb])+bytes.fromhex('0df0')
 native=bn.BinaryView.new(data);native.platform=arch.standalone_platform
 native.create_user_function(0);native.update_analysis_and_wait()
 f=native.get_function_at(0)
 for level in (f.llil,f.llil.ssa_form,f.mlil,f.mlil.ssa_form):
  assert level is not None
  assert not any(i.operation.name.endswith('UNIMPL') for i in level.instructions)
 native.file.close()
print('PASS: 160 signed/unsigned conversion cases and three native full-analysis functions')
