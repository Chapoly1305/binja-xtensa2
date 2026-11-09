"""Officially assembled MAC16 loads: native LLIL address and destination checks."""
import importlib,json,re,sys
from pathlib import Path
import binaryninja as bn
import semantic_probe as probe
arch=bn.Architecture['xtensa'];bn.set_worker_thread_count(2)
p=next(m for n,m in sys.modules.items() if n.endswith('.binja_xtensa') and hasattr(m,'XtensaLE'))
Instruction=importlib.import_module(p.__name__+'.instruction').Instruction
base_evaluate=probe.evaluate;memory={};loads=[]
def evaluate(x,state):
 if x.operation.name=='LLIL_LOAD':
  address=base_evaluate(x.src,state);loads.append(address);return memory[address]
 return base_evaluate(x,state)
probe.evaluate=evaluate
rows=[];examples=[]
for line in Path('/port/mac16_loads.dump').read_text().splitlines():
 m=re.search(r':\s*([a-f0-9]{6})\s+(ldinc|lddec)\s+m([0-3]), a(\d+)\s*$',line)
 if not m:continue
 data=bytes.fromhex(m[1])[::-1];name=m[2].upper();mr=int(m[3]);ar=int(m[4]);delta=4 if name=='LDINC' else -4
 decoded=Instruction.decode(data);assert decoded.valid and decoded.mnem==name and decoded.r==mr and decoded.s==ar
 tokens,length=arch.get_instruction_text(data,0)
 text=''.join(t.text for t in tokens);assert name in text and f'm{mr}, a{ar}' in text and length==3
 il=bn.LowLevelILFunction(arch);arch.get_instruction_low_level_il(data,0x40000000,il)
 il.append(il.ret(il.const_pointer(4,0x40000003)));il.finalize()
 for initial in [0,0xfffffffc]:
  expected=(initial+delta)&0xffffffff;memory.clear();memory[expected]=0x87654321;loads.clear()
  state={f'a{i}':0x1000+i*4 for i in range(16)};state.update({f'm{i}':i+1 for i in range(4)})
  state.update(ps=0,windowbase=0,windowstart=1);state[f'a{ar}']=initial;pc=0
  for _ in range(1000):
   x=il[pc];op=x.operation.name
   if op=='LLIL_SET_REG':state[probe.regname(x.dest)]=evaluate(x.src,state)
   elif op=='LLIL_IF':pc=int(x.true if evaluate(x.condition,state) else x.false);continue
   elif op=='LLIL_GOTO':pc=int(x.dest);continue
   elif op=='LLIL_RET':break
   elif op!='LLIL_NOP':raise AssertionError(str(x))
   pc+=1
  else:raise AssertionError('no return')
  assert loads==[expected] and state[f'a{ar}']==expected and state[f'm{mr}']==0x87654321
  assert all(state[f'm{i}']==i+1 for i in range(4) if i!=mr)
  rows.append(dict(instruction=name,mr=mr,ar=ar,initial=initial,address=expected))
 if ar==1:examples.append(data)
assert len(rows)==256
rejected=0
for op2 in [8,9]:
 for t,r,op1 in [(1,0,0),(0,4,0),(0,0,1),(15,15,15)]:
  ins=Instruction.decode(bytes([(t<<4)|4,r<<4,(op2<<4)|op1]));assert ins is None or not ins.valid;rejected+=1
for data in examples:
 view=bn.BinaryView.new(data+bytes.fromhex('0df0'));view.platform=arch.standalone_platform
 view.create_user_function(0);view.update_analysis_and_wait();f=view.get_function_at(0)
 for il in [f.llil,f.mlil,f.mlil.ssa_form]:
  assert il is not None and not any(x.operation.name.endswith('UNIMPL') for x in il.instructions)
 view.file.close()
Path('/port/mac16_load_results.json').write_text(json.dumps({'cases':rows,'reserved_rejected':rejected,'native_functions':len(examples),'scope':'Successful aligned loads with 32-bit wrap; general memory faults remain outside this test.'},indent=2)+'\n')
print('PASS: 256 MAC16 load cases, 8 reserved encodings and 8 native functions')
