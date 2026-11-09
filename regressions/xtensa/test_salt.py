"""Official SALT/SALTU encodings, signedness/aliasing and WindowCheck ordering."""
import importlib,itertools,json,re,sys
from pathlib import Path
import binaryninja as bn
import semantic_probe as probe
bn.set_worker_thread_count(2);a=bn.Architecture['xtensa']
p=next(m for n,m in sys.modules.items() if n.endswith('.binja_xtensa') and hasattr(m,'XtensaLE'))
Instruction=importlib.import_module(p.__name__+'.instruction').Instruction
fields=importlib.import_module(p.__name__+'.ar_operands')
enc={}
for line in Path('/port/salt.dump').read_text().splitlines():
 m=re.search(r':\s*([0-9a-f]{6})\s+(saltu?)\s+a(\d+), a(\d+), a(\d+)',line)
 if not m:continue
 raw=bytes.fromhex(m[1])[::-1];name=m[2].upper();r,s,t=map(int,m.group(3,4,5));ins=Instruction.decode(raw)
 assert ins.valid and (ins.mnem,ins.r,ins.s,ins.t,ins.length)==(name,r,s,t,3)
 assert fields.maximum_window_group(ins)==max(r,s,t)//4
 enc[name,r,s,t]=raw
assert len(enc)==8192
original=probe.evaluate
def evaluate(x,state):
 op=x.operation.name
 if op in ('LLIL_CMP_SLT','LLIL_CMP_ULT'):
  left,right=evaluate(x.left,state),evaluate(x.right,state)
  if op=='LLIL_CMP_SLT':left=signed(left);right=signed(right)
  return int(left<right)
 return original(x,state)
def signed(x):return x if x<0x80000000 else x-0x100000000
probe.evaluate=evaluate
cases=0
values=[0,1,2,0x7fffffff,0x80000000,0xfffffffe,0xffffffff]
for name in ['SALT','SALTU']:
 for r,s,t in itertools.product(range(4),repeat=3):
  raw=enc[name,r,s,t];il=bn.LowLevelILFunction(a);a.get_instruction_low_level_il(raw,0,il);il.finalize()
  assert len(il)==1 and il[0].operation.name=='LLIL_SET_REG'
  for left,right in itertools.product(values,repeat=2):
   state={f'a{i}':0x12345678 for i in range(16)};state[f'a{s}']=left;state[f'a{t}']=right
   lhs,rhs=state[f'a{s}'],state[f'a{t}'];expected=int(signed(lhs)<signed(rhs)) if name=='SALT' else int(lhs<rhs)
   assert evaluate(il[0].src,state)==expected,(name,r,s,t,left,right)
   cases+=1
faults=0
for name in ['SALT','SALTU']:
 for r,s,t in [(12,2,3),(2,12,3),(2,3,12)]:
  raw=enc[name,r,s,t];il=bn.LowLevelILFunction(a);a.get_instruction_low_level_il(raw,0x40000100,il);il.append(il.ret(il.const_pointer(4,0x40000103)));il.finalize()
  for wb in [0,15]:
   state={f'a{i}':0x100000+i for i in range(16)};state.update({f'ar{i}':0x200000+i for i in range(64)})
   old=state[f'a{r}'];state.update(ps=0x40000,windowbase=wb,windowstart=(1<<wb)|(1<<((wb+1)%16)),windowoverflow4=0x50000004,windowoverflow8=0x50000008,windowoverflow12=0x5000000c)
   pc=0;target=None
   for _ in range(1500):
    x=il[pc];op=x.operation.name
    if op=='LLIL_SET_REG':state[probe.regname(x.dest)]=evaluate(x.src,state)
    elif op=='LLIL_IF':pc=int(x.true if evaluate(x.condition,state) else x.false);continue
    elif op=='LLIL_GOTO':pc=int(x.dest);continue
    elif op=='LLIL_JUMP':target=evaluate(x.dest,state);break
    elif op!='LLIL_NOP':raise AssertionError(str(x))
    pc+=1
   assert target==0x5000000c and state['epc1']==0x40000100
   assert state[f'ar{(wb*4+r)%64}']==old,'Comparison committed before WindowCheck'
   faults+=1
for name in ['SALT','SALTU']:
 view=bn.BinaryView.new(enc[name,2,3,1]+bytes.fromhex('0df0'));view.platform=a.standalone_platform;view.add_function(0);view.update_analysis_and_wait();f=view.get_function_at(0)
 assert f and f.mlil.ssa_form is not None
 assert not any(i.operation.name=='LLIL_UNIMPL' for i in f.llil.instructions)
 view.file.close()
Path('/port/salt_results.json').write_text(json.dumps({'official_encodings':len(enc),'value_and_alias_cases':cases,'overflow_ordering_cases':faults,'native_functions':2},indent=2)+'\n')
print('PASS:',len(enc),'encodings,',cases,'values/aliases,',faults,'window faults and two native functions')
