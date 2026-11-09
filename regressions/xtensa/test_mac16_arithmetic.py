"""Official encodings plus independent 16x16/40-bit MAC16 arithmetic oracle."""
import importlib,json,re,sys
from pathlib import Path
import binaryninja as bn
import semantic_probe as probe
arch=bn.Architecture['xtensa'];bn.set_worker_thread_count(2)
p=next(m for n,m in sys.modules.items() if n.endswith('.binja_xtensa') and hasattr(m,'XtensaLE'))
Instruction=importlib.import_module(p.__name__+'.instruction').Instruction
base_evaluate=probe.evaluate
def evaluate(x,state):
 if x.operation.name=='LLIL_SX':
  value=evaluate(x.src,state);bits=x.src.size*8
  return (value-(1<<bits) if value&(1<<(bits-1)) else value)&((1<<(x.size*8))-1)
 if x.operation.name=='LLIL_MUL':return (evaluate(x.left,state)*evaluate(x.right,state))&((1<<(x.size*8))-1)
 return base_evaluate(x,state)
probe.evaluate=evaluate
rows=[];names=set();native={};encodings=0
mask=(1<<40)-1
for line in Path('/port/mac16_arithmetic.dump').read_text().splitlines():
 m=re.search(r':\s*([0-9a-f]{6})\s+((?:mul|mula|muls|umul)\.[ad]{2}\.[lh]{2})\s+([am]\d+), ([am]\d+)\s*$',line)
 if not m:continue
 data=bytes.fromhex(m[1])[::-1];name=m[2].upper();left=m[3];right=m[4];op,kind,half=name.split('.')
 ins=Instruction.decode(data);assert ins.valid and ins.mnem==name and ins.mac_left==left and ins.mac_right==right
 tokens,length=arch.get_instruction_text(data,0)
 assert length==3 and f'{left}, {right}' in ''.join(t.text for t in tokens)
 names.add(name);native.setdefault((op,kind),data);encodings+=1
 il=bn.LowLevelILFunction(arch);assert arch.get_instruction_low_level_il(data,0x40000000,il)==3
 il.append(il.ret(il.const_pointer(4,0x40000003)));il.finalize()
 for lv,rv in [(0x80000001,0xffff7fff),(0xffff8000,0x7fffffff),(0x00010001,0x00010001),(0x7fff0000,0x80000000)]:
  for acc in [0,(1<<39)-1,mask,(1<<32)-1,1<<32]:
   state={f'a{i}':0x1000+i for i in range(16)};state.update({f'm{i}':0x2000+i for i in range(4)})
   state.update(ps=0,windowbase=0,windowstart=1,acclo=acc&0xffffffff,acchi=acc>>32)
   state[left]=lv;state[right]=rv;before=dict(state)
   a=(lv>>(16 if half[0]=='H' else 0))&0xffff;b=(rv>>(16 if half[1]=='H' else 0))&0xffff
   if op!='UMUL':a=a-65536 if a&32768 else a;b=b-65536 if b&32768 else b
   product=a*b;expected=(acc+product if op=='MULA' else acc-product if op=='MULS' else product)&mask
   pc=0
   for _ in range(1000):
    x=il[pc];operation=x.operation.name
    if operation=='LLIL_SET_REG':state[probe.regname(x.dest)]=evaluate(x.src,state)
    elif operation=='LLIL_IF':pc=int(x.true if evaluate(x.condition,state) else x.false);continue
    elif operation=='LLIL_GOTO':pc=int(x.dest);continue
    elif operation=='LLIL_RET':break
    elif operation!='LLIL_NOP':raise AssertionError(str(x))
    pc+=1
   else:raise AssertionError('no terminal flow')
   actual=(state['acchi']<<32)|state['acclo'];assert actual==expected,(name,left,right,hex(acc),hex(expected),hex(actual))
   assert all(state[r]==before[r] for r in [*[f'a{i}' for i in range(16)],*[f'm{i}' for i in range(4)]])
   rows.append(dict(instruction=name,bytes=data.hex(),left=lv,right=rv,acc_before=acc,acc_after=actual))
assert len(names)==52 and encodings==176,(len(names),encodings)
reserved=[bytes([(t<<4)|4,(r<<4)|s,(op2<<4)|op1]) for op2,op1,r,s,t in [(7,4,1,1,2),(3,4,1,1,0),(3,4,0,1,1),(6,4,0,1,2),(6,4,1,0,2),(2,4,0,1,0),(2,4,0,0,1),(2,0,0,0,0)]]
for data in reserved:
 ins=Instruction.decode(data);assert ins is None or not ins.valid,data.hex()
for key,data in native.items():
 view=bn.BinaryView.new(data+bytes.fromhex('0df0'));view.platform=arch.standalone_platform
 view.create_user_function(0);view.update_analysis_and_wait();f=view.get_function_at(0)
 for il in [f.llil,f.mlil,f.mlil.ssa_form,f.hlil]:
  assert il is not None and not any(x.operation.name.endswith('UNIMPL') for x in il.instructions),(key,type(il).__name__)
 view.file.close()
Path('/port/mac16_arithmetic_results.json').write_text(json.dumps({'cases':rows,'mnemonics':sorted(names),'assembled_encodings':encodings,'reserved_rejected':len(reserved),'native_functions':len(native)},indent=2)+'\n')
print('PASS:',len(rows),'MAC16 arithmetic executions;',len(names),'mnemonics;',len(native),'native functions')
