"""Compound MAC16 successful loads preserve old overlapping MR/AR inputs."""
import importlib,json,re,sys
from pathlib import Path
import binaryninja as bn
import semantic_probe as probe
arch=bn.Architecture['xtensa'];bn.set_worker_thread_count(2)
p=next(m for n,m in sys.modules.items() if n.endswith('.binja_xtensa') and hasattr(m,'XtensaLE'))
Instruction=importlib.import_module(p.__name__+'.instruction').Instruction
base_evaluate=probe.evaluate;memory={};loads=[];at_load=[]
def evaluate(x,state):
 if x.operation.name=='LLIL_LOAD':
  address=evaluate(x.src,state);loads.append(address);at_load.append(dict(state));return memory[address]
 if x.operation.name=='LLIL_SX':
  value=evaluate(x.src,state);bits=x.src.size*8
  return (value-(1<<bits) if value&(1<<(bits-1)) else value)&((1<<(x.size*8))-1)
 if x.operation.name=='LLIL_MUL':return (evaluate(x.left,state)*evaluate(x.right,state))&((1<<(x.size*8))-1)
 return base_evaluate(x,state)
probe.evaluate=evaluate
rows=[];native={};encodings=0;overlaps=set();mask=(1<<40)-1
registers=[*[f'a{i}' for i in range(16)],*[f'm{i}' for i in range(4)],'acclo','acchi']
for line in Path('/port/mac16_compound.dump').read_text().splitlines():
 m=re.search(r':\s*([0-9a-f]{6})\s+(mula\.(?:da|dd)\.[lh]{2}\.ld(?:inc|dec))\s+(m\d+), (a\d+), (m\d+), ([am]\d+)\s*$',line)
 if not m:continue
 data=bytes.fromhex(m[1])[::-1];name=m[2].upper();dest,base,left,right=[m[i] for i in range(3,7)];_,kind,half,direction=name.split('.')
 ins=Instruction.decode(data);assert ins.valid and ins.mnem==name
 assert [ins.mac_destination,ins.mac_base,ins.mac_left,ins.mac_right]==[dest,base,left,right]
 tokens,length=arch.get_instruction_text(data,0);assert length==3 and f'{dest}, {base}, {left}, {right}' in ''.join(t.text for t in tokens)
 native.setdefault(name,data);encodings+=1
 il=bn.LowLevelILFunction(arch);assert arch.get_instruction_low_level_il(data,0x40000000,il)==3
 il.append(il.ret(il.const_pointer(4,0x40000003)));il.finalize()
 for initial in [0,0xfffffffc]:
  for acc in [0,mask]:
   for loaded in [0xa5c35a3c,0x7fff8000]:
    address=(initial+(4 if direction=='LDINC' else -4))&0xffffffff
    memory.clear();memory[address]=loaded;loads.clear();at_load.clear()
    state={f'a{i}':0x7fff8001+i for i in range(16)}
    state.update(m0=0x80007fff,m1=0xffff0001,m2=0x7fff8000,m3=0x0001ffff,ps=0,windowbase=0,windowstart=1,acclo=acc&0xffffffff,acchi=acc>>32)
    state[base]=initial;before=dict(state)
    a=(before[left]>>(16 if half[0]=='H' else 0))&0xffff;b=(before[right]>>(16 if half[1]=='H' else 0))&0xffff
    a=a-65536 if a&32768 else a;b=b-65536 if b&32768 else b;expected=(acc+a*b)&mask
    pc=0
    for _ in range(1000):
     x=il[pc];op=x.operation.name
     if op=='LLIL_SET_REG':state[probe.regname(x.dest)]=evaluate(x.src,state)
     elif op=='LLIL_IF':pc=int(x.true if evaluate(x.condition,state) else x.false);continue
     elif op=='LLIL_GOTO':pc=int(x.dest);continue
     elif op=='LLIL_RET':break
     elif op!='LLIL_NOP':raise AssertionError(str(x))
     pc+=1
    else:raise AssertionError('no terminal flow')
    assert loads==[address]
    assert all(at_load[0][r]==before[r] for r in registers),'Architectural output committed before memory access'
    assert ((state['acchi']<<32)|state['acclo'])==expected,(name,half,hex(expected),state)
    assert state[base]==address and state[dest]==loaded
    assert all(state[r]==before[r] for r in registers if r not in [base,dest,'acclo','acchi'])
    if dest==left:overlaps.add('mr_left')
    if dest==right:overlaps.add('mr_right')
    if base==right:overlaps.add('ar_base_right')
    rows.append(dict(instruction=name,bytes=data.hex(),base_before=initial,address=address,loaded=loaded,acc_before=acc,acc_after=expected))
assert encodings==512 and len(native)==16 and overlaps=={'mr_left','mr_right','ar_base_right'}
reserved=[]
for op2 in [0,1,4,5]:
 for op1,r,t in [(4,0,0),(8,8,0)]:
  data=bytes([(t<<4)|4,r<<4,(op2<<4)|op1]);ins=Instruction.decode(data);assert ins is None or not ins.valid;reserved.append(data.hex())
for op2 in [0,1]:
 ins=Instruction.decode(bytes([0x14,0,(op2<<4)|8]));assert ins is None or not ins.valid
for name,data in native.items():
 view=bn.BinaryView.new(data+bytes.fromhex('0df0'));view.platform=arch.standalone_platform
 view.create_user_function(0);view.update_analysis_and_wait();f=view.get_function_at(0)
 for il in [f.llil,f.mlil,f.mlil.ssa_form,f.hlil]:
  assert il is not None and not any(x.operation.name.endswith('UNIMPL') for x in il.instructions),(name,type(il).__name__)
 view.file.close()
Path('/port/mac16_compound_results.json').write_text(json.dumps({'cases':rows,'assembled_encodings':encodings,'native_functions':len(native),'reserved_rejected':len(reserved)+2,'overlaps':sorted(overlaps),'scope':'Successful aligned loads and 32-bit address wrap; generic memory-fault dispatch remains outside this test.'},indent=2)+'\n')
print('PASS:',len(rows),'compound MAC16 cases, 512 encodings, 16 native functions and 3 overlap classes')
