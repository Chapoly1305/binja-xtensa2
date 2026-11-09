"""MAC16 compound window overflow must precede loads and ACC/MR commits."""
import json,re
from pathlib import Path
import binaryninja as bn
import semantic_probe as probe
arch=bn.Architecture['xtensa'];examples={};rows=[]
for line in Path('/port/mac16_compound.dump').read_text().splitlines():
 m=re.search(r':\s*([0-9a-f]{6})\s+(mula\.(?:da|dd)\.[lh]{2}\.ld(?:inc|dec))\s+m\d+, a12,',line)
 if m:examples.setdefault(m[2],bytes.fromhex(m[1])[::-1])
assert len(examples)==16
for name,data in examples.items():
 il=bn.LowLevelILFunction(arch);arch.get_instruction_low_level_il(data,0x40000100,il)
 il.append(il.ret(il.const_pointer(4,0x40000103)));il.finalize()
 for wb in [0,15]:
  state={f'a{i}':0x100000+i for i in range(16)};state.update({f'ar{i}':0x200000+i for i in range(64)})
  state.update({f'm{i}':0x300000+i for i in range(4)})
  state.update(ps=0x40000,windowbase=wb,windowstart=(1<<wb)|(1<<((wb+1)%16)),acclo=0xabcdef01,acchi=0x80,
               windowoverflow4=0x50000004,windowoverflow8=0x50000008,windowoverflow12=0x5000000c)
  before=dict(state);pc=0;target=None
  for _ in range(1000):
   x=il[pc];op=x.operation.name
   if op=='LLIL_SET_REG':state[probe.regname(x.dest)]=probe.evaluate(x.src,state) # LOAD raises: must not execute.
   elif op=='LLIL_IF':pc=int(x.true if probe.evaluate(x.condition,state) else x.false);continue
   elif op=='LLIL_GOTO':pc=int(x.dest);continue
   elif op=='LLIL_JUMP':target=probe.evaluate(x.dest,state);break
   elif op!='LLIL_NOP':raise AssertionError(str(x))
   pc+=1
  assert target==0x5000000c and state['epc1']==0x40000100
  assert all(state[r]==before[r] for r in ['acclo','acchi','m0','m1','m2','m3'])
  rows.append(dict(instruction=name,window=wb,target=target))
Path('/port/mac16_overflow_results.json').write_text(json.dumps(rows,indent=2)+'\n')
print('PASS: 32 compound MAC16 window overflows commit no memory/ACC/MR effects')
