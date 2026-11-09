"""SSAI's split five-bit immediate, ISA 8.3.310; reserved upper t bits rejected."""
import importlib,json,sys
from pathlib import Path
import binaryninja as bn
from semantic_probe import evaluate,regname
arch=bn.Architecture['xtensa']
p=next(m for n,m in sys.modules.items() if n.endswith('.binja_xtensa') and hasattr(m,'XtensaLE'))
Instruction=importlib.import_module(p.__name__+'.instruction').Instruction
rows=[];rejected=0
for t in range(16):
 for s in range(16):
  data=bytes([t<<4,0x40|s,0x40]);ins=Instruction.decode(data)
  if t>=2:
   assert ins is None or not ins.valid,(t,s);rejected+=1;continue
  expected=s+(t<<4)
  assert ins.valid and ins.mnem=='SSAI' and ins.inline0(0)==expected
  tokens,length=arch.get_instruction_text(data,0)
  assert length==3 and tokens[0].text.strip()=='SSAI'
  il=bn.LowLevelILFunction(arch);assert arch.get_instruction_low_level_il(data,0,il)==3;il.finalize()
  assert len(il)==1 and il[0].operation.name=='LLIL_SET_REG' and regname(il[0].dest)=='sar'
  assert evaluate(il[0].src,{'sar':63})==expected
  rows.append({'bytes':data.hex(),'immediate':expected,'sar':expected})
Path('/port/ssai_results.json').write_text(json.dumps({'valid':rows,'reserved_rejected':rejected},indent=2)+'\n')
print('PASS: 32 native SSAI immediate values and 224 reserved encodings')
