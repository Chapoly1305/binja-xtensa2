"""Reserved MAC16 encodings never reach disassembly/lifting native callbacks."""
import importlib,itertools,json,sys
from pathlib import Path
import binaryninja as bn
bn.set_worker_thread_count(2)
arch=bn.Architecture['xtensa']
p=next(m for n,m in sys.modules.items() if n.endswith('.binja_xtensa') and hasattr(m,'XtensaLE'))
Instruction=importlib.import_module(p.__name__+'.instruction').Instruction
counts={'valid':0,'invalid':0};samples={}
for op2,op1,r,s,t in itertools.product(range(16),range(16),range(16),range(16),range(16)):
 data=bytes([(t<<4)|4,(r<<4)|s,(op2<<4)|op1])
 ins=Instruction.decode(data)
 assert ins is not None and ins.op0 == 4
 filtered=p.XtensaLE._decode_instruction(arch,data,0x40000000)
 if not ins.valid:
  assert filtered is None,(data.hex(),ins.mnem)
  counts['invalid']+=1
  # Exercise actual ctypes callbacks for each distinct rejected mnemonic.
  samples.setdefault(ins.mnem,data)
 else:
  assert filtered is not None
  for field in ['mac_left','mac_right','mac_destination','mac_base']:
   register=getattr(ins,field,None)
   assert register is None or register in arch.regs,(data.hex(),field,register)
  counts['valid']+=1
assert counts['valid']+counts['invalid']==1048576
for data in samples.values():
 assert arch.get_instruction_text(data,0x40000000) == ([], 0)
 il=bn.LowLevelILFunction(arch)
 assert arch.get_instruction_low_level_il(data,0x40000000,il) is None
 assert il.get_expr_count()==0
 info=arch.get_instruction_info(data,0x40000000)
 assert info is None
report={'counts':counts,'native_invalid_mnemonics':len(samples),'core':bn.core_version(),
        'scope':'All MAC16 arithmetic/compound field combinations; reserved operands rejected, not emulated as traps; valid semantics covered separately.'}
Path('/port/invalid_mac_results.json').write_text(json.dumps(report,indent=2)+'\n')
print('PASS:',json.dumps(report),flush=True)

# Invalid non-MAC slots must also abstain, while genuine ILL stays implemented.
for data in [bytes.fromhex('0e0000'),bytes.fromhex('0f0000')]:
 assert Instruction.decode(data).valid is False
 assert arch.get_instruction_info(data,0x40000000) is None
 assert arch.get_instruction_text(data,0x40000000)==([],0)
 il=bn.LowLevelILFunction(arch);assert arch.get_instruction_low_level_il(data,0x40000000,il) is None
 assert il.get_expr_count()==0
assert Instruction.decode(bytes.fromhex('000000')).valid is True
assert arch.get_instruction_info(bytes.fromhex('000000'),0x40000000).branches
