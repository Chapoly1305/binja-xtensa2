import json
from pathlib import Path
import binaryninja as bn
from semantic_probe import evaluate
arch=bn.Architecture['xtensa']
rows=[]
for op, opcode in [('L32E',9),('S32E',0x49)]:
    for field, offset in [(0,-64),(1,-60),(15,-4)]:
        data=bytes([0x20,(field<<4)|3,opcode])
        tokens,length=arch.get_instruction_text(data,0x40000000)
        il=bn.LowLevelILFunction(arch)
        arch.get_instruction_low_level_il(data,0x40000000,il);il.finalize()
        insns=list(il.instructions);assert len(insns)==1
        i=insns[0]
        address=i.src.src if op=='L32E' else i.dest
        observed=evaluate(address,{'a3':0x1000})
        assert observed==0x1000+offset,(op,field,observed)
        assert op in ''.join(t.text for t in tokens)
        rows.append({'instruction':op,'bytes':data.hex(),'expected_address':0x1000+offset,'observed_address':observed,'llil':str(i)})
Path('/port/window_memory_results.json').write_text(json.dumps(rows,indent=2)+'\n')
print('PASS: six native LLIL exception-window memory address cases')
