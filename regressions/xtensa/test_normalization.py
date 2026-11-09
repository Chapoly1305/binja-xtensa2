"""Native normalization lifting plus boundary-value and full-analysis checks."""
import json, random
from pathlib import Path
import binaryninja as bn
bn.set_worker_thread_count(2)
a=bn.Architecture['xtensa']
values={0,0xffffffff,0x80000000,0x7fffffff}
for bit in range(32):
    values.update({1<<bit, (1<<bit)-1, (~(1<<bit))&0xffffffff})
rng=random.Random(20261108)
values.update(rng.getrandbits(32) for _ in range(128))
rows=[]
for name,data,operation in [('NSA',bytes.fromhex('20e340'),'LLIL_CLS'),('NSAU',bytes.fromhex('20f340'),'LLIL_CLZ')]:
    tokens,length=a.get_instruction_text(data,0)
    assert tokens[0].text.strip()==name, tokens
    il=bn.LowLevelILFunction(a)
    a.get_instruction_low_level_il(data,0,il);il.finalize()
    inst=il[0]
    assert inst.operation.name=='LLIL_SET_REG' and str(inst.dest)=='a2'
    assert inst.src.operation.name==operation and str(inst.src.src.src)=='a3'
    for value in sorted(values):
        bits=f'{value:032b}'
        if name=='NSA':
            expected=len(bits)-len(bits.lstrip(bits[0]))-1
            normalized=value ^ (0xffffffff if value&0x80000000 else 0)
            observed=31-normalized.bit_length()
        else:
            expected=len(bits)-len(bits.lstrip('0'))
            observed=32-value.bit_length()
        assert observed==expected
    view=bn.BinaryView.new(data+bytes.fromhex('0df0'))
    view.platform=a.standalone_platform;view.add_function(0);view.update_analysis_and_wait()
    f=view.get_function_at(0)
    mlil=[str(i) for b in f.mlil for i in b]
    assert not any('unimplemented' in x for x in mlil)
    assert any(('cls' if name=='NSA' else 'clz') in x for x in mlil),mlil
    assert f.mlil.ssa_form is not None and f.hlil is not None
    rows.append({'instruction':name,'bytes':data.hex(),'llil':str(inst),'mlil':mlil,'boundary_and_random_inputs':len(values),'scope':'BN operation mapping and reference arithmetic; not hardware emulation'})
    view.file.close()
Path('/port/normalization_results.json').write_text(json.dumps(rows,indent=2)+'\n',encoding='utf-8')
print('PASS: native CLS/CLZ mappings, boundary arithmetic and full BN analysis')
