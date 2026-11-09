"""Check external-register data flow, including full BN SSA propagation.
Platform-specific privilege policy and external-device behavior are not simulated.
"""
import json
from pathlib import Path
import binaryninja as bn
bn.set_worker_thread_count(2)
a = bn.Architecture['xtensa']
rows = []
for name, selector, intrinsic in [('RER', 6, 'read_external_register'), ('WER', 7, 'write_external_register')]:
    for t, s in [(0, 0), (3, 2), (15, 8)]:
        data = bytes([t << 4, selector << 4 | s, 0x40])
        tokens, length = a.get_instruction_text(data, 0x40000000)
        assert tokens[0].text.strip() == name, tokens
        il = bn.LowLevelILFunction(a)
        a.get_instruction_low_level_il(data, 0x40000000, il)
        il.finalize()
        operations = [il[i] for i in range(len(il)) if il[i].operation.name == 'LLIL_INTRINSIC']
        assert len(operations) == 1
        inst = operations[0]
        assert str(inst.intrinsic) == intrinsic
        assert [str(x.src) for x in inst.params] == ([f'a{s}'] if name == 'RER' else [f'a{s}', f'a{t}'])
        assert [str(x) for x in inst.output] == ([f'a{t}'] if name == 'RER' else [])
        rows.append({'bytes': data.hex(), 'llil': str(inst)})
# Actual fixture RER a0,a0 followed by WER a3,a2 and RET.N.
view = bn.BinaryView.new(b'\x00\x60\x40\x30\x72\x40\x0d\xf0')
view.platform = a.standalone_platform
view.add_function(0)
view.update_analysis_and_wait()
f = view.get_function_at(0)
assert f is not None
mlil = [str(i) for block in f.mlil for i in block]
assert any('read_external_register' in i for i in mlil), mlil
assert any('write_external_register' in i for i in mlil), mlil
assert not any('unimplemented' in i for i in mlil), mlil
assert f.mlil.ssa_form is not None and f.hlil is not None
Path('/port/external_register_results.json').write_text(json.dumps({'cases': rows, 'mlil': mlil}, indent=2)+'\n', encoding='utf-8')
print('PASS: six native external-register cases and full MLIL/SSA/HLIL construction')
view.file.close()
