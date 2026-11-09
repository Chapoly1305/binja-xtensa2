"""Native decoder/LLIL regression for distinct data/instruction tag stores.
Opaque cache intrinsics do not claim implementation-specific cache simulation.
"""
import ast
import json
from pathlib import Path
import binaryninja as bn
root = Path('/port')
tree = ast.parse((root/'plugin/binja_xtensa/lifter.py').read_text(encoding='utf-8'))
seen = set()
for node in tree.body:
    names = [node.name] if isinstance(node, ast.FunctionDef) else [t.id for t in node.targets if isinstance(t, ast.Name)] if isinstance(node, ast.Assign) else []
    for name in names:
        if name.startswith('_lift_'):
            assert name not in seen, ('duplicate handler', name)
            seen.add(name)
arch = bn.Architecture['xtensa']
rows = []
for mnemonic, selector, intrinsic in [('SDCT', 9, 'store_data_cache_tag'), ('SICT', 1, 'store_instruction_cache_tag')]:
    for source, index in [(2, 3), (15, 8), (0, 0)]:
        data = bytes([source << 4, selector << 4 | index, 0xf1])
        tokens, length = arch.get_instruction_text(data, 0x40000000)
        assert tokens[0].text.strip() == mnemonic
        il = bn.LowLevelILFunction(arch)
        arch.get_instruction_low_level_il(data, 0x40000000, il)
        il.finalize()
        operations = [il[i] for i in range(len(il)) if il[i].operation.name == 'LLIL_INTRINSIC']
        assert len(operations) == 1
        statement = operations[0]
        assert statement.operation.name == 'LLIL_INTRINSIC', str(statement)
        assert str(statement.intrinsic) == intrinsic, str(statement)
        assert [str(x.src) for x in statement.params] == [f'a{index}', f'a{source}'], str(statement)
        rows.append({'mnemonic': mnemonic, 'bytes': data.hex(), 'llil': str(statement)})
(root/'cache_tag_results.json').write_text(json.dumps(rows, indent=2)+'\n', encoding='utf-8')
print('PASS: six native cache tag store cases; no duplicate lifter handlers')
