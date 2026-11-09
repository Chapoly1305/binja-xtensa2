"""Exception-option-2 decoding and successful privileged-return state checks.
RFDE covers NDEPC=0 only; general privilege exception dispatch remains separate.
"""
import json
from pathlib import Path
import binaryninja as bn
from semantic_probe import evaluate
arch = bn.Architecture['xtensa']
rows = []
for name, data in [('RFE', bytes.fromhex('003000')), ('RFDE', bytes.fromhex('003200'))]:
    tokens, length = arch.get_instruction_text(data, 0x40000000)
    assert tokens[0].text.strip() == name, tokens
    info = arch.get_instruction_info(data, 0x40000000)
    expected_branch = bn.BranchType.ExceptionBranch if name == 'RFUE' else bn.BranchType.FunctionReturn
    assert info.branches[0].type == expected_branch
    il = bn.LowLevelILFunction(arch)
    arch.get_instruction_low_level_il(data, 0x40000000, il)
    il.finalize()
    for ps in [0, 16, 0x40030, 0xffffff3f]:
        state = {'ps': ps, 'epc1': 0x40081234}
        transfer = None
        pc = 0
        for step in range(100):
            if pc >= len(il): break
            ins = il[pc];pc += 1
            if ins.operation.name == 'LLIL_IF':
                pc = int(ins.true if evaluate(ins.condition, state) else ins.false);continue
            if ins.operation.name == 'LLIL_GOTO':
                pc = int(ins.dest);continue
            if ins.operation.name == 'LLIL_SET_REG':
                state[str(ins.dest)] = evaluate(ins.src, state)
            elif ins.operation.name == 'LLIL_RET':
                transfer = evaluate(ins.dest, state)
                break
            elif ins.operation.name == 'LLIL_TRAP':
                transfer = 'illegal'
                break
            else:
                raise AssertionError(str(ins))
        assert transfer == ('illegal' if name == 'RFUE' else state['epc1'])
        assert state['ps'] == (ps & ~16 if name == 'RFE' else ps)
        rows.append({'instruction': name, 'bytes': data.hex(), 'ps_before': ps, 'ps_after': state['ps'], 'transfer': transfer})
Path('/port/exception_return_results.json').write_text(json.dumps(rows, indent=2)+'\n', encoding='utf-8')
print('PASS: eight exception-option-2 return cases and CFG classifications')
