"""Concrete ISA counterexamples using real instruction bytes and native BN LLIL.

The evaluator covers only the arithmetic/register subset used by these cases.
This is not a general Xtensa emulator or a corpus-wide accuracy measurement.
"""
from pathlib import Path
import json
import binaryninja as bn

arch = bn.Architecture['xtensa']


def regname(reg):
    return reg.name if hasattr(reg, 'name') else str(reg)


def evaluate(node, state):
    op = node.operation.name
    bits = node.size * 8
    mask = (1 << bits) - 1 if bits else 1
    if op == 'LLIL_CONST' or op == 'LLIL_CONST_PTR':
        value = node.constant
    elif op == 'LLIL_REG':
        value = state.get(regname(node.src), 0)
    elif op in ('LLIL_LOW_PART', 'LLIL_ZX'):
        value = evaluate(node.src, state)
    elif op == 'LLIL_FABS':
        value = evaluate(node.src, state) & 0x7fffffff
    elif op in ('LLIL_ADD', 'LLIL_SUB', 'LLIL_AND', 'LLIL_OR', 'LLIL_XOR',
                'LLIL_LSL', 'LLIL_LSR', 'LLIL_ASR', 'LLIL_MULU_DP', 'LLIL_MULS_DP'):
        left, right = evaluate(node.left, state), evaluate(node.right, state)
        if op == 'LLIL_ADD': value = left + right
        elif op == 'LLIL_SUB': value = left - right
        elif op == 'LLIL_AND': value = left & right
        elif op == 'LLIL_OR': value = left | right
        elif op == 'LLIL_XOR': value = left ^ right
        elif op == 'LLIL_LSL': value = (left & mask) << right
        elif op == 'LLIL_LSR': value = (left & mask) >> right
        elif op == 'LLIL_ASR': value = ((left & ((1 << (bits-1))-1)) - (left & (1 << (bits-1)))) >> right
        else:
            if op == 'LLIL_MULS_DP':
                sign = 1 << (bits - 1)
                left = (left & (sign - 1)) - (left & sign)
                right = (right & (sign - 1)) - (right & sign)
            value = left * right
            mask = (1 << (bits * 2)) - 1
    elif op == 'LLIL_TEST_BIT':
        return bool(evaluate(node.left, state) & (1 << evaluate(node.right, state)))
    elif op == 'LLIL_CMP_SLE':
        left,right=evaluate(node.left,state),evaluate(node.right,state)
        sign=1 << (node.left.size*8-1)
        signed=lambda x:(x & (sign-1))-(x & sign)
        return signed(left)<=signed(right)
    elif op == 'LLIL_CMP_UGE':
        return evaluate(node.left, state) >= evaluate(node.right, state)
    elif op == 'LLIL_CMP_NE':
        return evaluate(node.left, state) != evaluate(node.right, state)
    elif op == 'LLIL_CMP_E':
        return evaluate(node.left, state) == evaluate(node.right, state)
    else:
        raise ValueError('unsupported test evaluator expression: ' + op)
    return value & mask


cases = [
    {'id': 'integer_abs', 'bytes': ['907160'], 'state': {'a9': 0xffffffff}, 'output': 'a7', 'expected': 1},
    {'id': 'muluh_distinct_operands', 'bytes': ['4023a2'], 'state': {'a3': 0x10000, 'a4': 0x20000}, 'output': 'a2', 'expected': 2},
    {'id': 'mulsh_distinct_operands', 'bytes': ['4023b2'], 'state': {'a3': 0x10000, 'a4': 0x20000}, 'output': 'a2', 'expected': 2},
    {'id': 'ssl_then_sll', 'bytes': ['001340', '0024a1'], 'state': {'a3': 3, 'a4': 1}, 'output': 'a2', 'expected': 8},
    {'id': 'ssr_masks_low_five_bits', 'bytes': ['000340'], 'state': {'a3': 0x123}, 'output': 'sar', 'expected': 3},
    {'id': 'ssl_masks_low_five_bits', 'bytes': ['001340'], 'state': {'a3': 0x123}, 'output': 'sar', 'expected': 29},
    {'id': 'abs_s_source_register', 'bytes': ['1023fa'], 'state': {'f1': 0xbf800000, 'f3': 0xc0400000}, 'output': 'f2', 'expected': 0x40400000},
    {'id': 'callx8_target_before_rotation', 'bytes': ['e00000'], 'state': {'a0': 0x40001000, 'a8': 0x40002000}, 'output': 'call_target', 'expected': 0x40001000},
    {'id': 'rfi_restores_eps_not_epc', 'bytes': ['103300'], 'state': {'epc3': 0x40001000, 'eps3': 0x60020}, 'output': 'ps', 'expected': 0x60020},
    {'id': 'rsil_preserves_upper_ps_bits', 'bytes': ['206500'], 'state': {'ps': 0x60023}, 'output': 'ps', 'expected': 0x60025},
    {'id': 'waiti_preserves_upper_ps_bits', 'bytes': ['007500'], 'state': {'ps': 0x60023}, 'output': 'ps', 'expected': 0x60025},
]
results = []
for case in cases:
    state = dict(case['state'])
    il = bn.LowLevelILFunction(arch)
    address = 0x40000000
    assembly = []
    for encoded in case['bytes']:
        data = bytes.fromhex(encoded)
        tokens, length = arch.get_instruction_text(data, address)
        assembly.append(''.join(str(t.text) for t in tokens))
        assert arch.get_instruction_low_level_il(data, address, il) == length
        address += length
    il.finalize()
    instructions = [il[i] for i in range(len(il))]
    row = dict(case, assembly=assembly, llil=[str(i) for i in instructions])
    try:
        pc = 0
        for step in range(2000):
            if pc >= len(instructions): break
            insn = instructions[pc]
            pc += 1
            op = insn.operation.name
            if op == "LLIL_IF":
                pc = int(insn.true if evaluate(insn.condition,state) else insn.false)
                continue
            if op == "LLIL_GOTO":
                pc = int(insn.dest)
                continue
            if op == 'LLIL_SET_REG':
                state[regname(insn.dest)] = evaluate(insn.src, state) & ((1 << (insn.size * 8)) - 1)
            elif op == 'LLIL_CALL':
                state['call_target'] = evaluate(insn.dest, state)
                break
            elif op == 'LLIL_RET':
                state['return_target'] = evaluate(insn.dest, state)
                break
            elif op == 'LLIL_NOP':
                continue
            else:
                raise ValueError('unsupported test evaluator instruction: ' + op)
        row['observed'] = state[case['output']]
        row['matches_isa_expectation'] = row['observed'] == case['expected']
    except Exception as exc:
        row['probe_error'] = str(exc)
    results.append(row)
    print(json.dumps(row), flush=True)
Path('/port/semantic_probe_results.json').write_text(json.dumps(results, indent=2) + '\n')
