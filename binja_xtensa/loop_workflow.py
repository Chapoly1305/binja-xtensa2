"""Xtensa loop-end transformation for instruction and register-programmed bounds.

Fallthrough and conditional loop-end branches are supported. Functions writing
loop registers use runtime loop-end guards and indirect LBEG transfers.
Cross-function loop targets and context-dependent incoming loop state require
additional validation; registration remains opt-in until integration gates pass.
"""
import json
from binaryninja import Workflow, Activity, LowLevelILFunction, LowLevelILLabel
from .instruction import Instruction
from .lifter import lift
from . import vector_profile, window_tail_workflow

NAME = 'matteroverwatch.xtensa.loops'

def transform(context):
    source = context.lifted_il
    function, view = context.function, context.view
    if source is None or function.arch.name != 'xtensa':
        return
    machine = {}
    for instruction in source.instructions:
        address = instruction.address
        if address not in machine:
            try:
                machine[address] = Instruction.decode(view.read(address, 3))
            except Exception:
                continue
    loops = [(addr + insn.length, addr + 4 + insn.imm8)
             for addr, insn in machine.items() if insn.mnem in ('LOOP', 'LOOPNEZ', 'LOOPGTZ')]
    dynamic = any(insn.mnem in ('WSR', 'XSR') and insn.sr in (0, 1, 2)
                  for insn in machine.values())
    if not loops and not dynamic:
        return
    endpoints = {}
    for address, insn in machine.items():
        info = function.arch.get_instruction_info(view.read(address, 3), address)
        fallthrough = info is not None and (not info.branches or any(b.type.name=='FalseBranch' for b in info.branches))
        if not fallthrough:
            continue
        if dynamic:
            endpoints[address] = (None, address + insn.length)
        else:
            for begin, end in loops:
                if address + insn.length == end:
                    endpoints[address] = (begin, end)
    if not endpoints:
        return
    # The source tail may be owned by a branch that we re-lift below, while
    # other instruction sites still jump to it. Preserve its complete native
    # CFG region instead of deleting it with the branch's address-tagged IL.
    shared_tail_indices = set()
    tail_label = source.get_label_for_address(function.arch, 0x100000000)
    if tail_label is not None and tail_label.resolved:
        blocks = list(source.basic_blocks)
        pending = [b for b in blocks if b.start <= int(tail_label.operand) < b.end]
        visited = set()
        while pending:
            block = pending.pop()
            if block.start in visited:
                continue
            visited.add(block.start)
            shared_tail_indices.update(range(max(block.start, int(tail_label.operand))
                                             if block.start <= int(tail_label.operand) < block.end
                                             else block.start, block.end))
            pending.extend(edge.target for edge in block.outgoing_edges)
    dest = LowLevelILFunction(function.arch, source_func=function)
    dest.prepare_to_copy_function(source)
    # Re-lifted normal exits can target an instruction inside a source block.
    # prepare_to_copy_function does not provide a label for every such index.
    targets = {address: LowLevelILLabel() for address in machine}
    def transfer(address):
        label = targets.get(address)
        return dest.goto(label) if label is not None else dest.jump(dest.const_pointer(4, address))
    marked = set()
    relifted = set()
    def emit_check(address):
        begin, end = endpoints[address]
        repeat, done = LowLevelILLabel(), LowLevelILLabel()
        active = dest.compare_equal(4, dest.reg(4, 'lend'), dest.const(4, end))
        if begin is not None:
            active = dest.and_expr(1, active,
                dest.compare_equal(4, dest.reg(4, 'lbeg'), dest.const(4, begin)))
        enabled = dest.compare_equal(4, dest.and_expr(4, dest.reg(4, 'ps'), dest.const(4, 16)), dest.const(4, 0))
        condition = dest.and_expr(1, dest.and_expr(1, active, enabled),
                                 dest.compare_not_equal(4, dest.reg(4, 'lcount'), dest.const(4, 0)))
        dest.append(dest.if_expr(condition, repeat, done))
        dest.mark_label(repeat)
        dest.append(dest.set_reg(4, 'lcount', dest.sub(4, dest.reg(4, 'lcount'), dest.const(4, 1))))
        if begin is None:
            dest.append(dest.jump_to(dest.reg(4, 'lbeg'), targets))
        else:
            dest.append(dest.goto(targets[begin]))
        dest.mark_label(done)
    for block in source.basic_blocks:
        dest.prepare_to_copy_block(block)
        for index in range(block.start, block.end):
            instruction = source[index]
            address = instruction.address
            dest.set_current_address(address, block.arch)
            if address in targets and address not in marked:
                dest.mark_label(targets[address]); marked.add(address)
            if index in shared_tail_indices:
                dest.append(instruction.copy_to(dest))
                continue
            if address in endpoints:
                if address not in relifted:
                    def conditional(cond, decoded, pc, il):
                        taken, fallthrough = LowLevelILLabel(), LowLevelILLabel()
                        il.append(il.if_expr(cond, taken, fallthrough))
                        il.mark_label(taken)
                        il.append(transfer(decoded.target_offset(pc)))
                        il.mark_label(fallthrough)
                        emit_check(pc)
                        il.append(transfer(pc + decoded.length))
                        return decoded.length
                    dest._xtensa_conditional_handler = conditional
                    try:
                        lift(machine[address], address, dest, view.read(address, 3))
                        if not machine[address].mnem.startswith('B'):
                            # Run only after the instruction's normal completion;
                            # internal WindowCheck paths terminate before here.
                            emit_check(address)
                            dest.append(transfer(address + machine[address].length))
                    finally:
                        del dest._xtensa_conditional_handler
                    relifted.add(address)
                continue
            dest.append(instruction.copy_to(dest))
    dest.finalize()
    context.lifted_il = dest


def register():
    workflow = Workflow('core.function.metaAnalysis').clone(NAME)
    activity = 'matteroverwatch.xtensa.loopEnds'
    workflow.register_activity(Activity(json.dumps({'name':activity,'title':'Xtensa hardware loops','description':'Insert hardware loop-end control flow into lifted IL.','role':'action','eligibility':{'auto':{}}}), action=transform))
    vector_activity = 'matteroverwatch.xtensa.vectorProfile'
    workflow.register_activity(Activity(json.dumps({'name':vector_activity,'title':'Xtensa window vectors','description':'Bind explicitly selected vector layout to runtime VECBASE.','role':'action','eligibility':{'auto':{}}}), action=vector_profile.transform))
    tail_activity = 'matteroverwatch.xtensa.sharedWindowTail'
    workflow.register_activity(Activity(json.dumps({'name':tail_activity,'title':'Share window overflow tails','description':'Share identical terminal window-bank overflow transitions after preserving the fault PC.','role':'action','eligibility':{'auto':{}}}), action=window_tail_workflow.transform))
    assert workflow.insert_after('core.function.generateLiftedIL', [activity, tail_activity, vector_activity])
    workflow.register()
    return workflow

workflow = register()
