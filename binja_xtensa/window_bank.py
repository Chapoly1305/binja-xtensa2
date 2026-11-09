"""Explicit 64-register bank rotation for Xtensa window-management instructions.

Dispatch uses LLIL branches instead of hidden Python state. Each view/function
therefore has independent register state and deterministic lifting.
"""
from binaryninja import LowLevelILLabel, LLIL_TEMP


def _dispatch(il, selector, action):
    end = LowLevelILLabel()
    for window in range(16):
        match, next_window = LowLevelILLabel(), LowLevelILLabel()
        il.append(il.if_expr(il.compare_equal(4, selector, il.const(4, window)), match, next_window))
        il.mark_label(match)
        action(window)
        il.append(il.goto(end))
        il.mark_label(next_window)
    il.mark_label(end)


def rotate_bank(il, new_window):
    # Compute first: the expression may reference the old WINDOWBASE.
    il.append(il.set_reg(4, LLIL_TEMP(24), il.and_expr(4, new_window, il.const(4, 15))))
    old = il.and_expr(4, il.reg(4, 'windowbase'), il.const(4, 15))
    def save(window):
        for i in range(16):
            il.append(il.set_reg(4, 'ar'+str((window*4+i)%64), il.reg(4, 'a'+str(i))))
    _dispatch(il, old, save)
    il.append(il.set_reg(4, 'windowbase', il.reg(4, LLIL_TEMP(24))))
    def restore(window):
        for i in range(16):
            il.append(il.set_reg(4, 'a'+str(i), il.reg(4, 'ar'+str((window*4+i)%64))))
    _dispatch(il, il.reg(4, 'windowbase'), restore)
    # Materialize the join even when this is the final lifted instruction.
    il.append(il.nop())


def rotate_bank_compact(il, new_window):
    """Candidate native register-stack encoding, pending full-view validation."""
    il.append(il.set_reg(4, LLIL_TEMP(24), il.and_expr(4, new_window, il.const(4, 15))))
    il.append(il.set_reg(4, 'bank_top', il.const(4, 0)))
    def index(window, i):
        return il.and_expr(4, il.add(4, il.shift_left(4, window, il.const(1, 2)), il.const(4, i)), il.const(4, 63))
    for i in range(16):
        il.append(il.set_reg_stack_top_relative(4, 'physical_ar', index(il.reg(4, 'windowbase'), i), il.reg(4, 'a'+str(i))))
    il.append(il.set_reg(4, 'windowbase', il.reg(4, LLIL_TEMP(24))))
    for i in range(16):
        il.append(il.set_reg(4, 'a'+str(i), il.reg_stack_top_relative(4, 'physical_ar', index(il.reg(4, 'windowbase'), i))))
