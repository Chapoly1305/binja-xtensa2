"""Exception Option 2 state transitions (ISA section 4.4.1.10).

Vector addresses and optional DEPC presence are explicit configuration inputs.
"""
from binaryninja import LowLevelILLabel

def raise_exception(il, cause, address):
    double, normal, use_depc, use_epc = [LowLevelILLabel() for _ in range(4)]
    user, kernel = LowLevelILLabel(), LowLevelILLabel()
    il.append(il.if_expr(il.test_bit(4, il.reg(4, 'ps'), il.const(4, 4)), double, normal))
    il.mark_label(double)
    il.append(il.if_expr(il.compare_not_equal(1, il.reg(1, 'config_ndepc'), il.const(1, 0)), use_depc, use_epc))
    for label, register in [(use_depc,'depc'), (use_epc,'epc1')]:
        il.mark_label(label)
        il.append(il.set_reg(4, register, il.const_pointer(4, address)))
        finish(il, cause, 'doubleexception')
    il.mark_label(normal)
    il.append(il.set_reg(4, 'epc1', il.const_pointer(4, address)))
    il.append(il.if_expr(il.test_bit(4, il.reg(4, 'ps'), il.const(4, 5)), user, kernel))
    for label, vector in [(user,'userexception'), (kernel,'kernelexception')]:
        il.mark_label(label)
        finish(il, cause, vector)

def finish(il, cause, vector):
    il.append(il.set_reg(1, 'exccause', il.const(1, cause)))
    il.append(il.set_reg(4, 'ps', il.or_expr(4, il.reg(4, 'ps'), il.const(4, 16))))
    il.append(il.jump(il.reg(4, vector)))

def double_return(il):
    present, absent = LowLevelILLabel(), LowLevelILLabel()
    il.append(il.if_expr(il.compare_not_equal(1, il.reg(1, 'config_ndepc'), il.const(1, 0)), present, absent))
    il.mark_label(present);il.append(il.ret(il.reg(4, 'depc')))
    il.mark_label(absent);il.append(il.ret(il.reg(4, 'epc1')))
