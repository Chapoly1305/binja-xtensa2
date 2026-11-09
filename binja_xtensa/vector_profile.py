"""Explicit ESP32/S3 window vector layout, relative to runtime VECBASE.

Offsets are verified against all six retained references. The default leaves
configurable Xtensa vector inputs unresolved; absolute firmware bases are never
inferred from reference symbols.
"""
import json
from binaryninja import LowLevelILFunction, Settings
KEY = 'arch.xtensa.windowVectorProfile'
DEPC_KEY = 'arch.xtensa.depcPresence'
OFFSETS = {'windowoverflow4':0, 'windowunderflow4':64,
           'windowoverflow8':128, 'windowunderflow8':192,
           'windowoverflow12':256, 'windowunderflow12':320,
           'kernelexception':768, 'userexception':832, 'doubleexception':960}
settings = Settings()
settings.register_group('arch', 'Architecture')
settings.register_setting(KEY, json.dumps({'title':'Xtensa window vector layout',
    'description':'Explicit ESP32/S3 layout relative to runtime VECBASE; generic leaves vectors unresolved.',
    'type':'string', 'default':'generic', 'enum':['generic','esp32-esp32s3']}))

settings.register_setting(DEPC_KEY, json.dumps({'title':'Xtensa DEPC configuration',
    'description':'Explicit optional DEPC presence; unknown preserves both architectural paths.',
    'type':'string', 'default':'unknown', 'enum':['unknown','present','absent']}))

def transform(context):
    source, function = context.lifted_il, context.function
    if source is None or function.arch.name != 'xtensa':
        return
    bind_vectors = settings.get_string(KEY, context.view) == 'esp32-esp32s3'
    depc = settings.get_string(DEPC_KEY, context.view)
    if not bind_vectors and depc == 'unknown':
        return
    # Workflow-local mutation preserves instruction indices, labels and CFG.
    # Snapshot the expression count: replacements append new expressions.
    replacements = []
    vectors = {function.arch.get_reg_index(name): offset for name, offset in OFFSETS.items()} if bind_vectors else {}
    depc_index = function.arch.get_reg_index("config_ndepc") if depc != "unknown" else None
    for index in range(source.get_expr_count()):
        expression = source.get_expr(index)
        if expression is None or expression.operation.name != 'LLIL_REG':
            continue
        register = expression.src.index
        if register == depc_index:
            replacements.append((expression, source.const(1, 1 if depc == 'present' else 0)))
        elif register in vectors:
            replacements.append((expression, source.add(4, source.reg(4, 'vecbase'), source.const(4, vectors[register]))))
    for original, replacement in replacements:
        source.replace_expr(original, replacement)
    if replacements:
        source.finalize()
        context.lifted_il = source
