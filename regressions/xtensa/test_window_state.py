import json
from pathlib import Path
import binaryninja as bn
from semantic_probe import evaluate,regname
arch=bn.Architecture['xtensa'];rows=[]
assert all(arch.regs[r].size==4 for r in ['ps','windowbase','windowstart','litbase'])
def execute(data,state,address=0x40000000):
    il=bn.LowLevelILFunction(arch)
    arch.get_instruction_low_level_il(bytes.fromhex(data),address,il);il.finalize()
    pc=0
    for steps in range(1000):
        x=il[pc];op=x.operation.name
        if op=='LLIL_SET_REG':state[regname(x.dest)]=evaluate(x.src,state)
        elif op=='LLIL_IF':pc=int(x.true if evaluate(x.condition,state) else x.false);continue
        elif op=='LLIL_GOTO':pc=int(x.dest);continue
        elif op=='LLIL_NOP':pass
        elif op=='LLIL_RET':state['return_pc']=evaluate(x.dest,state);break
        else:raise AssertionError(str(x))
        pc+=1
        if pc==len(il):break
    else:raise AssertionError('execution limit exceeded')
    return state
for wb in [0,7,15]:
    for inc in [1,2,3]:
        state={'a1':0x1000,'a0':(inc<<30)|0x1234,'ps':0x40000|(inc<<16),'windowbase':wb,'windowstart':1<<wb}
        execute('364100',state)
        new=(wb+inc)&15
        assert state['a1']==0xfe0 and state['windowbase']==new
        assert state['windowstart']==(1<<wb)|(1<<new)
        execute('1df0',state)
        assert state['return_pc']==0x40001234 and state['windowbase']==wb and state['windowstart']==1<<wb
        rows.append({'kind':'entry_return_bookkeeping','wb':wb,'increment':inc,'passed':True})
for op,data in [('RFWO','003400'),('RFWU','003500')]:
    for wb in [0,7,15]:
        for old in [0,8,15]:
            state={'ps':0x60010|(old<<8),'windowbase':wb,'windowstart':0x5555,'epc1':0x40004567}
            execute(data,state)
            assert state['ps']==0x60000|(old<<8)
            assert state['windowbase']==old and state['return_pc']==0x40004567
            expected=(0x5555|(1<<wb)) if op=='RFWU' else (0x5555&~(1<<wb))
            assert state['windowstart']==expected
            rows.append({'kind':op,'wb':wb,'old_wb':old,'passed':True})
Path('/port/window_state_results.json').write_text(json.dumps(rows,indent=2)+'\n')
print('PASS: 27 window-state bookkeeping cases; physical bank/exception dispatch not covered')
