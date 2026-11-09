import json
from pathlib import Path
import binaryninja as bn
from semantic_probe import evaluate,regname
arch=bn.Architecture['xtensa'];rows=[]
for opcode,data in [('RFWO','003400'),('RFWU','003500')]:
    il=bn.LowLevelILFunction(arch)
    assert arch.get_instruction_low_level_il(bytes.fromhex(data),0x40000000,il)==3
    il.finalize();instructions=[il[i] for i in range(len(il))]
    for current in range(16):
        for old in range(16):
            state={f'ar{i}':0x100000+i for i in range(64)}
            state.update({f'a{i}':0x200000+i for i in range(16)})
            state.update(ps=0x60010|(old<<8),windowbase=current,windowstart=0x5555,epc1=0x40001000)
            expected=[state[f'ar{i}'] for i in range(64)]
            for i in range(16):expected[(current*4+i)%64]=state[f'a{i}']
            pc=0;returned=False
            for steps in range(500):
                x=instructions[pc];op=x.operation.name
                if op=='LLIL_SET_REG':state[regname(x.dest)]=evaluate(x.src,state)
                elif op=='LLIL_IF':pc=int(x.true if evaluate(x.condition,state) else x.false);continue
                elif op=='LLIL_GOTO':pc=int(x.dest);continue
                elif op=='LLIL_RET':assert evaluate(x.dest,state)==0x40001000;returned=True;break
                elif op=='LLIL_NOP':pass
                else:raise AssertionError(op)
                pc+=1
            assert returned
            assert state['ps']==0x60000|(old<<8)
            assert state['windowbase']==old
            expected_ws=(0x5555|(1<<current)) if opcode=='RFWU' else (0x5555&~(1<<current))
            assert state['windowstart']==expected_ws
            assert all(state[f'ar{i}']==expected[i] for i in range(64))
            assert all(state[f'a{i}']==expected[(old*4+i)%64] for i in range(16))
            rows.append({'opcode':opcode,'current_window':current,'restored_window':old,'passed':True})
Path('/port/exception_bank_results.json').write_text(json.dumps(rows,indent=2)+'\n')
print('PASS: 512 native LLIL window exception return bank/state cases')
