import json
from pathlib import Path
import binaryninja as bn
from semantic_probe import evaluate,regname
arch=bn.Architecture['xtensa'];rows=[]
for encoded in range(16):
    delta=encoded if encoded<8 else encoded-16
    data=bytes([encoded<<4,0x80,0x40])
    il=bn.LowLevelILFunction(arch)
    assert arch.get_instruction_low_level_il(data,0x40000000,il)==3
    il.append(il.ret(il.const_pointer(4, 0x40000100)))
    il.finalize();instructions=[il[i] for i in range(len(il))]
    for wb in range(16):
        bank=[0x100000+i for i in range(64)]
        logical=[0x200000+i for i in range(16)]
        state={f'ar{i}':value for i,value in enumerate(bank)}
        state.update({f'a{i}':value for i,value in enumerate(logical)})
        state['windowbase']=wb
        expected=list(bank)
        for i,value in enumerate(logical):expected[(wb*4+i)%64]=value
        new=(wb+delta)%16
        pc=0
        for steps in range(500):
            if pc==len(instructions):break
            x=instructions[pc];op=x.operation.name
            if op=='LLIL_SET_REG':state[regname(x.dest)]=evaluate(x.src,state)
            elif op=='LLIL_IF':pc=int(x.true if evaluate(x.condition,state) else x.false);continue
            elif op=='LLIL_GOTO':pc=int(x.dest);continue
            elif op=='LLIL_NOP':pass
            elif op=='LLIL_RET':pc=len(instructions);break
            else:raise AssertionError(op)
            pc+=1
        assert pc==len(instructions),(delta,wb,pc,len(instructions),[(i,str(x)) for i,x in enumerate(instructions) if i<3 or i>len(instructions)-5])
        assert state['windowbase']==new
        assert all(state[f'ar{i}']==expected[i] for i in range(64))
        assert all(state[f'a{i}']==expected[(new*4+i)%64] for i in range(16))
        rows.append({'window':wb,'delta':delta,'new_window':new,'passed':True})
Path('/port/rotw_results.json').write_text(json.dumps(rows,indent=2)+'\n')
print('PASS: 256 native LLIL ROTW cases, all windows and signed immediates')
