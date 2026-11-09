import json
from pathlib import Path
import binaryninja as bn
from semantic_probe import evaluate,regname
arch=bn.Architecture['xtensa'];rows=[]
for n in [4,8,12]:
    for source in [None,0,1,3,8,15]:
        data=(bytes([5 | ((n//4)<<4),0,0]) if source is None else bytes([0xc0|((n//4)<<4),source,0]))
        il=bn.LowLevelILFunction(arch)
        assert arch.get_instruction_low_level_il(data,0x40000000,il)==3
        il.finalize();state={f'a{i}':0x40001000+i*0x100 for i in range(16)};state['ps']=0x5a040a23;initial=dict(state);called=False
        pc=0
        for step in range(2000):
            if pc>=len(il): break
            x=il[pc];pc+=1
            op=x.operation.name
            if op=='LLIL_IF':
                pc=int(x.true if evaluate(x.condition,state) else x.false);continue
            if op=='LLIL_GOTO':
                pc=int(x.dest);continue
            if op=='LLIL_NOP':continue
            if op=='LLIL_SET_REG':
                state[regname(x.dest)]=evaluate(x.src,state)
                if regname(x.dest) not in ('temp16','ps'):
                    assert bn.ILInstructionAttribute.ILTransparentCopy in x.attributes
            elif op=='LLIL_CALL':
                assert state['ps']==((initial['ps']&0xfffcffff)|((n//4)<<16))
                assert evaluate(x.dest,state)==(0x40000004 if source is None else initial[f'a{source}'])
                assert state['a1']==initial['a1']
                assert all(state[f'a{i}']==initial[f'a{i+n}'] for i in range(16-n) if i!=1)
                # Callee return state with distinct values exposes copy overlap.
                state.update({f'a{i}':0xabc000+i for i in range(16)});called=True
            else:raise AssertionError(op)
        assert called
        assert all(state[f'a{i}']==initial[f'a{i}'] for i in range(n))
        assert all(state[f'a{i+n}']==0xabc000+i for i in range(16-n))
        rows.append({'window':n,'target_register':source,'bytes':data.hex(),'passed':True})
Path('/port/call_window_results.json').write_text(json.dumps(rows,indent=2)+'\n')
print('PASS: 18 native LLIL window-call mappings and return restorations')
