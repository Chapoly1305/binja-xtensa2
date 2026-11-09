"""Differential execution of baseline vs shared overflow tails at two PCs."""
import importlib,json,sys
from pathlib import Path
from types import SimpleNamespace
import binaryninja as bn
from semantic_probe import evaluate,regname
bn.set_worker_thread_count(2);arch=bn.Architecture['xtensa']
plugin=next(m for n,m in sys.modules.items() if n.endswith('.binja_xtensa') and hasattr(m,'XtensaLE'))
tail_module=importlib.import_module(plugin.__name__+'.window_tail_workflow')
transform=tail_module.transform
view=bn.BinaryView.new(bytes.fromhex('0df0'));view.platform=arch.standalone_platform
view.create_user_function(0);view.update_analysis_and_wait();f=view.get_function_at(0)
lifter=importlib.import_module(plugin.__name__+'.lifter')
baseline={'__package__':plugin.__name__}
exec(Path('/port/baseline_window_exceptions.txt').read_text(),baseline)
optimized=lifter.window_check
def build(check):
 il=bn.LowLevelILFunction(arch,source_func=f)
 assert il.get_label_for_address(arch,0x100000000) is None
 lifter.window_check=check
 try:
  for pc,data in [(0x40000000,'402380'),(0x40000003,'c02380')]:
   il.set_current_address(pc)
   assert arch.get_instruction_low_level_il(bytes.fromhex(data),pc,il)==3
  il.append(il.ret(il.const_pointer(4,0x40000006)));il.finalize()
 finally:lifter.window_check=optimized
 return il
source=build(baseline['window_check']);dest=build(optimized)
assert len(dest)<len(source)*0.8,(len(source),len(dest))
# A second fresh IL must define its own tail rather than reuse another function.
independent=build(optimized)
assert len(independent)==len(dest)
def reachable(il):
 seen=set();todo=[0]
 while todo:
  i=todo.pop()
  if i in seen:continue
  seen.add(i);ins=il[i];op=ins.operation.name
  if op=='LLIL_IF':todo.extend([int(ins.true),int(ins.false)])
  elif op=='LLIL_GOTO':todo.append(int(ins.dest))
  elif op not in ('LLIL_RET','LLIL_JUMP'):todo.append(i+1)
 return len(seen)
assert reachable(dest)<reachable(source)*0.8,(reachable(source),reachable(dest))
def execute(il,state):
 pc=0
 for _ in range(2000):
  ins=il[pc];op=ins.operation.name
  if op=='LLIL_SET_REG':state[regname(ins.dest)]=evaluate(ins.src,state)
  elif op=='LLIL_IF':pc=int(ins.true if evaluate(ins.condition,state) else ins.false);continue
  elif op=='LLIL_GOTO':pc=int(ins.dest);continue
  elif op in ('LLIL_JUMP','LLIL_RET'):return op,evaluate(ins.dest,state),state
  elif op!='LLIL_NOP':raise AssertionError(str(ins))
  pc+=1
 raise AssertionError('Non-terminating IL')
rows=[];fault_pcs=set()
for wb in range(16):
 for occupied in range(8):
  for ps in [0,0x40000,0x40010]:
   state={f'ar{i}':0x100000+i for i in range(64)}
   state.update({f'a{i}':0x200000+i for i in range(16)})
   ws=1<<wb
   for d in range(1,4):
    if occupied&(1<<(d-1)):ws|=1<<((wb+d)%16)
   state.update(ps=ps,windowbase=wb,windowstart=ws)
   state.update({f'windowoverflow{x}':0x50000000+x for x in [4,8,12]})
   before=execute(source,dict(state));after=execute(dest,dict(state))
   assert after==execute(independent,dict(state))
   assert before==after,(wb,occupied,ps,before,after)
   if before[0]=='LLIL_JUMP':fault_pcs.add(before[2]['epc1'])
   rows.append(dict(window=wb,occupied=occupied,ps=ps,transfer=before[:2]))
assert fault_pcs=={0x40000000,0x40000003},fault_pcs
Path('/port/core_label_results.json').write_text(json.dumps({'copied_before':len(source),'copied_after':len(dest),'independent_il_instructions':len(independent),'cases':rows,'reachable_before':reachable(source),'reachable_after':reachable(dest),'fault_pcs':sorted(fault_pcs)},indent=2)+'\n')
print('PASS:',len(rows),'baseline/transformed state comparisons;',reachable(source),'->',reachable(dest),'reachable instructions')
view.file.close()
