import json,math,re,struct
from pathlib import Path
import binaryninja as bn
arch=bn.Architecture['xtensa'];bn.set_worker_thread_count(2)
def f32(x):
 try:return struct.unpack('<f',struct.pack('<f',x))[0]
 except OverflowError:return math.copysign(math.inf,x)
def evaluate(x,state):
 op=x.operation.name
 if op=='LLIL_REG':return state[str(x.src)]
 if op in ('LLIL_CONST','LLIL_CONST_PTR','LLIL_FLOAT_CONST'):return x.constant
 if op=='LLIL_LOW_PART':return evaluate(x.src,state)&((1<<(8*x.size))-1)
 if op=='LLIL_FMUL':return f32(evaluate(x.left,state)*evaluate(x.right,state))
 if op=='LLIL_OR':return int(evaluate(x.left,state))|int(evaluate(x.right,state))
 if op=='LLIL_FCMP_UO':return math.isnan(evaluate(x.left,state)) or math.isnan(evaluate(x.right,state))
 if op=='LLIL_FCMP_GE':return evaluate(x.left,state)>=evaluate(x.right,state)
 if op=='LLIL_FCMP_LE':return evaluate(x.left,state)<=evaluate(x.right,state)
 if op=='LLIL_FTRUNC':
  value=math.trunc(evaluate(x.src,state));assert -(1<<(8*x.size-1))<=value<(1<<(8*x.size-1))
  return value
 raise AssertionError(str(x))
def execute(il,value):
 state={'f3':value};pc=0
 for _ in range(100):
  x=il[pc];op=x.operation.name
  if op=='LLIL_SET_REG':state[str(x.dest)]=evaluate(x.src,state)
  elif op=='LLIL_IF':pc=int(x.true if evaluate(x.condition,state) else x.false);continue
  elif op=='LLIL_GOTO':pc=int(x.dest);continue
  elif op=='LLIL_RET':return state['a2']
  elif op!='LLIL_NOP':raise AssertionError(str(x))
  pc+=1
 raise AssertionError('nonterminating conversion')
view=bn.BinaryView.new(bytes.fromhex('0df0'));view.platform=arch.standalone_platform
view.create_user_function(0);view.update_analysis_and_wait();function=view.get_function_at(0)
inputs=[-math.inf,-2.0**40,-2147483648.,-2147483520.,-2.9,-0.1,-0.,0.,0.5,2.9,2147483648.,4294967040.,4294967296.,2.0**40,math.inf,math.nan]
rows=[];native_count=0
for line in Path('/port/trunc.dump').read_text().splitlines():
 m=re.search(r':\s+([0-9a-f]{6})\s+(u?trunc)\.s\s+a2, f3, (\d+)',line)
 if not m:continue
 encoded,mnemonic,scale=m.groups();scale=int(scale);data=bytes.fromhex(encoded)[::-1]
 il=bn.LowLevelILFunction(arch,source_func=function)
 assert arch.get_instruction_low_level_il(data,0,il)==3
 il.append(il.ret(il.const_pointer(4,0x100)));il.finalize()
 upper=(1<<32)-1 if mnemonic=='utrunc' else (1<<31)-1
 for value in inputs:
  value=f32(value);scaled=f32(value*2.0**scale)
  if math.isnan(scaled) or scaled>=upper+1:expected=upper
  elif scaled<=-2147483648:expected=0x80000000
  else:expected=math.trunc(scaled)&0xffffffff
  actual=execute(il,value)
  assert actual==expected,(mnemonic,scale,value,expected,actual)
  rows.append(dict(mnemonic=mnemonic,scale=scale,input=repr(value),expected=expected,actual=actual))
 if scale in (0,15):
  native=bn.BinaryView.new(data+bytes.fromhex('0df0'));native.platform=arch.standalone_platform
  native.create_user_function(0);native.update_analysis_and_wait();f=native.get_function_at(0)
  for level in (f.llil,f.llil.ssa_form,f.mlil,f.mlil.ssa_form):
   assert level is not None and not any(i.operation.name.endswith('UNIMPL') for i in level.instructions)
  native_count+=1;native.file.close()
assert len(rows)==512 and native_count==4
Path('/port/trunc_results.json').write_text(json.dumps({'cases':rows,'native_functions':native_count,'scope':'Value/saturation paths only; FSR flags and coprocessor exceptions not covered'},indent=2)+'\n')
print('PASS: 512 TRUNC/UTRUNC scaling, saturation, NaN/infinity cases and four native functions')
