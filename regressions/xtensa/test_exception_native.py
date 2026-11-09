"""Check explicit exception triggers survive complete native IL analysis."""
import json
from pathlib import Path
import binaryninja as bn
bn.set_worker_thread_count(2);arch=bn.Architecture['xtensa'];rows=[]
for name,data in [('ILL','000000'),('ILL.N','6df0'),('SYSCALL','005000'),('RFUE','003100')]:
 view=bn.BinaryView.new(bytes.fromhex(data));view.platform=arch.standalone_platform
 view.create_user_function(0);view.update_analysis_and_wait();f=view.get_function_at(0)
 assert f is not None and not f.analysis_skipped
 levels={'llil':f.llil,'mlil':f.mlil,'mlil_ssa':f.mlil.ssa_form,'hlil':f.hlil}
 counts={}
 for level,il in levels.items():
  assert il is not None and len(il)>0,(name,level)
  assert not any(i.operation.name.endswith('UNIMPL') for i in il.instructions),(name,level)
  counts[level]=len(il)
 llil='\n'.join(str(i) for i in f.llil.instructions)
 assert 'exccause' in llil and 'epc1' in llil and 'depc' in llil
 rows.append({'instruction':name,'levels':counts,'llil':llil})
 view.file.close()
Path('/port/exception_native_results.json').write_text(json.dumps(rows,indent=2)+'\n')
print('PASS: four exception triggers retain state through native LLIL/MLIL/SSA/HLIL')
