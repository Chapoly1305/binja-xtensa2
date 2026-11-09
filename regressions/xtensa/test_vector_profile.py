"""Full native workflow checks for generic and ESP32/S3 vector inputs."""
import importlib,json,sys
from pathlib import Path
import binaryninja as bn
bn.set_worker_thread_count(2)
a=bn.Architecture['xtensa']
p=next(m for n,m in sys.modules.items() if n.endswith('.binja_xtensa') and hasattr(m,'XtensaLE'))
w=importlib.import_module(p.__name__+'.loop_workflow')
v=importlib.import_module(p.__name__+'.vector_profile')
rows=[]
for profile in ['generic','esp32-esp32s3']:
    for label,code in [('entry','3641000df0'),('retw','1df0'),('movsp','1012000df0')]:
        view=bn.BinaryView.new(bytes.fromhex(code));view.platform=a.standalone_platform
        assert bn.Settings().set_string('analysis.workflows.functionWorkflow',w.NAME,view)
        assert bn.Settings().set_string(v.KEY,profile,view)
        view.add_function(0);view.update_analysis_and_wait()
        f=view.get_function_at(0);assert f is not None
        jumps=[i for i in f.llil.instructions if i.operation.name=='LLIL_JUMP']
        texts=[str(i.dest) for i in jumps]
        if profile=='generic':
            assert any('window' in x or 'exception' in x for x in texts),texts
        else:
            assert any('vecbase' in x for x in texts),texts
            assert not any('windowoverflow' in x or 'windowunderflow' in x or 'exception' in x for x in texts),texts
        assert f.mlil.ssa_form is not None and f.hlil is not None
        rows.append({'profile':profile,'instruction':label,'jump_destinations':texts})
        view.file.close()
Path('/port/vector_profile_results.json').write_text(json.dumps(rows,indent=2)+'\n',encoding='utf-8')
print('PASS: six full native generic/profiled window vector cases')
