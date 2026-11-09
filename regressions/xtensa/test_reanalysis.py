"""Native WARP smoke on real esp_random bytes, not corpus recognition metrics."""
import hashlib,importlib,json,sys
from pathlib import Path
import binaryninja as bn
from binaryninja import warp
arch=bn.Architecture['xtensa'];bn.set_worker_thread_count(2)
plugin=next(m for n,m in sys.modules.items() if n.endswith('.binja_xtensa') and hasattr(m,'XtensaLE'))
workflow=sys.modules[plugin.__name__+'.loop_workflow']  # Must register through exported plugin entrypoint.
root=Path('/port/reanalysis_probe');start=0x4008513c
plugin_root=Path('/port/plugin')
def plugin_hashes():
    return {str(p.relative_to(plugin_root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(plugin_root.rglob('*.py'))}
plugin_provenance=plugin_hashes()
options={'analysis.linearSweep.controlFlowGraph':False,'analysis.mode':'full','analysis.debugInfo.internal':False,'arch.xtensa.windowVectorProfile':'esp32-esp32s3','analysis.workflows.functionWorkflow':workflow.NAME}
reference=bn.load(str(root/'reference.elf'),options=options)
f=reference.get_function_at(start);assert f is not None
assert f.symbol.raw_name=='esp_random'
reference_guid=str(warp.get_function_guid(f))
for reanalysis_round in range(3):
    f.reanalyze()
    reference.update_analysis_and_wait()
    f=reference.get_function_at(start)
    assert str(warp.get_function_guid(f))==reference_guid
    assert f.llil is not None and f.mlil is not None
    print('Reanalysis GUID stable:',reanalysis_round,reference_guid,flush=True)
processor=warp.WarpProcessor(worker_count=1)
processor.add_binary_view(reference);artifact=processor.start()
output=root/'reference.warp';output.write_bytes(bytes(artifact.to_data_buffer()))
reopened=warp.WarpFile(str(output));functions=sum(len(c.functions) for c in reopened.chunks)
assert functions>0
container=warp.WarpContainer.add('xtensa_port_native_probe')
assert container.add_source(str(output)) is not None
rows=[]
for iteration in range(3):
    view=bn.load(str(root/'target.elf'),options=options)
    target=view.get_function_at(start)
    discovered=target is not None
    if target is None:
        view.create_user_function(start)
        view.update_analysis_and_wait()
        target=view.get_function_at(start)
    assert target is not None
    assert view.read(start,58)==reference.read(start,58)
    before=str(warp.get_function_guid(target))
    warp.run_matcher(view);view.update_analysis_and_wait()
    matched=warp.WarpFunction.get_matched(target) is not None
    row={'iteration':iteration,'automatically_discovered':discovered,'boundary_seeded':not discovered,'target_guid':before,'matched':matched,'name':target.symbol.raw_name}
    print(json.dumps(row),flush=True);rows.append(row)
    assert before==reference_guid
    assert matched and target.symbol.raw_name=='esp_random'
    view.file.close()
assert plugin_hashes()==plugin_provenance, 'Plugin sources changed during validation'
result={'plugin_sha256':plugin_provenance,'workflow':workflow.NAME,'analysis_options':options,'core':bn.core_version(),'reference_guid':reference_guid,'warp_functions':functions,'warp_bytes':output.stat().st_size,'reanalyzed_reference_rounds':3,'rounds':rows,'inputs':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in [root/'reference.elf',root/'target.elf']},'scope':'One extracted real firmware function including ENTRY/CALL8/RETW; stripped same-byte roundtrip with a seeded function start if not discovered; not cross-build recognition or DCL accuracy.'}
(root/'native_warp_results.json').write_text(json.dumps(result,indent=2)+'\n')
print('PASS: native WARP export/reload and three independent target views')
