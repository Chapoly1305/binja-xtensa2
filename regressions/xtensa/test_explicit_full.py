"""Exercise candidate compact banking through native BN analysis and WARP."""
import importlib,json,sys,time
from pathlib import Path
import binaryninja as bn
from binaryninja import warp


def run_case(arch,name,data):
    begin=time.monotonic()
    view=bn.BinaryView.new(bytes.fromhex(data));view.platform=arch.standalone_platform
    f=processor=artifact=il=None
    try:
        view.create_user_function(0);view.update_analysis_and_wait()
        f=view.get_function_at(0);assert f is not None
        assert f.llil is not None and f.mlil is not None and f.hlil is not None
        for il in [f.llil,f.llil.ssa_form,f.mlil,f.mlil.ssa_form]:
            assert len(il)>0
            print(name, type(il).__name__, 'unimplemented', [str(i) for i in il.instructions if i.operation.name.endswith('UNIMPL')],flush=True)
        view.define_user_symbol(bn.Symbol(bn.SymbolType.FunctionSymbol,0,'probe_'+name))
        processor=warp.WarpProcessor(worker_count=1);processor.add_binary_view(view);artifact=processor.start()
        count=sum(len(c.functions) for c in artifact.chunks)
        assert count>0
        row={'function':name,'seconds':round(time.monotonic()-begin,3),'llil_instructions':len(f.llil),'mlil_instructions':len(f.mlil),'warp_functions':count,'unimplemented':{type(level).__name__+str(index):sum(i.operation.name.endswith('UNIMPL') for i in level.instructions) for index,level in enumerate([f.llil,f.llil.ssa_form,f.mlil,f.mlil.ssa_form])},'guid':str(warp.get_function_guid(f)),'mlil':[str(i) for i in f.mlil.instructions]}
        print(json.dumps({k:v for k,v in row.items() if k!='mlil'}),flush=True)
        return row
    finally:
        # Release native WARP/IL references while the Python APIs are still alive.
        artifact=processor=f=il=None
        view.file.close()


def main():
    arch=bn.Architecture['xtensa'];bn.set_worker_thread_count(2)
    plugin=next(m for n,m in sys.modules.items() if n.endswith('.binja_xtensa') and hasattr(m,'XtensaLE'))
    lifter=importlib.import_module(plugin.__name__+'.lifter')
    banks=importlib.import_module(plugin.__name__+'.window_bank')
    lifter.rotate_bank=banks.rotate_bank
    rows=[run_case(arch,name,data) for name,data in [('rotw_return','1080400df0'),('rfwo','003400'),('rfwu','003500')]]
    Path('/port/explicit_full_results.json').write_text(json.dumps(rows,indent=2)+'\n')
    assert not any(any(row['unimplemented'].values()) for row in rows), 'Native analysis loses register-stack semantics'


if __name__=='__main__':main()
