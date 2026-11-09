"""Guard evidence for metadata-derived entry registration, without scanning."""
import importlib.util,json
from pathlib import Path
from types import SimpleNamespace as NS
root=Path('/port');spec=importlib.util.spec_from_file_location('entry_helper',root/'plugin/binja_xtensa/elf_entry.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
fixture=root/'entry_guard_fixtures';fixture.mkdir(exist_ok=True)
header=(root/'warp_probe/target.elf').read_bytes()[:52];entry=int.from_bytes(header[24:28],'little');rows=[]
def run(label,data=None,segment=None,database=False,arch='xtensa',view_type='ELF',registered=False):
 source=fixture/(label+'.elf');source.write_bytes(header if data is None else data);calls=[]
 view=NS(file=NS(has_database=database),arch=NS(name=arch),view_type=view_type,entry_functions=[NS(start=entry)] if registered else [],add_entry_point=calls.append,get_segment_at=lambda _:segment)
 result=module.initialize_elf_entry(view,source);rows.append({'case':label,'result':result,'calls':calls});return result,calls
valid=NS(start=entry,executable=True,data_length=58)
assert run('valid',segment=valid)[1]==[entry]
assert run('already_registered',segment=valid,registered=True)[1]==[]
assert run('database_preserved',segment=valid,database=True)[0]['status']=='preserved_database'
assert run('wrong_architecture',segment=valid,arch='arm')[1]==[]
assert run('raw_view',segment=valid,view_type='Raw')[1]==[]
assert run('short_header',data=header[:20],segment=valid)[1]==[]
assert run('wrong_magic',data=b'BAD!'+header[4:],segment=valid)[1]==[]
for label,offset,value in [('relocatable',16,1),('wrong_machine',18,40)]:
 altered=bytearray(header);altered[offset:offset+2]=value.to_bytes(2,'little');assert run(label,data=altered,segment=valid)[1]==[]
assert run('unmapped')[1]==[]
assert run('nonexecutable',segment=NS(start=entry,executable=False,data_length=58))[1]==[]
assert run('bss_only',segment=NS(start=entry,executable=True,data_length=0))[1]==[]
assert run('at_file_backed_end',segment=NS(start=entry-58,executable=True,data_length=58))[1]==[]
zero=bytearray(header);zero[24:28]=b'\0'*4
assert run('valid_zero_address',data=zero,segment=NS(start=0,executable=True,data_length=58))[1]==[0]
(root/'entry_guard_results.json').write_text(json.dumps(rows,indent=2)+'\n')
print('PASS:',len(rows),'ELF entry registration guards')
