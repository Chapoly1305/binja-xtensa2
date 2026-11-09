"""Run the current native regression suite with immutable-source evidence.

Invoke with run_bn.sh run_regressions.py. Expected-failing compact bank prototype
is excluded; its rejection evidence remains in compact_full_results.json.
"""
import hashlib,json,subprocess,time
from pathlib import Path
ROOT=Path('/port')
TESTS=['test_loop_ordinary_overflow.py','test_loop_shared_tail.py','test_reanalysis.py','test_mac16_compound.py','test_mac16_overflow.py','test_mac16_arithmetic.py','test_acchi_access.py','test_mac16_loads.py','test_core_label.py','test_ssai.py','semantic_probe.py','test_general_window.py','test_window_memory.py','test_call_windows.py',
       'test_window_state.py','test_rotw.py','test_exception_banks.py',
       'test_entry_overflow.py','test_retw_underflow.py','test_loop_execution.py',
       'test_branch_loop.py','test_loop_overflow.py','test_dynamic_loop.py','test_cache_tags.py',
       'test_external_registers.py','test_exception_returns.py','test_general_exception.py','test_exception_native.py','test_movsp.py',
       'test_intrinsic_contracts.py','test_normalization.py',
       'test_vector_profile.py','test_depc_profile.py','test_vector_runtime.py','test_explicit_full.py',
       'test_native_warp.py']
TESTS=list(dict.fromkeys(['test_trunc.py','test_unsigned_float.py','test_loop_execution.py','test_dynamic_loop.py','test_loop_ordinary_overflow.py','test_loop_shared_tail.py','test_branch_loop.py','test_loop_overflow.py']+TESTS))
TESTS=list(dict.fromkeys(['test_vector_profile.py','test_depc_profile.py','test_vector_runtime.py','test_reanalysis.py']+TESTS))
TESTS=['test_salt.py']+TESTS
TESTS=['test_invalid_mac.py','test_elf_entry_guards.py']+TESTS
def hashes():
    paths=sorted((ROOT/'plugin').rglob('*.py'))+[ROOT/t for t in TESTS]+[ROOT/'warp_probe/reference.elf',ROOT/'warp_probe/target.elf',ROOT/'reanalysis_probe/reference.elf',ROOT/'reanalysis_probe/target.elf',ROOT/'salt.dump',ROOT/'salt.S',ROOT/'trunc.dump',ROOT/'unsigned.dump',ROOT/'baseline_window_exceptions.txt',ROOT/'mac16_loads.dump',ROOT/'mac16_arithmetic.dump',ROOT/'mac16_compound.dump']
    return {str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
expected=hashes()
run=ROOT/'regressions'/time.strftime('%Y%m%dT%H%M%SZ',time.gmtime())
run.mkdir(parents=True,exist_ok=False)
report={'source_sha256':expected,'tests':[],'complete':False,'scope':'Targeted semantics/native analysis/WARP roundtrip; not DCL recognition accuracy.'}
def save():
    temporary=run/'manifest.tmp'
    temporary.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    temporary.replace(run/'manifest.json')
save()
for test in TESTS:
    assert hashes()==expected,'Sources changed during regression run'
    begin=time.monotonic()
    with (run/(test+'.log')).open('w',encoding='utf-8') as log:
        result=subprocess.run(['/opt/binaryninja/bnpython3',str(ROOT/test)],stdout=log,stderr=subprocess.STDOUT)
    row={'test':test,'exit_code':result.returncode,'seconds':round(time.monotonic()-begin,3)}
    if test=='semantic_probe.py' and result.returncode==0:
        probe=json.loads((ROOT/'semantic_probe_results.json').read_text())
        row['all_isa_expectations_pass']=all(x.get('matches_isa_expectation') is True for x in probe)
    report['tests'].append(row);save();print(json.dumps(row),flush=True)
    assert result.returncode==0 and row.get('all_isa_expectations_pass',True),row
assert hashes()==expected,'Sources changed during regression run'
report['complete']=True;save()
print('PASS: full targeted suite; manifest',run/'manifest.json',flush=True)
