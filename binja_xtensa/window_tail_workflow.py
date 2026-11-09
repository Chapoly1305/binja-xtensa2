"""Experimental sharing of generated, terminal WindowCheck overflow tails.

Each source instruction retains its own PS/EPC update. Only the following
identical terminal transition, parameterized by temp25, is shared. This is not
an arbitrary CFG optimizer and does not alter ROTW or underflow transitions.
"""
from binaryninja import LowLevelILFunction,LowLevelILLabel,LLIL_TEMP
from .window_bank import rotate_bank
from .window_exceptions import window_bit

def _discarded_tail_blocks(source, blocks, sites):
 """Remove only closed generated overflow regions, never general dead code.

 A candidate must retain one faulting machine address, terminate only at the
 known overflow vector registers, and have no incoming edge from retained IL
 other than its own cut block. Unknown shapes are copied unchanged.
 """
 discarded=set()
 for cut in blocks:
  matched=sites.intersection(range(cut.start,cut.end))
  if not matched:continue
  address=source[min(matched)].address
  region={};pending=[edge.target for edge in cut.outgoing_edges]
  valid=True
  while pending:
   block=pending.pop()
   if block.start in region:continue
   if block.start==cut.start:
    valid=False;break
   region[block.start]=block
   if any(source[i].address!=address for i in range(block.start,block.end)):
    valid=False;break
   edges=list(block.outgoing_edges)
   if edges:
    pending.extend(edge.target for edge in edges)
   else:
    last=source[block.end-1]
    if (last.operation.name!='LLIL_JUMP' or last.dest.operation.name!='LLIL_REG'
        or str(last.dest.src) not in ('windowoverflow4','windowoverflow8','windowoverflow12')):
     valid=False;break
  if valid and all(edge.source.start in region or edge.source.start==cut.start
                   for block in region.values() for edge in block.incoming_edges):
   discarded.update(region)
 return discarded

def transform(context):
 source=context.lifted_il
 if source is None or context.function.arch.name!='xtensa':return
 sites=set()
 blocks=list(source.basic_blocks)
 for block in blocks:
  for i in range(block.start,block.end-1):
   epc=source[i]
   if epc.operation.name!='LLIL_SET_REG' or str(epc.dest)!='epc1':continue
   nxt=source[i+1]
   if (epc.operation.name=='LLIL_SET_REG' and str(epc.dest)=='epc1'
       and epc.src.operation.name=='LLIL_CONST_PTR'
       and nxt.operation.name=='LLIL_SET_REG' and str(nxt.dest)=='temp24'
       and nxt.size==4 and str(nxt.src)=='(windowbase + temp25.d) & 0xf'):
    sites.add(i)
 if len(sites)<2:return
 discarded=_discarded_tail_blocks(source,blocks,sites)
 dest=LowLevelILFunction(context.function.arch,source_func=context.function)
 dest.prepare_to_copy_function(source);shared=LowLevelILLabel()
 for block in blocks:
  if block.start in discarded:continue
  dest.prepare_to_copy_block(block)
  for i in range(block.start,block.end):
   ins=source[i];dest.set_current_address(ins.address,block.arch)
   dest.append(ins.copy_to(dest))
   if i in sites:
    dest.append(dest.goto(shared));break
 dest.set_current_address(source[min(sites)].address,context.function.arch)
 dest.mark_label(shared)
 rotate_bank(dest,dest.add(4,dest.reg(4,'windowbase'),dest.reg(4,LLIL_TEMP(25))))
 for offset,vector in [(1,4),(2,8)]:
  hit,onward=LowLevelILLabel(),LowLevelILLabel()
  dest.append(dest.if_expr(window_bit(dest,offset),hit,onward));dest.mark_label(hit)
  dest.append(dest.jump(dest.reg(4,'windowoverflow'+str(vector))));dest.mark_label(onward)
 dest.append(dest.jump(dest.reg(4,'windowoverflow12')))
 dest.finalize();context.lifted_il=dest
