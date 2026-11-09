"""
Binary Ninja Xtensa (and ESP8266) support

This package offers several features:

Xtensa (little-endian):
    * correct length decoding for nearly all instructions
    * correct mnemonic decoding for nearly all instructions
    * fully correct disassembly for most instructions you'll see. In some places
      there are comments documenting skipped features. The disassembler took over
      10 hours to write, and the firmware I'm looking at didn't have a lot of
      floating point instructions :)
    * objdump-equivalent disassembly for all the instructions in the firmware I
      had laying around (complete with a pytest scaffolding to test this)
    * lifting to BNIL for 80+ of the most common instructions. This is enough
      for useful decompilation, courtesy of the Binary Ninja core.
    * a CallingConvention that matches what the documentation says GCC does.
      After adding this and setting it default, Binary Ninja started recognizing
      a good amount of function arguments.
    * declared support for whatever ELF architecture the ESP8266 tools in
      platformio generate... so if you open up an elf it builds you, it should
      recognize the architecture.

ESP8266-specific:
    * a BinaryView implementation that attempts to detect and load ESP8266
      firmware dumps. The current implementation is hacky, but it's able to
      examine multiple .bin dumps I've obtained through different methods.

      * These dumps sometimes contain multiple binaries (namely, a bootloader
        plus user code. I've added a "Open with Options" option to choose which
        of the binaries you want to look at. By default, it tries to pick the
        last binary containing parsed segments.

What it doesn't yet do:
    * anything with windowed registers
    * anything with the optional vector unit
    * disassemble and lift most of the boolean instructions
    * lift most floating point instructions
    * deal with special registers (I figure you might as well look at the asm
      for that anyway)
    * help you find `main` in a raw binary :)

I've abused Python metaprogramming throughout, so it should be possible to fix
each of the above inaccuracies on a per-instruction basis if the need arises.
I've attempted to document how that works.
"""

from binaryninja import (Architecture, BinaryViewType, CallingConvention,
                         IntrinsicInfo, InstructionInfo, InstructionTextToken,
                         IntrinsicInput, RegisterInfo, log, LowLevelILFunction, 
                         RegisterStackInfo, types)
from binaryninja.enums import (BranchType, Endianness, FlagRole,
                               LowLevelILFlagCondition)

from .instruction import Instruction, InstructionType
from .disassembly import disassemble_instruction
from .lifter import lift
from .binaryview import ESPFirmware


__all__ = ['XtensaLE']


class XtensaLE(Architecture):
    name = 'xtensa'
    endianness = Endianness.LittleEndian

    default_int_size = 4
    address_size = 4
    max_instr_length = 3
    instr_alignment = 1  # Xtensa allows byte-aligned instructions (24-bit + 16-bit narrow)

    # Uses for regs are from "CALL0 Register Usage and Stack Layout (8.1.2)"
    link_reg = 'a0'
    stack_pointer = 'a1'
    regs = {
        'a0': RegisterInfo("a0", 4, 0), # ret addr
        'a1': RegisterInfo("a1", 4, 0), # sp (callee-saved)
        'a2': RegisterInfo("a2", 4, 0), # arg1
        'a3': RegisterInfo("a3", 4, 0), # arg2
        'a4': RegisterInfo("a4", 4, 0), # arg3
        'a5': RegisterInfo("a5", 4, 0), # arg4
        'a6': RegisterInfo("a6", 4, 0), # arg5
        'a7': RegisterInfo("a7", 4, 0), # arg6
        'a8': RegisterInfo("a8", 4, 0), # static chain (see section 8.1.8)
        'a9': RegisterInfo("a9", 4, 0),
        'a10': RegisterInfo("a10", 4, 0),
        'a11': RegisterInfo("a11", 4, 0),
        'a12': RegisterInfo("a12", 4, 0), # callee-saved
        'a13': RegisterInfo("a13", 4, 0), # callee-saved
        'a14': RegisterInfo("a14", 4, 0), # callee-saved
        'a15': RegisterInfo("a15", 4, 0), # optional stack-frame pointer

        # Floating register 4.3.11.1
        'fcr': RegisterInfo("fcr", 4, 0), # Floating-point control register
        'fsr': RegisterInfo("fsr", 4, 0), # Floating-point status register
        'sar': RegisterInfo("sar", 1, 0), # Shift Address Register: Not a GPR
    }
    # PS 4.4.1.3 The Miscellaneous Program State Register (PS) under the Exception Option
    # Floating-point registers Chapter 4.3.11
    for i in range(16):
        regs[f"f{i}"] = RegisterInfo(f"f{i}", 4, 0)
    # Boolean registers - Chapter 4.3.10
    # Theoretically 16 1-bit register, represented as 1 16-bit register, but makes decompilation unclear
    for i in range(16):
        regs[f"b{i}"] = RegisterInfo(f"b{i}", 1, 0)

    # Physical AR register file — 64 entries (Chapter 4.3.4, Table 4–155).
    # a0–a15 are a sliding window into ar0–ar63, offset by WINDOWBASE.
    for i in range(64):
        regs[f"ar{i}"] = RegisterInfo(f"ar{i}", 4, 0)

    regs['bank_top'] = RegisterInfo('bank_top', 4, 0)
    reg_stacks = {'physical_ar': RegisterStackInfo([f'ar{i}' for i in range(64)], [], 'bank_top')}

    for vector in ('windowoverflow4','windowoverflow8','windowoverflow12',
                   'windowunderflow4','windowunderflow8','windowunderflow12',
                   'userexception','kernelexception','doubleexception'):
        regs[vector] = RegisterInfo(vector, 4, 0)

    regs['config_ndepc'] = RegisterInfo('config_ndepc', 1, 0)

    # Window management registers (used by ENTRY/RETW/CALL8/CALL12 lifting).
    # WINDOWBASE (SR 72): physical register index of the current a0.
    # WINDOWSTART (SR 73): bitmask of valid windows (bit N set iff the window
    #   starting at physical register N*4 is valid).
    regs['windowbase'] = RegisterInfo('windowbase', 1, 0)
    regs['windowstart'] = RegisterInfo('windowstart', 4, 0)

    sr_map = Instruction._special_reg_map
    for i in range(256):
        if i in sr_map:
            regs[sr_map[i][0].lower()] = RegisterInfo(sr_map[i][0].lower(), sr_map[i][1], 0)
        else:
            regs["sr"+str(i)] = RegisterInfo("sr"+str(i), 4, 0)

    for k,val in Instruction._special_reg_map.items():
        regs[val[0].lower()] = RegisterInfo(val[0].lower(), val[1], 0)

    ur_map = Instruction._user_reg_map
    for i in range(256):
        if i in ur_map:
            regs[ur_map[i][0].lower()] = RegisterInfo(ur_map[i][0].lower(), ur_map[i][1], 0)
        else:
            regs["ur"+str(i)] = RegisterInfo("ur"+str(i), 4, 0)


    # Do we have flags?
    flags = {}
    flag_roles = {}
    flag_write_types = {}
    flags_written_by_flag_write_type = {}
    flags_required_for_flag_condition = {}

    intrinsics = {
        # Core Architecture
        "read_external_register": IntrinsicInfo(
            [IntrinsicInput(types.Type.int(4, False), "address")],
            [types.Type.int(4, False)]),
        "write_external_register": IntrinsicInfo(
            [IntrinsicInput(types.Type.int(4, False), "address"),
             IntrinsicInput(types.Type.int(4, False), "value")], []),
        "memw": IntrinsicInfo([], []),
        "isync": IntrinsicInfo([], []),
        "dsync": IntrinsicInfo([], []),
        "esync": IntrinsicInfo([], []),
        "rsync": IntrinsicInfo([], []),
        "extw": IntrinsicInfo([], []),
        
        # Debug Option
        "debug_break": IntrinsicInfo([], []),

        # Data Cache Option
        "data_cache_hit_invalidate": IntrinsicInfo([IntrinsicInput(types.Type.int(4, False), "arg0")], []),
        "data_cache_hit_writeback": IntrinsicInfo([IntrinsicInput(types.Type.int(4, False), "arg0")], []),
        "data_cache_hit_writeback_invalidate": IntrinsicInfo([IntrinsicInput(types.Type.int(4, False), "arg0")], []),
        "data_cache_index_invalidate": IntrinsicInfo([IntrinsicInput(types.Type.int(4, False), "arg0")], []),
        "data_cache_index_writeback": IntrinsicInfo([IntrinsicInput(types.Type.int(4, False), "arg0")], []),
        "data_cache_index_writeback_invalidate": IntrinsicInfo([IntrinsicInput(types.Type.int(4, False), "arg0")], []),
        "data_cache_prefetch_for_read": IntrinsicInfo([IntrinsicInput(types.Type.int(4, False), "arg0")], []),
        "data_cache_prefetch_for_read_once": IntrinsicInfo([IntrinsicInput(types.Type.int(4, False), "arg0")], []),
        "data_cache_prefetch_for_write": IntrinsicInfo([IntrinsicInput(types.Type.int(4, False), "arg0")], []),
        "data_cache_prefetch_for_write_once": IntrinsicInfo([IntrinsicInput(types.Type.int(4, False), "arg0")], []),

        # Data Cache Index Option
        "data_cache_hit_unlock": IntrinsicInfo([IntrinsicInput(types.Type.int(4, False), "arg0")], []),
        "data_cache_index_unlock": IntrinsicInfo([IntrinsicInput(types.Type.int(4, False), "arg0")], []),
        "data_cache_prefetch_and_lock": IntrinsicInfo([IntrinsicInput(types.Type.int(4, False), "arg0")], []),
    
        # Instruction Cache Option
        "instruction_cache_hit_invalidate": IntrinsicInfo([IntrinsicInput(types.Type.int(4, False), "arg0")], []),
        "instruction_cache_index_invalidate": IntrinsicInfo([IntrinsicInput(types.Type.int(4, False), "arg0")], []),
        "instruction_cache_prefetch": IntrinsicInfo([IntrinsicInput(types.Type.int(4, False), "arg0")], []),

        # Instruction Cache Index Lock Option
        "instruction_cache_hit_unlock": IntrinsicInfo([IntrinsicInput(types.Type.int(4, False), "arg0")], []),
        "instruction_cache_index_unlock": IntrinsicInfo([IntrinsicInput(types.Type.int(4, False), "arg0")], []),
        "instruction_cache_prefetch_and_lock": IntrinsicInfo([IntrinsicInput(types.Type.int(4, False), "arg0")], []),

        # Debug and Exception Option 
        "exception_wait": IntrinsicInfo([], []),
        "return_from_debug_and_dispatch": IntrinsicInfo([], []),
        "return_from_debug_operation": IntrinsicInfo([], []),    
    
        # Region Protection option
        "invalidate_data_TLB_entry": IntrinsicInfo([IntrinsicInput(types.Type.int(4, False), "arg0")], []),
        "invalidate_instruciton_TLB_entry": IntrinsicInfo([IntrinsicInput(types.Type.int(4, False), "arg0")], []),
    
        # Region Translation Option (page 156)
        # MMU Option (page 158)
        "probe_data_TLB": IntrinsicInfo([IntrinsicInput(types.Type.int(4, False), "arg0")], [types.Type.int(4, False)]),
        "probe_instruction_TLB": IntrinsicInfo([IntrinsicInput(types.Type.int(4, False), "arg0")], [types.Type.int(4, False)]),
        "read_data_TLB_entry_virtual": IntrinsicInfo([IntrinsicInput(types.Type.int(4, False), "arg0")], [types.Type.int(4, False)]),
        "read_data_TLB_entry_translation": IntrinsicInfo([IntrinsicInput(types.Type.int(4, False), "arg0")], [types.Type.int(4, False)]),
        "read_instruction_TLB_entry_virtual": IntrinsicInfo([IntrinsicInput(types.Type.int(4, False), "arg0")], [types.Type.int(4, False)]),
        "read_instruction_TLB_entry_translation": IntrinsicInfo([IntrinsicInput(types.Type.int(4, False), "arg0")], [types.Type.int(4, False)]),
        "write_data_TLB_entry": IntrinsicInfo([IntrinsicInput(types.Type.int(4, False), "arg0"), IntrinsicInput(types.Type.int(4, False), "arg1")], []),
        "write_instruction_TLB_entry": IntrinsicInfo([IntrinsicInput(types.Type.int(4, False), "arg0"), IntrinsicInput(types.Type.int(4, False), "arg1")], []),

        # Instruction Cache Test Option
        "load_instruction_cache_tag": IntrinsicInfo([IntrinsicInput(types.Type.int(4, False), "arg0")], [types.Type.int(4, False)]),
        "load_instruction_cache_word": IntrinsicInfo([IntrinsicInput(types.Type.int(4, False), "arg0")], [types.Type.int(4, False)]),
        "store_instruction_cache_tag": IntrinsicInfo([IntrinsicInput(types.Type.int(4, False), "arg0"), IntrinsicInput(types.Type.int(4, False), "arg1")], []),
        "store_instruction_cache_word": IntrinsicInfo([IntrinsicInput(types.Type.int(4, False), "arg0"), IntrinsicInput(types.Type.int(4, False), "arg1")], []),

        #  Data Cache Test Option
        "load_data_cache_tag": IntrinsicInfo([IntrinsicInput(types.Type.int(4, False), "arg0")], [types.Type.int(4, False)]),
        "store_data_cache_tag": IntrinsicInfo([IntrinsicInput(types.Type.int(4, False), "arg0"), IntrinsicInput(types.Type.int(4, False), "arg1")], []),

        # Conditional Store Option
        "store_32bit_compare_conditional": IntrinsicInfo([IntrinsicInput(types.Type.int(4, False), "arg0"), IntrinsicInput(types.Type.int(4, False), "arg1"), IntrinsicInput(types.Type.int(4, False), "arg2")], [types.Type.int(4, False)]),

        # Miscelaneaous Operations Option - Placeholders
        "normalization_shift_amount": IntrinsicInfo([IntrinsicInput(types.Type.int(4, False), "arg0")], [types.Type.int(4, False)]),
        "normalization_shift_amount_unsigned": IntrinsicInfo([IntrinsicInput(types.Type.int(4, False), "arg0")], [types.Type.int(4, False)]),

        # Multiprocessor Synchronization Option 
        "acquire": IntrinsicInfo([], []),
    }    

    def _decode_instruction(self, data, addr):
        insn = None
        try:
            insn = Instruction.decode(data)
            # Honor decoder validity for every opcode family, including MAC16
            # loads whose invalid operands can name nonexistent MR registers.
            # Unsupported/reserved slots are unknown, not implemented ILL traps.
            if insn is not None and insn.valid is False:
                return None
        except:
            pass
        return insn

    def get_instruction_info(self, data, addr):
        # Instruction information must be a pure function of bytes/address.
        # BN revisits addresses across analyses and views; global visit guards
        # corrupt instruction lengths and CFG edges on those legitimate calls.
        insn = self._decode_instruction(data, addr)
        if not insn:
            return None
        result = InstructionInfo()
        length = insn.length
        if length is None or length <= 0 or length > 3:
            length = 3
        result.length = length

        # Add branches
        if insn.mnem in ["RET", "RET.N", "RETW", "RETW.N"]:
            result.add_branch(BranchType.FunctionReturn)
        # Returns from interrups or exceptions
        elif insn.mnem in ("RFUE", "ILL", "ILL.N", "SYSCALL"):
            result.add_branch(BranchType.ExceptionBranch)
        elif insn.mnem in ["RFI", "RFME", "RFWO", "RFWU", "RFE", "RFDE"]:
            result.add_branch(BranchType.FunctionReturn)
        # Section 3.8.4 "Jump and Call Instructions
        elif insn.mnem in ["J"]:
            target = insn.target_offset(addr)
            # A self-loop is valid executable control flow.
            if target is not None:
                result.add_branch(BranchType.UnconditionalBranch, target)
        elif insn.mnem in ["JX"]:
            result.add_branch(BranchType.IndirectBranch)
        elif insn.mnem in ["CALL0", "CALL4", "CALL8", "CALL12"]:
            target = insn.target_offset(addr)
            if target is not None:
                result.add_branch(BranchType.CallDestination, target)
        elif insn.mnem in ["CALLX0", "CALLX4", "CALLX8", "CALLX12"]:
            result.add_branch(BranchType.IndirectBranch)
        elif insn.mnem in ["LOOPNEZ", "LOOPGTZ"]:
            result.add_branch(BranchType.TrueBranch, addr + 4 + insn.imm8)
            result.add_branch(BranchType.FalseBranch, addr + length)
        elif insn.mnem == "LOOP":
            result.add_branch(BranchType.UnconditionalBranch, addr + length)

        elif insn.mnem.replace(".", "_") in [k for k in Instruction._target_offset_map.keys() if
                           k.startswith("B")]: # lol
            target = insn.target_offset(addr)
            if target is not None:
                result.add_branch(BranchType.TrueBranch, target)
            result.add_branch(BranchType.FalseBranch, addr + length)

        return result

    def get_instruction_text(self, data, addr):
        insn = self._decode_instruction(data, addr)
        if not insn:
            return None
        text = disassemble_instruction(insn, addr)
        return text, insn.length

    def get_instruction_low_level_il(self, data:bytes, addr:int, il:LowLevelILFunction):
        insn = self._decode_instruction(data, addr)
        if not insn:
            return None
        return lift(insn, addr, il, data)


class XtensaCall0CallingConvention(CallingConvention):
    # a0 is dubiously caller saved... it's the ret addr / link register
    caller_saved_regs = ["a0", "a2", "a3", "a4", "a5", "a6", "a7", "a8", "a9",
                         "a10", "a11"]
    int_arg_regs = ["a2", "a3", "a4", "a5", "a6", "a7"]
    implicitly_defined_regs =[f"b{i}" for i in range(16)]
    int_return_reg = "a2"
    high_int_return_reg = "a3"


def fix_xtensa_sections(bv):
    """Post-load fix: reclassify .literal sections as read-only data.

    Xtensa ELFs use a .literal section (literal pool for L32R).  The ELF
    loader may mark it executable because it lives in a text segment.
    Reclassifying avoids the analyzer creating false functions in the
    literal pool and reduces analysis noise.
    """
    from binaryninja.enums import SectionSemantics
    for section_name in ('.literal', '.lit4', '.lit8'):
        sec = bv.get_section_by_name(section_name)
        if sec is not None:
            bv.add_auto_section(
                section_name,
                sec.start,
                sec.end - sec.start,
                SectionSemantics.ReadOnlyDataSectionSemantics,
            )


def register_stuff():
    XtensaLE.register()

    # Register ourselves with the ELF loader
    BinaryViewType['ELF'].register_arch(94, Endianness.LittleEndian,
                                        Architecture['xtensa'])
    arch = Architecture['xtensa']
    arch.register_calling_convention(XtensaCall0CallingConvention(arch, "default"))

    # If we register on the Architecture's standalone platform, it seems to use our
    # calling convention without showing __convention("default") on every function
    esp_plat = arch.standalone_platform
    esp_plat.default_calling_convention = arch.calling_conventions['default']

    ESPFirmware.register()


register_stuff()

from .elf_entry import initialize_elf_entry
