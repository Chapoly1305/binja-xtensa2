"""AR operand roles for WindowCheck, independent of display rendering.

Derived from the audited decoder/disassembler operand inventory. Floating-point,
boolean, immediate and opcode fields must never be treated as AR operands.
Special window-management instructions implement their own checks.
"""
AR_FIELDS = {'ABS': 'rt', 'ABS_S': '', 'ADD': 'rst', 'ADDI': 'ts', 'ADDI_N': 'rs', 'ADDMI': 'ts', 'ADDX2': 'rst', 'ADDX4': 'rst', 'ADDX8': 'rst', 'ADD_N': 'rst', 'ADD_S': '', 'ALL4': '', 'ALL8': '', 'AND': 'rst', 'ANDB': '', 'ANDBC': '', 'ANY4': '', 'ANY8': '', 'BALL': 'st', 'BANY': 'st', 'BBC': 'st', 'BBCI': 's', 'BBCI_L': 's', 'BBS': 'st', 'BBSI': 's', 'BBSI_L': 's', 'BEQ': 'st', 'BEQI': 's', 'BEQZ': 's', 'BEQZ_N': 's', 'BF': '', 'BGE': 'st', 'BGEI': 's', 'BGEU': 'st', 'BGEUI': 's', 'BGEZ': 's', 'BLT': 'st', 'BLTI': 's', 'BLTU': 'st', 'BLTUI': 's', 'BLTZ': 's', 'BNALL': 'st', 'BNE': 'st', 'BNEI': 's', 'BNEZ': 's', 'BNEZ_N': 's', 'BNONE': 'st', 'BREAK': '', 'BREAK_N': '', 'BT': '', 'CALL0': '', 'CALL12': '', 'CALL4': '', 'CALL8': '', 'CALLX0': 's', 'CALLX12': 's', 'CALLX4': 's', 'CALLX8': 's', 'CEIL_S': 'r', 'CLAMPS': 'rs', 'DHI': 's', 'DHU': 's', 'DHWB': 's', 'DHWBI': 's', 'DII': 's', 'DIU': 's', 'DIWB': 's', 'DIWBI': 's', 'DPFL': 's', 'DPFR': 's', 'DPFRO': 's', 'DPFW': 's', 'DPFWO': 's', 'DSYNC': '', 'ENTRY': 's', 'ESYNC': '', 'EXCW': '', 'EXTUI': 'rt', 'EXTW': '', 'FLOAT_S': 's', 'FLOOR_S': 'r', 'IDTLB': 's', 'IHI': 's', 'IHU': 's', 'III': 's', 'IITLB': 's', 'IIU': 's', 'ILL': '', 'ILL_N': '', 'IPF': 's', 'IPFL': 's', 'ISYNC': '', 'J': '', 'JX': 's', 'L16SI': 'ts', 'L16UI': 'ts', 'L32AI': 'ts', 'L32E': 'ts', 'L32E_N': 'ts', 'L32I': 'ts', 'L32I_N': 'ts', 'L32R': 't', 'L8UI': 'ts', 'LDCT': 'ts', 'LDDEC': 's', 'LDINC': 's', 'LICT': 'ts', 'LICW': 'ts', 'LOOP': 's', 'LOOPGTZ': 's', 'LOOPNEZ': 's', 'LSI': 's', 'LSIU': 's', 'LSX': 'st', 'LSXU': 'st', 'MADD_S': '', 'MAX': 'rst', 'MAXU': 'rst', 'MEMW': '', 'MIN': 'rst', 'MINU': 'rst', 'MOVEQZ': 'rst', 'MOVEQZ_S': 't', 'MOVF': 'rs', 'MOVF_S': '', 'MOVGEZ': 'rst', 'MOVGEZ_S': 't', 'MOVI': 't', 'MOVI_N': 's', 'MOVLTZ': 'rst', 'MOVLTZ_S': 't', 'MOVNEZ': 'rst', 'MOVNEZ_S': 't', 'MOVSP': 'ts', 'MOVT': 'rs', 'MOVT_S': '', 'MOV_N': 'ts', 'MOV_S': '', 'MSUB_S': '', 'MUL16S': 'rst', 'MUL16U': 'rst', 'MULL': 'rst', 'MULSH': 'rst', 'MULUH': 'rst', 'MUL_S': '', 'NEG': 'rt', 'NEG_S': '', 'NOP': '', 'NOP_N': '', 'NSA': 'ts', 'NSAU': 'ts', 'OEQ_S': '', 'OLE_S': '', 'OLT_S': '', 'OR': 'rst', 'ORB': '', 'ORBC': '', 'PDTLB': 'ts', 'PITLB': 'ts', 'QUOS': 'rst', 'QUOU': 'rst', 'RDTLB0': 'ts', 'RDTLB1': 'ts', 'REMS': 'rst', 'REMU': 'rst', 'RER': 'ts', 'RET': '', 'RETW': '', 'RETW_N': '', 'RET_N': '', 'RFDD': '', 'RFDE': '', 'RFDO': '', 'RFE': '', 'RFI': '', 'RFME': '', 'RFR': 'r', 'RFUE': '', 'RFWO': '', 'RFWU': '', 'RITLB0': 'ts', 'RITLB1': 'ts', 'ROTW': '', 'ROUND_S': 'r', 'RSIL': 't', 'RSR': 't', 'RSYNC': '', 'RUR': 't', 'S16I': 'ts', 'S32C1I': 'ts', 'S32E': 'ts', 'S32I': 'ts', 'S32I_N': 'ts', 'S32RI': 'ts', 'S8I': 'ts', 'SDCT': 'ts', 'SEXT': 'rs', 'SICT': 'ts', 'SICW': 'ts', 'SIMCALL': '', 'SLL': 'rs', 'SLLI': 'rs', 'SRA': 'rt', 'SRAI': 'rt', 'SRC': 'rst', 'SRL': 'rt', 'SRLI': 'rt', 'SSA8B': 's', 'SSA8L': 's', 'SSAI': '', 'SSI': 's', 'SSIU': 's', 'SSL': 's', 'SSR': 's', 'SSX': 'st', 'SSXU': 'st', 'SUB': 'rst', 'SUBX2': 'rst', 'SUBX4': 'rst', 'SUBX8': 'rst', 'SUB_S': '', 'SYSCALL': '', 'TRUNC_S': 'r', 'UEQ_S': '', 'UFLOAT_S': 's', 'ULE_S': '', 'ULT_S': '', 'UN_S': '', 'UTRUNC_S': 'r', 'WAITI': '', 'WDTLB': 'ts', 'WER': 'ts', 'WFR': 's', 'WITLB': 'ts', 'WSR': 't', 'WUR': 't', 'XOR': 'rst', 'XORB': '', 'XSR': 't'}
for _operation in ("MUL", "MULA", "MULS", "UMUL"):
    for _kind, _fields in (("AA", "st"), ("AD", "s"), ("DA", "t"), ("DD", "")):
        if _operation == "UMUL" and _kind != "AA":
            continue
        for _half in ("LL", "HL", "LH", "HH"):
            AR_FIELDS[_operation + "_" + _kind + "_" + _half] = _fields

for _kind, _fields in (("DA", "st"), ("DD", "s")):
    for _half in ("LL", "HL", "LH", "HH"):
        for _load in ("LDINC", "LDDEC"):
            AR_FIELDS["MULA_" + _kind + "_" + _half + "_" + _load] = _fields

IMPLICIT_AR = {'CALL0': [0], 'CALL12': [12], 'CALL4': [4], 'CALL8': [8], 'CALLX0': [0], 'CALLX12': [12], 'CALLX4': [4], 'CALLX8': [8], 'RET': [0], 'RET_N': [0]}
SPECIAL_WINDOW_RULES = frozenset(['ENTRY', 'RETW', 'RETW_N', 'ROTW',
                                 'RFWO', 'RFWU', 'L32E', 'S32E'])

def maximum_window_group(insn):
    name = insn.mnem.replace('.', '_')
    if name in SPECIAL_WINDOW_RULES:
        return 0
    if name not in AR_FIELDS:
        raise ValueError('Missing AR operand metadata: ' + name)
    registers = [getattr(insn, field) for field in AR_FIELDS[name]]
    registers.extend(IMPLICIT_AR.get(name, ()))
    return max(registers, default=0) >> 2

AR_FIELDS.update({"SALT": "rst", "SALTU": "rst"})
