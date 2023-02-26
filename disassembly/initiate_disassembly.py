"""
initiate_disassembly.py

@Author - Ethan Brown - ewb0020@auburn.edu
@Version - 16 FEB 23

Use Capstone to initiate disassembly
"""
from capstone import *
from capstone.x86 import *

def initiate_disassembly(pe):
    code_section = None
    for section in pe.sections:
        if section.Characteristics & 0x20:  # IMAGE_SCN_CNT_CODE
            code_section = section             # Inspiration from ChatGPT
            break
    if code_section is None:
        raise ValueError("Code section not found")
    print(code_section)

    CODE_BASE = code_section.VirtualAddress
    CODE_SIZE = code_section.Misc_VirtualSize
    CODE_END = CODE_BASE + CODE_SIZE
    CODE_BYTES = pe.get_memory_mapped_image()[CODE_BASE:CODE_END]  # loads binary into memory and extracts code section
    code_instructions = []
    md = Cs(CS_ARCH_X86, CS_MODE_32)            # Inspiration from ChatGPT, sanity check with docs
    md.skipdata = True
    for insn in md.disasm(CODE_BYTES, CODE_BASE):
        code_instructions.append(insn)


    print(CODE_BASE)
    print(CODE_SIZE)
    print(CODE_END)
    for instruction in code_instructions:
        print(instruction)
    pass



def skip_data_callback(code, offset):
    return 1
