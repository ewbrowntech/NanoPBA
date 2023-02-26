"""
initial_disassembly.py

@Author - Ethan Brown - ewb0020@auburn.edu
@Version - 26 FEB 23

Use Capstone to initiate initial_disassembly
"""
from capstone import *


def perform_initial_disassembly_new(pe):
    code_section = None
    for section in pe.sections:
        if section.Characteristics & 0x20:  # IMAGE_SCN_CNT_CODE
            code_section = section             # Inspiration from ChatGPT
            break
    if code_section is None:
        raise ValueError("Code section not found")

    CODE_BASE = code_section.VirtualAddress
    CODE_SIZE = code_section.Misc_VirtualSize
    CODE_END = CODE_BASE + CODE_SIZE
    CODE_BYTES = pe.get_memory_mapped_image()[CODE_BASE:CODE_END]  # loads binary into memory and extracts code section

    md = Cs(CS_ARCH_X86, CS_MODE_64)

    instructions = []
    current_start_byte = CODE_BASE

    while not (current_start_byte == CODE_END):
        generator = md.disasm(CODE_BYTES, current_start_byte)
        i = generator.__next__()

        potential_instruction = {
                "raw_bytes": i.bytes,
                "elements": []
            }
        
        potential_instruction["elements"].append(i.address)
        potential_instruction["elements"].append(i.size)
        potential_instruction["elements"].append(i.mnemonic)
        potential_instruction["elements"].append(i.op_str)

        instructions.append(potential_instruction)

        # Increment by one byte
        current_start_byte += 1

    initial_disassembly = {
        "CODE_BASE": CODE_BASE,
        "CODE_SIZE": CODE_SIZE,
        "CODE_END": CODE_END,
        "instructions": instructions
    }

    return initial_disassembly
