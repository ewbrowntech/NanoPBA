"""
initial_disassembly.py

@Author - Ethan Brown - ewb0020@auburn.edu
@Version - 26 FEB 23

Use Capstone to initiate initial_disassembly
"""
from capstone import *


def perform_initial_disassembly(pe):
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

    for byte in CODE_BYTES:
        code = byte.to_bytes(1, byteorder='little')
        disassembled_instruction = md.disasm_lite(code, CODE_BASE)

        potential_instruction = {
                "raw_bytes": byte,
                "elements": []
            }

        for element in disassembled_instruction:
            potential_instruction["elements"].append(element)

        instructions.append(potential_instruction)

    initial_disassembly = {
        "CODE_BASE": CODE_BASE,
        "CODE_SIZE": CODE_SIZE,
        "CODE_END": CODE_END,
        "instructions": instructions
    }

    return initial_disassembly
