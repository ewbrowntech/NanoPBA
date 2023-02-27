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
    offset = 0

    while not (offset == CODE_SIZE):
        try:
            generator = md.disasm(CODE_BYTES[offset:], CODE_BASE + offset, count=1)
            i = generator.__next__()
            
            potential_instruction = create_potential_instruction(i.bytes, i.address, i.size, i.mnemonic, i.op_str)
            instructions.append(potential_instruction)
        except StopIteration:
            # This should trigger when there is an invalid instruction
            potential_instruction = create_potential_instruction(CODE_BYTES[offset], CODE_BASE + offset, 1, "BAD", "")
            instructions.append(potential_instruction)

        # Increment by one byte
        offset += 1

    initial_disassembly = {
        "CODE_BASE": CODE_BASE,
        "CODE_SIZE": CODE_SIZE,
        "CODE_END": CODE_END,
        "instructions": instructions
    }

    return initial_disassembly

def create_potential_instruction(bytes, address, size, mnemonic, op_str):
    potential_instruction = {
            "raw_bytes": bytes,
            "elements": []
        }
    
    potential_instruction["elements"].append(address)
    potential_instruction["elements"].append(size)
    potential_instruction["elements"].append(mnemonic)
    potential_instruction["elements"].append(op_str)

    return potential_instruction