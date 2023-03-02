"""
hint_finder.py

@Author - Jason Barbieri - jab0180@auburn.edu
@Version - 26 FEB 23

Generates a list of hints according to the hint-finding heuristics presented in
"Probabilistic Disassembly" by K. Miller, Y. Kwon, Y. Sun, et. al. This is not
and exhaustive collection of all possible heuristics--just the ones presented in
the paper.
"""
from disassembly.def_use_relation import def_use_relation
import capstone

def find_hints(superset):
    ''' This function takes the parsed instruction superset and generates 
        hints based on the heuristics given in the paper.
    '''
    
    hints = []

    # for instruction in superset['instructions']:
    #     hints.append(None)
    
    # I'm sure these heuristic functions could be generalized into their own
    # interface, but I think that would be a bit over-engineered for this
    # implementation
    hints.extend(heuristic1())
    hints.extend(heuristic2())
    hints.extend(heuristic3(superset))

    return hints
    
def heuristic1(superset, hints):
    hints = []
    superset = []
    known_targets = {}

    # Initialize a Capstone disassembler for x86-64 architecture
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

    for i, instr in md.disasm(superset, 0):
        try:
            print((instr.address, instr.mnemonic, instr.op_str))
        except capstone.CsError:
            hints[i] = 0

    # Disassemble the binary code and print out the target addresses of call instructions
    for instr in md.disasm(superset, 0):
        if instr.mnemonic == "call":
            target_address = instr.address + instr.size + instr.operands[0].value.imm

    for instr in superset['instructions']:
        address = instr['elements'][0]
        mnemonic = instr['elements'][2]
        op_str = instr['elements'][3]

    for i, instr in enumerate(superset):
        if instr.mnemonic is target_address:
            target = target_address
            known_targets[target]
            hints[i] = 1
    return hints

def heuristic2():
    ''' Control Flow Crossing: if there are three valid instructions i1, i2, and i3
        with i2 and i3 next to each other, then i3 being the transfer target of i1,
        and i2 having and abitrary valid instruction has 50% chance to write to some
        register of some flag bit (and the other 50% chance of writing only to memory)
    '''
    return {}

def heuristic3(superset):
    ''' Register Define-Use Relation: Instructions i1 and i2 have a define-use relation
        if i1 defines the value of a register (or some flag bit) and i2 uses the register.
    '''
    hints = def_use_relation(superset)
    return hints
