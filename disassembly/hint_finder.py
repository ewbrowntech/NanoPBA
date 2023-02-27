"""
hint_finder.py

@Author - Jason Barbieri - jab0180@auburn.edu
@Version - 26 FEB 23

Generates a list of hints according to the hint-finding heuristics presented in
"Probabilistic Disassembly" by K. Miller, Y. Kwon, Y. Sun, et. al. This is not
and exhaustive collection of all possible heuristics--just the ones presented in
the paper.
"""

def find_hints(superset):
    ''' This function takes the parsed instruction superset and generates 
        hints based on the heuristics given in the paper.
    '''
    
    hints = []

    for instruction in superset['instructions']:
        hints.append(None)
    
    # I'm sure these heuristic functions could be generalized into their own
    # interface, but I think that would be a bit over-engineered for this
    # implementation
    hints.extend(heuristic1())
    hints.extend(heuristic2())
    hints.extend(heuristic3())
    
    return hints
    
def heuristic1():
    ''' Control Flow Convergence: if there are three potential instructions i1, i2,
        and i3 with i3 being the transfer target of both i1 and i2, there is a good
        chance that they are not data bytes.
    '''
    return {}

def heuristic2():
    ''' Control Flow Crossing: if there are three valid instructions i1, i2, and i3
        with i2 and i3 next to each other, then i3 being the transfer target of i1,
        and i2 having and abitrary valid instruction has 50% chance to write to some
        register of some flag bit (and the other 50% chance of writing only to memory)
    '''
    return {}

def heuristic3():
    ''' Register Define-Use Relation: Instructions i1 and i2 have a define-use relation
        if i1 defines the value of a register (or some flag bit) and i2 uses the register.
    '''
    return {}