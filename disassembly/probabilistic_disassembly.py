import numpy as np

def prob_disassembly(superset, hints):
    ''' This function produces the posterior probabilities of each instruction in the
        instruction superset being a true positive instruction (i.e., the probability
        that the instruction at address i is a true positive given the probabilities
        that the instructions that instruction i depends on are data bytes.
        
        INPUT:
        superset - the set of all instructions that can be decompiled from the
            binary indexed by address.
        hints - list of hints where the hint at index i is a prior probability
            (i.e., the probability that the instruction is a data byte).
         
        OUTPUT:
        posterior - the calculated posteriors
    '''
    
    # The probability that address i is a data byte
    D = {}
    
    # The set of hints, denoted by a set of addresses that reach the address i
    RH = {}
    
    # Initialize the values for D (1.0 if invalid, None if valid)
    # 1.0 means that the address must be a data byte
    for addr in superset.addresses.toList():
        if is_invalid_inst(superset[i]):
            D[addr] = 1.0
        else:
            D[addr] = none
        
        # Show that we have not found any hints pointing to the address yet
        RH[addr] = {}
        
    # This flag is false if there has been a change in the pobabilities during forward
    # or backward propagation. Hence, the algorithm ends when there are no updates to
    # the posteriors.
    fixed_point = False
    
    while not fixed_point:
        fixed_point = True
        
        fixed_point = forward_prop(superset, hints, D, RH, fixed_point)
        
 
def forward_prop(superset, hints, D, RH, fixed_point):
    for addr in superset:
        # If the instruction at the current address is definitely a data byte, then it
        # does not give any hints for the posteriors of any other instruction
        if D[addr] == 1:
            continue
        
        # If addr denotes a hint and addr has not been added to RH[addr], add it to RH[addr]
        # and update D[addr] to the product of the priors of all hints in RH[addr]. For
        # a better understanding of how D is updated, look at disassembler_data_structure_test.py
        if (not (hints[addr] = none)) and (not (addr in RH[addr])):
            RH[addr].append(addr)
            D[addr] = np.prod([hints[i] for i in RH[addr]])
            
        # Propagate the hints in RH[i] to i's control flow successor(s)
        for n in <set of next instructions from i along control flow>:
            # If there are hints for this address (i.e., RH[addr]) that aren't in the proceeding
            # instruction's set of hints, propagate the hints at addr to successor n via union, and
            # update D[n]. If successor n has a smaller address (i.e., it already has been updated
            # in the current round), then there needs to be another iteration of the whole algorithm
            # (i.e., set fixed_point to false)
            if not (len([i for i in RH[addr] if not (i in RH[n])]) = 0):
                RH[n] = list(set(RH[addr]) | set(RH[n]))
                D[n] = np.prod([hints[i] for i in RH[n])
                
                if n < addr:
                    fixed_point = false
                    
    return fixed_point
    
def prop_to_occlusion_space():
    pass

def back_prop():
    pass
 
def is_invalid_inst(instruction):
    ''' This function accepts an instruction and determines if it is a valid instruction.
    '''
    pass