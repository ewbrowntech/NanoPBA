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
        
    fixed_point = False
    
    while not fixed_point:
        fixed_point = True
        
 
def forward_prop():
    pass
    
def prop_to_occlusion_space():
    pass

def back_prop():
    pass
 
def is_invalid_inst(instruction):
    ''' This function accepts an instruction and determines if it is a valid instruction.
    '''
    pass