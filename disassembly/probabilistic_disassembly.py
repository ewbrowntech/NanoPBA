"""
probabilistic_disassembly.py

@Author - Jason Barbieri - jab0180@auburn.edu
@Version - 26 FEB 23

Performs probabilistic disassembly on a given instruction superset. The logic used in
this algorithm was translated directly from the pseudocode of Algorithm 1 in
"Probabilistic Disassembly" by K. Miller, Y. Kwon, Y. Sun, et. al.
"""

import numpy as np
from disassembly.ctrl_flow_generator import ctrl_flow_generator

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
        posteriors - the calculated posteriors
    '''
    
    # Get the control flow generator singleton
    cf_gen = ctrl_flow_generator(superset['CODE_SIZE'])

    # The probability that address i is a data byte. This is a list where the 
    # indices correlate with the corresponding instruction's offset from the
    # start of the instruction block. This was done to allow for a more intuitive
    # way to search through the list (rather than having to search through keys)
    D = []
    
    # The set of hints, denoted by a set of addresses that reach the address i
    RH = []
    
    # The calculated posteriors 
    posteriors = []
    
    # Initialize the values for D (1.0 if invalid, None if valid)
    # 1.0 means that the address must be a data byte
    for (i, instruction) in enumerate(superset['instructions']):
        if is_invalid_inst(instruction):
            D.append(1.0)
        else:
            D.append(None)
        
        # Show that we have not found any hints pointing to the address yet
        RH.append({})
        
    # This flag is false if there has been a change in the pobabilities during forward
    # or backward propagation. Hence, the algorithm ends when there are no updates to
    # the posteriors.
    fixed_point = False
    
    while not fixed_point:
        fixed_point = True
        
        fixed_point = forward_prop(cf_gen, superset, hints, D, RH, fixed_point)
        prop_to_occlusion_space(superset, D)
        fixed_point = back_prop(cf_gen, superset, D, fixed_point)
    
    # Compute the posterior probabilities by normalization
    for instruction in superset['instructions']:
        # Get the address for the sake of readability
        addr = instruction['elements'][0]

        # If an instruction starting at addr is invalid, the posterior is set to 0 (i.e., instruction addr
        # is not a true positive)
        if D[addr] == 1:
            posteriors[addr] = 0
            continue
        
        s = 1 / D[addr]
        
        # Sum up the inverse probability D for all instructions occluded with addr (including addr itself)
        # This variable s seems to be the marginal probability
        for j in get_occluding_set(superset, addr):
            s = s + (1 / D[j])
        
        # The posterior probabilities are computed as the ratio bewteen (1 / D[addr]) and s
        posteriors[addr] = (1 / D[addr]) / s

    return posteriors

def forward_prop(cf_gen, superset, hints, D, RH, fixed_point):
    ''' Passes all hints relating to each instruction up the control flow heirarchy to each of the
        instruction's parents. Also updates the instruction's probability of being a data byte    
    '''
    
    for (i, instruction) in enumerate(superset['instructions']):
        # Get the address for the sake of readability
        #addr = instruction['elements'][0]

        # If the instruction at the current address is definitely a data byte, then it
        # does not give any hints for the posteriors of any other instruction
        if D[i] == 1:
            continue
        
        # If addr denotes a hint and addr has not been added to RH[addr], add it to RH[addr]
        # and update D[addr] to the product of the priors of all hints in RH[addr]. For
        # a better understanding of how D is updated, look at disassembler_data_structure_test.py
        if (not (hints[i] == None)) and (not (i in RH[i])):
            RH[i].append(i)
            D[i] = np.prod([hints[j] for j in RH[i]])
            
        # Propagate the hints in RH[i] to i's control flow successor(s)
        test = cf_gen.get_next_instructions(superset, instruction)
        for n in test:
            # If there are hints for this address (i.e., RH[addr]) that aren't in the proceeding
            # instruction's set of hints, propagate the hints at addr to successor n via union, and
            # update D[n]. If successor n has a smaller address (i.e., it already has been updated
            # in the current round), then there needs to be another iteration of the whole algorithm
            # (i.e., set fixed_point to false)
            if not (len([j for j in RH[i] if not (j in RH[n])]) == 0):
                RH[n] = list(set(RH[i]) | set(RH[n]))
                D[n] = np.prod([hints[j] for j in RH[n]])
                
                # If successor n has a smaller address (i.e., it already has been updated in the current
                # round), then there needs to be another iteration of the whole algorithm (i.e., set
                # fixed_point to false)
                if n < i:
                    fixed_point = False
                    
    return fixed_point
    
def prop_to_occlusion_space(superset, D):
    ''' This function traverses all the addresses and performs local propagation of probabilities within
        the occlusion space of individual instructions.
    '''    
    for instruction in superset['instructions']:
        # Get the address for the sake of readability
        addr = instruction['elements'][0]

        # Get the occluding set, but only include addresses that have probabilities
        occluding_set = get_occluding_set(superset, D, addr)
        occluding_set = [prob for prob in occluding_set if not (prob == None)]
        
        # If the probability of the instruction at addr being a data byte has not been determined and
        # there is at least one instruction in the occluding set that has a probability, calculate the
        # probability that the instruction at addr is a data byte
        if (D[addr] == None) and (len(occluding_set) > 0):
            D[addr] = 1 - min(occluding_set)          

def back_prop(cf_gen, superset, D, fixed_point):
    ''' This function traverses from the end of the superset to the beginning (in contrast to forward_prop() and
        prop_to_occlusion_space()). For each address addr, if you have more evidence that addr is data (i.e., if
        its control flow predecessor p does not have any probability or a smaller probability), then set p to have
        the same probability of denoting data bytes.
    '''
    
    for instruction in reversed(superset):
        # Get the address for the sake of readability
        addr = instruction['elements'][0]

        for p in cf_gen.get_prev_instructions(superset, addr):
            # The probability of a preceeding byte being a data byte cannot be less than the probability
            # that the child byte is a data byte.
            if (D[p] == None) or (D[p] < D[addr]):
                D[p] = D[addr]
                
                # If p has a larger address that addr, then we can tell that p has already been traversed.
                # Hence, we need another iteration to ensure that p's changes are pro
                if p > addr:
                    fixed_point = False
                    
    return fixed_point

def get_occluding_set(superset, D, addr):
    ''' Returns the list of instructions in the instruction superset that occlude the instruction at address addr.
        The returned list also includes the probability that the occluding instruction is a data byte.
    '''
    pass
 
def is_invalid_inst(instruction):
    ''' This function accepts an instruction and determines if it is a valid instruction.
    '''
    return instruction['elements'][2] == 'BAD'