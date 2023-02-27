class ctrl_flow_generator:
    # Make this class a Singleton
    def __new__(cls, num_instructions):
        if not hasattr(cls, 'instance'):
            cls.instance = super(ctrl_flow_generator, cls).__new__(cls)

            # This list structure is the cached control flow
            # The index is the address offset from the start of the instruction block,
            # and the value is address offset of the next instruction in the flow
            cls.instance.flow_cache = []

            # Make an entry for each possible instruction in the flow cache
            for i in range(num_instructions):
                cls.instance.flow_cache.append({'predecessors': [], 'successors': []})
        return cls.instance

    def make_graph(self, superset):
        ''' This method calls make_graph_starting_at for every instruction in the superset, thus 
            generating the entire control flow graph. This method is for organization and readability.
        '''
        
        for instruction in superset['instructions']:
            self.make_graph_starting_at(superset, instruction)

    def make_graph_starting_at(self, superset, start_instruction):
        ''' Generates the control flow graph starting from start_instruction and stores it to cache.
            This method does not return anything; it is only used to populate the cache
        '''
        
        current_instruction = start_instruction

        # A list of branches to be analyzed. This is populated by jump targets because there are two
        # branches to analyze
        additional_targets = []

        terminate = False

        # While there are instructions to find in the control flow...
        while not terminate:
            # Check to see if the next address is already in the cache
            next_addr = self.check_cached_flow_graph(superset['CODE_BASE'], current_instruction['elements'][0])

            # If the next address is not cached, calculate the next address
            if next_addr == []:
                # Get the index of the flow cache that correlates with the current instruction
                flow_cache_index = int(current_instruction['elements'][0]) - superset['CODE_BASE']

                if current_instruction['elements'][2] == 'call':
                    # Only follow the call if the target is an address. Otherwise, act like there
                    # is no target
                    if current_instruction['elements'][3][0:2] == '0x':
                        # Convert target from hex to decimal
                        next_addr = int(current_instruction['elements'][3], 16)
                        next_addr -= superset['CODE_BASE']

                        # If the next address is past the last possible instruction, the control flow has reached
                        # the end of the program, so there is no "next address"
                        if next_addr >= len(superset['instructions']):
                            next_addr = None
                        else:
                            # Update the cache
                            self.flow_cache[flow_cache_index]['successors'].append(next_addr)
                            self.flow_cache[next_addr]['predecessors'].append(current_instruction['elements'][0] - superset['CODE_BASE'])
                    else:
                        next_addr = None
                elif current_instruction['elements'][2][0] == 'BAD':
                    # If we run into an invalid instruction, there is no next instruction
                    next_addr = None
                else:
                    # If the current instruction is a jump, check if the target is direct
                    # We are assuming that all jump instructions and only jump instructions
                    # begin with 'j'
                    if current_instruction['elements'][2][0] == 'j':
                        # If the target is an address, add the target to a list of instructions to
                        # analyze later. If there is an indirect jump target, ignore it, because 
                        # the authors of the paper determined that it is not necessary to calculate
                        # indirect jump targets (Section IV, Step III)
                        if current_instruction['elements'][3][0:2] == '0x':
                            # Convert target from hex to decimal
                            next_addr = int(current_instruction['elements'][3], 16)
                            next_addr -= superset['CODE_BASE']

                            # If the jump target is past the end of the program, mark the instruction as invalid
                            if next_addr > superset['CODE_SIZE']:
                                superset['instructions'][flow_cache_index]['elements'][2] = 'BAD'
                                superset['instructions'][flow_cache_index]['elements'][3] = ''
                            # If the jump target has not already been analyzed
                            elif not (next_addr in additional_targets):
                                additional_targets.append(next_addr)

                    # If the current instruction is not a jump or invalid, then go to the next
                    # instruction (current address + instruction size)
                    next_addr = current_instruction['elements'][0] + current_instruction['elements'][1]
                    next_addr -= superset['CODE_BASE']

                    # If the next address is past the last possible instruction, the control flow has reached
                    # the end of the program, so there is no "next address"
                    if next_addr >= len(superset['instructions']):
                        next_addr = None
                    else:
                        # Update the cache
                        self.flow_cache[flow_cache_index]['successors'].append(next_addr)
                        self.flow_cache[next_addr]['predecessors'].append(current_instruction['elements'][0] - superset['CODE_BASE'])
            else:
                # If the current instruction has been cached, then the rest of the subgraph coming from the
                # cached instruction should have already been cached
                next_addr = None

            # If there is no next instruction, terminate the loop
            if next_addr == None:
                if len(additional_targets) > 0:
                    t = additional_targets.pop()
                    current_instruction = superset['instructions'][t]
                else:
                    terminate = True
            else:
                # Update the current instruction
                current_instruction = superset['instructions'][next_addr]

    def get_next_instructions(self, superset, start_instruction):
        ''' Gets the set of instructions that follow addr in the control flow. Note that the
            list will be in breadth-first order; hence, this should only be used if you just
            need to enumerate the places that control could flow to during execution
        '''

        # Create the control flow list
        control_flow = [] 
        current_instruction = start_instruction

        # A list of addresses that control can flow to, but we haven't processed yet.
        # This will be populated when we have a jump instruction because there are two
        # possible places that control can flow to       
        control_queue = []

        # Pre-load the control queue with the initial instructions targets
        control_queue.extend(self.check_cached_flow_graph(superset['CODE_BASE'], current_instruction['elements'][0]))

        # While there are still addresses to traverse
        while len(control_queue) > 0:
            # Add the next address to the control flow list
            next_addr = control_queue.pop()
            control_flow.append(next_addr)

            # Add the next address's flow targets to the queue 
            control_queue.extend(self.flow_cache[next_addr]['successors'])

        return control_flow

    def get_prev_instructions(self, superset, start_instruction):
        ''' Gets the set of instructions that preceed addr in the control flow. Note that the
            list will be in breadth-first order; hence, this should only be used if you just
            need to enumerate the places that control could flow to during execution
        '''
        
        # Create the control flow list
        control_flow = [] 
        current_instruction = start_instruction

        # A list of addresses that control can flow to, but we haven't processed yet.
        # This will be populated when we have a jump instruction because there are two
        # possible places that control can flow to       
        control_queue = []

        # Pre-load the control queue with the initial instructions targets
        offset = current_instruction['elements'][0] - superset['CODE_BASE']
        control_queue.extend(self.flow_cache[offset]['predecessors'])

        # While there are still addresses to traverse
        while len(control_queue) > 0:
            # Add the next address to the control flow list
            next_addr = control_queue.pop()
            control_flow.append(next_addr)

            # Add the next address's flow targets to the queue 
            control_queue.extend(self.flow_cache[next_addr]['predecessors'])

        return control_flow

    def check_cached_flow_graph(self, start, addr):
        ''' Checks the chache to see if the control flow has already been calculated for the
            given address. start denotes the address of the first instruction byte, and address
            is the location 
        '''

        offset = addr - start
        return self.flow_cache[offset]['successors']