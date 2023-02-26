import numpy as np

# This script is testing how the data structures should work in the probabilistic_disassembly.py file

DH = {'addr1': -1,
	  'addr2': -1,
	  'addr3': -1,
	  'addr4': -1,
	  'addr5': -1
	  }

# Probability that the address at the key is a data byte
hints = {'addr1': 0.5, 'addr2': 0.25, 'addr3': 0.9, 'addr4': 0.01, 'addr5': 0.3}

RH = {'addr1': [],
	  'addr2': [],
	  'addr3': ['addr1'],
	  'addr4': ['addr2', 'addr3'],
	  'addr5': ['addr1', 'addr2', 'addr4']
	  }

addr = 'addr5'

DH[addr] = np.prod([hints[i] for i in RH[addr]])
print([hints[i] for i in RH[addr]])
print(DH[addr])

# Take the inverse intersection of the two hint sets
print([i for i in RH['addr5'] if not (i in RH['addr3'])])

# Take the unique union of the two hint sets
print(list(set(RH['addr5']) | set(RH['addr3'])))