"""
print_initial_disassembly.py

@Author - Ethan Brown - ewb0020@auburn.edu
@Version - 26 FEB 23

Print the initial disassembly
"""


def print_initial_disassembly(initial_disassembly):
    print("\n----- INITIAL DISASSEMBLY -----")
    print("Potential Instructions:")
    for instruction in initial_disassembly["instructions"]:
        print(instruction)
    print("\nCode Base: " + str(initial_disassembly["CODE_BASE"]))
    print("Code Endpoint: " + str(initial_disassembly["CODE_END"]))
    print("Code Size: " + str(initial_disassembly["CODE_SIZE"]))
    print("# of Potential Instructions: " + str(len(initial_disassembly["instructions"])))


