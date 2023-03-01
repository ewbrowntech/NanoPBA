"""
def_use_relation.py

@Author - Ethan Brown - ewb0020@auburn.edu
@Version - 28 FEB 23
"""


def def_use_relation(superset):
    registers = {}
    relations = []

    for instruction in superset['instructions']:
        print()
        print(instruction)
        address = instruction['elements'][0]
        mnemonic = instruction['elements'][2]
        op_str = instruction['elements'][3]
        print("Address: " + str(address))
        print("Mnemonic: " + mnemonic)
        print("Op Str: " + op_str)
        if len(op_str.split(", ")) == 2:
            ops = op_str.split(", ")
            src, dst = ops
            print("Src: " + src + " | Dst: " + dst)
            for token in ops:
                if token.startswith('r') or token.startswith('e'):
                    print("--- Uses register ---")
                    reg_name = token
                    if reg_name in registers:
                        relation = {
                            'instr_index': superset['instructions'].index(instruction),
                            'mnemonic': mnemonic,
                            'ops': ops,
                            'register': reg_name,
                            'definition': registers[reg_name],
                            'usage': address
                        }
                        print(relation)
                        if relation not in relations:
                            relations.append(relation)

            if dst.startswith('r') or dst.startswith('e'):
                print("--- Defines register ---")
                registers[dst] = address
                print("Registers: " + str(registers))

    for relation in relations:
        print("Index: " + str(relation['instr_index']) + "     \t| Mnemonic: \"" + relation['mnemonic'] + "\"   \t| Register: "
                        + relation['register'] + "   \t| Def: " + str(relation['definition']) + "   \t| Use: "
                        + str(relation['usage']))

    return relations
