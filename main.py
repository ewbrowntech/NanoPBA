"""
main.py

@Author - Ethan Brown - ewb0020@auburn.edu
@Version - 26 FEB 23

Runs disassembler
"""
import argparse
from header.parse_header import parse_header
from header.print_header import print_header
from initial_disassembly.initial_disassembly import perform_initial_disassembly
from initial_disassembly.print_initial_disassembly import print_initial_disassembly
from disassembly.hint_finder import find_hints
from disassembly.probabilistic_disassembly import prob_disassembly
from disassembly.ctrl_flow_generator import ctrl_flow_generator
import pefile

from initial_disassembly.initial_disassembly_new import perform_initial_disassembly_new

# Run disassembler
def main():
    arg_parser = argparse.ArgumentParser(add_help=False)
    arg_parser.add_argument('-h', '--header', action='store_true')
    arg_parser.add_argument('-id', '--initial_disassembly', action='store_true')
    arg_parser.add_argument('-hint', '--hints', action='store_true')
    arg_parser.add_argument('-p', '--posteriors', action='store_true')
    arg_parser.add_argument('-i', '--imports', action='store_true')
    arg_parser.add_argument('-r', '--resources', action='store_true')
    arg_parser.add_argument('-s', '--sections', action='store_true')
    arg_parser.add_argument('-v', '--verbose', action='store_true')
    arg_parser.add_argument('filepath')
    args = arg_parser.parse_args()

    if args.header and args.verbose:
        args.imports = True
        args.resources = True
        args.sections = True

    # Load file at filepath
    filepath = args.filepath
    print("Filepath: " + filepath)
    pe = pefile.PE(filepath)

    # Parse PE header and print the information therein
    header = parse_header(pe)
    if args.header:
        print_header(header, args)
    #initial_disassembly = perform_initial_disassembly(pe)
    initial_disassembly = perform_initial_disassembly_new(pe)
    if args.initial_disassembly:
        print_initial_disassembly(initial_disassembly)
    
    # Generate the control flow graph
    cf_gen = ctrl_flow_generator(initial_disassembly['CODE_SIZE'])
    cf_gen.make_graph(initial_disassembly)

    # Find the hints from the instruction superset
    hints = find_hints(initial_disassembly)
    if args.hints:
        print(hints)

    # Get the posterior probability that any given byte is not a data byte
    posteriors = prob_disassembly(initial_disassembly, hints)
    if args.posteriors:
        print(posteriors)

if __name__ == '__main__':
    main()
