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
import pefile


# Run disassembler
def main():
    arg_parser = argparse.ArgumentParser(add_help=False)
    arg_parser.add_argument('-h', '--header', action='store_true')
    arg_parser.add_argument('-id', '--initial_disassembly', action='store_true')
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
    initial_disassembly = perform_initial_disassembly(pe)
    if args.initial_disassembly:
        print_initial_disassembly(initial_disassembly)
    
    # Find the hints from the instruction superset
    find_hints(initial_disassembly)


if __name__ == '__main__':
    main()
