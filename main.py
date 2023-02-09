"""
main.py

@Author - Ethan Brown - ewb0020@auburn.edu
@Version - 09 FEB 23

Runs disassembler
"""
import argparse
from header.parse_header import parse_header
from header.print_header import print_header
import pefile


# Run disassembler
def main():
    arg_parser = argparse.ArgumentParser(add_help=False)
    arg_parser.add_argument('-h', '--header', action='store_true')
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


if __name__ == '__main__':
    main()
