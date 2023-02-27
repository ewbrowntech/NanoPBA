"""
print_header.py

@Author - Ethan Brown - ewb0020@auburn.edu
@Version - 09 FEB 23

Print the info extracted from the file header
"""


# Run print operation
def print_header(header, args):
    print("\n----- HEADER -----")
    for key, value in header.items():
        if type(value) != list:  # Some values are trees and require their own methods, the remaining do not
            print(str(key) + ":\t" + str(value))

        elif key == "Import Table":
            print(str(key))
            print_imports(value, args.imports)
        elif key == "Export Table":
            print(str(key))
            print_exports(value)
        elif key == "Resource Table":
            print(str(key))
            print_resources(value, args.resources)
        elif key == "Section Table":
            print(str(key))
            print_sections(value, args.sections)


# Print the import table
def print_imports(import_table, doPrintImportNames):
    for import_entry in import_table:
        print("  -", import_entry["DLL"])
        if doPrintImportNames:
            for import_ in import_entry["Imports"]:
                print("     -", import_.decode('utf-8'))


# Print the export table (if it exists)
def print_exports(export_table):
    if export_table is None:
        print(" None")
        return
    for export_entry in export_table:
        print("  -", export_entry)


# Print the resource table
def print_resources(resource_table, doPrintResourceIDs):
    if resource_table is None:
        print(" None")
        return
    for resource_entry in resource_table:
        print("  -", resource_entry["Type"])
        if doPrintResourceIDs:
            for resourceID in resource_entry["ID"]:
                print("    -", resourceID)


# Print the section header info table
def print_sections(section_table, doPrintSectionInfo):
    for section_entry in section_table:
        print("  -", section_entry["Name"])
        if doPrintSectionInfo:
            print("    - VSize:\t", section_entry["Virtual Size"])
            print("    - VAddress:\t", section_entry["Virtual Address"])
            print("    - DSize:\t", section_entry["Data Size"])
            print("    - DPointer:\t", section_entry["Data Pointer"])


# Print the debug information (if it exists)
def print_debug_info(debug_info):
    if debug_info is None:
        print(" None")
        return
    for debug_entry in debug_info:
        print("  -", debug_entry)
