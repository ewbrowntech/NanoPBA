"""
parse_header.py
@Author - Ethan Brown - ewb0020@auburn.edu
@Version - 09 FEB 23
Parse and extract info from PE file header
"""
import pefile


# Run the parsing operation
def parse_header(pe):
    file_header = pe.FILE_HEADER
    optional_header = pe.OPTIONAL_HEADER
    import_directory = pe.DIRECTORY_ENTRY_IMPORT

    try:  # Get export directory (if it exists)
        export_directory = pe.DIRECTORY_ENTRY_EXPORT
    except AttributeError:
        export_directory = None

    resource_directory = pe.DIRECTORY_ENTRY_RESOURCE
    sections = pe.sections

    try:  # Get debug directory (if it exists)
        debug_information = pe.DIRECTORY_ENTRY_DEBUG
    except AttributeError:
        debug_information = None

    try:  # Get TLS (Thread Local Storage) directory (if it exists)
        tls_directory = pe.DIRECTORY_ENTRY_TLS
    except AttributeError:
        tls_directory = None

    header_info = {
        "Machine Type":         pefile.MACHINE_TYPE[file_header.Machine],
        "Entry Point":          optional_header.AddressOfEntryPoint,
        "Import Table":         parse_imports(import_directory),
        "Export Table":         parse_exports(export_directory),
        "Resource Table":       parse_resources(resource_directory),
        "Section Table":        parse_sections(sections),
        "Debug Info":           parse_debug_info(debug_information),
        "TLS Callback":         parse_tls_callback(tls_directory)
    }
    return header_info


# Parse import table
def parse_imports(import_directory):
    import_table = []
    for entry in import_directory:
        import_entry = {"DLL": entry.dll.decode('utf-8'), "Imports": []}
        for import_ in entry.imports:
            import_entry["Imports"].append(import_.name)
        import_table.append(import_entry)
    return import_table


# Parse export table
def parse_exports(export_directory):
    if export_directory is None:
        export_table = None
    else:
        export_table = []
        for export in export_directory:
            export_entry = export.name.decode('utf-8')
            export_table.append(export_entry)
    return export_table


# Parse resource table
def parse_resources(resource_directory):
    resource_table = []
    for resource_type in resource_directory.entries:
        resource_entry = {"Type": pefile.RESOURCE_TYPE.get(resource_type.id, resource_type.id), "ID": []}
        for resource_id in resource_type.directory.entries:
            resource_entry["ID"].append(resource_id.id)
        resource_table.append(resource_entry)
    return resource_table


# Parse section headers
def parse_sections(sections):
    section_table = []
    for section in sections:
        section_entry = {
            "Name":             section.Name.decode().strip("\x00"),
            "Virtual Size":     "0x{:x}".format(section.Misc_VirtualSize),
            "Virtual Address":  "0x{:x}".format(section.VirtualAddress),
            "Data Size":        "0x{:x}".format(section.SizeOfRawData),
            "Data Pointer":     "0x{:x}".format(section.PointerToRawData)
        }
        section_table.append(section_entry)
    return section_table


# Parse debug information
def parse_debug_info(debug_information):
    if debug_information is None:
        debug_table = None
    else:
        debug_table = []
        for datum in debug_information:
            debug_table.append(datum.struct.Type)
    return debug_table


# Parse the TLS (Thread Local Storage) callback
def parse_tls_callback(tls_directory):
    if tls_directory is None:
        return None
    else:
        return tls_directory.struct.AddressOfCallBacks