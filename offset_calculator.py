"""
offset_calculator.py
@Author - Dalton Price - dhp0015@auburn.edu
@Version - 14 FEB 23
Calculate the offset of the file from the file entry point
"""
import filepath as filepath
import pefile

pe = pefile.PE(filepath)
text_section = None
data_section = None

# get the entry point
entrypoint = pe.OPTIONAL_HEADER.AddressOfEntryPoint

# compute memory address where the entry code will be loaded into memory
entrypoint_address = entrypoint + pe.OPTIONAL_HEADER.ImageBase

# loop through all sections in pe file
for section in pe.sections:
    if section.Name.decode().strip('\x00') == '.text':
        text_section = section
        text_section_address = text_section.VirtualAddress
        break
    if section.Name.decode().strip('\x00') == '.data':
        data_section = section
        break

text_offset = text_section.PointerToRawData
data_offset = data_section.PointerToRawData

result = entrypoint_address + text_offset
print(f'The offset of the .text section is 0x{text_offset:X}')


#could us the data gotten in the print header.py and do calcs w that