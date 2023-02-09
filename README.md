# Probabilistic Disassembly of Windows PE Binaries using Python
Authors: Jason Barbieri, Ethan Brown, & Dalton Price

## Background
This project is part of the course "COMP-5970/6970 - Binary Program Analysis" at Auburn University.

Our attempt is based primarily of the paper 
["Probabilistic Disassembly (Miller, Kwon, Sun, Zhang, Zhang, Lin)"](https://www.cs.purdue.edu/homes/zhan3299/res/ICSE19.pdf), 
published by the Purdue University Department of Computer Science

## Implementation
 - We are using the [pefile](https://pypi.org/project/pefile/) library by Ero Carrera to parse the header.

## Usage
1. Clone the project into a directory
2. Navigate to that new project root directory
3. Initiate Disassembly using the following command:
        
        python main.py [flags] [filepath]
    The following flags are provided:
    
        "-h" : Print information contained within the header
        
        In addition to "-h"
        "-i" : Print import names
        "-r" : Print resource ID's
        "-s" : Print additional section information

        "-v" : Verbose mode (Print all available information)
    <!-- tsk -->
        IMPORTANT NOTES: 
            1. The given filepath must be ABSOLUTE
            2. Any backslashes therein be escaped ("C:\Documents\example.exe" -> "C:\\Documents\\example.exe")
