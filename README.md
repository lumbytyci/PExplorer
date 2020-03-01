[![Build Status](https://travis-ci.com/lumbytyci/PExplorer.svg?branch=master)](https://travis-ci.com/lumbytyci/PExplorer)

# PExplorer
PExplorer is a linux terminal tool written in C which handles parsing of PE files. <br>
PE (Portable Executable) is the format used by Win32 systems for executable (image) and object files, analogous <br>
to ELF in linux based systems.

Please refer to the [official documentation](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format) regarding the PE Format.

## Building
```bash
$ make
```
## Usage
```bash
$ ./pexplorer <path-to-exe>
```

## Output Example
<pre>MZ Header:
	Magic:                             0x5a4d (MZ)
	Bytes in last page:                   144
	Pages:                                  3
	Relocation items:                       0
	Header size:                            4
	Minimum allocation:                     0
	Maximum allocation:                 65535
	Initial SS:                             0
	Initial SP:                          0xb8
	Initial IP:                             0
	Initial CS:                             0
	Checksum:                               0
	Relocation table offset:             0x40

PE Header: 
	Magic:                             0x4550
	Machine:                            0x14c IMAGE_FILE_MACHINE_I386
	Number of sections:                     4
	Timestamp:                     1146304591
	Pointer to symbol table:                0
	Number of symbols:                      0
	Optional header size:                0xe0
	Characteristics:                    0x10f
	Characteristic flags:
		IMAGE_FILE_RELOCS_STRIPPED
		IMAGE_FILE_EXECUTABLE_IMAGE
		IMAGE_FILE_LINE_NUMS_STRIPPED
		IMAGE_FILE_LOCAL_SYMS_STRIPPED
		IMAGE_FILE_32BIT_MACHINE
</pre>
