#include <string.h>

#include "pefile.h"

void extract_ms_dos_header(void *memblock, ms_dos_header *header) {
    memcpy(header, memblock, 28);
}

uint32_t extract_pe_header_offset(void *memblock) {
    return *(uint32_t *)((uint8_t *)memblock + MS_DOS_H_SIGNATURE_LOCATION);
}

void extract_pe_header(void *memblock, pe_file_header *header) {
    uint32_t pe_header_offset = extract_pe_header_offset(memblock);
    memcpy(header, (uint8_t *)memblock + pe_header_offset, 24);
}

const char* machine_value_to_str(uint16_t machine) {
    switch(machine) {
        case 0x0:
            return "IMAGE_FILE_MACHINE_UNKNOWN\0";
        case 0x1d3:
            return "IMAGE_FILE_MACHINE_AM33\0";
        case 0x8664:
            return "IMAGE_FILE_MACHINE_AMD64\0";
        case 0x1c0:
            return "IMAGE_FILE_MACHINE_ARM\0";
        case 0xaa64:
            return "IMAGE_FILE_MACHINE_ARM64\0";
        case 0x1c4:
            return "IMAGE_FILE_MACHINE_ARMNT\0";
        case 0xebc:
            return "IMAGE_FILE_MACHINE_EBC\0";
        case 0x14c:
            return "IMAGE_FILE_MACHINE_I386\0";
        case 0x200:
            return "IMAGE_FILE_MACHINE_IA64\0";
        case 0x9041:
            return "IMAGE_FILE_MACHINE_M32R\0";
        case 0x266:
            return "IMAGE_FILE_MACHINE_MIPS16\0";
        case 0x366:
            return "IMAGE_FILE_MACHINE_MIPSFPU\0";
        case 0x466:
            return "IMAGE_FILE_MACHINE_MIPSFPU16\0";
        case 0x1f0:
            return "IMAGE_FILE_MACHINE_POWERPC\0";
        case 0x1f1:
            return "IMAGE_FILE_MACHINE_POWERPCFP\0";
        case 0x166:
            return "IMAGE_FILE_MACHINE_R4000\0";
        case 0x5032:
            return "IMAGE_FILE_MACHINE_RISCV32\0";
        case 0x5064:
            return "IMAGE_FILE_MACHINE_RISCV64\0";
        case 0x5128:
            return "IMAGE_FILE_MACHINE_RISCV128\0";
        case 0x1a2:
            return "IMAGE_FILE_MACHINE_SH3\0";
        case 0x1a3:
            return "IMAGE_FILE_MACHINE_SH3DSP\0";
        case 0x1a6:
            return "IMAGE_FILE_MACHINE_SH4\0";
        case 0x1a8:
            return "IMAGE_FILE_MACHINE_SH5\0";
        case 0x1c2:
            return "IMAGE_FILE_MACHINE_THUMB\0";
        case 0x169:
            return "IMAGE_FILE_MACHINE_WCEMIPSV2\0";
    }
}
