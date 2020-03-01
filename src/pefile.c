#include <string.h>

#include "pefile.h"

void extract_ms_dos_header(void *memblock, ms_dos_header *header) {
    memcpy(header, memblock, 28);
}

uint32_t extract_pe_header_offset(void *memblock) {
    return *(uint32_t *)((uint8_t *)memblock + MS_DOS_H_SIGNATURE_LOCATION);
}
