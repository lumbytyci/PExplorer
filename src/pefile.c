#include "pefile.h"

void extract_ms_dos_header(void *memblock, ms_dos_header *header) {
    uint16_t header_magic = *((uint16_t *)memblock);
    uint32_t pe_signature_offset = (uint32_t)(*((uint8_t* )memblock + MS_DOS_H_SIGNATURE_LOCATION));

    header->magic = header_magic;
    header->pe_header_offset = pe_signature_offset;
}
