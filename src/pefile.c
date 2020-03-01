#include "pefile.h"

void extract_ms_dos_header(void *memblock, ms_dos_header *header) {
    uint16_t header_magic = *((uint16_t *)memblock);
    header->magic = header_magic;
}
