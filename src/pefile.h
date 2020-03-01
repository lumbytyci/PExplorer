#ifndef pe_file_h
#define pe_file_h

#define MS_DOS_H_SIGNATURE_LOCATION 0x3c

#include <inttypes.h>

typedef struct {
    uint16_t magic;
    uint32_t pe_header_offset;
} ms_dos_header;

void extract_ms_dos_header(void *memblock, ms_dos_header *header); 

#endif
