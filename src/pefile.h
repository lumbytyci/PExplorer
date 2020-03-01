#ifndef pe_file_h
#define pe_file_h

#include <inttypes.h>

typedef struct {
    uint16_t magic;
} ms_dos_header;

void extract_ms_dos_header(void *memblock, ms_dos_header *header); 

#endif
