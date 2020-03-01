#ifndef pe_file_h
#define pe_file_h

#define MS_DOS_H_SIGNATURE_LOCATION 0x3c

#include <inttypes.h>

typedef struct {
    uint16_t magic;
    uint16_t extra_bytes; /* Number of bytes in last page */
    uint16_t pages;
    uint16_t relocation_items;
    uint16_t header_size;
    uint16_t min_allocation;
    uint16_t max_allocation;
    uint16_t initial_ss_reg;
    uint16_t initial_sp_reg;
    uint16_t checksum;
    uint16_t initial_ip_reg;
    uint16_t initial_cs_reg;
    uint16_t relocation_table;
    uint16_t overlay;
} ms_dos_header;

typedef struct {

} pe_header;

void extract_ms_dos_header(void *memblock, ms_dos_header *header); 
uint32_t extract_pe_header_offset(void *memblock);

#endif
