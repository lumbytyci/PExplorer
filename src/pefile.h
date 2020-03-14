#ifndef pexp_pe_file_h
#define pexp_pe_file_h

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
    uint32_t magic;
    uint16_t machine;
    uint16_t number_of_sections;
    uint32_t timestamp;
    uint32_t ptr_to_symbol_table;
    uint32_t num_of_symbols;
    uint16_t optional_header_size;
    uint16_t characteristics;
} pe_file_header;

typedef struct {
    uint16_t magic;
    uint8_t major_linker_version;
    uint8_t minor_linker_version;
    uint32_t size_of_initialized_data;
    uint32_t size_of_uninitialized_data;
    uint32_t entry_point_addr;
    uint32_t base_of_code;
} pe_optional_header_std_fields;

typedef struct {
    uint32_t image_base;
    uint32_t section_alignment;
    uint32_t file_alignment;
    uint16_t major_os_version;
    uint16_t minor_os_version;
    uint16_t major_img_version;
    uint16_t minor_img_version;
    uint16_t major_subsys_version;
    uint16_t minor_subsys_version;
    uint32_t win32_version_value;
    uint32_t size_of_image;
    uint32_t size_of_headers;
    uint32_t checksum;
    uint16_t subsystem;
    uint16_t dll_characteristics;
    uint32_t size_of_stack_reserve;
    uint32_t size_of_stack_commit;
    uint32_t size_of_heap_reserve;
    uint32_t size_of_heap_commit;
    uint32_t loader_flags;
    uint32_t num_of_rva_and_sizes;
} pe_optional_header_nt_fields;

typedef struct {
    
} pe_optional_header_data_dirs;

typedef struct {

} pe_optional_header;


void extract_ms_dos_header(void *memblock, ms_dos_header *header); 
uint32_t extract_pe_header_offset(void *memblock);
void extract_pe_header(void *memblock, pe_file_header *header);
const char* machine_value_to_str(uint16_t machine);
uint32_t is_image_file(pe_file_header *header);


#endif
