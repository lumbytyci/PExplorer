#include <stdlib.h>
#include <inttypes.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>

#include "pexplorer.h"
#include "pefile.h"
#include "characteristics.h"

int main(int argc, char **argv) {
    
    if(argc < 2) {
        fprintf(stderr, "Usage %s <path-to-exe>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    int fd;
    struct stat file_stats;

    fd = open(argv[1], O_RDONLY);
    if(!fd) {
        perror("Failed to open binary file");
        exit(EXIT_FAILURE);
    }

    if(fstat(fd, &file_stats) == -1) {
        perror("Failed to get file stats");
        exit(EXIT_FAILURE);
    }

    size_t file_size = file_stats.st_size;

    void *memblock = mmap(NULL, file_size, PROT_READ, MAP_PRIVATE, fd, 0); 
    if(memblock == MAP_FAILED) {
        perror("Failed to map PE file");
        exit(EXIT_FAILURE);
    }

    ms_dos_header ms_header = {0};
    extract_ms_dos_header(memblock, &ms_header);

    if(ms_header.magic != 0x5a4d) {
        fprintf(stderr, "File is not PE format.\n");
        exit(EXIT_FAILURE);
    }
    
    pe_file_header pe_header = {0};
    extract_pe_header(memblock, &pe_header);
    
    
    pexp_print_ms_dos_header(&ms_header);
    pexp_print_pe_file_header(&pe_header);

    if(munmap(memblock, file_size) == -1) {
        perror("Failed to delete mapping");
        exit(EXIT_FAILURE);
    }
    
    return 0;
}

static void pexp_print_ms_dos_header(ms_dos_header *h) {
    puts("\nMZ Header:");
    printf("\t%-25s %#15x (%c%c)\n", "Magic:", h->magic, *(char *)&h->magic, *((char *)&h->magic + 1));
    printf("\t%-25s %15u\n", "Bytes in last page:",(unsigned int)h->extra_bytes);
    printf("\t%-25s %15u\n", "Pages:", (unsigned int)h->pages);
    printf("\t%-25s %15u\n", "Relocation items:", (unsigned int)h->relocation_items);
    printf("\t%-25s %15u\n", "Header size:", (unsigned int)h->header_size);
    printf("\t%-25s %15u\n", "Minimum allocation:", (unsigned int)h->min_allocation);
    printf("\t%-25s %15u\n", "Maximum allocation:", (unsigned int)h->max_allocation);
    printf("\t%-25s %#15x\n", "Initial SS:", h->initial_ss_reg);
    printf("\t%-25s %#15x\n", "Initial SP:", h->initial_sp_reg);
    printf("\t%-25s %#15x\n", "Initial IP:", h->initial_ip_reg);
    printf("\t%-25s %#15x\n", "Initial CS:", h->initial_cs_reg);
    printf("\t%-25s %#15x\n", "Checksum:", h->checksum);
    printf("\t%-25s %#15x\n", "Relocation table offset:", h->relocation_table);
}

static void pexp_print_pe_file_header(pe_file_header *h) {
    puts("\nPE Header: ");
    printf("\t%-25s %#15x\n", "Magic:", h->magic);
    printf("\t%-25s %#15x %s\n","Machine:", h->machine, machine_value_to_str(h->machine));
    printf("\t%-25s %15u\n", "Number of sections:", (unsigned int)h->number_of_sections);
    printf("\t%-25s %15lu\n", "Timestamp:", (unsigned long)h->timestamp);
    printf("\t%-25s %#15x\n", "Pointer to symbol table:", h->ptr_to_symbol_table);
    printf("\t%-25s %15lu\n", "Number of symbols:", (unsigned long)h->num_of_symbols);
    printf("\t%-25s %#15x\n", "Optional header size:", h->optional_header_size);
    printf("\t%-25s %#15x\n", "Characteristics:", h->characteristics);
    puts("\tCharacteristic flags:");

    uint16_t c = h->characteristics;
   
    PEXP_PRINT_CHARACTERISTIC_IF_EXISTS(c, IMAGE_FILE_RELOCS_STRIPPED, "IMAGE_FILE_RELOCS_STRIPPED");
    PEXP_PRINT_CHARACTERISTIC_IF_EXISTS(c, IMAGE_FILE_EXECUTABLE_IMAGE, "IMAGE_FILE_EXECUTABLE_IMAGE");
    PEXP_PRINT_CHARACTERISTIC_IF_EXISTS(c, IMAGE_FILE_LINE_NUMS_STRIPPED, "IMAGE_FILE_LINE_NUMS_STRIPPED");
    PEXP_PRINT_CHARACTERISTIC_IF_EXISTS(c, IMAGE_FILE_LOCAL_SYMS_STRIPPED, "IMAGE_FILE_LOCAL_SYMS_STRIPPED");
    PEXP_PRINT_CHARACTERISTIC_IF_EXISTS(c, IMAGE_FILE_AGGRESSIVE_WS_TRIM, "IMAGE_FILE_AGGRESSIVE_WS_TRIM");
    PEXP_PRINT_CHARACTERISTIC_IF_EXISTS(c, IMAGE_FILE_LARGE_ADDRESS_AWARE, "IMAGE_FILE_LARGE_ADDRESS_AWARE");
    PEXP_PRINT_CHARACTERISTIC_IF_EXISTS(c, IMAGE_FILE_BYTES_REVERSED_LO, "IMAGE_FILE_BYTES_REVERSED_LO");
    PEXP_PRINT_CHARACTERISTIC_IF_EXISTS(c, IMAGE_FILE_32BIT_MACHINE, "IMAGE_FILE_32BIT_MACHINE");
    PEXP_PRINT_CHARACTERISTIC_IF_EXISTS(c, IMAGE_FILE_DEBUG_STRIPPED, "IMAGE_FILE_DEBUG_STRIPPED");
    PEXP_PRINT_CHARACTERISTIC_IF_EXISTS(c, IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP, "IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP");
    PEXP_PRINT_CHARACTERISTIC_IF_EXISTS(c, IMAGE_FILE_NET_RUN_FROM_SWAP, "IMAGE_FILE_NET_RUN_FROM_SWAP");
    PEXP_PRINT_CHARACTERISTIC_IF_EXISTS(c, IMAGE_FILE_SYSTEM, "IMAGE_FILE_SYSTEM");
    PEXP_PRINT_CHARACTERISTIC_IF_EXISTS(c, IMAGE_FILE_DLL, "IMAGE_FILE_DLL");
    PEXP_PRINT_CHARACTERISTIC_IF_EXISTS(c, IMAGE_FILE_UP_SYSTEM_ONLY, "IMAGE_FILE_UP_SYSTEM_ONLY");
    PEXP_PRINT_CHARACTERISTIC_IF_EXISTS(c, IMAGE_FILE_BYTES_REVERSED_HI, "IMAGE_FILE_BYTES_REVERSED_HI");
}
