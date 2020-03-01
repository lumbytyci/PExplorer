#include <stdlib.h>
#include <inttypes.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>

#include "pexplorer.h"
#include "pefile.h"

int main(int argc, char **argv) {
    int fd;
    struct stat file_stats;

    fd = open("../binaries/sample.exe", O_RDONLY);
    if(!fd) {
        perror("Failed to open binary file");
        exit(EXIT_FAILURE);
    }

    if(fstat(fd, &file_stats) == -1) {
        perror("Failed to get file stats");
        exit(EXIT_FAILURE);
    }

    size_t file_size = file_stats.st_size;
    printf("Size of the PE file is %lu bytes\n", file_size);

    void *memblock = mmap(NULL, file_size, PROT_READ, MAP_PRIVATE, fd, 0); 
    if (memblock == MAP_FAILED) {
        perror("Failed to map PE file");
        exit(EXIT_FAILURE);
    }

    ms_dos_header ms_header = {0};
    extract_ms_dos_header(memblock, &ms_header);
    // printf("PE header offset: %X\n", extract_pe_header_offset(memblock));

    pexp_print_ms_dos_header(&ms_header);

    if(munmap(memblock, file_size) == -1) {
        perror("Failed to delete mapping");
        exit(EXIT_FAILURE);
    }
    
    return 0;
}

static void pexp_print_ms_dos_header(ms_dos_header *h) {
    puts("MZ Header: \n");
    printf("\tMagic: %#x (%c%c)\n", h->magic, *(char *)&h->magic, *((char *)&h->magic + 1));
    printf("\tBytes in last page: %u\n", (unsigned int)h->extra_bytes);
    printf("\tPages: %u\n", (unsigned int)h->pages);
    printf("\tRelocation items: %u\n", (unsigned int)h->relocation_items);
    printf("\tHeader size: %u\n", (unsigned int)h->header_size);
    printf("\tMinimum allocation: %u\n", (unsigned int)h->min_allocation);
    printf("\tMaximum allocation: %u\n", (unsigned int)h->max_allocation);
    printf("\tInitial SS: %#x\n", h->initial_ss_reg);
    printf("\tInitial SP: %#x\n", h->initial_sp_reg);
    printf("\tInitial IP: %#x\n", h->initial_ip_reg);
    printf("\tInitial CS: %#x\n", h->initial_cs_reg);
    printf("\tChecksum: %#x\n", h->checksum);
    printf("\tAddress of relocation table: %#x\n", h->relocation_table);
}
