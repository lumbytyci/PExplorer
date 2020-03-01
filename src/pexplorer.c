#include <stdlib.h>
#include <inttypes.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>

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

    //printf("First few bytes are: \n");
    //printf("%c %c\n", *(char *)memblock, *(char *)(memblock +1));

    ms_dos_header ms_header = {0};
    extract_ms_dos_header(memblock, &ms_header);
    printf("The ms dos header: %X\n", ms_header.magic);

    if(munmap(memblock, file_size) == -1) {
        perror("Failed to delete mapping");
        exit(EXIT_FAILURE);
    }
    
    return 0;
}
