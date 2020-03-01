#ifndef pexp_pexplorer_h
#define pexp_pexplorer_h

#include "pefile.h"

static void pexp_print_ms_dos_header(ms_dos_header *header);
static void pexp_print_pe_file_header(pe_file_header *header);

#define PEXP_PRINT_CHARACTERISTIC_IF_EXISTS(chr, flag, msg) \
    if(chr & flag) {                                        \
        printf("\t\t%s\n", msg);                              \
    }                                                       \

#endif
