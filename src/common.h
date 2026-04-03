#ifndef DLFREEZE_COMMON_H
#define DLFREEZE_COMMON_H

#include <stdint.h>

#define DLFRZ_MAGIC    "DLFREEZ"   /* 7 chars + NUL = 8 bytes */
#define DLFRZ_VERSION  1

#define DLFRZ_FLAG_MAIN_EXE    0x01
#define DLFRZ_FLAG_INTERP      0x02
#define DLFRZ_FLAG_SHLIB       0x04
#define DLFRZ_FLAG_DLOPEN      0x08

struct dlfrz_entry {
    uint64_t data_offset;
    uint64_t data_size;
    uint32_t flags;
    uint32_t name_offset;   /* offset into string table */
};

struct dlfrz_footer {
    char     magic[8];
    uint32_t version;
    uint32_t num_entries;
    uint64_t manifest_offset;
    uint64_t strtab_offset;
    uint64_t strtab_size;
    uint8_t  pad[24];
};

#define ALIGN_UP(x, align) (((x) + (align) - 1) & ~((uint64_t)(align) - 1))

#endif /* DLFREEZE_COMMON_H */
