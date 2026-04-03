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

/*
 * Loader-info sentinel — lives in the bootstrap's .data section.
 * The packer patches payload_vaddr / payload_filesz after writing the frozen
 * binary.  At runtime the bootstrap checks these fields; when UPX (or a
 * similar tool) has compressed the binary, the footer at EOF may be damaged,
 * but this struct is inside a PT_LOAD segment and survives decompression.
 */
#define DLFRZ_LOADER_MAGIC "DLFRZLDR"

struct dlfrz_loader_info {
    char     magic[8];         /* "DLFRZLDR"                          */
    uint64_t payload_vaddr;    /* VA where the payload is mapped      */
    uint64_t payload_filesz;   /* bytes from payload start to EOF     */
    uint64_t payload_foff;     /* file-offset where payload starts    */
};

/*
 * Per-library metadata for the in-process loader (-d mode).
 * One entry per dlfrz_entry, same index.
 * Written by the packer right before the footer.
 * The footer's pad[0..7] holds the file offset of this array (0 if absent).
 */
struct dlfrz_lib_meta {
    uint64_t base_addr;     /* pre-assigned load address              */
    uint64_t vaddr_lo;      /* lowest PT_LOAD p_vaddr                 */
    uint64_t vaddr_hi;      /* highest (p_vaddr + p_memsz)            */
    uint64_t entry;         /* e_entry (raw value from ELF header)    */
    uint32_t phdr_off;      /* e_phoff                                */
    uint16_t phdr_num;      /* e_phnum                                */
    uint16_t phdr_entsz;    /* e_phentsize                            */
    uint32_t flags;         /* DLFRZ_FLAG_*                           */
    uint32_t _reserved;
};

#define ALIGN_UP(x, align) (((x) + (align) - 1) & ~((uint64_t)(align) - 1))

#endif /* DLFREEZE_COMMON_H */
