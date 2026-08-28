#ifndef DLFREEZE_COMMON_H
#define DLFREEZE_COMMON_H

#include <stdint.h>

#define DLFRZ_MAGIC    "DLFREEZ"   /* 7 chars + NUL = 8 bytes */
#define DLFRZ_VERSION  4

/* The direct loader uses fixed-capacity startup object state.  The packer
 * must never emit direct metadata whose ELF closure exceeds this contract. */
#define DLFRZ_DIRECT_MAX_OBJECTS 512

#define DLFRZ_FLAG_MAIN_EXE    0x01
#define DLFRZ_FLAG_INTERP      0x02
#define DLFRZ_FLAG_SHLIB       0x04
#define DLFRZ_FLAG_DLOPEN      0x08  /* object is lazy until a traced load */
#define DLFRZ_FLAG_PRELINKED   0x10  /* segments contain pre-applied relocations */
#define DLFRZ_FLAG_NEEDS_RTLD  0x20  /* imports _rtld_global/_rtld_global_ro      */
#define DLFRZ_FLAG_DATA        0x40  /* embedded data file (not ELF)              */
#define DLFRZ_FLAG_RUNTIME_SCAN 0x80 /* needs runtime special/IRELATIVE scan      */
#define DLFRZ_FLAG_DATA_VIRTUAL 0x100 /* placeholder data entry, not openable      */
#define DLFRZ_FLAG_DATA_NEGATIVE 0x200 /* path was probed at trace and did not exist */
#define DLFRZ_FLAG_DLOPEN_EARLY 0x400 /* map dormant dlopen closure before TLS setup */
#define DLFRZ_FLAG_DLOPEN_ROOT  0x800 /* object was a direct traced dlopen request     */
#define DLFRZ_FLAG_DLOPEN_PATHFUL 0x1000 /* exact traced request contains '/'           */
#define DLFRZ_FLAG_NEEDED_PATHFUL 0x2000 /* manifest name is an exact pathful DT_NEEDED */
#define DLFRZ_FLAG_DATA_DIRECTORY 0x4000 /* captured directory identity, not a file      */

/* A traced request is an alias of an ELF object, not a statement about when
 * that object enters the process.  In particular, a startup DT_NEEDED object
 * may later be opened through an exact pathful request.  DLFRZ_FLAG_DLOPEN
 * remains clear for that object so it is startup-mapped, while the request
 * offset and DLFRZ_FLAG_DLOPEN_PATHFUL retain the alias for dlopen replay.
 * Keep this flag relation shared by the producer and bootstrap admission. */
static inline int dlfrz_manifest_entry_flags_canonical(
    uint32_t flags, int has_dlopen_request,
    int dlopen_request_is_pathful)
{
    const uint32_t known_flags = DLFRZ_FLAG_MAIN_EXE |
                                 DLFRZ_FLAG_INTERP |
                                 DLFRZ_FLAG_SHLIB |
                                 DLFRZ_FLAG_DLOPEN |
                                 DLFRZ_FLAG_DATA |
                                 DLFRZ_FLAG_DATA_VIRTUAL |
                                 DLFRZ_FLAG_DATA_NEGATIVE |
                                 DLFRZ_FLAG_DLOPEN_PATHFUL |
                                 DLFRZ_FLAG_NEEDED_PATHFUL |
                                 DLFRZ_FLAG_DATA_DIRECTORY;
    const uint32_t kind = flags & (DLFRZ_FLAG_MAIN_EXE |
                                   DLFRZ_FLAG_INTERP |
                                   DLFRZ_FLAG_SHLIB |
                                   DLFRZ_FLAG_DATA);
    const uint32_t data_state = flags & (DLFRZ_FLAG_DATA_VIRTUAL |
                                         DLFRZ_FLAG_DATA_NEGATIVE |
                                         DLFRZ_FLAG_DATA_DIRECTORY);
    const int request = has_dlopen_request != 0;
    const int pathful_request = dlopen_request_is_pathful != 0;

    return (flags & ~known_flags) == 0 &&
           (kind == DLFRZ_FLAG_MAIN_EXE ||
            kind == DLFRZ_FLAG_INTERP ||
            kind == DLFRZ_FLAG_SHLIB ||
            kind == DLFRZ_FLAG_DATA) &&
           (!(flags & DLFRZ_FLAG_DLOPEN) ||
            (flags & DLFRZ_FLAG_SHLIB)) &&
           (!(flags & DLFRZ_FLAG_DLOPEN_PATHFUL) ||
            (flags & DLFRZ_FLAG_SHLIB)) &&
           (!(flags & DLFRZ_FLAG_NEEDED_PATHFUL) ||
            (flags & DLFRZ_FLAG_SHLIB)) &&
           (!data_state || (flags & DLFRZ_FLAG_DATA)) &&
           (!data_state || !(data_state & (data_state - 1))) &&
           (!request || (flags & DLFRZ_FLAG_SHLIB)) &&
           (!pathful_request || request) &&
           ((flags & DLFRZ_FLAG_DLOPEN_PATHFUL) != 0) ==
               (request && pathful_request);
}

struct dlfrz_entry {
    uint64_t data_offset;
    uint64_t data_size;
    uint32_t flags;
    uint32_t name_offset;   /* dependency/extraction identity in strtab */
    uint32_t dlopen_request_offset; /* exact traced request, or zero */
    /* Exact first loader-visible l_name.  Zero means name_offset; this keeps
     * main/data entries canonical while separating DSO lookup identity from
     * introspection and $ORIGIN ownership. */
    uint32_t logical_name_offset;
};

struct dlfrz_footer {
    char     magic[8];
    uint32_t version;
    uint32_t num_entries;
    uint64_t manifest_offset;
    uint64_t strtab_offset;
    uint64_t strtab_size;
    uint8_t  pad[24]; /* [0..7]=meta_off, [8..15]=fixup_off, [16..23]=fixup_count */
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
    uint64_t phdr_file_off; /* external table's exact e_phoff, or zero */
    uint32_t phdr_off;      /* table vaddr, or DLFRZ_PHDR_EXTERNAL     */
    uint16_t phdr_num;      /* e_phnum                                */
    uint16_t phdr_entsz;    /* e_phentsize                            */
    uint32_t flags;         /* DLFRZ_FLAG_*                           */
    uint32_t runtime_fixup_off;   /* index into footer fixup table      */
    uint32_t runtime_fixup_count; /* number of runtime fixups           */
    uint32_t _reserved;
};

/* A valid ELF program-header table need not be covered by PT_LOAD.  Direct
 * mode retains an aligned, read-only copy for that case.  Keeping the exact
 * 64-bit file offset in phdr_file_off avoids narrowing valid large/sparse
 * ELF files while preserving the metadata structure's format and size. */
#define DLFRZ_PHDR_EXTERNAL UINT32_MAX

#define ALIGN_UP(x, align) (((x) + (align) - 1) & ~((uint64_t)(align) - 1))

#endif /* DLFREEZE_COMMON_H */
