#include "glibc_layout.h"

#include <elf.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

enum {
    IMAGE_SIZE = 1024,
    DYNAMIC_OFFSET = 192,
    DYNSYM_OFFSET = 320,
    DYNSTR_OFFSET = 384,
    GNU_HASH_OFFSET = 448,
    GNU_HASH_SHIFT_OFFSET = GNU_HASH_OFFSET + 3 * sizeof(uint32_t)
};

static void store_u32(unsigned char *where, uint32_t value)
{
    memcpy(where, &value, sizeof(value));
}

static int build_valid_image(unsigned char image[IMAGE_SIZE])
{
    Elf64_Ehdr ehdr = {0};
    Elf64_Phdr phdr[2] = {{0}};
    Elf64_Dyn dynamic[6] = {{0}};
    Elf64_Sym symbols[2] = {{0}};
    uint64_t bloom = UINT64_MAX;
    const char strings[] = "\0gnu_hash_shift_probe";
    const uint32_t name_hash =
        dlfrz_elf64_gnu_name_hash("gnu_hash_shift_probe");

    memset(image, 0, IMAGE_SIZE);
    memcpy(ehdr.e_ident, ELFMAG, SELFMAG);
    ehdr.e_ident[EI_CLASS] = ELFCLASS64;
    ehdr.e_ident[EI_DATA] = ELFDATA2LSB;
    ehdr.e_ident[EI_VERSION] = EV_CURRENT;
    ehdr.e_type = ET_DYN;
#if defined(__x86_64__)
    ehdr.e_machine = EM_X86_64;
#elif defined(__aarch64__)
    ehdr.e_machine = EM_AARCH64;
#else
#error unsupported test architecture
#endif
    ehdr.e_version = EV_CURRENT;
    ehdr.e_ehsize = sizeof(ehdr);
    ehdr.e_phoff = sizeof(ehdr);
    ehdr.e_phentsize = sizeof(Elf64_Phdr);
    ehdr.e_phnum = 2;

    phdr[0].p_type = PT_LOAD;
    phdr[0].p_flags = PF_R;
    phdr[0].p_filesz = IMAGE_SIZE;
    phdr[0].p_memsz = IMAGE_SIZE;
    phdr[0].p_align = 8;
    phdr[1].p_type = PT_DYNAMIC;
    phdr[1].p_flags = PF_R;
    phdr[1].p_offset = DYNAMIC_OFFSET;
    phdr[1].p_vaddr = DYNAMIC_OFFSET;
    phdr[1].p_filesz = sizeof(dynamic);
    phdr[1].p_memsz = sizeof(dynamic);
    phdr[1].p_align = 8;

    dynamic[0].d_tag = DT_SYMTAB;
    dynamic[0].d_un.d_ptr = DYNSYM_OFFSET;
    dynamic[1].d_tag = DT_STRTAB;
    dynamic[1].d_un.d_ptr = DYNSTR_OFFSET;
    dynamic[2].d_tag = DT_STRSZ;
    dynamic[2].d_un.d_val = sizeof(strings);
    dynamic[3].d_tag = DT_SYMENT;
    dynamic[3].d_un.d_val = sizeof(Elf64_Sym);
    dynamic[4].d_tag = DT_GNU_HASH;
    dynamic[4].d_un.d_ptr = GNU_HASH_OFFSET;
    dynamic[5].d_tag = DT_NULL;

    symbols[1].st_name = 1;
    symbols[1].st_info = ELF64_ST_INFO(STB_GLOBAL, STT_FUNC);
    symbols[1].st_shndx = 1;

    memcpy(image, &ehdr, sizeof(ehdr));
    memcpy(image + ehdr.e_phoff, phdr, sizeof(phdr));
    memcpy(image + DYNAMIC_OFFSET, dynamic, sizeof(dynamic));
    memcpy(image + DYNSYM_OFFSET, symbols, sizeof(symbols));
    memcpy(image + DYNSTR_OFFSET, strings, sizeof(strings));

    store_u32(image + GNU_HASH_OFFSET, 1);                  /* nbuckets */
    store_u32(image + GNU_HASH_OFFSET + 4, 1);              /* symoffset */
    store_u32(image + GNU_HASH_OFFSET + 8, 1);              /* bloom size */
    store_u32(image + GNU_HASH_SHIFT_OFFSET, 31);           /* valid edge */
    memcpy(image + GNU_HASH_OFFSET + 16, &bloom, sizeof(bloom));
    store_u32(image + GNU_HASH_OFFSET + 24, 1);             /* bucket */
    store_u32(image + GNU_HASH_OFFSET + 28, name_hash | 1); /* chain */
    return 1;
}

static int rejects_shift(unsigned char image[IMAGE_SIZE],
                         const struct dlfrz_elf64_dyn_view *valid_view,
                         uint32_t shift)
{
    struct dlfrz_elf64_dyn_view reparsed;
    int exported;
    int parsed;

    store_u32(image + GNU_HASH_SHIFT_OFFSET, shift);

    /* Exercise the lookup helper independently of parser admission.  Before
     * the bound was shared with the runtime parser this expression shifted a
     * 32-bit hash by 32 or more, which is undefined behavior. */
    exported = dlfrz_elf64_gnu_hash_exports(
        valid_view, "gnu_hash_shift_probe", 1);
    parsed = dlfrz_elf64_dyn_view_init(image, IMAGE_SIZE, &reparsed);
    if (exported != 0 || parsed != 0) {
        fprintf(stderr,
                "GNU hash bloom shift %u was admitted (export=%d parse=%d)\n",
                shift, exported, parsed);
        return 0;
    }
    return 1;
}

int main(void)
{
    _Alignas(8) unsigned char image[IMAGE_SIZE];
    struct dlfrz_elf64_dyn_view view;

    if (!build_valid_image(image) ||
        !dlfrz_elf64_dyn_view_init(image, sizeof(image), &view) ||
        dlfrz_elf64_dyn_view_find(
            &view, "gnu_hash_shift_probe", NULL, NULL) != 1) {
        fputs("valid GNU hash boundary control was rejected\n", stderr);
        return 1;
    }
    if (!rejects_shift(image, &view, 32) ||
        !rejects_shift(image, &view, 63) ||
        !rejects_shift(image, &view, UINT32_MAX))
        return 1;

    store_u32(image + GNU_HASH_SHIFT_OFFSET, 31);
    if (!dlfrz_elf64_dyn_view_init(image, sizeof(image), &view) ||
        dlfrz_elf64_dyn_view_find(
            &view, "gnu_hash_shift_probe", NULL, NULL) != 1) {
        fputs("valid GNU hash control did not survive mutation restore\n",
              stderr);
        return 1;
    }
    return 0;
}
