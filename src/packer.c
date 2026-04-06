#include "packer.h"
#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <elf.h>

/* Starting base address for direct-loaded objects (above bootstrap VA) */
#define DIRECT_LOAD_BASE  0x200000000ULL

/* ------------------------------------------------------------------ */
static int append_file(FILE *out, const char *path, size_t *written)
{
    FILE *in = fopen(path, "rb");
    if (!in) { perror(path); return -1; }

    char buf[65536];
    size_t total = 0, n;
    while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
        if (fwrite(buf, 1, n, out) != n) { fclose(in); return -1; }
        total += n;
    }
    fclose(in);
    *written = total;
    return 0;
}

static int write_pad(FILE *out, size_t cur, size_t align)
{
    size_t target = ALIGN_UP(cur, align);
    size_t pad = target - cur;
    while (pad > 0) {
        char zeros[4096] = {0};
        size_t chunk = pad > sizeof(zeros) ? sizeof(zeros) : pad;
        if (fwrite(zeros, 1, chunk, out) != chunk) return -1;
        pad -= chunk;
    }
    return 0;
}

static size_t filesize(const char *path)
{
    struct stat st;
    return (stat(path, &st) == 0) ? (size_t)st.st_size : 0;
}

static uint64_t find_named_symbol(FILE *f, const Elf64_Ehdr *ehdr,
                                  const char *target)
{
    if (ehdr->e_shoff == 0 || ehdr->e_shnum == 0 || ehdr->e_shentsize == 0)
        return 0;

    size_t shsz = (size_t)ehdr->e_shnum * ehdr->e_shentsize;
    uint8_t *shdrs = malloc(shsz);
    if (!shdrs) return 0;

    if (fseek(f, ehdr->e_shoff, SEEK_SET) != 0 ||
        fread(shdrs, 1, shsz, f) != shsz) {
        free(shdrs);
        return 0;
    }

    uint64_t found = 0;
    for (int i = 0; i < ehdr->e_shnum; i++) {
        Elf64_Shdr *sh = (Elf64_Shdr *)(shdrs + i * ehdr->e_shentsize);
        if (sh->sh_type != SHT_SYMTAB && sh->sh_type != SHT_DYNSYM) continue;
        if (sh->sh_link >= ehdr->e_shnum || sh->sh_entsize != sizeof(Elf64_Sym))
            continue;

        Elf64_Shdr *str_sh = (Elf64_Shdr *)(shdrs + sh->sh_link * ehdr->e_shentsize);
        char *strtab = malloc(str_sh->sh_size ? (size_t)str_sh->sh_size : 1);
        Elf64_Sym *syms = malloc(sh->sh_size ? (size_t)sh->sh_size : 1);
        if (!strtab || !syms) {
            free(strtab);
            free(syms);
            continue;
        }

        if (fseek(f, str_sh->sh_offset, SEEK_SET) != 0 ||
            fread(strtab, 1, str_sh->sh_size, f) != str_sh->sh_size ||
            fseek(f, sh->sh_offset, SEEK_SET) != 0 ||
            fread(syms, 1, sh->sh_size, f) != sh->sh_size) {
            free(strtab);
            free(syms);
            continue;
        }

        size_t nsyms = sh->sh_size / sizeof(Elf64_Sym);
        for (size_t j = 0; j < nsyms; j++) {
            Elf64_Sym *sym = &syms[j];
            if (sym->st_name >= str_sh->sh_size) continue;
            if (sym->st_shndx == SHN_UNDEF) continue;
            if (strcmp(strtab + sym->st_name, target) != 0) continue;
            found = sym->st_value;
            break;
        }

        free(strtab);
        free(syms);
        if (found) break;
    }

    free(shdrs);
    return found;
}

/*
 * Extract `main` address from _start for stripped PIE binaries.
 * Scans the entry point code for `lea disp32(%rip), %rdi` (48 8d 3d XX XX XX XX)
 * which loads the `main` pointer before calling __libc_start_main.
 */
static uint64_t find_main_from_entry(FILE *f, const Elf64_Ehdr *ehdr,
                                     const uint8_t *phdrs)
{
    uint64_t entry_va = ehdr->e_entry;

    /* Map entry VA to file offset */
    uint64_t entry_foff = 0;
    int found_seg = 0;
    for (int i = 0; i < ehdr->e_phnum; i++) {
        Elf64_Phdr *ph = (Elf64_Phdr *)(phdrs + i * ehdr->e_phentsize);
        if (ph->p_type != PT_LOAD) continue;
        if (entry_va >= ph->p_vaddr &&
            entry_va < ph->p_vaddr + ph->p_filesz) {
            entry_foff = ph->p_offset + (entry_va - ph->p_vaddr);
            found_seg = 1;
            break;
        }
    }
    if (!found_seg) return 0;

    /* Read 64 bytes at entry point */
    uint8_t code[64];
    if (fseek(f, entry_foff, SEEK_SET) != 0) return 0;
    size_t nr = fread(code, 1, sizeof(code), f);
    if (nr < 16) return 0;

    /* Scan for: 48 8d 3d XX XX XX XX  (lea disp32(%rip), %rdi) */
    for (size_t i = 0; i + 7 <= nr; i++) {
        if (code[i] == 0x48 && code[i+1] == 0x8d && code[i+2] == 0x3d) {
            int32_t disp;
            memcpy(&disp, &code[i+3], 4);
            /* RIP at time of lea = entry_va + i + 7 */
            uint64_t main_va = entry_va + i + 7 + (int64_t)disp;
            fprintf(stderr, "dlfreeze: extracted main=0x%lx from _start\n",
                    (unsigned long)main_va);
            return main_va;
        }
    }
    return 0;
}

/* ---- compute per-library metadata for direct loading ------------- */
static int compute_lib_meta(const char *path, uint64_t base, uint32_t flags,
                            struct dlfrz_lib_meta *meta)
{
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); return -1; }

    Elf64_Ehdr ehdr;
    if (fread(&ehdr, 1, sizeof(ehdr), f) != sizeof(ehdr)) {
        fclose(f); return -1;
    }
    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0 ||
        ehdr.e_ident[EI_CLASS] != ELFCLASS64) {
        fprintf(stderr, "dlfreeze: %s: not a 64-bit ELF\n", path);
        fclose(f); return -1;
    }

    meta->base_addr  = base;
    meta->entry      = ehdr.e_entry;
    meta->main_sym   = 0;
    meta->phdr_off   = (uint32_t)ehdr.e_phoff;
    meta->phdr_num   = ehdr.e_phnum;
    meta->phdr_entsz = ehdr.e_phentsize;
    meta->flags      = flags;
    meta->_reserved  = 0;

    /* Read program headers to get VA span */
    size_t phsz = ehdr.e_phnum * ehdr.e_phentsize;
    uint8_t *phdrs = malloc(phsz);
    if (!phdrs) { fclose(f); return -1; }
    fseek(f, ehdr.e_phoff, SEEK_SET);
    if (fread(phdrs, 1, phsz, f) != phsz) {
        free(phdrs); fclose(f); return -1;
    }

    uint64_t lo = UINT64_MAX, hi = 0;
    for (int i = 0; i < ehdr.e_phnum; i++) {
        Elf64_Phdr *ph = (Elf64_Phdr *)(phdrs + i * ehdr.e_phentsize);
        if (ph->p_type != PT_LOAD) continue;
        if (ph->p_vaddr < lo) lo = ph->p_vaddr;
        uint64_t end = ph->p_vaddr + ph->p_memsz;
        if (end > hi) hi = end;
    }

    if (flags & DLFRZ_FLAG_MAIN_EXE) {
        meta->main_sym = find_named_symbol(f, &ehdr, "main");
        if (!meta->main_sym)
            meta->main_sym = find_main_from_entry(f, &ehdr, phdrs);
    }

    free(phdrs);
    fclose(f);

    if (lo > hi) { lo = hi = 0; }
    meta->vaddr_lo = lo;
    meta->vaddr_hi = hi;
    return 0;
}

/* ---- ELF patching for UPX compatibility -------------------------- */
/*
 * After writing the frozen binary (bootstrap + payload), we patch the
 * ELF headers so that:
 *
 *  1. The "DLFRZLDR" sentinel in .data is filled with the payload VA
 *     and size.  This survives UPX decompression because it lives in a
 *     PT_LOAD segment.
 *
 *  2. A spare program-header entry (PT_GNU_STACK) is converted into a
 *     PT_LOAD that maps the payload region.  UPX compresses all PT_LOAD
 *     segments and decompresses them back at runtime, so the payload
 *     becomes accessible in virtual memory even after UPX.
 *
 *  3. Section-header metadata is zeroed out (UPX strips it anyway).
 */
static int patch_elf_for_upx(const char *path, size_t bootstrap_sz,
                              size_t payload_off, size_t total_sz)
{
    FILE *f = fopen(path, "r+b");
    if (!f) { perror(path); return -1; }

    /* Read enough of the bootstrap to get ELF + phdr + scan for sentinel */
    /* We need to read the full bootstrap to find DLFRZLDR in .data */
    uint8_t *hdr = malloc(bootstrap_sz);
    if (!hdr) { fclose(f); return -1; }
    if (fread(hdr, 1, bootstrap_sz, f) != bootstrap_sz) {
        free(hdr); fclose(f); return -1;
    }

    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)hdr;

    /* --- Find the highest VA used by existing PT_LOAD segments --- */
    uint64_t max_va = 0;
    for (int i = 0; i < ehdr->e_phnum; i++) {
        Elf64_Phdr *ph = (Elf64_Phdr *)(hdr + ehdr->e_phoff + i * ehdr->e_phentsize);
        if (ph->p_type == PT_LOAD) {
            uint64_t end = ph->p_vaddr + ph->p_memsz;
            if (end > max_va) max_va = end;
        }
    }

    /* Payload VA: next page-aligned address after the last PT_LOAD */
    uint64_t payload_vaddr = ALIGN_UP(max_va, 4096);
    size_t payload_filesz = total_sz - payload_off;

    /* --- Find and repurpose PT_GNU_STACK → PT_LOAD for payload --- */
    int found_stack = 0;
    for (int i = 0; i < ehdr->e_phnum; i++) {
        Elf64_Phdr *ph = (Elf64_Phdr *)(hdr + ehdr->e_phoff + i * ehdr->e_phentsize);
        if (ph->p_type == PT_GNU_STACK) {
            ph->p_type   = PT_LOAD;
            ph->p_flags  = PF_R;
            ph->p_offset = payload_off;
            ph->p_vaddr  = payload_vaddr;
            ph->p_paddr  = payload_vaddr;
            ph->p_filesz = payload_filesz;
            ph->p_memsz  = payload_filesz;
            ph->p_align  = 4096;
            found_stack = 1;
            break;
        }
    }
    if (!found_stack) {
        fprintf(stderr, "dlfreeze: warning: no PT_GNU_STACK to repurpose\n");
        /* Continue anyway — file-based path will still work */
    }

    /* --- Strip section-header table --- */
    ehdr->e_shoff     = 0;
    ehdr->e_shentsize = 0;
    ehdr->e_shnum     = 0;
    ehdr->e_shstrndx  = 0;

    /* --- Patch the DLFRZLDR sentinel in .data --- */
    const char sentinel[] = "DLFRZLDR";
    int patched = 0;
    for (size_t i = 0; i + sizeof(struct dlfrz_loader_info) <= bootstrap_sz; i++) {
        if (memcmp(hdr + i, sentinel, 8) == 0) {
            /* Verify this is our struct (followed by three zero uint64s) */
            uint64_t v1, v2, v3;
            memcpy(&v1, hdr + i + 8, 8);
            memcpy(&v2, hdr + i + 16, 8);
            memcpy(&v3, hdr + i + 24, 8);
            if (v1 == 0 && v2 == 0 && v3 == 0) {
                /* Patch with real values */
                uint64_t foff = payload_off;
                memcpy(hdr + i + 8, &payload_vaddr, 8);
                memcpy(hdr + i + 16, &payload_filesz, 8);
                memcpy(hdr + i + 24, &foff, 8);
                patched = 1;
                break;
            }
        }
    }
    if (!patched) {
        fprintf(stderr, "dlfreeze: warning: DLFRZLDR sentinel not found\n");
    }

    /* --- Write modified header back --- */
    rewind(f);
    if (fwrite(hdr, 1, bootstrap_sz, f) != bootstrap_sz) {
        free(hdr); fclose(f); return -1;
    }

    free(hdr);
    fclose(f);
    return 0;
}

/* ------------------------------------------------------------------ */
int pack_frozen(const struct pack_options *opts)
{
    FILE *out = fopen(opts->output_path, "wb");
    if (!out) { perror(opts->output_path); return -1; }

    size_t off = 0, written;

    /* 1. bootstrap binary ------------------------------------------ */
    if (append_file(out, opts->bootstrap_path, &written) < 0) goto fail;
    size_t bootstrap_sz = written;
    off += written;

    /* total entries: main-exe + interpreter? + libs */
    int nent = 1 + (opts->deps->interp_path ? 1 : 0) + opts->deps->count;
    struct dlfrz_entry *entries = calloc(nent, sizeof(*entries));
    /* Parallel array of source paths for lib_meta computation */
    const char **src_paths = calloc(nent, sizeof(char *));

    /* build string table ------------------------------------------- */
    size_t strsz = 0;
    const char *exe_base = strrchr(opts->exe_path, '/');
    exe_base = exe_base ? exe_base + 1 : opts->exe_path;
    strsz += strlen(exe_base) + 1;

    const char *interp_base = NULL;
    if (opts->deps->interp_path) {
        interp_base = strrchr(opts->deps->interp_path, '/');
        interp_base = interp_base ? interp_base + 1 : opts->deps->interp_path;
        strsz += strlen(interp_base) + 1;
    }
    for (int i = 0; i < opts->deps->count; i++)
        strsz += strlen(opts->deps->libs[i].name) + 1;

    char *strtab = calloc(1, strsz);
    size_t stroff = 0;
    int eidx = 0;

    /* 2. main executable ------------------------------------------- */
    write_pad(out, off, 4096); off = ALIGN_UP(off, 4096);
    size_t payload_off = off;   /* start of the payload region */
    entries[eidx].data_offset = off;
    entries[eidx].flags       = DLFRZ_FLAG_MAIN_EXE;
    entries[eidx].name_offset = stroff;
    strcpy(strtab + stroff, exe_base); stroff += strlen(exe_base) + 1;
    if (append_file(out, opts->exe_path, &written) < 0) goto fail2;
    entries[eidx].data_size = written;
    src_paths[eidx] = opts->exe_path;
    off += written; eidx++;

    /* 3. interpreter ----------------------------------------------- */
    if (opts->deps->interp_path) {
        write_pad(out, off, 4096); off = ALIGN_UP(off, 4096);
        entries[eidx].data_offset = off;
        entries[eidx].flags       = DLFRZ_FLAG_INTERP;
        entries[eidx].name_offset = stroff;
        strcpy(strtab + stroff, interp_base); stroff += strlen(interp_base) + 1;
        if (append_file(out, opts->deps->interp_path, &written) < 0) goto fail2;
        entries[eidx].data_size = written;
        src_paths[eidx] = opts->deps->interp_path;
        off += written; eidx++;
    }

    /* 4. shared libraries ------------------------------------------ */
    for (int i = 0; i < opts->deps->count; i++) {
        write_pad(out, off, 4096); off = ALIGN_UP(off, 4096);
        entries[eidx].data_offset = off;
        entries[eidx].flags       = DLFRZ_FLAG_SHLIB;
        if (opts->deps->libs[i].from_dlopen)
            entries[eidx].flags |= DLFRZ_FLAG_DLOPEN;
        entries[eidx].name_offset = stroff;
        strcpy(strtab + stroff, opts->deps->libs[i].name);
        stroff += strlen(opts->deps->libs[i].name) + 1;
        if (append_file(out, opts->deps->libs[i].path, &written) < 0) goto fail2;
        entries[eidx].data_size = written;
        src_paths[eidx] = opts->deps->libs[i].path;
        off += written; eidx++;
    }

    /* 5. string table ---------------------------------------------- */
    write_pad(out, off, 8); off = ALIGN_UP(off, 8);
    size_t strtab_off = off;
    if (fwrite(strtab, 1, strsz, out) != strsz) goto fail2;
    off += strsz;

    /* 6. manifest -------------------------------------------------- */
    write_pad(out, off, 8); off = ALIGN_UP(off, 8);
    size_t manifest_off = off;
    size_t manifest_sz  = eidx * sizeof(struct dlfrz_entry);
    if (fwrite(entries, 1, manifest_sz, out) != manifest_sz) goto fail2;
    off += manifest_sz;

    /* 6b. loader metadata (direct-load mode) ----------------------- */
    size_t meta_off = 0;
    if (opts->direct_load) {
        struct dlfrz_lib_meta *metas = calloc(eidx, sizeof(*metas));
        if (!metas) goto fail2;

        uint64_t base = DIRECT_LOAD_BASE;
        for (int i = 0; i < eidx; i++) {
            if (compute_lib_meta(src_paths[i], base, entries[i].flags,
                                  &metas[i]) < 0) {
                free(metas); goto fail2;
            }
            uint64_t span = metas[i].vaddr_hi - (metas[i].vaddr_lo & ~0xFFFULL);
            base += ALIGN_UP(span, 0x200000); /* 2 MB gap between objects */
        }

        write_pad(out, off, 8); off = ALIGN_UP(off, 8);
        meta_off = off;
        size_t metasz = eidx * sizeof(struct dlfrz_lib_meta);
        if (fwrite(metas, 1, metasz, out) != metasz) {
            free(metas); goto fail2;
        }
        off += metasz;
        free(metas);

        printf("  mode       : direct-load (in-process loader)\n");
    }

    /* 7. footer ---------------------------------------------------- */
    struct dlfrz_footer ft;
    memset(&ft, 0, sizeof(ft));
    memcpy(ft.magic, DLFRZ_MAGIC, 8);
    ft.version         = DLFRZ_VERSION;
    ft.num_entries     = (uint32_t)eidx;
    ft.manifest_offset = manifest_off;
    ft.strtab_offset   = strtab_off;
    ft.strtab_size     = strsz;
    /* pad[0..7] = loader metadata offset (0 if not in direct-load mode) */
    if (meta_off)
        memcpy(ft.pad, &meta_off, sizeof(meta_off));
    if (fwrite(&ft, 1, sizeof(ft), out) != sizeof(ft)) goto fail2;

    free(entries);
    free(strtab);
    free(src_paths);
    fclose(out);
    chmod(opts->output_path, 0755);

    /* 8. patch ELF for UPX compatibility --------------------------- */
    size_t total_sz = filesize(opts->output_path);
    if (patch_elf_for_upx(opts->output_path, bootstrap_sz,
                           payload_off, total_sz) < 0) {
        fprintf(stderr, "dlfreeze: ELF patching failed\n");
        return -1;
    }

    printf("Frozen binary: %s\n", opts->output_path);
    printf("  bootstrap  : %zu bytes\n", bootstrap_sz);
    printf("  embedded   : %d files\n", eidx);
    printf("  total size : %zu bytes\n", total_sz);
    return 0;

fail2:
    free(entries);
    free(strtab);
    free(src_paths);
fail:
    fprintf(stderr, "dlfreeze: packing failed\n");
    fclose(out);
    return -1;
}
