#include "packer.h"
#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
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

/* ==== Pre-linker: resolve relocations at freeze time ================== */

/*
 * Pre-link all objects: apply relocations offline so the loader can skip
 * the relocation pass at runtime.  This is done in a child process that
 * mmaps libraries at their assigned base addresses, runs the relocation
 * engine (including IRELATIVE resolvers), and writes the patched writable
 * segments back to the frozen binary.
 */

struct prelink_obj {
    const char       *name;
    uint64_t          base;
    uint32_t          flags;
    const Elf64_Sym  *dynsym;
    const char       *dynstr;
    uint32_t          dynsym_count;
    const uint32_t   *gnu_hash;
    const uint16_t   *versym;

    const Elf64_Rela *rela;
    size_t            rela_count;
    const Elf64_Rela *jmprel;
    size_t            jmprel_count;
    const Elf64_Relr *relr;
    size_t            relr_count;

    int64_t           tls_tpoff;
    size_t            tls_modid;
    uint64_t          tls_memsz;
    uint64_t          tls_align;
};

static uint32_t pl_gnu_hash(const char *name)
{
    uint32_t h = 5381;
    for (const uint8_t *p = (const uint8_t *)name; *p; p++)
        h = h * 33 + *p;
    return h;
}

static const Elf64_Sym *pl_lookup_gnu(const struct prelink_obj *obj,
                                       const char *name, uint32_t gh)
{
    const uint32_t *ht = obj->gnu_hash;
    if (!ht) return NULL;
    uint32_t nbuckets = ht[0], symoffset = ht[1], bloom_size = ht[2], bloom_shift = ht[3];
    const uint64_t *bloom = (const uint64_t *)&ht[4];
    const uint32_t *buckets = (const uint32_t *)(bloom + bloom_size);
    const uint32_t *chain = &buckets[nbuckets];

    uint64_t word = bloom[(gh / 64) % bloom_size];
    uint64_t mask = (1ULL << (gh % 64)) | (1ULL << ((gh >> bloom_shift) % 64));
    if ((word & mask) != mask) return NULL;

    uint32_t idx = buckets[gh % nbuckets];
    if (idx < symoffset) return NULL;

    const Elf64_Sym *fallback = NULL;
    for (;;) {
        uint32_t hv = chain[idx - symoffset];
        if ((hv | 1) == (gh | 1)) {
            const Elf64_Sym *s = &obj->dynsym[idx];
            if (s->st_shndx != 0 && strcmp(obj->dynstr + s->st_name, name) == 0) {
                /* Prefer default version (versym without HIDDEN bit) */
                if (!obj->versym || !(obj->versym[idx] & 0x8000))
                    return s;
                if (!fallback)
                    fallback = s;
            }
        }
        if (hv & 1) break;
        idx++;
    }
    return fallback;
}

static const Elf64_Sym *pl_lookup_linear(const struct prelink_obj *obj,
                                          const char *name)
{
    const Elf64_Sym *fallback = NULL;
    for (uint32_t i = 1; i < obj->dynsym_count; i++) {
        const Elf64_Sym *s = &obj->dynsym[i];
        if (s->st_shndx == 0) continue;
        if (strcmp(obj->dynstr + s->st_name, name) == 0) {
            if (!obj->versym || !(obj->versym[i] & 0x8000))
                return s;
            if (!fallback)
                fallback = s;
        }
    }
    return fallback;
}

static uint64_t pl_resolve_sym(struct prelink_obj *objs, int nobj,
                                const char *name)
{
    uint32_t gh = pl_gnu_hash(name);
    for (int i = 0; i < nobj; i++) {
        const Elf64_Sym *sym = objs[i].gnu_hash
            ? pl_lookup_gnu(&objs[i], name, gh)
            : pl_lookup_linear(&objs[i], name);
        if (sym) {
            /* Don't call IFUNC resolvers at pre-link time — they need
             * _rtld_global_ro from the embedded GOT which isn't seeded
             * yet.  Return 0; the loader will resolve IFUNC at runtime. */
            if (ELF64_ST_TYPE(sym->st_info) == STT_GNU_IFUNC)
                return 0;
            return objs[i].base + sym->st_value;
        }
    }
    return 0;
}

static void pl_parse_dynamic(struct prelink_obj *obj, uint64_t base,
                              const uint8_t *phdr_base,
                              uint16_t phdr_num, uint16_t phdr_entsz)
{
    const Elf64_Phdr *dyn_ph = NULL;
    for (int i = 0; i < phdr_num; i++) {
        const Elf64_Phdr *ph = (const Elf64_Phdr *)(phdr_base + i * phdr_entsz);
        if (ph->p_type == PT_DYNAMIC) { dyn_ph = ph; break; }
    }
    if (!dyn_ph) return;

    const Elf64_Dyn *dyn = (const Elf64_Dyn *)(base + dyn_ph->p_vaddr);
    size_t dyn_count = dyn_ph->p_memsz / sizeof(Elf64_Dyn);

    uint64_t symtab = 0, strtab = 0, strsz = 0;
    uint64_t v_rela = 0, rela_sz = 0;
    uint64_t jmprel = 0, pltrelsz = 0;
    uint64_t v_relr = 0, relr_sz = 0;
    uint64_t hash_addr = 0;
    uint64_t versym_addr = 0;

    for (size_t i = 0; i < dyn_count && dyn[i].d_tag != DT_NULL; i++) {
        switch (dyn[i].d_tag) {
        case DT_SYMTAB:       symtab = dyn[i].d_un.d_ptr;       break;
        case DT_STRTAB:       strtab = dyn[i].d_un.d_ptr;       break;
        case DT_STRSZ:        strsz  = dyn[i].d_un.d_val;       break;
        case DT_RELA:         v_rela = dyn[i].d_un.d_ptr;       break;
        case DT_RELASZ:       rela_sz = dyn[i].d_un.d_val;      break;
        case DT_JMPREL:       jmprel = dyn[i].d_un.d_ptr;       break;
        case DT_PLTRELSZ:     pltrelsz = dyn[i].d_un.d_val;     break;
        case DT_GNU_HASH:     hash_addr = dyn[i].d_un.d_ptr;    break;
        case DT_VERSYM:       versym_addr = dyn[i].d_un.d_ptr;  break;
        case 36: /* DT_RELR */   v_relr = dyn[i].d_un.d_ptr;    break;
        case 35: /* DT_RELRSZ */ relr_sz = dyn[i].d_un.d_val;   break;
        }
    }

    if (symtab)      obj->dynsym   = (const Elf64_Sym *)(base + symtab);
    if (strtab)      obj->dynstr   = (const char *)(base + strtab);
    if (hash_addr)   obj->gnu_hash = (const uint32_t *)(base + hash_addr);
    if (versym_addr) obj->versym   = (const uint16_t *)(base + versym_addr);

    if (obj->gnu_hash) {
        const uint32_t *ht = obj->gnu_hash;
        uint32_t nb = ht[0], so = ht[1], bs = ht[2];
        const uint32_t *bk = (const uint32_t *)((const uint64_t *)&ht[4] + bs);
        const uint32_t *ch = &bk[nb];
        uint32_t mx = so;
        for (uint32_t b = 0; b < nb; b++)
            if (bk[b] > mx) mx = bk[b];
        if (mx >= so)
            while (!(ch[mx - so] & 1)) mx++;
        obj->dynsym_count = mx + 1;
    } else if (strsz > 0 && strtab > symtab) {
        obj->dynsym_count = (uint32_t)((strtab - symtab) / sizeof(Elf64_Sym));
    }

    if (v_rela)     obj->rela       = (const Elf64_Rela *)(base + v_rela);
    obj->rela_count   = rela_sz / sizeof(Elf64_Rela);
    if (jmprel)     obj->jmprel     = (const Elf64_Rela *)(base + jmprel);
    obj->jmprel_count = pltrelsz / sizeof(Elf64_Rela);
    if (v_relr)     obj->relr       = (const Elf64_Relr *)(base + v_relr);
    obj->relr_count   = relr_sz / sizeof(Elf64_Relr);

    for (int i = 0; i < phdr_num; i++) {
        const Elf64_Phdr *ph = (const Elf64_Phdr *)(phdr_base + i * phdr_entsz);
        if (ph->p_type == PT_TLS) {
            obj->tls_memsz  = ph->p_memsz;
            obj->tls_align  = ph->p_align ? ph->p_align : 1;
            break;
        }
    }
}

static void pl_apply_relr(struct prelink_obj *obj)
{
    uint64_t base = obj->base;
    const Elf64_Relr *relr = obj->relr;
    size_t count = obj->relr_count;
    uint64_t *where = NULL;

    for (size_t i = 0; i < count; i++) {
        Elf64_Relr entry = relr[i];
        if ((entry & 1) == 0) {
            where = (uint64_t *)(base + entry);
            *where++ += base;
        } else {
            uint64_t bitmap = entry >> 1;
            for (int j = 0; bitmap; j++, bitmap >>= 1)
                if (bitmap & 1)
                    where[j] += base;
            where += 63;
        }
    }
}

static int pl_apply_rela(struct prelink_obj *obj,
                          const Elf64_Rela *rtab, size_t count,
                          struct prelink_obj *all, int nobj, int pass)
{
    uint64_t base = obj->base;
    for (size_t i = 0; i < count; i++) {
        const Elf64_Rela *r = &rtab[i];
        uint64_t *slot = (uint64_t *)(base + r->r_offset);
        uint32_t type  = ELF64_R_TYPE(r->r_info);
        uint32_t sidx  = ELF64_R_SYM(r->r_info);

        if (type == R_X86_64_IRELATIVE) {
            /* Skip IRELATIVE at pre-link time — resolver needs a seeded
             * _rtld_global_ro GOT entry.  Loader handles these at runtime. */
            continue;
        }
        if (pass == 1) continue;

        switch (type) {
        case R_X86_64_RELATIVE:
            *slot = base + r->r_addend;
            break;

        case R_X86_64_GLOB_DAT:
        case R_X86_64_JUMP_SLOT:
        case R_X86_64_64: {
            const char *name = obj->dynstr + obj->dynsym[sidx].st_name;
            uint64_t addr = pl_resolve_sym(all, nobj, name);
            *slot = addr + r->r_addend;
            break;
        }

        case R_X86_64_COPY: {
            const char *name = obj->dynstr + obj->dynsym[sidx].st_name;
            uint64_t src_size = obj->dynsym[sidx].st_size;
            for (int j = 0; j < nobj; j++) {
                if (&all[j] == obj) continue;
                const Elf64_Sym *s = all[j].gnu_hash
                    ? pl_lookup_gnu(&all[j], name, pl_gnu_hash(name))
                    : pl_lookup_linear(&all[j], name);
                if (s && s->st_shndx != 0) {
                    uint64_t sz = src_size ? src_size : s->st_size;
                    memcpy((void *)(base + r->r_offset),
                           (void *)(all[j].base + s->st_value), sz);
                    break;
                }
            }
            break;
        }

        case R_X86_64_TPOFF64: {
            if (sidx != 0) {
                const char *name = obj->dynstr + obj->dynsym[sidx].st_name;
                for (int j = 0; j < nobj; j++) {
                    const Elf64_Sym *s = all[j].gnu_hash
                        ? pl_lookup_gnu(&all[j], name, pl_gnu_hash(name))
                        : pl_lookup_linear(&all[j], name);
                    if (s && s->st_shndx != 0) {
                        *(int64_t *)slot = all[j].tls_tpoff + (int64_t)s->st_value + r->r_addend;
                        goto tpoff_done;
                    }
                }
                *(int64_t *)slot = obj->tls_tpoff + r->r_addend;
            } else {
                *(int64_t *)slot = obj->tls_tpoff + r->r_addend;
            }
            tpoff_done:
            break;
        }

        case R_X86_64_DTPMOD64: {
            if (sidx != 0) {
                const char *name = obj->dynstr + obj->dynsym[sidx].st_name;
                size_t mid = obj->tls_modid ? obj->tls_modid : 1;
                for (int j = 0; j < nobj; j++) {
                    const Elf64_Sym *s = all[j].gnu_hash
                        ? pl_lookup_gnu(&all[j], name, pl_gnu_hash(name))
                        : pl_lookup_linear(&all[j], name);
                    if (s && s->st_shndx != 0) {
                        mid = all[j].tls_modid ? all[j].tls_modid : (size_t)(j + 1);
                        break;
                    }
                }
                *slot = mid;
            } else {
                *slot = obj->tls_modid ? obj->tls_modid : 1;
            }
            break;
        }

        case R_X86_64_DTPOFF64: {
            if (sidx != 0) {
                uint64_t off = obj->dynsym[sidx].st_value;
                if (obj->dynsym[sidx].st_shndx == 0) {
                    const char *name = obj->dynstr + obj->dynsym[sidx].st_name;
                    for (int j = 0; j < nobj; j++) {
                        const Elf64_Sym *s = all[j].gnu_hash
                            ? pl_lookup_gnu(&all[j], name, pl_gnu_hash(name))
                            : pl_lookup_linear(&all[j], name);
                        if (s && s->st_shndx != 0) {
                            off = s->st_value;
                            break;
                        }
                    }
                }
                *slot = off + r->r_addend;
            } else {
                *slot = r->r_addend;
            }
            break;
        }

        default:
            break;
        }
    }
    return 0;
}

static int prelink_objects(const char *output_path,
                           const struct dlfrz_entry *entries,
                           const struct dlfrz_lib_meta *metas,
                           int nobj)
{
    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return -1; }

    if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
            return 0;
        fprintf(stderr, "dlfreeze: pre-linker %s\n",
                WIFSIGNALED(status) ? "crashed" : "failed");
        return -1;
    }

    /* ==== Child process ==== */

    FILE *outf = fopen(output_path, "r+b");
    if (!outf) _exit(1);

    struct prelink_obj *objs = calloc(nobj, sizeof(*objs));
    if (!objs) _exit(1);

    /* 1. Map all objects at assigned base addresses and load segments */
    for (int i = 0; i < nobj; i++) {
        const struct dlfrz_lib_meta *m = &metas[i];
        uint64_t base = m->base_addr;

            /* Skip ld.so — the loader never maps it at runtime */
            if (m->flags & DLFRZ_FLAG_INTERP) continue;

        uint64_t lo   = m->vaddr_lo & ~0xFFFULL;
        uint64_t hi   = ALIGN_UP(m->vaddr_hi, 4096);
        uint64_t span = hi - lo + 4 * 4096;

        void *mapped = mmap((void *)(base + lo), span,
                            PROT_READ | PROT_WRITE | PROT_EXEC,
                            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
                            -1, 0);
        if (mapped == MAP_FAILED) _exit(1);

        /* Read program headers */
        size_t phsz = m->phdr_num * m->phdr_entsz;
        uint8_t *phdr_buf = malloc(phsz);
        if (!phdr_buf) _exit(1);
        fseek(outf, entries[i].data_offset + m->phdr_off, SEEK_SET);
        if (fread(phdr_buf, 1, phsz, outf) != phsz) _exit(1);

        /* Load each PT_LOAD segment */
        for (int p = 0; p < m->phdr_num; p++) {
            const Elf64_Phdr *ph = (const Elf64_Phdr *)(phdr_buf + p * m->phdr_entsz);
            if (ph->p_type != PT_LOAD || ph->p_filesz == 0) continue;
            fseek(outf, entries[i].data_offset + ph->p_offset, SEEK_SET);
            if (fread((void *)(base + ph->p_vaddr), 1, ph->p_filesz, outf) != ph->p_filesz)
                _exit(1);
            if (ph->p_memsz > ph->p_filesz)
                memset((void *)(base + ph->p_vaddr + ph->p_filesz), 0,
                       ph->p_memsz - ph->p_filesz);
        }

        objs[i].base = base;
        objs[i].flags = m->flags;
        objs[i].name = "";

        /* 2. Parse PT_DYNAMIC */
        pl_parse_dynamic(&objs[i], base,
                         (const uint8_t *)(base + m->phdr_off),
                         m->phdr_num, m->phdr_entsz);

        free(phdr_buf);
    }

    /* 3. Compute TLS layout (same algorithm as loader).
     * modid must match the loader's scheme: modid = (non-INTERP index) + 1.
     * The loader iterates only non-INTERP objects and assigns oi+1, so we
     * must count the same way — INTERP objects don't occupy an oi slot. */
    uint64_t total_tls = 0;
    int oi = 0;  /* non-INTERP object counter; matches loader's oi */
    for (int i = 0; i < nobj; i++) {
        if (metas[i].flags & DLFRZ_FLAG_INTERP) continue;  /* no oi slot */
        if (objs[i].tls_memsz > 0) {
            uint64_t align = objs[i].tls_align;
            total_tls = ALIGN_UP(total_tls + objs[i].tls_memsz, align);
            objs[i].tls_tpoff = -(int64_t)total_tls;
            objs[i].tls_modid = (size_t)(oi + 1);  /* matches loader's oi+1 */
        }
        oi++;
    }

    /* 4. Apply relocations */
    /* Pass 0: all except IRELATIVE */
    for (int i = 0; i < nobj; i++) {
            if (metas[i].flags & DLFRZ_FLAG_INTERP) continue;
        pl_apply_relr(&objs[i]);
        if (objs[i].rela_count > 0)
            pl_apply_rela(&objs[i], objs[i].rela, objs[i].rela_count,
                          objs, nobj, 0);
        if (objs[i].jmprel_count > 0)
            pl_apply_rela(&objs[i], objs[i].jmprel, objs[i].jmprel_count,
                          objs, nobj, 0);
    }
    /* Pass 1: IRELATIVE (resolvers can read populated GOTs) */
    for (int i = 0; i < nobj; i++) {
            if (metas[i].flags & DLFRZ_FLAG_INTERP) continue;
        if (objs[i].rela_count > 0)
            pl_apply_rela(&objs[i], objs[i].rela, objs[i].rela_count,
                          objs, nobj, 1);
        if (objs[i].jmprel_count > 0)
            pl_apply_rela(&objs[i], objs[i].jmprel, objs[i].jmprel_count,
                          objs, nobj, 1);
    }

    /* 5. Write patched segments back to frozen binary */
    for (int i = 0; i < nobj; i++) {
        const struct dlfrz_lib_meta *m = &metas[i];
            if (m->flags & DLFRZ_FLAG_INTERP) continue;
        uint64_t base = objs[i].base;
        const uint8_t *phdr_mem = (const uint8_t *)(base + m->phdr_off);

        for (int p = 0; p < m->phdr_num; p++) {
            const Elf64_Phdr *ph = (const Elf64_Phdr *)(phdr_mem + p * m->phdr_entsz);
            if (ph->p_type != PT_LOAD || ph->p_filesz == 0) continue;
            uint64_t foff = entries[i].data_offset + ph->p_offset;
            fseek(outf, foff, SEEK_SET);
            if (fwrite((void *)(base + ph->p_vaddr), 1, ph->p_filesz, outf) != ph->p_filesz)
                _exit(1);
        }
    }

    fclose(outf);
    free(objs);
    _exit(0);
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
    struct dlfrz_lib_meta *metas = NULL;
    if (opts->direct_load) {
        metas = calloc(eidx, sizeof(*metas));
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

    /* Save entries/count for pre-linker (called after fclose) */
    int eidx_save = eidx;
    struct dlfrz_entry *entries_copy = NULL;
    if (metas) {
        entries_copy = malloc(eidx * sizeof(*entries));
        if (entries_copy)
            memcpy(entries_copy, entries, eidx * sizeof(*entries));
    }

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
        free(metas);
        return -1;
    }

    /* 9. pre-link: apply relocations at freeze time ---------------- */
    if (metas) {
        printf("  pre-linking...\n");
        if (prelink_objects(opts->output_path, entries_copy, metas, eidx_save) == 0) {
            printf("  pre-linked : yes\n");
            /* Set DLFRZ_FLAG_PRELINKED on all metas and rewrite them */
            FILE *mf = fopen(opts->output_path, "r+b");
            if (mf) {
                for (int i = 0; i < eidx_save; i++)
                    metas[i].flags |= DLFRZ_FLAG_PRELINKED;
                fseek(mf, meta_off, SEEK_SET);
                fwrite(metas, sizeof(*metas), eidx_save, mf);
                fclose(mf);
            }
        } else {
            printf("  pre-linked : no (failed, will use runtime relocation)\n");
        }
        free(metas);
        free(entries_copy);
    }

    printf("Frozen binary: %s\n", opts->output_path);
    printf("  bootstrap  : %zu bytes\n", bootstrap_sz);
    printf("  embedded   : %d files\n", eidx_save);
    printf("  total size : %zu bytes\n", total_sz);
    return 0;

fail2:
    free(entries);
    free(strtab);
    free(src_paths);
    free(metas);
fail:
    fprintf(stderr, "dlfreeze: packing failed\n");
    fclose(out);
    return -1;
}
