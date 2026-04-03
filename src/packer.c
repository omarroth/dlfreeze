#include "packer.h"
#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

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

/* ------------------------------------------------------------------ */
int pack_frozen(const struct pack_options *opts)
{
    FILE *out = fopen(opts->output_path, "wb");
    if (!out) { perror(opts->output_path); return -1; }

    size_t off = 0, written;

    /* 1. bootstrap binary ------------------------------------------ */
    if (append_file(out, opts->bootstrap_path, &written) < 0) goto fail;
    off += written;

    /* total entries: main-exe + interpreter? + libs */
    int nent = 1 + (opts->deps->interp_path ? 1 : 0) + opts->deps->count;
    struct dlfrz_entry *entries = calloc(nent, sizeof(*entries));

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
    entries[eidx].data_offset = off;
    entries[eidx].flags       = DLFRZ_FLAG_MAIN_EXE;
    entries[eidx].name_offset = stroff;
    strcpy(strtab + stroff, exe_base); stroff += strlen(exe_base) + 1;
    if (append_file(out, opts->exe_path, &written) < 0) goto fail2;
    entries[eidx].data_size = written;
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

    /* 7. footer ---------------------------------------------------- */
    struct dlfrz_footer ft;
    memset(&ft, 0, sizeof(ft));
    memcpy(ft.magic, DLFRZ_MAGIC, 8);
    ft.version         = DLFRZ_VERSION;
    ft.num_entries     = (uint32_t)eidx;
    ft.manifest_offset = manifest_off;
    ft.strtab_offset   = strtab_off;
    ft.strtab_size     = strsz;
    if (fwrite(&ft, 1, sizeof(ft), out) != sizeof(ft)) goto fail2;

    free(entries);
    free(strtab);
    fclose(out);
    chmod(opts->output_path, 0755);

    printf("Frozen binary: %s\n", opts->output_path);
    printf("  bootstrap  : %zu bytes\n", filesize(opts->bootstrap_path));
    printf("  embedded   : %d files\n", eidx);
    printf("  total size : %zu bytes\n", filesize(opts->output_path));
    return 0;

fail2:
    free(entries);
    free(strtab);
fail:
    fprintf(stderr, "dlfreeze: packing failed\n");
    fclose(out);
    return -1;
}
