/*
 * dlfreeze bootstrap – statically-linked runtime stub.
 *
 * This small binary IS the frozen executable.  It:
 *   1. Reads the embedded payload from /proc/self/exe
 *   2. If direct-load metadata is present, maps libraries in-process
 *      and transfers control without ld.so (no tmpdir).
 *   3. Otherwise, extracts all files to a temporary directory and
 *      forks: child execve()s the real program via the bundled ld.so,
 *      parent waits and cleans up the tmpdir.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <signal.h>
#include <errno.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <stdint.h>

#include "common.h"
#include "loader.h"

/* Packer scans the binary for this sentinel and patches it. */
static volatile struct dlfrz_loader_info g_loader_info
    __attribute__((used, section(".data")))
    = { {'D','L','F','R','Z','L','D','R'}, 0, 0, 0 };

/* ---- globals ----------------------------------------------------- */
static volatile pid_t g_child;
static char g_tmpdir[PATH_MAX];

/* ---- tmpdir selection -------------------------------------------- */
static int make_workdir(char *out, size_t out_sz)
{
    if (snprintf(out, out_sz, "/tmp/dlfreeze.XXXXXX") >= (int)out_sz)
        return -1;
    return mkdtemp(out) ? 0 : -1;
}

/* ---- signal forwarding ------------------------------------------- */
static void fwd_signal(int sig) {
    if (g_child > 0) kill(g_child, sig);
}

/* ---- recursive rm ------------------------------------------------ */
static void rmtree(const char *path)
{
    struct stat st;
    if (lstat(path, &st) < 0) return;
    if (S_ISDIR(st.st_mode)) {
        DIR *d = opendir(path);
        if (!d) return;
        struct dirent *e;
        while ((e = readdir(d))) {
            if (e->d_name[0] == '.' &&
                (e->d_name[1] == '\0' ||
                 (e->d_name[1] == '.' && e->d_name[2] == '\0')))
                continue;
            char child[PATH_MAX];
            snprintf(child, sizeof(child), "%s/%s", path, e->d_name);
            rmtree(child);
        }
        closedir(d);
        rmdir(path);
    } else {
        unlink(path);
    }
}

/* ---- extract one embedded blob to a file ------------------------- */
static const char *bs_basename(const char *path)
{
    const char *base = path;
    while (*path) { if (*path == '/') base = path + 1; path++; }
    return base;
}

static int bs_is_musl_interp_path(const char *path)
{
    const char *base = bs_basename(path);

    return strncmp(base, "ld-musl", 7) == 0;
}

static int extract(int srcfd, const char *dst,
                   uint64_t off, uint64_t sz, int exec)
{
    int dfd = open(dst, O_WRONLY | O_CREAT | O_TRUNC, exec ? 0755 : 0644);
    if (dfd < 0) { perror(dst); return -1; }
    if (lseek(srcfd, off, SEEK_SET) < 0) { close(dfd); return -1; }

    char buf[65536];
    uint64_t rem = sz;
    while (rem > 0) {
        size_t want = rem > sizeof(buf) ? sizeof(buf) : rem;
        ssize_t nr = read(srcfd, buf, want);
        if (nr <= 0) { close(dfd); return -1; }
        ssize_t wr = 0;
        while (wr < nr) {
            ssize_t w = write(dfd, buf + wr, nr - wr);
            if (w <= 0) { close(dfd); return -1; }
            wr += w;
        }
        rem -= nr;
    }
    close(dfd);
    return 0;
}

/* ---- extract from memory (UPX path) to a file -------------------- */
static int extract_mem(const uint8_t *base, uint64_t base_foff,
                       const char *dst, uint64_t off, uint64_t sz, int exec)
{
    int dfd = open(dst, O_WRONLY | O_CREAT | O_TRUNC, exec ? 0755 : 0644);
    if (dfd < 0) { perror(dst); return -1; }
    const uint8_t *src = base + (off - base_foff);
    uint64_t rem = sz;
    while (rem > 0) {
        size_t want = rem > 65536 ? 65536 : rem;
        ssize_t w = write(dfd, src, want);
        if (w <= 0) { close(dfd); return -1; }
        src += w;
        rem -= w;
    }
    close(dfd);
    return 0;
}

/* ---- main -------------------------------------------------------- */
extern char **environ;

int main(int argc, char **argv)
{
    /* 1. open our own executable */
    char self[PATH_MAX];
    ssize_t sl = readlink("/proc/self/exe", self, sizeof(self)-1);
    if (sl < 0) { perror("readlink"); return 127; }
    self[sl] = '\0';

    int sfd = open(self, O_RDONLY);
    if (sfd < 0) { perror(self); return 127; }

    struct stat st;
    if (fstat(sfd, &st) < 0) { perror("fstat"); close(sfd); return 127; }

    /* 2. read footer — try from end of file first (normal path) */
    struct dlfrz_footer ft;
    int from_memory = 0;
    const uint8_t *mem_base = NULL;

    if (pread(sfd, &ft, sizeof(ft), st.st_size - sizeof(ft)) == sizeof(ft) &&
        memcmp(ft.magic, DLFRZ_MAGIC, 8) == 0) {
        /* normal path — /proc/self/exe is intact */
    } else if (g_loader_info.payload_vaddr != 0 &&
               g_loader_info.payload_filesz != 0) {
        /* UPX path — payload is decompressed in our virtual memory.
         * The packer mapped the payload into a PT_LOAD segment at
         * payload_vaddr; after UPX decompression, it's at that VA.
         * File offsets in the manifest need to be translated:
         *   mem_ptr = mem_base + (file_offset - payload_foff)       */
        mem_base = (const uint8_t *)(uintptr_t)g_loader_info.payload_vaddr;
        const uint8_t *footer_ptr =
            mem_base + g_loader_info.payload_filesz - sizeof(ft);
        memcpy(&ft, footer_ptr, sizeof(ft));
        if (memcmp(ft.magic, DLFRZ_MAGIC, 8) != 0) {
            fprintf(stderr, "dlfreeze-bootstrap: no embedded payload\n");
            close(sfd); return 127;
        }
        from_memory = 1;
    } else {
        fprintf(stderr, "dlfreeze-bootstrap: no embedded payload\n");
        close(sfd); return 127;
    }

    if (ft.version != DLFRZ_VERSION) {
        fprintf(stderr, "dlfreeze-bootstrap: unsupported version %u\n", ft.version);
        close(sfd); return 127;
    }

    /* 3. read string table */
    char *strtab = malloc(ft.strtab_size);
    if (!strtab) {
        fprintf(stderr, "dlfreeze-bootstrap: cannot read strtab\n");
        close(sfd); return 127;
    }
    if (from_memory) {
        memcpy(strtab,
               mem_base + (ft.strtab_offset - g_loader_info.payload_foff),
               ft.strtab_size);
    } else {
        if (pread(sfd, strtab, ft.strtab_size, ft.strtab_offset) !=
            (ssize_t)ft.strtab_size) {
            fprintf(stderr, "dlfreeze-bootstrap: cannot read strtab\n");
            close(sfd); return 127;
        }
    }

    /* 4. read manifest */
    size_t msz = ft.num_entries * sizeof(struct dlfrz_entry);
    struct dlfrz_entry *ent = malloc(msz);
    if (!ent) {
        fprintf(stderr, "dlfreeze-bootstrap: cannot read manifest\n");
        close(sfd); return 127;
    }
    if (from_memory) {
        memcpy(ent,
               mem_base + (ft.manifest_offset - g_loader_info.payload_foff),
               msz);
    } else {
        if (pread(sfd, ent, msz, ft.manifest_offset) != (ssize_t)msz) {
            fprintf(stderr, "dlfreeze-bootstrap: cannot read manifest\n");
            close(sfd); return 127;
        }
    }

    /* 5. check for direct-load metadata in footer pad[0..7] */
    uint64_t meta_off = 0;
    uint64_t fixup_off = 0;
    uint64_t fixup_count = 0;
    memcpy(&meta_off, ft.pad, sizeof(meta_off));
    memcpy(&fixup_off, ft.pad + 8, sizeof(fixup_off));
    memcpy(&fixup_count, ft.pad + 16, sizeof(fixup_count));
    if (meta_off != 0) {
        /* Direct-load mode: try in a child first so we can fall back to
         * extraction if the in-process loader fails for this binary. */
        size_t metasz = ft.num_entries * sizeof(struct dlfrz_lib_meta);
        struct dlfrz_lib_meta *metas = malloc(metasz);
        if (!metas) {
            fprintf(stderr, "dlfreeze-bootstrap: cannot alloc lib_meta\n");
            free(ent); free(strtab); close(sfd); return 127;
        }

        if (from_memory) {
            memcpy(metas,
                   mem_base + (meta_off - g_loader_info.payload_foff),
                   metasz);
        } else {
            if (pread(sfd, metas, metasz, meta_off) != (ssize_t)metasz) {
                fprintf(stderr, "dlfreeze-bootstrap: cannot read lib_meta\n");
                free(metas); free(ent); free(strtab); close(sfd);
                return 127;
            }
        }

        /* Set up mem/mem_foff for the loader.
         * Normal path: mmap the entire file.
         * UPX path: payload is already in virtual memory. */
        const uint8_t *ldr_mem;
        uint64_t ldr_mem_foff;
        int ldr_srcfd;

        if (from_memory) {
            ldr_mem = mem_base;
            ldr_mem_foff = g_loader_info.payload_foff;
            ldr_srcfd = -1;
        } else {
            void *file_map = mmap(NULL, st.st_size, PROT_READ,
                                  MAP_PRIVATE, sfd, 0);
            if (file_map == MAP_FAILED) {
                perror("mmap");
                free(metas); free(ent); free(strtab); close(sfd);
                return 127;
            }
            ldr_mem = (const uint8_t *)file_map;
            ldr_mem_foff = 0;
            ldr_srcfd = sfd;
        }

        const uint32_t *runtime_fixups = NULL;
        uint32_t runtime_fixup_count = 0;
        if (fixup_off != 0 && fixup_count != 0 &&
            fixup_count <= UINT32_MAX &&
            fixup_off >= ldr_mem_foff) {
            runtime_fixups = (const uint32_t *)(ldr_mem + (fixup_off - ldr_mem_foff));
            runtime_fixup_count = (uint32_t)fixup_count;
        }

        /* DLFREEZE_NO_FORK=1 → run loader_run() directly (for debugging) */
        if (getenv("DLFREEZE_NO_FORK")) {
            loader_run(ldr_mem, ldr_mem_foff, ldr_srcfd, metas, ent, strtab,
                       ft.num_entries, runtime_fixups, runtime_fixup_count,
                       argc, argv, environ);
            fprintf(stderr, "dlfreeze-bootstrap: in-process loader failed\n");
            close(sfd);
            return 127;
        }

        /* Pre-linked binaries: run loader in-process (no fork), since
         * pre-linking makes the loader path very reliable and the fork
         * adds >1ms of overhead.  Non-prelinked binaries still use
         * fork for crash-recovery fallback to extraction mode. */
        int is_prelinked = 0;
        for (uint32_t pi = 0; pi < ft.num_entries; pi++) {
            if (metas[pi].flags & DLFRZ_FLAG_PRELINKED) {
                is_prelinked = 1;
                break;
            }
        }

        if (is_prelinked) {
            loader_run(ldr_mem, ldr_mem_foff, ldr_srcfd, metas, ent, strtab,
                       ft.num_entries, runtime_fixups, runtime_fixup_count,
                       argc, argv, environ);
            /* loader_run returns only on failure */
            fprintf(stderr, "dlfreeze-bootstrap: in-process loader failed\n");
            close(sfd);
            return 127;
        }

        pid_t lpid = fork();
        if (lpid < 0) {
            perror("fork");
            free(metas); free(ent); free(strtab); close(sfd);
            return 127;
        }

        if (lpid == 0) {
            /* loader_run() does NOT return on success */
            loader_run(ldr_mem, ldr_mem_foff, ldr_srcfd, metas, ent, strtab,
                       ft.num_entries, runtime_fixups, runtime_fixup_count,
                       argc, argv, environ);
            close(sfd);
            fprintf(stderr, "dlfreeze-bootstrap: in-process loader failed\n");
            _exit(127);
        }

        int lst = 0;
        while (waitpid(lpid, &lst, 0) < 0)
            if (errno != EINTR) break;

        if (from_memory == 0 && ldr_mem_foff == 0 && ldr_mem)
            munmap((void *)ldr_mem, st.st_size);

        free(metas);

        if (WIFEXITED(lst)) {
            int rc = WEXITSTATUS(lst);
            if (rc != 127) {
                free(ent); free(strtab); close(sfd);
                return rc;
            }
        } else if (WIFSIGNALED(lst)) {
            /* Crash in direct mode — try the extraction fallback. */
        }

        fprintf(stderr,
                "dlfreeze-bootstrap: direct-load failed, falling back to extraction\n");
    }

    /* 6. create workdir for extraction fallback (/tmp only). */
    if (make_workdir(g_tmpdir, sizeof(g_tmpdir)) < 0) {
        perror("mkdtemp"); close(sfd); return 127;
    }

    /* 7. extract all files */
    char exe_path[PATH_MAX + 256]    = {0};
    char interp_path[PATH_MAX + 256] = {0};

    for (uint32_t i = 0; i < ft.num_entries; i++) {
        const char *name = strtab + ent[i].name_offset;
        char dst[PATH_MAX + 256];
        snprintf(dst, sizeof(dst), "%s/%s", g_tmpdir, bs_basename(name));

        int is_exec = (ent[i].flags & (DLFRZ_FLAG_MAIN_EXE | DLFRZ_FLAG_INTERP));

        int rc;
        if (from_memory) {
            rc = extract_mem(mem_base, g_loader_info.payload_foff,
                             dst, ent[i].data_offset, ent[i].data_size,
                             is_exec);
        } else {
            rc = extract(sfd, dst, ent[i].data_offset,
                         ent[i].data_size, is_exec);
        }
        if (rc < 0) {
            fprintf(stderr, "dlfreeze-bootstrap: extract failed: %s\n", name);
            rmtree(g_tmpdir);
            close(sfd); return 127;
        }

        if (ent[i].flags & DLFRZ_FLAG_MAIN_EXE)
            snprintf(exe_path, sizeof(exe_path), "%s", dst);
        if (ent[i].flags & DLFRZ_FLAG_INTERP)
            snprintf(interp_path, sizeof(interp_path), "%s", dst);
    }
    free(ent); free(strtab); close(sfd);

    if (!exe_path[0]) {
        fprintf(stderr, "dlfreeze-bootstrap: no main executable in payload\n");
        rmtree(g_tmpdir); return 127;
    }

    /* 8. build argv for the real program.
     *    glibc keeps working well when we exec the bundled interpreter
     *    directly, but musl toolchain drivers such as clang inspect
     *    /proc/self/exe to re-exec themselves as helper modes (-cc1,
     *    etc.). Launching musl through ld-musl makes /proc/self/exe
     *    point at the interpreter instead of the executable, which
     *    breaks that self-reexec flow. */
    int nac; char **nav;
    int use_interp_launcher = interp_path[0] && !bs_is_musl_interp_path(interp_path);
    if (use_interp_launcher) {
        nac = argc + 3;
        nav = calloc(nac + 1, sizeof(char *));
        nav[0] = interp_path;
        nav[1] = (char *)"--library-path";
        nav[2] = g_tmpdir;
        nav[3] = exe_path;
        for (int i = 1; i < argc; i++) nav[i+3] = argv[i];
    } else {
        nac = argc;
        nav = calloc(nac + 1, sizeof(char *));
        nav[0] = exe_path;
        for (int i = 1; i < argc; i++) nav[i] = argv[i];
    }

    /* 9. set LD_LIBRARY_PATH */
    const char *oldlp = getenv("LD_LIBRARY_PATH");
    char lp[PATH_MAX * 2];
    if (oldlp && oldlp[0])
        snprintf(lp, sizeof(lp), "%s:%s", g_tmpdir, oldlp);
    else
        snprintf(lp, sizeof(lp), "%s", g_tmpdir);
    setenv("LD_LIBRARY_PATH", lp, 1);
    setenv("DLFREEZE_TMPDIR", g_tmpdir, 1);

    /* 10. fork→exec, parent waits + cleans up */
    g_child = fork();
    if (g_child < 0) {
        perror("fork"); rmtree(g_tmpdir); return 127;
    }

    if (g_child == 0) {
        /* child ── become the real program */
        if (use_interp_launcher)
            execve(interp_path, nav, environ);
        else
            execve(exe_path, nav, environ);
        perror("execve");
        _exit(127);
    }

    /* parent ── forward signals & wait */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = fwd_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    int sigs[] = { SIGINT, SIGTERM, SIGHUP, SIGQUIT, SIGUSR1, SIGUSR2,
                   SIGPIPE, SIGALRM, SIGCONT, SIGTSTP, SIGTTIN, SIGTTOU, 0 };
    for (int i = 0; sigs[i]; i++) sigaction(sigs[i], &sa, NULL);

    int status;
    while (waitpid(g_child, &status, 0) < 0)
        if (errno != EINTR) break;

    rmtree(g_tmpdir);
    free(nav);

    if (WIFEXITED(status))
        return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) {
        struct sigaction dfl = { .sa_handler = SIG_DFL };
        sigaction(WTERMSIG(status), &dfl, NULL);
        raise(WTERMSIG(status));
    }
    return 127;
}
