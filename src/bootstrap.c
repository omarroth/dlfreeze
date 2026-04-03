/*
 * dlfreeze bootstrap – statically-linked runtime stub.
 *
 * This small binary IS the frozen executable.  It:
 *   1. Reads the embedded payload from /proc/self/exe
 *   2. Extracts all files to a temporary directory
 *   3. Forks: child execve()s the real program via the bundled ld.so,
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
#include <stdint.h>

/* ---- payload format (must match common.h) ------------------------ */
#define DLFRZ_MAGIC   "DLFREEZ"
#define DLFRZ_VERSION 1

#define DLFRZ_FLAG_MAIN_EXE  0x01
#define DLFRZ_FLAG_INTERP    0x02
#define DLFRZ_FLAG_SHLIB     0x04

struct dlfrz_entry {
    uint64_t data_offset;
    uint64_t data_size;
    uint32_t flags;
    uint32_t name_offset;
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
 * Loader-info sentinel — patched by the packer.
 * Lives in .data so it survives UPX compression/decompression.
 * The packer scans for "DLFRZLDR" and writes the payload virtual address
 * and the base file-offset so the bootstrap can locate the payload even
 * when /proc/self/exe has been compressed by UPX.
 */
#define DLFRZ_LOADER_MAGIC "DLFRZLDR"

struct dlfrz_loader_info {
    char     magic[8];         /* "DLFRZLDR"                              */
    uint64_t payload_vaddr;    /* VA where packer mapped the payload      */
    uint64_t payload_filesz;   /* total bytes in the payload PT_LOAD      */
    uint64_t payload_foff;     /* original file offset of payload start   */
};

/* Packer scans the binary for this sentinel and patches it. */
static volatile struct dlfrz_loader_info g_loader_info
    __attribute__((used, section(".data")))
    = { {'D','L','F','R','Z','L','D','R'}, 0, 0, 0 };

/* ---- globals ----------------------------------------------------- */
static volatile pid_t g_child;
static char g_tmpdir[PATH_MAX];

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

    /* 5. create tmpdir */
    snprintf(g_tmpdir, sizeof(g_tmpdir), "/tmp/dlfreeze.XXXXXX");
    if (!mkdtemp(g_tmpdir)) {
        perror("mkdtemp"); close(sfd); return 127;
    }

    /* 6. extract all files */
    char exe_path[PATH_MAX + 256]    = {0};
    char interp_path[PATH_MAX + 256] = {0};

    for (uint32_t i = 0; i < ft.num_entries; i++) {
        const char *name = strtab + ent[i].name_offset;
        char dst[PATH_MAX + 256];
        snprintf(dst, sizeof(dst), "%s/%s", g_tmpdir, name);

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

    /* 7. build argv for the real program
     *    format: <interp> --library-path <tmpdir> <exe> [user-args …] */
    int nac; char **nav;
    if (interp_path[0]) {
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

    /* 8. set LD_LIBRARY_PATH */
    const char *oldlp = getenv("LD_LIBRARY_PATH");
    char lp[PATH_MAX * 2];
    if (oldlp && oldlp[0])
        snprintf(lp, sizeof(lp), "%s:%s", g_tmpdir, oldlp);
    else
        snprintf(lp, sizeof(lp), "%s", g_tmpdir);
    setenv("LD_LIBRARY_PATH", lp, 1);
    setenv("DLFREEZE_TMPDIR", g_tmpdir, 1);

    /* 9. fork→exec, parent waits + cleans up */
    g_child = fork();
    if (g_child < 0) {
        perror("fork"); rmtree(g_tmpdir); return 127;
    }

    if (g_child == 0) {
        /* child ── become the real program */
        if (interp_path[0])
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
