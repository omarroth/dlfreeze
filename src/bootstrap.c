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
#include <elf.h>

#include "common.h"
#include "loader.h"

/* Packer scans the binary for this sentinel and patches it. */
static volatile struct dlfrz_loader_info g_loader_info
    __attribute__((used, section(".data")))
    = { {'D','L','F','R','Z','L','D','R'}, 0, 0, 0 };

/* ---- globals ----------------------------------------------------- */
static volatile pid_t g_child;
static volatile sig_atomic_t g_forwarded_signal;
static char g_tmpdir[PATH_MAX];

static const int g_forward_signals[] = {
    SIGINT, SIGTERM, SIGHUP, SIGQUIT, SIGUSR1, SIGUSR2,
    SIGPIPE, SIGALRM, SIGCONT, SIGTSTP, SIGTTIN, SIGTTOU
};

#define FORWARD_SIGNAL_COUNT \
    (sizeof(g_forward_signals) / sizeof(g_forward_signals[0]))

/* ---- tmpdir selection -------------------------------------------- */
static int make_workdir(char *out, size_t out_sz)
{
    if (snprintf(out, out_sz, "/tmp/dlfreeze.XXXXXX") >= (int)out_sz)
        return -1;
    return mkdtemp(out) ? 0 : -1;
}

static int ensure_parent_dirs(const char *path)
{
    char buf[PATH_MAX + 256];
    char *p;

    if (!path || !path[0])
        return -1;
    if (snprintf(buf, sizeof(buf), "%s", path) >= (int)sizeof(buf))
        return -1;

    for (p = buf + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        if (mkdir(buf, 0755) < 0 && errno != EEXIST)
            return -1;
        *p = '/';
    }
    return 0;
}

/* ---- signal forwarding ------------------------------------------- */
static void fwd_signal(int sig) {
    g_forwarded_signal = sig;
    if (g_child > 0) kill(g_child, sig);
}

static void build_forward_signal_set(sigset_t *set)
{
    sigemptyset(set);
    for (size_t i = 0; i < FORWARD_SIGNAL_COUNT; i++)
        sigaddset(set, g_forward_signals[i]);
}

static int install_forward_signal_handlers(struct sigaction *old_actions)
{
    struct sigaction action;
    size_t installed = 0;

    memset(&action, 0, sizeof(action));
    action.sa_handler = fwd_signal;
    sigemptyset(&action.sa_mask);
    action.sa_flags = SA_RESTART;

    for (; installed < FORWARD_SIGNAL_COUNT; installed++) {
        if (sigaction(g_forward_signals[installed], &action,
                      &old_actions[installed]) < 0)
            break;
    }
    if (installed == FORWARD_SIGNAL_COUNT)
        return 0;
    while (installed > 0) {
        installed--;
        sigaction(g_forward_signals[installed], &old_actions[installed],
                  NULL);
    }
    return -1;
}

static void restore_forward_signal_handlers(
    const struct sigaction *old_actions)
{
    for (size_t i = 0; i < FORWARD_SIGNAL_COUNT; i++)
        sigaction(g_forward_signals[i], &old_actions[i], NULL);
}

static void reraise_child_signal(int signal_number)
{
    struct sigaction action;
    sigset_t unblocked;

    memset(&action, 0, sizeof(action));
    action.sa_handler = SIG_DFL;
    sigemptyset(&action.sa_mask);
    sigaction(signal_number, &action, NULL);

    sigemptyset(&unblocked);
    sigaddset(&unblocked, signal_number);
    sigprocmask(SIG_UNBLOCK, &unblocked, NULL);
    raise(signal_number);
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

static int bs_env_enabled(const char *name)
{
    const char *value = getenv(name);

    return value && value[0] && value[0] != '0';
}

static ssize_t full_pread(int fd, void *buffer, size_t size, off_t offset)
{
    unsigned char *out = buffer;
    size_t done = 0;

    while (done < size) {
        ssize_t len = pread(fd, out + done, size - done, offset + (off_t)done);

        if (len < 0 && errno == EINTR)
            continue;
        if (len <= 0)
            return len < 0 ? -1 : (ssize_t)done;
        done += (size_t)len;
    }
    return (ssize_t)done;
}

static int files_identical(const char *left, const char *right)
{
    int left_fd = -1, right_fd = -1;
    struct stat left_st, right_st;
    unsigned char left_buf[16384], right_buf[16384];
    int identical = 0;

    if (!left || !right || !left[0] || !right[0])
        return 0;
    left_fd = open(left, O_RDONLY | O_CLOEXEC);
    if (left_fd < 0)
        goto out;
    right_fd = open(right, O_RDONLY | O_CLOEXEC);
    if (right_fd < 0)
        goto out;
    if (fstat(left_fd, &left_st) < 0 || fstat(right_fd, &right_st) < 0 ||
        !S_ISREG(left_st.st_mode) || !S_ISREG(right_st.st_mode) ||
        left_st.st_size != right_st.st_size)
        goto out;

    for (off_t offset = 0; offset < left_st.st_size;) {
        size_t remaining = (size_t)(left_st.st_size - offset);
        size_t chunk = remaining < sizeof(left_buf) ? remaining
                                                   : sizeof(left_buf);
        ssize_t left_len = full_pread(left_fd, left_buf, chunk, offset);
        ssize_t right_len = full_pread(right_fd, right_buf, chunk, offset);

        if (left_len != (ssize_t)chunk || right_len != (ssize_t)chunk ||
            memcmp(left_buf, right_buf, chunk) != 0)
            goto out;
        offset += (off_t)chunk;
    }
    identical = 1;

out:
    if (left_fd >= 0)
        close(left_fd);
    if (right_fd >= 0)
        close(right_fd);
    return identical;
}

static int bs_debug_enabled(void)
{
    return bs_env_enabled("DLFREEZE_DEBUG");
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

static int payload_range_valid(uint64_t offset, uint64_t length,
                               uint64_t payload_offset,
                               uint64_t payload_size)
{
    uint64_t relative;

    if (offset < payload_offset)
        return 0;
    relative = offset - payload_offset;
    return relative <= payload_size && length <= payload_size - relative;
}

static int u64_add_checked(uint64_t left, uint64_t right, uint64_t *out)
{
    if (right > UINT64_MAX - left)
        return 0;
    *out = left + right;
    return 1;
}

static int u64_align_up_checked(uint64_t value, uint64_t align,
                                uint64_t *out)
{
    uint64_t mask;

    if (align == 0 || (align & (align - 1)) != 0)
        return 0;
    mask = align - 1;
    if (value > UINT64_MAX - mask)
        return 0;
    *out = (value + mask) & ~mask;
    return 1;
}

static int embedded_name_valid(const char *name)
{
    const char *p = name;

    if (!p || !p[0])
        return 0;
    while (*p) {
        const char *component;
        size_t length;

        while (*p == '/')
            p++;
        if (!*p)
            break;
        component = p;
        while (*p && *p != '/')
            p++;
        length = (size_t)(p - component);
        if ((length == 1 && component[0] == '.') ||
            (length == 2 && component[0] == '.' && component[1] == '.'))
            return 0;
    }
    return 1;
}

static int manifest_is_valid(const struct dlfrz_footer *footer,
                             const struct dlfrz_entry *entries,
                             const char *strtab,
                             uint64_t payload_offset,
                             uint64_t payload_size)
{
    const uint32_t known_flags = DLFRZ_FLAG_MAIN_EXE |
                                 DLFRZ_FLAG_INTERP |
                                 DLFRZ_FLAG_SHLIB |
                                 DLFRZ_FLAG_DLOPEN |
                                 DLFRZ_FLAG_DATA |
                                 DLFRZ_FLAG_DATA_VIRTUAL |
                                 DLFRZ_FLAG_DATA_NEGATIVE;
    uint32_t main_count = 0;
    uint32_t interp_count = 0;

    if (!footer->strtab_size || footer->strtab_size > SIZE_MAX)
        return 0;

    for (uint32_t i = 0; i < footer->num_entries; i++) {
        const char *name;
        uint32_t flags = entries[i].flags;
        uint32_t kind = flags & (DLFRZ_FLAG_MAIN_EXE |
                                 DLFRZ_FLAG_INTERP |
                                 DLFRZ_FLAG_SHLIB |
                                 DLFRZ_FLAG_DATA);

        if ((flags & ~known_flags) != 0 ||
            (kind != DLFRZ_FLAG_MAIN_EXE &&
             kind != DLFRZ_FLAG_INTERP &&
             kind != DLFRZ_FLAG_SHLIB &&
             kind != DLFRZ_FLAG_DATA) ||
            ((flags & DLFRZ_FLAG_DLOPEN) &&
             !(flags & DLFRZ_FLAG_SHLIB)) ||
            ((flags & (DLFRZ_FLAG_DATA_VIRTUAL |
                       DLFRZ_FLAG_DATA_NEGATIVE)) &&
             !(flags & DLFRZ_FLAG_DATA)) ||
            (flags & DLFRZ_FLAG_DATA_VIRTUAL &&
             flags & DLFRZ_FLAG_DATA_NEGATIVE) ||
            entries[i].name_offset >= footer->strtab_size)
            return 0;
        name = strtab + entries[i].name_offset;
        if (!memchr(name, '\0', footer->strtab_size - entries[i].name_offset) ||
            !embedded_name_valid(name) ||
            (!(entries[i].flags & (DLFRZ_FLAG_DATA_VIRTUAL |
                                    DLFRZ_FLAG_DATA_NEGATIVE)) &&
             !payload_range_valid(entries[i].data_offset,
                                  entries[i].data_size,
                                  payload_offset, payload_size)))
            return 0;
        if (entries[i].flags & DLFRZ_FLAG_MAIN_EXE)
            main_count++;
        if (entries[i].flags & DLFRZ_FLAG_INTERP)
            interp_count++;
    }
    return main_count == 1 && interp_count <= 1;
}

static int direct_metadata_is_valid(const uint8_t *mem, uint64_t mem_foff,
                                    const struct dlfrz_lib_meta *metas,
                                    const struct dlfrz_entry *entries,
                                    uint32_t num_entries,
                                    uint32_t runtime_fixup_count)
{
    const uint32_t entry_type_mask = DLFRZ_FLAG_MAIN_EXE |
                                     DLFRZ_FLAG_INTERP |
                                     DLFRZ_FLAG_SHLIB |
                                     DLFRZ_FLAG_DLOPEN |
                                     DLFRZ_FLAG_DATA;
    const uint32_t metadata_flag_mask = entry_type_mask |
                                        DLFRZ_FLAG_PRELINKED |
                                        DLFRZ_FLAG_NEEDS_RTLD |
                                        DLFRZ_FLAG_RUNTIME_SCAN;
    long page_size_long = sysconf(_SC_PAGESIZE);
    if (page_size_long <= 0 ||
        ((uint64_t)page_size_long & ((uint64_t)page_size_long - 1)) != 0)
        return 0;
    const uint64_t page_size = (uint64_t)page_size_long;
#if defined(__aarch64__)
    /* Both supported AArch64 TLS variants reserve two words above TP. */
    uint64_t total_tls = 16;
#else
    uint64_t total_tls = 0;
#endif

    for (uint32_t i = 0; i < num_entries; i++) {
        const struct dlfrz_entry *entry = &entries[i];
        const struct dlfrz_lib_meta *meta = &metas[i];

        if (meta->flags & ~metadata_flag_mask)
            return 0;
        if (meta->_reserved != 0)
            return 0;
        if ((meta->flags & entry_type_mask) !=
            (entry->flags & entry_type_mask))
            return 0;
        if (meta->runtime_fixup_off > runtime_fixup_count ||
            meta->runtime_fixup_count >
                runtime_fixup_count - meta->runtime_fixup_off)
            return 0;

        if (entry->flags & DLFRZ_FLAG_DATA) {
            if ((meta->flags & ~DLFRZ_FLAG_PRELINKED) != DLFRZ_FLAG_DATA ||
                meta->base_addr != 0 ||
                meta->vaddr_lo != 0 || meta->vaddr_hi != 0 ||
                meta->phdr_num != 0 || meta->phdr_entsz != 0 ||
                meta->runtime_fixup_count != 0)
                return 0;
            continue;
        }

        if (entry->data_offset < mem_foff ||
            entry->data_size < sizeof(Elf64_Ehdr))
            return 0;

        const uint8_t *elf = mem + (entry->data_offset - mem_foff);
        const Elf64_Ehdr *ehdr = (const Elf64_Ehdr *)elf;
#if defined(__x86_64__)
        const uint16_t expected_machine = EM_X86_64;
#elif defined(__aarch64__)
        const uint16_t expected_machine = EM_AARCH64;
#else
#error "Unsupported architecture"
#endif

        if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0 ||
            ehdr->e_ident[EI_CLASS] != ELFCLASS64 ||
            ehdr->e_ident[EI_DATA] != ELFDATA2LSB ||
            ehdr->e_ident[EI_VERSION] != EV_CURRENT ||
            ehdr->e_version != EV_CURRENT ||
            ehdr->e_machine != expected_machine ||
            (ehdr->e_type != ET_DYN && ehdr->e_type != ET_EXEC) ||
            ehdr->e_ehsize != sizeof(*ehdr) ||
            ehdr->e_phentsize != sizeof(Elf64_Phdr) ||
            ehdr->e_phnum == 0 ||
            meta->phdr_num != ehdr->e_phnum ||
            meta->phdr_entsz != ehdr->e_phentsize ||
            ehdr->e_phoff > entry->data_size ||
            (uint64_t)ehdr->e_phnum >
                (entry->data_size - ehdr->e_phoff) / sizeof(Elf64_Phdr))
            return 0;

        const Elf64_Phdr *phdrs =
            (const Elf64_Phdr *)(elf + ehdr->e_phoff);
        uint64_t lo = UINT64_MAX;
        uint64_t hi = 0;
        uint64_t phdr_vaddr = UINT64_MAX;
        uint64_t tls_memsz = 0;
        uint64_t tls_align = 1;
        uint16_t tls_count = 0;
        const Elf64_Phdr *tls_phdr = NULL;
        const uint64_t phdr_file_end =
            ehdr->e_phoff + (uint64_t)ehdr->e_phnum * sizeof(Elf64_Phdr);

        for (uint16_t p = 0; p < ehdr->e_phnum; p++) {
            const Elf64_Phdr *ph = &phdrs[p];

            if (ph->p_type == PT_LOAD && ph->p_align > 1 &&
                ((ph->p_align & (ph->p_align - 1)) != 0 ||
                 (ph->p_vaddr & (ph->p_align - 1)) !=
                    (ph->p_offset & (ph->p_align - 1)) ||
                 (meta->base_addr & (ph->p_align - 1)) != 0))
                return 0;
            if (ph->p_type == PT_TLS) {
                if (++tls_count != 1 ||
                    (ph->p_align > 1 &&
                     (ph->p_align & (ph->p_align - 1)) != 0))
                    return 0;
                tls_memsz = ph->p_memsz;
                tls_align = ph->p_align ? ph->p_align : 1;
                tls_phdr = ph;
            }
            if (ph->p_offset > entry->data_size ||
                ph->p_filesz > entry->data_size - ph->p_offset ||
                ph->p_memsz > UINT64_MAX - ph->p_vaddr)
                return 0;
            if ((ph->p_type == PT_LOAD || ph->p_type == PT_DYNAMIC ||
                 ph->p_type == PT_TLS) && ph->p_filesz > ph->p_memsz)
                return 0;
            if (ph->p_type != PT_LOAD)
                continue;

            if (ph->p_vaddr < lo)
                lo = ph->p_vaddr;
            if (ph->p_vaddr + ph->p_memsz > hi)
                hi = ph->p_vaddr + ph->p_memsz;
            if (ehdr->e_phoff >= ph->p_offset &&
                phdr_file_end - ph->p_offset <= ph->p_filesz)
                phdr_vaddr = ph->p_vaddr +
                             (ehdr->e_phoff - ph->p_offset);
        }

        if (tls_phdr) {
            if ((tls_phdr->p_vaddr & (tls_align - 1)) !=
                (tls_phdr->p_offset & (tls_align - 1)))
                return 0;
            if (tls_phdr->p_filesz != 0) {
                int template_contained = 0;

                for (uint16_t p = 0; p < ehdr->e_phnum; p++) {
                    const Elf64_Phdr *load = &phdrs[p];
                    uint64_t delta;

                    if (load->p_type != PT_LOAD ||
                        tls_phdr->p_vaddr < load->p_vaddr ||
                        tls_phdr->p_offset < load->p_offset)
                        continue;
                    delta = tls_phdr->p_vaddr - load->p_vaddr;
                    if (tls_phdr->p_offset - load->p_offset != delta ||
                        delta > load->p_filesz ||
                        tls_phdr->p_filesz > load->p_filesz - delta ||
                        delta > load->p_memsz ||
                        tls_phdr->p_filesz > load->p_memsz - delta)
                        continue;
                    template_contained = 1;
                    break;
                }
                if (!template_contained)
                    return 0;
            }
        }

        if (tls_count != 0 && tls_memsz != 0 &&
            !(entry->flags & (DLFRZ_FLAG_INTERP |
                              DLFRZ_FLAG_DLOPEN |
                              DLFRZ_FLAG_DATA))) {
            uint64_t next_tls;

#if defined(__aarch64__)
            if (!u64_align_up_checked(total_tls, tls_align, &next_tls) ||
                !u64_add_checked(next_tls, tls_memsz, &total_tls))
                return 0;
#else
            if (!u64_add_checked(total_tls, tls_memsz, &next_tls) ||
                !u64_align_up_checked(next_tls, tls_align, &total_tls))
                return 0;
#endif
            if (total_tls > INT64_MAX)
                return 0;
        }

        if (lo >= hi || phdr_vaddr == UINT64_MAX ||
            phdr_vaddr > UINT32_MAX ||
            meta->vaddr_lo != lo || meta->vaddr_hi != hi ||
            meta->entry != ehdr->e_entry ||
            meta->phdr_off != phdr_vaddr ||
            ((entry->flags & DLFRZ_FLAG_MAIN_EXE) &&
             (meta->entry < lo || meta->entry >= hi)) ||
            ((entry->flags & DLFRZ_FLAG_MAIN_EXE) && meta->main_sym == 0) ||
            (!(entry->flags & DLFRZ_FLAG_MAIN_EXE) && meta->main_sym != 0) ||
            (meta->main_sym != 0 &&
             (meta->main_sym < lo || meta->main_sym >= hi)) ||
            (meta->base_addr & (page_size - 1)) != 0 ||
            hi > UINT64_MAX - (page_size - 1) ||
            meta->base_addr >
                UINT64_MAX - ((hi + page_size - 1) & ~(page_size - 1)) ||
            meta->base_addr +
                ((hi + page_size - 1) & ~(page_size - 1)) >
                UINT64_MAX - 4 * page_size)
            return 0;
    }

    for (uint32_t i = 0; i < num_entries; i++) {
        if (entries[i].flags & DLFRZ_FLAG_DATA)
            continue;
        uint64_t left_lo = metas[i].base_addr +
                           (metas[i].vaddr_lo & ~(page_size - 1));
        uint64_t left_hi = metas[i].base_addr +
                           ((metas[i].vaddr_hi + page_size - 1) &
                            ~(page_size - 1)) + 4 * page_size;

        for (uint32_t j = i + 1; j < num_entries; j++) {
            if (entries[j].flags & DLFRZ_FLAG_DATA)
                continue;
            uint64_t right_lo = metas[j].base_addr +
                                (metas[j].vaddr_lo & ~(page_size - 1));
            uint64_t right_hi = metas[j].base_addr +
                                ((metas[j].vaddr_hi + page_size - 1) &
                                 ~(page_size - 1)) + 4 * page_size;

            if (left_lo < right_hi && right_lo < left_hi)
                return 0;
        }
    }
    return 1;
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

    if (st.st_size >= (off_t)sizeof(ft) &&
        pread(sfd, &ft, sizeof(ft), st.st_size - sizeof(ft)) == sizeof(ft) &&
        memcmp(ft.magic, DLFRZ_MAGIC, 8) == 0) {
        /* normal path — /proc/self/exe is intact */
    } else if (g_loader_info.payload_vaddr != 0 &&
               g_loader_info.payload_filesz >= sizeof(ft)) {
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

    uint64_t payload_offset = 0;
    uint64_t payload_size = (uint64_t)st.st_size;
    if (from_memory) {
        payload_offset = g_loader_info.payload_foff;
        payload_size = g_loader_info.payload_filesz;
    } else if (g_loader_info.payload_foff != 0 &&
               g_loader_info.payload_filesz != 0 &&
               g_loader_info.payload_foff <= (uint64_t)st.st_size &&
               g_loader_info.payload_filesz <=
                   (uint64_t)st.st_size - g_loader_info.payload_foff) {
        payload_offset = g_loader_info.payload_foff;
        payload_size = g_loader_info.payload_filesz;
    }
    if (ft.num_entries == 0 ||
        !payload_range_valid(ft.strtab_offset, ft.strtab_size,
                             payload_offset, payload_size) ||
        !payload_range_valid(ft.manifest_offset,
                             (uint64_t)ft.num_entries *
                                 sizeof(struct dlfrz_entry),
                             payload_offset, payload_size)) {
        fprintf(stderr, "dlfreeze-bootstrap: invalid payload layout\n");
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
            free(strtab); close(sfd); return 127;
        }
    }

    /* 4. read manifest */
    size_t msz = ft.num_entries * sizeof(struct dlfrz_entry);
    struct dlfrz_entry *ent = malloc(msz);
    if (!ent) {
        fprintf(stderr, "dlfreeze-bootstrap: cannot read manifest\n");
        free(strtab); close(sfd); return 127;
    }
    if (from_memory) {
        memcpy(ent,
               mem_base + (ft.manifest_offset - g_loader_info.payload_foff),
               msz);
    } else {
        if (pread(sfd, ent, msz, ft.manifest_offset) != (ssize_t)msz) {
            fprintf(stderr, "dlfreeze-bootstrap: cannot read manifest\n");
            free(ent); free(strtab); close(sfd); return 127;
        }
    }

    if (!manifest_is_valid(&ft, ent, strtab, payload_offset, payload_size)) {
        fprintf(stderr, "dlfreeze-bootstrap: invalid manifest\n");
        free(ent); free(strtab); close(sfd); return 127;
    }

    /* 5. check for direct-load metadata in footer pad[0..7] */
    uint64_t meta_off = 0;
    uint64_t fixup_off = 0;
    uint64_t fixup_count = 0;
    memcpy(&meta_off, ft.pad, sizeof(meta_off));
    memcpy(&fixup_off, ft.pad + 8, sizeof(fixup_off));
    memcpy(&fixup_count, ft.pad + 16, sizeof(fixup_count));
    if (meta_off != 0) {
        /* Direct-load mode: try in a child first.  A clean, runtime-relocated
         * payload may fall back to extraction before application handoff;
         * a prelinked payload must never be handed back to the system rtld. */
        size_t metasz = ft.num_entries * sizeof(struct dlfrz_lib_meta);
        if (!payload_range_valid(meta_off, metasz,
                                 payload_offset, payload_size) ||
            fixup_count > UINT32_MAX ||
            (fixup_count != 0 &&
             (fixup_off == 0 || fixup_count > UINT64_MAX / sizeof(uint32_t) ||
              !payload_range_valid(fixup_off,
                                   fixup_count * sizeof(uint32_t),
                                   payload_offset, payload_size)))) {
            fprintf(stderr, "dlfreeze-bootstrap: invalid direct-load metadata\n");
            free(ent); free(strtab); close(sfd); return 127;
        }
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
        if (fixup_off != 0 && fixup_count != 0) {
            runtime_fixups = (const uint32_t *)(ldr_mem + (fixup_off - ldr_mem_foff));
            runtime_fixup_count = (uint32_t)fixup_count;
        }

        if (!direct_metadata_is_valid(ldr_mem, ldr_mem_foff, metas, ent,
                                      ft.num_entries,
                                      runtime_fixup_count)) {
            fprintf(stderr,
                    "dlfreeze-bootstrap: invalid direct-load object metadata\n");
            if (from_memory == 0 && ldr_mem_foff == 0)
                munmap((void *)ldr_mem, st.st_size);
            free(metas); free(ent); free(strtab); close(sfd);
            return 127;
        }

        int prelinked_payload = 0;
        for (uint32_t i = 0; i < ft.num_entries; i++) {
            if (!(metas[i].flags & DLFRZ_FLAG_DATA) &&
                (metas[i].flags & DLFRZ_FLAG_PRELINKED)) {
                prelinked_payload = 1;
                break;
            }
        }

        /* DLFREEZE_NO_FORK=1 → run loader_run() directly (for debugging) */
        if (bs_env_enabled("DLFREEZE_NO_FORK")) {
            loader_run(ldr_mem, ldr_mem_foff, ldr_srcfd, metas, ent, strtab,
                       ft.num_entries, runtime_fixups, runtime_fixup_count,
                       -1,
                       argc, argv, environ);
            if (bs_debug_enabled())
                fprintf(stderr, "dlfreeze-bootstrap: in-process loader failed\n");
            close(sfd);
            return 127;
        }

        /* Run direct-load in a child so clean-payload failures before
         * application handoff can fall back without duplicated effects. */
        int handoff_pipe[2];
        if (pipe2(handoff_pipe, O_CLOEXEC) < 0) {
            perror("pipe2");
            free(metas); free(ent); free(strtab); close(sfd);
            return 127;
        }
        sigset_t forward_set, old_mask;
        struct sigaction old_forward_actions[FORWARD_SIGNAL_COUNT];
        build_forward_signal_set(&forward_set);
        if (sigprocmask(SIG_BLOCK, &forward_set, &old_mask) < 0) {
            perror("sigprocmask");
            close(handoff_pipe[0]); close(handoff_pipe[1]);
            free(metas); free(ent); free(strtab); close(sfd);
            return 127;
        }
        pid_t lpid = fork();
        if (lpid < 0) {
            perror("fork");
            sigprocmask(SIG_SETMASK, &old_mask, NULL);
            close(handoff_pipe[0]); close(handoff_pipe[1]);
            free(metas); free(ent); free(strtab); close(sfd);
            return 127;
        }

        if (lpid == 0) {
            sigprocmask(SIG_SETMASK, &old_mask, NULL);
            close(handoff_pipe[0]);
            /* loader_run() does NOT return on success */
            loader_run(ldr_mem, ldr_mem_foff, ldr_srcfd, metas, ent, strtab,
                       ft.num_entries, runtime_fixups, runtime_fixup_count,
                       handoff_pipe[1],
                       argc, argv, environ);
            close(handoff_pipe[1]);
            close(sfd);
            if (bs_debug_enabled())
                fprintf(stderr, "dlfreeze-bootstrap: in-process loader failed\n");
            _exit(127);
        }

        close(handoff_pipe[1]);
        g_child = lpid;
        g_forwarded_signal = 0;
        if (install_forward_signal_handlers(old_forward_actions) < 0) {
            perror("sigaction");
            sigprocmask(SIG_SETMASK, &old_mask, NULL);
            kill(lpid, SIGKILL);
            while (waitpid(lpid, NULL, 0) < 0 && errno == EINTR) {}
            g_child = -1;
            close(handoff_pipe[0]);
            if (from_memory == 0 && ldr_mem_foff == 0 && ldr_mem)
                munmap((void *)ldr_mem, st.st_size);
            free(metas); free(ent); free(strtab); close(sfd);
            return 127;
        }
        sigprocmask(SIG_SETMASK, &old_mask, NULL);

        int lst = 0;
        while (waitpid(lpid, &lst, 0) < 0)
            if (errno != EINTR) break;

        sigprocmask(SIG_BLOCK, &forward_set, NULL);
        int direct_interrupted = g_forwarded_signal != 0;
        g_child = -1;
        restore_forward_signal_handlers(old_forward_actions);
        sigprocmask(SIG_SETMASK, &old_mask, NULL);

        char handoff_marker;
        ssize_t handoff_len;
        do {
            handoff_len = read(handoff_pipe[0], &handoff_marker,
                               sizeof(handoff_marker));
        } while (handoff_len < 0 && errno == EINTR);
        close(handoff_pipe[0]);
        int application_started = handoff_len == 1 &&
            handoff_marker == DLFRZ_HANDOFF_APPLICATION_STARTED;
        int terminal_refusal = handoff_len == 1 &&
            handoff_marker == DLFRZ_HANDOFF_TERMINAL_REFUSAL;

        if (from_memory == 0 && ldr_mem_foff == 0 && ldr_mem)
            munmap((void *)ldr_mem, st.st_size);

        free(metas);

        if (terminal_refusal) {
            free(ent); free(strtab); close(sfd);
            return 127;
        }
        if (application_started || direct_interrupted) {
            free(ent); free(strtab); close(sfd);
            if (WIFEXITED(lst))
                return WEXITSTATUS(lst);
            if (WIFSIGNALED(lst))
                reraise_child_signal(WTERMSIG(lst));
            return 127;
        }
        if (prelinked_payload) {
            fprintf(stderr,
                    "dlfreeze: refusing extraction fallback for a prelinked "
                    "direct-load artifact\n");
            free(ent); free(strtab); close(sfd);
            return 127;
        }
    }

    /* 6. create workdir for extraction fallback (/tmp only). */
    if (make_workdir(g_tmpdir, sizeof(g_tmpdir)) < 0) {
        perror("mkdtemp"); close(sfd); return 127;
    }

    /* 7. extract all files */
    char exe_path[PATH_MAX + 256]    = {0};
    char exe_identity[PATH_MAX + 256] = {0};
    char interp_path[PATH_MAX + 256] = {0};
    char system_interp_path[PATH_MAX + 256] = {0};
    int has_data_entries = 0;

    for (uint32_t i = 0; i < ft.num_entries; i++) {
        if ((ent[i].flags & DLFRZ_FLAG_DATA) != 0) {
            has_data_entries = 1;
            break;
        }
    }

    for (uint32_t i = 0; i < ft.num_entries; i++) {
        const char *name = strtab + ent[i].name_offset;
        if ((ent[i].flags & DLFRZ_FLAG_DATA_NEGATIVE) != 0)
            continue;

        if ((ent[i].flags & DLFRZ_FLAG_DATA_VIRTUAL) != 0) {
            const char marker[] = "/.dir";
            size_t name_len = strlen(name);
            size_t marker_len = sizeof(marker) - 1;

            if (name_len > marker_len &&
                strcmp(name + name_len - marker_len, marker) == 0) {
                char dst[PATH_MAX + 256];
                int n;

                if (name[0] == '/')
                    n = snprintf(dst, sizeof(dst), "%s%.*s", g_tmpdir,
                                 (int)(name_len - marker_len), name);
                else
                    n = snprintf(dst, sizeof(dst), "%s/%.*s", g_tmpdir,
                                 (int)(name_len - marker_len), name);
                if (n < 0 || n >= (int)sizeof(dst) ||
                    ensure_parent_dirs(dst) < 0 ||
                    (mkdir(dst, 0755) < 0 && errno != EEXIST)) {
                    fprintf(stderr, "dlfreeze-bootstrap: mkdir failed: %s\n", dst);
                    rmtree(g_tmpdir);
                    close(sfd); return 127;
                }
            }
            continue;
        }

        char dst[PATH_MAX + 256];
        /* Extract DATA entries and DLOPEN entries at their full original
         * path so path-based loaders find them.  When data files are present,
         * also keep an absolute main executable under that same tree so
         * executable-relative resource discovery sees a coherent root.
         * Without data entries, keep the main executable flat so runtimes can
         * continue to use the target system's resource tree.  System shared
         * libraries (DT_NEEDED-style soname lookup) go flat into g_tmpdir
         * (used as LD_LIBRARY_PATH). */
        int use_full_path = (name[0] == '/') &&
            ((has_data_entries && (ent[i].flags & DLFRZ_FLAG_MAIN_EXE) != 0) ||
             ((ent[i].flags & DLFRZ_FLAG_DATA) != 0) ||
             ((ent[i].flags & DLFRZ_FLAG_DLOPEN) != 0));
        if (use_full_path)
            snprintf(dst, sizeof(dst), "%s%s", g_tmpdir, name);
        else
            snprintf(dst, sizeof(dst), "%s/%s", g_tmpdir, bs_basename(name));

        int is_exec = (ent[i].flags & (DLFRZ_FLAG_MAIN_EXE | DLFRZ_FLAG_INTERP));

        if (ensure_parent_dirs(dst) < 0) {
            fprintf(stderr, "dlfreeze-bootstrap: mkdir failed: %s\n", dst);
            rmtree(g_tmpdir);
            close(sfd); return 127;
        }

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

        if (use_full_path && (ent[i].flags & DLFRZ_FLAG_DLOPEN) != 0) {
            char flat[PATH_MAX + 256];
            snprintf(flat, sizeof(flat), "%s/%s", g_tmpdir, bs_basename(name));
            if (strcmp(flat, dst) != 0) {
                unlink(flat);
                if (link(dst, flat) < 0) {
                    if (from_memory) {
                        rc = extract_mem(mem_base, g_loader_info.payload_foff,
                                         flat, ent[i].data_offset,
                                         ent[i].data_size, is_exec);
                    } else {
                        rc = extract(sfd, flat, ent[i].data_offset,
                                     ent[i].data_size, is_exec);
                    }
                    if (rc < 0) {
                        fprintf(stderr, "dlfreeze-bootstrap: extract failed: %s\n", name);
                        rmtree(g_tmpdir);
                        close(sfd); return 127;
                    }
                }
            }
        }

        if (ent[i].flags & DLFRZ_FLAG_MAIN_EXE) {
            snprintf(exe_path, sizeof(exe_path), "%s", dst);
            snprintf(exe_identity, sizeof(exe_identity), "%s", name);
        }
        if (ent[i].flags & DLFRZ_FLAG_INTERP) {
            snprintf(interp_path, sizeof(interp_path), "%s", dst);
            snprintf(system_interp_path, sizeof(system_interp_path), "%s", name);
        }
    }
    free(ent); free(strtab); close(sfd);

    if (!exe_path[0]) {
        fprintf(stderr, "dlfreeze-bootstrap: no main executable in payload\n");
        rmtree(g_tmpdir); return 127;
    }

    /* 8. Build argv for the real program.  Prefer normal kernel PT_INTERP
     * startup when the target has a byte-identical interpreter.  Besides
     * preserving normal /proc/self/exe and self-reexec behavior, this avoids
     * relying on libc-specific command-line options.  If the interpreter is
     * absent or differs, launch the executable through the bundled copy so
     * the bundled libc and loader remain a matched pair. */
    int launcher_available = interp_path[0] != '\0';
    int direct_available = !launcher_available ||
        (system_interp_path[0] == '/' && access(system_interp_path, X_OK) == 0);
    int use_interp_launcher = launcher_available &&
        !(direct_available && files_identical(system_interp_path, interp_path));

    /* Build the kernel and explicit-interpreter argv variants. */
    char **direct_nav = calloc((size_t)argc + 1, sizeof(char *));
    if (!direct_nav) {
        rmtree(g_tmpdir);
        return 127;
    }
    direct_nav[0] = exe_identity[0] ? exe_identity : exe_path;
    for (int i = 1; i < argc; i++)
        direct_nav[i] = argv[i];

    char **launcher_nav = NULL;
    if (launcher_available) {
        launcher_nav = calloc((size_t)argc + 2, sizeof(char *));
        if (!launcher_nav) {
            free(direct_nav);
            rmtree(g_tmpdir);
            return 127;
        }
        launcher_nav[0] = interp_path;
        launcher_nav[1] = exe_path;
        for (int i = 1; i < argc; i++)
            launcher_nav[i + 1] = argv[i];
    }

    char **nav = use_interp_launcher ? launcher_nav : direct_nav;

    /* 9. set LD_LIBRARY_PATH */
    const char *oldlp = getenv("LD_LIBRARY_PATH");
    char lp[PATH_MAX * 2];
    if (oldlp && oldlp[0])
        snprintf(lp, sizeof(lp), "%s:%s", g_tmpdir, oldlp);
    else
        snprintf(lp, sizeof(lp), "%s", g_tmpdir);
    setenv("LD_LIBRARY_PATH", lp, 1);
    setenv("DLFREEZE_TMPDIR", g_tmpdir, 1);
    setenv("DLFREEZE_EXTRACT_ROOT", g_tmpdir, 1);

    /* 10. fork→exec, parent waits + cleans up. */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = fwd_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    int sigs[] = { SIGINT, SIGTERM, SIGHUP, SIGQUIT, SIGUSR1, SIGUSR2,
                   SIGPIPE, SIGALRM, SIGCONT, SIGTSTP, SIGTTIN, SIGTTOU, 0 };
    for (int i = 0; sigs[i]; i++) sigaction(sigs[i], &sa, NULL);

    int status = 0;
    g_child = fork();
    if (g_child < 0) {
        perror("fork"); rmtree(g_tmpdir);
        free(direct_nav); free(launcher_nav);
        return 127;
    }

    if (g_child == 0) {
        if (use_interp_launcher)
            execve(interp_path, nav, environ);
        else
            execve(exe_path, nav, environ);
        perror("execve");
        _exit(127);
    }

    while (waitpid(g_child, &status, 0) < 0)
        if (errno != EINTR) break;

    rmtree(g_tmpdir);
    free(direct_nav);
    free(launcher_nav);

    if (WIFEXITED(status))
        return WEXITSTATUS(status);
    if (WIFSIGNALED(status))
        reraise_child_signal(WTERMSIG(status));
    return 127;
}
