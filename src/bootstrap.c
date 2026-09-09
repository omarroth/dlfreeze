/*
 * dlfreeze bootstrap – statically-linked runtime stub.
 *
 * This small binary IS the frozen executable.  It:
 *   1. Reads the embedded payload from its mapped PT_LOAD segment, with
 *      /proc/self/exe retained only as a compatibility fallback
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
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/sysmacros.h>
#include <sys/statvfs.h>
#include <sys/vfs.h>
#include <stdint.h>
#include <elf.h>

#include "common.h"
#include "load_segments.h"
#include "loader.h"

/* Some standalone musl sysroots intentionally omit Linux kernel headers. */
#ifndef PROC_SUPER_MAGIC
#define PROC_SUPER_MAGIC 0x9fa0
#endif
#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif
#ifndef MREMAP_MAYMOVE
#define MREMAP_MAYMOVE 1
#endif
#ifndef MREMAP_FIXED
#define MREMAP_FIXED 2
#endif
#ifndef MREMAP_DONTUNMAP
#define MREMAP_DONTUNMAP 4
#endif
#ifndef MADV_WIPEONFORK
#define MADV_WIPEONFORK 18
#endif

/*
 * Reserve one program-header slot for the packer to turn into the payload
 * PT_LOAD.  Do not rely on a toolchain-provided build-id or property note:
 * several perfectly valid static musl linkers emit neither.  The reference
 * from main keeps this allocatable note alive under --gc-sections.
 *
 * The descriptor is intentionally a private marker rather than runtime
 * metadata.  It remains covered by the bootstrap's ordinary read-only LOAD;
 * only its PT_NOTE program header is repurposed in the frozen output.
 */
extern const unsigned char dlfrz_payload_note[];
__asm__(
#if defined(__aarch64__)
    ".pushsection .note.dlfreeze.payload,\"a\",%note\n"
#else
    ".pushsection .note.dlfreeze.payload,\"a\",@note\n"
#endif
    ".balign 4\n"
    ".global dlfrz_payload_note\n"
    "dlfrz_payload_note:\n"
    ".long 8\n"                 /* n_namesz */
    ".long 8\n"                 /* n_descsz */
    ".long 0x44504c44\n"        /* private note type: DPLD */
    ".ascii \"DLFREEZE\"\n"    /* note owner */
    ".balign 4\n"
    ".ascii \"DLFRZPLD\"\n"    /* descriptor / packer marker */
    ".balign 4\n"
    ".popsection\n");

/* Packer scans the binary for this sentinel and patches it. */
static volatile struct dlfrz_loader_info g_loader_info
    __attribute__((used, section(".data")))
    = { {'D','L','F','R','Z','L','D','R'}, 0, 0, 0 };

static volatile struct dlfrz_premap_info g_premap_info
    __attribute__((used, section(".data")))
    = { {'D','L','F','R','Z','P','M','1'}, 0, 0 };
static struct dlfrz_premap_range g_bs_premaps[DLFRZ_PREMAP_MAX_PHDRS];
static struct dlfrz_premap_range g_bs_premap_selected[DLFRZ_PREMAP_MAX_PHDRS];
static size_t g_bs_premap_count;

/* ---- globals ----------------------------------------------------- */
static volatile pid_t g_child;
static volatile sig_atomic_t g_forwarded_signal;
static char g_tmpdir[PATH_MAX];
static int g_tmpdir_fd = -1;
static int g_tmp_parent_fd = -1;
static dev_t g_tmpdir_dev;
static ino_t g_tmpdir_ino;
static int g_bootstrap_secure_mode;
extern char **environ;

static int authenticated_fdinfo_mount_id(int fd, uint64_t *mount_id)
{
    char path[64];
    char *line = NULL;
    size_t line_capacity = 0;
    FILE *stream;
    int info_fd;
    int path_len;
    int result = -1;
    int saved_errno = ENOENT;

    path_len = snprintf(path, sizeof(path), "/proc/self/fdinfo/%d", fd);
    if (path_len < 0 || (size_t)path_len >= sizeof(path)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    info_fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (info_fd < 0)
        return -1;
    {
        struct statfs filesystem;
        int filesystem_result;

        /* A path named /proc can be supplied by the mount namespace.  Do
         * not consume its text as kernel identity evidence until the opened
         * descriptor itself proves that it belongs to procfs. */
        memset(&filesystem, 0, sizeof(filesystem));
        filesystem_result = fstatfs(info_fd, &filesystem);
        if (filesystem_result != 0) {
            /* A seccomp SIGSYS handler may resume an unexecuted syscall with
             * an unexpected nonnegative return value.  Only the documented
             * exact success value can authorize bytes from fdinfo. */
            saved_errno = filesystem_result < 0 && errno ? errno : EIO;
            close(info_fd);
            errno = saved_errno;
            return -1;
        }
        if ((unsigned long)filesystem.f_type !=
            (unsigned long)PROC_SUPER_MAGIC) {
            saved_errno = ENODEV;
            close(info_fd);
            errno = saved_errno;
            return -1;
        }
    }
    stream = fdopen(info_fd, "r");
    if (!stream) {
        saved_errno = errno;
        close(info_fd);
        errno = saved_errno;
        return -1;
    }

    for (;;) {
        static const char field[] = "mnt_id:";
        ssize_t line_length;
        char *end;
        char *value;
        uint64_t parsed = 0;

        /* EOF does not define errno.  Clear it before getline so a stream
         * error is never diagnosed from an unrelated earlier syscall. */
        errno = 0;
        line_length = getline(&line, &line_capacity, stream);
        if (line_length < 0) {
            if (ferror(stream))
                saved_errno = errno ? errno : EIO;
            break;
        }
        end = line + (size_t)line_length;
        if (end > line && end[-1] == '\n')
            end--;
        if ((size_t)(end - line) < sizeof(field) - 1 ||
            memcmp(line, field, sizeof(field) - 1) != 0)
            continue;
        value = line + sizeof(field) - 1;
        while (value < end && (*value == ' ' || *value == '\t'))
            value++;
        if (value == end) {
            saved_errno = EINVAL;
            goto out;
        }
        while (value < end && *value >= '0' && *value <= '9') {
            unsigned digit = (unsigned)(*value - '0');

            if (parsed > (UINT64_MAX - digit) / 10) {
                saved_errno = EOVERFLOW;
                goto out;
            }
            parsed = parsed * 10 + digit;
            value++;
        }
        if (value != end) {
            saved_errno = EINVAL;
            goto out;
        }
        *mount_id = parsed;
        result = 0;
        break;
    }
out:
    free(line);
    if (fclose(stream) != 0 && result == 0) {
        result = -1;
        saved_errno = errno;
    }
    if (result < 0)
        errno = saved_errno;
    return result;
}

enum contained_filesystem_probe_kind {
    CONTAINED_FS_MOUNT_STATX_SAME = 1,
    CONTAINED_FS_MOUNT_FDINFO_SAME = 2,
    CONTAINED_FS_EXECUTION = 3
};

#define CONTAINED_FS_WAIT_CLONE UINT32_C(0x80000000)

enum contained_filesystem_probe_outcome {
    /* Avoid zero so an unmodified wait status can never authorize a probe. */
    CONTAINED_FS_PROBE_TRUE = 64,
    CONTAINED_FS_PROBE_FALSE = 65,
    CONTAINED_FS_PROBE_UNKNOWN = 66
};

static void contained_filesystem_probe_child(
    enum contained_filesystem_probe_kind kind, int first_fd, int second_fd)
    __attribute__((noreturn));
static void contained_filesystem_probe_child(
    enum contained_filesystem_probe_kind kind, int first_fd, int second_fd)
{
    enum contained_filesystem_probe_outcome outcome =
        CONTAINED_FS_PROBE_UNKNOWN;

    switch (kind) {
    case CONTAINED_FS_MOUNT_STATX_SAME:
#if defined(SYS_statx) && defined(STATX_MNT_ID) && defined(AT_EMPTY_PATH)
        {
            struct statx first_status;
            struct statx second_status;
            long first_result;
            long second_result;

            memset(&first_status, 0, sizeof(first_status));
            memset(&second_status, 0, sizeof(second_status));
            first_result = syscall(
                SYS_statx, first_fd, "",
                AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW,
                STATX_MNT_ID, &first_status);
            second_result = syscall(
                SYS_statx, second_fd, "",
                AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW,
                STATX_MNT_ID, &second_status);
            if (first_result == 0 && second_result == 0 &&
                (first_status.stx_mask & STATX_MNT_ID) != 0 &&
                (second_status.stx_mask & STATX_MNT_ID) != 0)
                outcome = first_status.stx_mnt_id ==
                              second_status.stx_mnt_id
                    ? CONTAINED_FS_PROBE_TRUE
                    : CONTAINED_FS_PROBE_FALSE;
        }
#endif
        break;
    case CONTAINED_FS_MOUNT_FDINFO_SAME:
        {
            uint64_t first_mount;
            uint64_t second_mount;

            if (authenticated_fdinfo_mount_id(
                    first_fd, &first_mount) == 0 &&
                authenticated_fdinfo_mount_id(
                    second_fd, &second_mount) == 0)
                outcome = first_mount == second_mount
                    ? CONTAINED_FS_PROBE_TRUE
                    : CONTAINED_FS_PROBE_FALSE;
        }
        break;
    case CONTAINED_FS_EXECUTION:
#ifdef ST_NOEXEC
        {
            struct statfs filesystem;
            int filesystem_result;

            /* Avoid fstatvfs wrappers which may collapse an unexpected
             * positive fstatfs result into success after a handled SIGSYS.
             * Linux exposes the same ST_* mount flags in statfs.f_flags. */
            memset(&filesystem, 0, sizeof(filesystem));
            filesystem_result = fstatfs(first_fd, &filesystem);
            if (filesystem_result == 0)
                outcome = (filesystem.f_flags & ST_NOEXEC) == 0
                    ? CONTAINED_FS_PROBE_TRUE
                    : CONTAINED_FS_PROBE_FALSE;
        }
#endif
        break;
    default:
        break;
    }
    _exit((int)outcome);
}

/* Optional filesystem interfaces are particularly likely to be absent from
 * old seccomp allowlists, some of which use SECCOMP_RET_KILL or TRAP instead
 * of returning an error.  Execute each probe in an exit-signal-zero clone:
 * it is COW-isolated, generates no SIGCHLD, and is reaped explicitly with
 * __WCLONE.  Thus the inherited SIGCHLD action and the complete signal mask
 * remain byte-for-byte untouched in both parent and child.
 *
 * A missing or malformed exit status is simply "unknown" to the caller.
 * Comparisons happen wholly inside the child, so containment adds no pipe,
 * socket, shared-memory, or descriptor-lifecycle dependency to extraction. */
static int contained_filesystem_probe(
    enum contained_filesystem_probe_kind kind, int first_fd, int second_fd)
{
    int child_status = -1;
    int saved_errno = EIO;
    long child;
    long waited;

    if (first_fd < 0 ||
        (kind != CONTAINED_FS_EXECUTION && second_fd < 0)) {
        errno = EINVAL;
        return -1;
    }

#ifdef SYS_clone
    child = syscall(SYS_clone, 0, 0, 0, 0, 0);
#else
    child = -1;
    errno = ENOSYS;
#endif
    if (child < 0) {
        if (errno)
            saved_errno = errno;
        errno = saved_errno;
        return -1;
    }
    if (child == 0)
        contained_filesystem_probe_child(kind, first_fd, second_fd);

    do {
        waited = syscall(SYS_wait4, child, &child_status,
                         (int)CONTAINED_FS_WAIT_CLONE, NULL);
    } while (waited < 0 && errno == EINTR);
    if (waited != child) {
        if (waited < 0)
            saved_errno = errno;
        errno = saved_errno;
        return -1;
    }
    if (!WIFEXITED(child_status)) {
        errno = EIO;
        return -1;
    }
    switch (WEXITSTATUS(child_status)) {
    case CONTAINED_FS_PROBE_TRUE:
        return 1;
    case CONTAINED_FS_PROBE_FALSE:
        return 0;
    default:
        errno = ENOTSUP;
        return -1;
    }
}

static int directory_fds_are_on_same_mount(int first_fd, int second_fd)
{
    /* statx is direct kernel evidence.  Authenticated procfs fdinfo covers
     * older kernels and sysroots.  Each potentially filtered interface gets
     * its own disposable child so a fatal denial of the first does not
     * prevent the independent fallback from being attempted. */
    int same = contained_filesystem_probe(
        CONTAINED_FS_MOUNT_STATX_SAME, first_fd, second_fd);

    if (same >= 0)
        return same;
    return contained_filesystem_probe(
        CONTAINED_FS_MOUNT_FDINFO_SAME, first_fd, second_fd);
}

/* Returns one for executable, zero for a proven noexec mount, and -1 when
 * the optional query is unavailable or its disposable child was killed. */
static int directory_execution_support(int fd)
{
    return contained_filesystem_probe(CONTAINED_FS_EXECUTION, fd, -1);
}

#if defined(NSIG)
#define FORWARD_SIGNAL_CAPACITY NSIG
#elif defined(_NSIG)
#define FORWARD_SIGNAL_CAPACITY _NSIG
#else
/* Linux exposes signals 1..64 on every supported architecture. */
#define FORWARD_SIGNAL_CAPACITY 65
#endif

static int signal_can_report_synchronous_fault(int sig)
{
    return sig == SIGILL || sig == SIGTRAP || sig == SIGBUS ||
           sig == SIGFPE || sig == SIGSEGV || sig == SIGSYS;
}

/* Every catchable Linux signal except SIGCHLD is application-visible when it
 * is sent to the wrapper process.  Fault-number signals need special handling
 * below because those same numbers can also originate synchronously inside
 * the supervisor. */
static int signal_should_forward(int sig)
{
    switch (sig) {
    case SIGHUP:
    case SIGINT:
    case SIGQUIT:
    case SIGILL:
    case SIGTRAP:
    case SIGABRT:
    case SIGBUS:
    case SIGFPE:
    case SIGUSR1:
    case SIGSEGV:
    case SIGUSR2:
    case SIGPIPE:
    case SIGALRM:
    case SIGTERM:
#ifdef SIGSTKFLT
    case SIGSTKFLT:
#endif
    case SIGCONT:
    case SIGTSTP:
    case SIGTTIN:
    case SIGTTOU:
    case SIGURG:
    case SIGXCPU:
    case SIGXFSZ:
    case SIGVTALRM:
    case SIGPROF:
    case SIGWINCH:
#ifdef SIGIO
    case SIGIO:
#endif
#ifdef SIGPWR
    case SIGPWR:
#endif
    case SIGSYS:
        return 1;
    default:
        break;
    }
#if defined(SIGRTMIN) && defined(SIGRTMAX)
    if (sig >= SIGRTMIN && sig <= SIGRTMAX)
        return 1;
#endif
    return 0;
}

/* SA_RESETHAND protects the supervisor from retrying a real synchronous
 * fault.  For an asynchronously sent fault-number signal the handler rearms
 * this immutable action before forwarding, so repeated application signals
 * retain the same semantics.  sigaction() is async-signal-safe. */
static struct sigaction g_fault_forward_action;

/* ---- tmpdir selection -------------------------------------------- */
static int mkdirat_with_exact_mode(int dirfd, const char *name, mode_t mode);

#define WORKDIR_CREATE_ATTEMPTS 128U
#define WORKDIR_RANDOM_BYTES 16U

static int read_exact_fd(int fd, void *buffer, size_t size)
{
    unsigned char *bytes = buffer;
    size_t consumed = 0;

    while (consumed < size) {
        ssize_t count = read(fd, bytes + consumed, size - consumed);

        if (count > 0) {
            consumed += (size_t)count;
            continue;
        }
        if (count < 0 && errno == EINTR)
            continue;
        if (count == 0)
            errno = EIO;
        return -1;
    }
    return 0;
}

/* Random names limit collision-based denial of service; mkdirat() is the
 * operation that establishes ownership atomically, and an existing name is
 * never opened.  Keep a process-local fallback for old kernels, seccomp, and
 * chroots without /dev/urandom. */
static void workdir_random_bytes(unsigned char bytes[WORKDIR_RANDOM_BYTES])
{
    /* Prefer the established device interface.  Avoid an optional raw
     * getrandom probe: inherited seccomp filters may kill unknown syscalls
     * instead of returning ENOSYS/EPERM. */
    {
        int random_fd = open("/dev/urandom",
                             O_RDONLY | O_CLOEXEC | O_NOFOLLOW);

        if (random_fd >= 0) {
            struct stat status;

            if (fstat(random_fd, &status) == 0 &&
                S_ISCHR(status.st_mode) && major(status.st_rdev) == 1 &&
                minor(status.st_rdev) == 9 &&
                read_exact_fd(random_fd, bytes, WORKDIR_RANDOM_BYTES) == 0) {
                close(random_fd);
                return;
            }
            close(random_fd);
        }
    }

    {
        uint64_t process = (uint64_t)(unsigned long)getpid();
        uint64_t first = (process << 32) ^ process ^
            UINT64_C(0x9e3779b97f4a7c15);
        uint64_t second = (first << 29) | (first >> 35);

        /* Predictability is harmless here: mkdirat() establishes ownership
         * atomically.  Do not expose a live pointer in the directory name
         * merely to make this collision-only fallback look random. */
        second ^= UINT64_C(0xd1b54a32d192ed03);
        memcpy(bytes, &first, sizeof(first));
        memcpy(bytes + sizeof(first), &second, sizeof(second));
    }
}

static int workdir_path_component_is_trusted(const struct stat *status)
{
    uid_t effective_uid = geteuid();

    if (!status || !S_ISDIR(status->st_mode)) {
        errno = ENOTDIR;
        return 0;
    }
    /* A directory owner can replace an immediate child even when the sticky
     * bit excludes other writers.  Every controller of the absolute path
     * handed to ld.so must therefore be either root or this effective user. */
    if (status->st_uid != 0 && status->st_uid != effective_uid) {
        errno = EACCES;
        return 0;
    }
    if ((status->st_mode & (S_IWGRP | S_IWOTH)) != 0 &&
        (status->st_mode & S_ISVTX) == 0) {
        errno = EACCES;
        return 0;
    }
    return 1;
}

static int loader_search_path_is_literal(const char *path)
{
    /* glibc accepts both ':' and ';' as list separators and expands dynamic
     * string tokens beginning with '$'.  Other supported loaders accept at
     * least the colon form.  There is no portable escaping syntax here. */
    if (!path || strpbrk(path, ":;$") != NULL) {
        errno = EINVAL;
        return 0;
    }
    return 1;
}

static void format_workdir_name(
    char name[sizeof("dlfreeze.") - 1 + WORKDIR_RANDOM_BYTES * 2 + 1],
    const unsigned char random_bytes[WORKDIR_RANDOM_BYTES], unsigned attempt)
{
    static const char prefix[] = "dlfreeze.";
    static const char hex[] = "0123456789abcdef";
    unsigned char varied[WORKDIR_RANDOM_BYTES];
    size_t offset = sizeof(prefix) - 1;

    memcpy(varied, random_bytes, sizeof(varied));
    for (size_t i = 0; i < sizeof(attempt); i++)
        varied[sizeof(varied) - 1 - i] ^=
            (unsigned char)(attempt >> (i * CHAR_BIT));
    memcpy(name, prefix, sizeof(prefix) - 1);
    for (size_t i = 0; i < sizeof(varied); i++) {
        name[offset++] = hex[varied[i] >> 4];
        name[offset++] = hex[varied[i] & 0x0f];
    }
    name[offset] = '\0';
}

/* Resolve TMPDIR once, then reopen every component relative to an already
 * bound descriptor.  A TMPDIR symlink is accepted by recording its canonical
 * target, but no symlink is trusted while that canonical target is opened. */
static int open_canonical_directory(const char *candidate, char *canonical,
                                    size_t canonical_size,
                                    struct stat *status_out)
{
    char resolved[PATH_MAX];
    char component[NAME_MAX + 1];
    const char *cursor;
    size_t resolved_length;
    int current_fd;

    if (!candidate || candidate[0] != '/') {
        errno = EINVAL;
        return -1;
    }
    if (!realpath(candidate, resolved))
        return -1;
    resolved_length = strlen(resolved);
    if (resolved_length == 0 || resolved[0] != '/' ||
        resolved_length >= canonical_size) {
        errno = ENAMETOOLONG;
        return -1;
    }

    if (!loader_search_path_is_literal(resolved))
        return -1;

    current_fd = open("/", O_PATH | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (current_fd < 0)
        return -1;
    {
        struct stat root_status;

        if (fstat(current_fd, &root_status) < 0 ||
            !workdir_path_component_is_trusted(&root_status)) {
            int saved_errno = errno;

            close(current_fd);
            errno = saved_errno;
            return -1;
        }
    }
    cursor = resolved + 1;
    while (*cursor) {
        const char *end = strchr(cursor, '/');
        size_t length = end ? (size_t)(end - cursor) : strlen(cursor);
        struct stat next_status;
        int next_fd;

        if (length == 0 || length > NAME_MAX) {
            close(current_fd);
            errno = ENAMETOOLONG;
            return -1;
        }
        memcpy(component, cursor, length);
        component[length] = '\0';
        next_fd = openat(current_fd, component,
                         O_PATH | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (next_fd < 0) {
            int saved_errno = errno;

            close(current_fd);
            errno = saved_errno;
            return -1;
        }
        if (fstat(next_fd, &next_status) < 0 ||
            !workdir_path_component_is_trusted(&next_status)) {
            int saved_errno = errno;

            close(next_fd);
            close(current_fd);
            errno = saved_errno;
            return -1;
        }
        close(current_fd);
        current_fd = next_fd;
        cursor = end ? end + 1 : cursor + length;
    }

    {
        struct stat opened;
        struct stat path_status;

        if (fstat(current_fd, &opened) < 0 ||
            fstatat(AT_FDCWD, resolved, &path_status,
                    AT_SYMLINK_NOFOLLOW) < 0) {
            int saved_errno = errno;

            close(current_fd);
            errno = saved_errno;
            return -1;
        }
        if (!workdir_path_component_is_trusted(&opened) ||
            !workdir_path_component_is_trusted(&path_status)) {
            int saved_errno = errno;

            close(current_fd);
            errno = saved_errno;
            return -1;
        }
        if (opened.st_dev != path_status.st_dev ||
            opened.st_ino != path_status.st_ino) {
            close(current_fd);
            errno = ESTALE;
            return -1;
        }
        *status_out = opened;
    }
    memcpy(canonical, resolved, resolved_length + 1);
    return current_fd;
}

static int directory_fds_are_same_instance(int first_fd, int second_fd)
{
    struct stat first_status;
    struct stat second_status;
    int same_mount;

    if (fstat(first_fd, &first_status) < 0 ||
        fstat(second_fd, &second_status) < 0)
        return 0;
    if (!S_ISDIR(first_status.st_mode) ||
        !S_ISDIR(second_status.st_mode) ||
        first_status.st_dev != second_status.st_dev ||
        first_status.st_ino != second_status.st_ino) {
        errno = ESTALE;
        return 0;
    }
    same_mount = directory_fds_are_on_same_mount(first_fd, second_fd);
    if (same_mount == 0) {
        errno = ESTALE;
        return 0;
    }
    return 1;
}

static void remove_created_workdir(int parent_fd, const char *name,
                                   int workdir_fd, int identity_valid,
                                   dev_t device, ino_t inode)
{
    struct stat current;

    if (workdir_fd >= 0)
        close(workdir_fd);
    if (identity_valid &&
        fstatat(parent_fd, name, &current, AT_SYMLINK_NOFOLLOW) == 0 &&
        S_ISDIR(current.st_mode) && current.st_dev == device &&
        current.st_ino == inode)
        (void)unlinkat(parent_fd, name, AT_REMOVEDIR);
}

static int make_workdir_in(const char *candidate, char *out, size_t out_sz)
{
    unsigned char random_bytes[WORKDIR_RANDOM_BYTES];
    char canonical[PATH_MAX];
    char name[sizeof("dlfreeze.") - 1 + WORKDIR_RANDOM_BYTES * 2 + 1];
    struct stat parent_status;
    struct stat created_status;
    struct stat opened_status;
    int parent_fd;
    int workdir_fd = -1;
    int parent_alias_fd = -1;
    int workdir_alias_fd = -1;
    int created_identity_valid = 0;
    int n;

    parent_fd = open_canonical_directory(candidate, canonical,
                                         sizeof(canonical), &parent_status);
    if (parent_fd < 0)
        return -1;
    {
        int execution_support = directory_execution_support(parent_fd);

        if (execution_support == 0) {
            int saved_errno = EACCES;

            close(parent_fd);
            errno = saved_errno;
            return -1;
        }
    }
    workdir_random_bytes(random_bytes);
    for (unsigned attempt = 0; attempt < WORKDIR_CREATE_ATTEMPTS; attempt++) {
        format_workdir_name(name, random_bytes, attempt);
        if (mkdirat_with_exact_mode(parent_fd, name, 0700) == 0)
            goto created;
        if (errno != EEXIST) {
            int saved_errno = errno;

            close(parent_fd);
            errno = saved_errno;
            return -1;
        }
    }
    close(parent_fd);
    errno = EEXIST;
    return -1;

created:
    memset(&created_status, 0, sizeof(created_status));
    if (fstatat(parent_fd, name, &created_status,
                AT_SYMLINK_NOFOLLOW) < 0)
        goto fail_created;
    if (!S_ISDIR(created_status.st_mode)) {
        errno = ESTALE;
        goto fail_created;
    }
    created_identity_valid = 1;
    workdir_fd = openat(parent_fd, name,
                        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (workdir_fd < 0 || fstat(workdir_fd, &opened_status) < 0)
        goto fail_created;
    if (!S_ISDIR(opened_status.st_mode) ||
        opened_status.st_dev != created_status.st_dev ||
        opened_status.st_ino != created_status.st_ino) {
        errno = ESTALE;
        goto fail_created;
    }
    {
        int chmod_result;

        do {
            chmod_result = fchmod(workdir_fd, 0700);
        } while (chmod_result < 0 && errno == EINTR);
        if (chmod_result < 0)
            goto fail_created;
    }
    if (fstat(workdir_fd, &opened_status) < 0)
        goto fail_created;
    if ((opened_status.st_mode & 07777) != 0700) {
        errno = EACCES;
        goto fail_created;
    }
    {
        int execution_support = directory_execution_support(workdir_fd);

        if (execution_support == 0) {
            errno = EACCES;
            goto fail_created;
        }
    }

    n = snprintf(out, out_sz, "%s%s%s", canonical,
                 strcmp(canonical, "/") == 0 ? "" : "/", name);
    if (n < 0 || (size_t)n >= out_sz) {
        errno = ENAMETOOLONG;
        goto fail_created;
    }

    /* Extraction and cleanup use descriptors, but ld.so and execve require
     * absolute paths.  Reopen both complete aliases and compare mount
     * instances as well as inode identities before admitting those paths. */
    parent_alias_fd = open(canonical,
                           O_PATH | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    workdir_alias_fd = open(out,
                            O_PATH | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (parent_alias_fd < 0 || workdir_alias_fd < 0 ||
        !directory_fds_are_same_instance(parent_fd, parent_alias_fd) ||
        !directory_fds_are_same_instance(workdir_fd, workdir_alias_fd))
        goto fail_created;
    close(parent_alias_fd);
    parent_alias_fd = -1;
    close(workdir_alias_fd);
    workdir_alias_fd = -1;

    g_tmp_parent_fd = parent_fd;
    g_tmpdir_fd = workdir_fd;
    g_tmpdir_dev = opened_status.st_dev;
    g_tmpdir_ino = opened_status.st_ino;
    return 0;

fail_created:
    {
        int saved_errno = errno ? errno : EIO;
        dev_t device = created_status.st_dev;
        ino_t inode = created_status.st_ino;

        if (parent_alias_fd >= 0)
            close(parent_alias_fd);
        if (workdir_alias_fd >= 0)
            close(workdir_alias_fd);
        if (workdir_fd >= 0) {
            struct stat trusted;

            if (fstat(workdir_fd, &trusted) == 0) {
                device = trusted.st_dev;
                inode = trusted.st_ino;
                created_identity_valid = 1;
            }
        }
        remove_created_workdir(parent_fd, name, workdir_fd,
                               created_identity_valid, device, inode);
        close(parent_fd);
        errno = saved_errno;
        return -1;
    }
}

static int make_workdir(char *out, size_t out_sz)
{
    const char *tmpdir = NULL;

    if (g_tmpdir_fd >= 0 || g_tmp_parent_fd >= 0) {
        errno = EBUSY;
        return -1;
    }
    if (!g_bootstrap_secure_mode)
        tmpdir = getenv("TMPDIR");
    if (tmpdir && tmpdir[0] == '/' &&
        make_workdir_in(tmpdir, out, out_sz) == 0)
        return 0;

    /* TMPDIR is a preference, not a reason to fail an otherwise-runnable
     * artifact.  /tmp receives exactly the same admission checks. */
    return make_workdir_in("/tmp", out, out_sz);
}

static int mkdirat_with_exact_mode(int dirfd, const char *name, mode_t mode)
{
    mode_t old_umask = umask(0);
    int rc = mkdirat(dirfd, name, mode);
    int saved_errno = errno;

    umask(old_umask);
    errno = saved_errno;
    return rc;
}

static int ensure_relative_directories(int rootfd, const char *path,
                                       int include_last)
{
    char *copy;
    char *component;
    int current_fd;

    if (!path || !path[0])
        return -1;
    copy = strdup(path);
    if (!copy)
        return -1;
    current_fd = openat(rootfd, ".",
                        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (current_fd < 0) {
        free(copy);
        return -1;
    }

    component = copy;
    for (;;) {
        char *separator = strchr(component, '/');
        int next_fd;

        if (!separator && !include_last)
            break;
        if (separator)
            *separator = '\0';
        if (!component[0] ||
            (mkdirat_with_exact_mode(current_fd, component, 0755) < 0 &&
             errno != EEXIST))
            goto fail;
        next_fd = openat(current_fd, component,
                         O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (next_fd < 0)
            goto fail;
        close(current_fd);
        current_fd = next_fd;
        if (!separator)
            break;
        component = separator + 1;
    }
    close(current_fd);
    free(copy);
    return 0;

fail:
    close(current_fd);
    free(copy);
    return -1;
}

/* ---- signal forwarding ------------------------------------------- */
static int is_job_control_signal(int sig)
{
    return sig == SIGCONT || sig == SIGTSTP ||
           sig == SIGTTIN || sig == SIGTTOU;
}

/* Linux reports terminal-driver broadcasts with SI_KERNEL.  Those signals
 * are delivered to every member of the foreground/background process group,
 * so forwarding them would deliver a duplicate to the supervised process.
 *
 * SI_KERNEL is not itself evidence of a process-group broadcast: inherited
 * interval timers also use it, and those timers remain attached to this
 * process across exec but are not inherited by the supervisor's fork child.
 * Such process-local kernel signals must still be forwarded. */
static int signal_is_terminal_group_broadcast(int sig)
{
    return sig == SIGHUP || sig == SIGINT || sig == SIGQUIT ||
           sig == SIGCONT || sig == SIGTSTP || sig == SIGTTIN ||
           sig == SIGTTOU || sig == SIGWINCH;
}

static void fwd_signal(int sig, siginfo_t *info, void *context)
{
    int saved_errno = errno;

    (void)context;

    /* Positive si_code values on these signal numbers describe a fault
     * raised by the kernel, not an asynchronous signal sent to the wrapper.
     * Do not misdeliver a bootstrap fault as an application event.  The
     * handler was installed with SA_RESETHAND, so queueing the same signal
     * makes the wrapper terminate natively after this handler returns; kill
     * the supervised child first so a loader/bootstrap fault cannot orphan
     * it. */
    if (info && info->si_code > 0 &&
        signal_can_report_synchronous_fault(sig)) {
        if (g_child > 0)
            (void)kill(g_child, SIGKILL);
        if (kill(getpid(), sig) < 0)
            _exit(128 + sig);
        errno = saved_errno;
        return;
    }
    if (signal_can_report_synchronous_fault(sig) &&
        sigaction(sig, &g_fault_forward_action, NULL) < 0) {
        if (g_child > 0)
            (void)kill(g_child, SIGKILL);
        _exit(128 + sig);
    }

    /* A stop/continue cycle is not an interrupted direct-load attempt. */
    if (!is_job_control_signal(sig))
        g_forwarded_signal = sig;

    /* The terminal driver sends these broadcasts to the entire process
     * group.  The application shares that group with this supervisor and has
     * therefore already received them.  Other SI_KERNEL sources can be
     * process-local and need forwarding just like process-directed signals. */
    if (g_child > 0 &&
        (!info || info->si_code != SI_KERNEL ||
         !signal_is_terminal_group_broadcast(sig)))
        kill(g_child, sig);
    errno = saved_errno;
}

static void build_forward_signal_set(sigset_t *set)
{
    sigemptyset(set);
    for (int sig = 1; sig < FORWARD_SIGNAL_CAPACITY; sig++)
        if (signal_should_forward(sig))
            sigaddset(set, sig);
}

static int install_forward_signal_handlers(struct sigaction *old_actions)
{
    struct sigaction action;
    int failed_signal = FORWARD_SIGNAL_CAPACITY;

    memset(&action, 0, sizeof(action));
    action.sa_sigaction = fwd_signal;
    sigemptyset(&action.sa_mask);

    for (int sig = 1; sig < FORWARD_SIGNAL_CAPACITY; sig++) {
        if (!signal_should_forward(sig))
            continue;
        action.sa_flags = SA_RESTART | SA_SIGINFO;
        if (signal_can_report_synchronous_fault(sig)) {
            action.sa_flags |= SA_RESETHAND;
            g_fault_forward_action = action;
        }
        if (sigaction(sig, &action, &old_actions[sig]) < 0) {
            failed_signal = sig;
            break;
        }
    }
    if (failed_signal == FORWARD_SIGNAL_CAPACITY)
        return 0;
    for (int sig = 1; sig < failed_signal; sig++)
        if (signal_should_forward(sig))
            sigaction(sig, &old_actions[sig], NULL);
    return -1;
}

static int fail_supervised_wait(pid_t child, const sigset_t *forward_set,
                                int failure_errno)
{
    int block_errno = 0;

    if (sigprocmask(SIG_BLOCK, forward_set, NULL) < 0)
        block_errno = errno;
    /* Clearing the forwarding target before reaping also makes the failure
     * path safe if blocking signals unexpectedly failed. */
    g_child = -1;
    (void)kill(child, SIGKILL);
    while (waitpid(child, NULL, 0) < 0 && errno == EINTR) {}
    errno = failure_errno ? failure_errno : block_errno;
    return -1;
}

/* Wait for a supervised application without breaking shell job control.
 * The wrapper and application intentionally remain in the same process group
 * so they share the controlling terminal.  The wrapper catches stop signals
 * in order to forward process-directed delivery, but it must not remain alive
 * while the application is stopped: wait for proof of the child stop, then
 * stop ourselves.  The shell's later SIGCONT resumes the whole group.
 *
 * Observe terminal status without consuming it, then block forwarding and
 * clear g_child before waitpid() releases the PID.  This closes the otherwise
 * tiny window in which a signal handler could send to a recycled process ID.
 * The forwarding set remains blocked when this function returns. */
static int wait_for_supervised_child(pid_t child, int *status_out,
                                     const sigset_t *forward_set)
{
    for (;;) {
        siginfo_t observed;

        memset(&observed, 0, sizeof(observed));
        if (waitid(P_PID, (id_t)child, &observed,
                   WEXITED | WSTOPPED | WCONTINUED | WNOWAIT) < 0) {
            if (errno == EINTR)
                continue;
            return fail_supervised_wait(child, forward_set, errno);
        }
        if (observed.si_code == CLD_EXITED ||
            observed.si_code == CLD_KILLED ||
            observed.si_code == CLD_DUMPED) {
            int status;
            pid_t waited;

            if (sigprocmask(SIG_BLOCK, forward_set, NULL) < 0)
                return fail_supervised_wait(child, forward_set, errno);
            g_child = -1;
            do {
                waited = waitpid(child, &status, 0);
            } while (waited < 0 && errno == EINTR);
            if (waited != child)
                return -1;
            *status_out = status;
            return 0;
        }
        if (observed.si_code == CLD_STOPPED ||
            observed.si_code == CLD_TRAPPED) {
            siginfo_t consumed;

            memset(&consumed, 0, sizeof(consumed));
            while (waitid(P_PID, (id_t)child, &consumed, WSTOPPED) < 0) {
                if (errno != EINTR)
                    return fail_supervised_wait(child, forward_set, errno);
            }
            if (kill(getpid(), SIGSTOP) < 0) {
                return fail_supervised_wait(child, forward_set, errno);
            }
            continue;
        }
        if (observed.si_code == CLD_CONTINUED) {
            siginfo_t consumed;

            memset(&consumed, 0, sizeof(consumed));
            while (waitid(P_PID, (id_t)child, &consumed, WCONTINUED) < 0) {
                if (errno != EINTR)
                    return fail_supervised_wait(child, forward_set, errno);
            }
            continue;
        }
        return fail_supervised_wait(child, forward_set, EPROTO);
    }
}

static void restore_forward_signal_handlers(
    const struct sigaction *old_actions)
{
    for (int sig = 1; sig < FORWARD_SIGNAL_CAPACITY; sig++)
        if (signal_should_forward(sig))
            sigaction(sig, &old_actions[sig], NULL);
}

/* SIG_IGN and SA_NOCLDWAIT make Linux auto-reap children.  A frozen program
 * is allowed to inherit either setting, but the wrapper itself must override
 * it while it owns a supervisor child.  The child restores the exact incoming
 * action before loader handoff/exec so application-visible disposition is not
 * changed.  Callers block SIGCHLD across this transition and fork. */
static int install_waitable_sigchld(struct sigaction *old_action)
{
    struct sigaction action;

    memset(&action, 0, sizeof(action));
    action.sa_handler = SIG_DFL;
    sigemptyset(&action.sa_mask);
    return sigaction(SIGCHLD, &action, old_action);
}

static int restore_inherited_sigchld(const struct sigaction *old_action)
{
    return sigaction(SIGCHLD, old_action, NULL);
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

/* ---- extraction-directory cleanup -------------------------------- */
static int same_file_identity(const struct stat *st, dev_t dev, ino_t ino)
{
    return st->st_dev == dev && st->st_ino == ino;
}

static int directory_is_on_workdir_mount(int fd)
{
    return g_tmpdir_fd >= 0 &&
           directory_fds_are_on_same_mount(g_tmpdir_fd, fd) == 1;
}

#define CLEANUP_INITIAL_DEPTH 16

struct cleanup_directory_frame {
    DIR *directory;
    char *name_in_parent;
    dev_t dev;
    ino_t ino;
};

static void empty_directory_fd(int rootfd)
{
    struct cleanup_directory_frame *frames;
    size_t capacity = CLEANUP_INITIAL_DEPTH;
    size_t depth = 0;
    int scanfd = fcntl(rootfd, F_DUPFD_CLOEXEC, 0);

    if (scanfd < 0)
        return;
    frames = calloc(capacity, sizeof(*frames));
    if (!frames) {
        close(scanfd);
        return;
    }
    frames[0].directory = fdopendir(scanfd);
    if (!frames[0].directory) {
        close(scanfd);
        free(frames);
        return;
    }
    depth = 1;

    while (depth != 0) {
        struct cleanup_directory_frame *frame = &frames[depth - 1];
        int current_fd = dirfd(frame->directory);
        struct dirent *entry = current_fd >= 0
            ? readdir(frame->directory) : NULL;

        if (entry) {
            struct stat before;
            struct stat opened;
            int childfd;
            DIR *child_directory;
            char *child_name;

            if (entry->d_name[0] == '.' &&
                (entry->d_name[1] == '\0' ||
                 (entry->d_name[1] == '.' && entry->d_name[2] == '\0')))
                continue;
            if (fstatat(current_fd, entry->d_name, &before,
                        AT_SYMLINK_NOFOLLOW) < 0)
                continue;
            if (!S_ISDIR(before.st_mode)) {
                (void)unlinkat(current_fd, entry->d_name, 0);
                continue;
            }

            childfd = openat(current_fd, entry->d_name,
                             O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
            if (childfd < 0)
                continue;
            if (fstat(childfd, &opened) < 0 ||
                !directory_is_on_workdir_mount(childfd) ||
                !same_file_identity(&opened, before.st_dev, before.st_ino)) {
                close(childfd);
                continue;
            }
            if (depth == capacity) {
                struct cleanup_directory_frame *grown;
                size_t new_capacity;

                if (capacity > SIZE_MAX / 2 / sizeof(*frames)) {
                    close(childfd);
                    continue;
                }
                new_capacity = capacity * 2;
                grown = realloc(frames, new_capacity * sizeof(*frames));
                if (!grown) {
                    close(childfd);
                    continue;
                }
                memset(grown + capacity, 0,
                       (new_capacity - capacity) * sizeof(*grown));
                frames = grown;
                capacity = new_capacity;
            }
            child_name = strdup(entry->d_name);
            if (!child_name) {
                close(childfd);
                continue;
            }
            child_directory = fdopendir(childfd);
            if (!child_directory) {
                close(childfd);
                free(child_name);
                continue;
            }

            frames[depth].directory = child_directory;
            frames[depth].name_in_parent = child_name;
            frames[depth].dev = opened.st_dev;
            frames[depth].ino = opened.st_ino;
            depth++;
            continue;
        }

        {
            char *name = frame->name_in_parent;
            dev_t dev = frame->dev;
            ino_t ino = frame->ino;

            (void)closedir(frame->directory);
            memset(frame, 0, sizeof(*frame));
            depth--;
            if (depth != 0) {
                struct stat current;
                int parent_fd = dirfd(frames[depth - 1].directory);

                if (parent_fd >= 0 &&
                    fstatat(parent_fd, name, &current,
                            AT_SYMLINK_NOFOLLOW) == 0 &&
                    S_ISDIR(current.st_mode) &&
                    same_file_identity(&current, dev, ino))
                    (void)unlinkat(parent_fd, name, AT_REMOVEDIR);
            }
            free(name);
        }
    }
    free(frames);
}

static void cleanup_workdir(void)
{
    struct stat current;
    const char *name = strrchr(g_tmpdir, '/');

    if (g_tmpdir_fd >= 0) {
        empty_directory_fd(g_tmpdir_fd);
        close(g_tmpdir_fd);
        g_tmpdir_fd = -1;
    }
    if (g_tmp_parent_fd >= 0) {
        name = name ? name + 1 : g_tmpdir;
        if (name[0] &&
            fstatat(g_tmp_parent_fd, name, &current,
                    AT_SYMLINK_NOFOLLOW) == 0 &&
            S_ISDIR(current.st_mode) &&
            same_file_identity(&current, g_tmpdir_dev, g_tmpdir_ino))
            (void)unlinkat(g_tmp_parent_fd, name, AT_REMOVEDIR);
        close(g_tmp_parent_fd);
        g_tmp_parent_fd = -1;
    }
}

/* ---- extract one embedded blob to a file ------------------------- */
static const char *bs_basename(const char *path)
{
    const char *base = path;
    while (*path) { if (*path == '/') base = path + 1; path++; }
    return base;
}

enum extraction_path_kind {
    EXTRACTION_PATH_NONE = 0,
    EXTRACTION_PATH_FILE,
    EXTRACTION_PATH_DIRECTORY
};

struct extraction_plan_entry {
    char *relative_path;
    char *full_path;
    char *alias_relative_path;
    char *alias_full_path;
    enum extraction_path_kind kind;
    int materialize;
    int executable;
    int alias_materialize;
    int alias_executable;
};

struct extraction_destination {
    const char *relative_path;
    enum extraction_path_kind kind;
    uint64_t data_offset;
    uint64_t data_size;
    size_t order;
    int *materialize;
    int *executable;
};

static void free_extraction_plan(struct extraction_plan_entry *plan,
                                 uint32_t count)
{
    if (!plan)
        return;
    for (uint32_t i = 0; i < count; i++) {
        free(plan[i].relative_path);
        free(plan[i].full_path);
        free(plan[i].alias_relative_path);
        free(plan[i].alias_full_path);
    }
    free(plan);
}

/* Convert an embedded path into one canonical path relative to the private
 * extraction root.  Canonicalization is also important for collision checks:
 * repeated separators must not create distinct strings for the same file. */
static int normalize_extraction_path(const char *input, size_t input_len,
                                     char **out)
{
    char *normalized;
    size_t read_pos = 0;
    size_t write_pos = 0;

    *out = NULL;
    if (!input || input_len == SIZE_MAX) {
        errno = EINVAL;
        return -1;
    }
    normalized = malloc(input_len + 1);
    if (!normalized)
        return -1;

    while (read_pos < input_len) {
        size_t component_start;
        size_t component_len;

        while (read_pos < input_len && input[read_pos] == '/')
            read_pos++;
        if (read_pos == input_len)
            break;
        component_start = read_pos;
        while (read_pos < input_len && input[read_pos] != '/')
            read_pos++;
        component_len = read_pos - component_start;
        if ((component_len == 1 && input[component_start] == '.') ||
            (component_len == 2 && input[component_start] == '.' &&
             input[component_start + 1] == '.')) {
            free(normalized);
            errno = EINVAL;
            return -1;
        }
        if (write_pos != 0)
            normalized[write_pos++] = '/';
        memcpy(normalized + write_pos, input + component_start,
               component_len);
        write_pos += component_len;
    }

    if (write_pos == 0) {
        free(normalized);
        errno = EINVAL;
        return -1;
    }
    normalized[write_pos] = '\0';
    *out = normalized;
    return 0;
}

static int size_add_checked(size_t left, size_t right, size_t *out)
{
    if (right > SIZE_MAX - left)
        return 0;
    *out = left + right;
    return 1;
}

static int join_extraction_root(const char *relative_path, char **out)
{
    size_t root_len = strlen(g_tmpdir);
    size_t relative_len = strlen(relative_path);
    size_t full_size;
    char *full_path;

    *out = NULL;
    if (!size_add_checked(root_len, 1, &full_size) ||
        !size_add_checked(full_size, relative_len, &full_size) ||
        !size_add_checked(full_size, 1, &full_size)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    full_path = malloc(full_size);
    if (!full_path)
        return -1;
    memcpy(full_path, g_tmpdir, root_len);
    full_path[root_len] = '/';
    memcpy(full_path + root_len + 1, relative_path, relative_len + 1);
    *out = full_path;
    return 0;
}

static int build_flat_relative_path(const char *name, char **out)
{
    const char *base;
    char *flat;

    if (!name || !name[0]) {
        errno = EINVAL;
        return -1;
    }
    /* Only the final component is materialized for extraction-mode objects.
     * Prefix components belong to the original request/source identity and
     * may legitimately include `.` or `..` (for example `./program`).  Do not
     * reject those harmless spellings, but never copy them into the private
     * extraction root. */
    base = bs_basename(name);
    if (!base[0] || strcmp(base, ".") == 0 || strcmp(base, "..") == 0) {
        errno = EINVAL;
        return -1;
    }
    flat = strdup(base);
    if (!flat)
        return -1;
    *out = flat;
    return 0;
}

static int extraction_destination_cmp(const void *left_ptr,
                                      const void *right_ptr)
{
    const struct extraction_destination *left = left_ptr;
    const struct extraction_destination *right = right_ptr;

    return strcmp(left->relative_path, right->relative_path);
}

static int size_multiply_checked(size_t left, size_t right, size_t *out)
{
    if (right != 0 && left > SIZE_MAX / right)
        return 0;
    *out = left * right;
    return 1;
}

static int extraction_destinations_conflict(
    struct extraction_destination *destinations, size_t count)
{
    /* Multiple logical manifest roles may intentionally share one embedded
     * object (for example, a runtime loader which is also libc).  Coalesce
     * only an exact shared manifest range: equal names or merely equal bytes
     * are not sufficient proof that a malformed artifact is unambiguous. */
    for (size_t begin = 0; begin < count;) {
        size_t end = begin + 1;
        size_t owner = begin;
        int executable = *destinations[begin].executable;

        while (end < count &&
               strcmp(destinations[begin].relative_path,
                      destinations[end].relative_path) == 0)
            end++;
        for (size_t i = begin + 1; i < end; i++) {
            if (destinations[i].kind != destinations[begin].kind ||
                (destinations[i].kind == EXTRACTION_PATH_FILE &&
                 (destinations[i].data_offset !=
                      destinations[begin].data_offset ||
                  destinations[i].data_size !=
                      destinations[begin].data_size)))
                return 1;
            if (destinations[i].order < destinations[owner].order)
                owner = i;
            executable = executable || *destinations[i].executable;
        }
        if (end - begin > 1) {
            for (size_t i = begin; i < end; i++) {
                *destinations[i].materialize = i == owner;
                *destinations[i].executable = executable;
            }
        }
        begin = end;
    }

    for (size_t i = 0; i < count; i++) {
        const char *path = destinations[i].relative_path;
        size_t path_len;
        size_t prefix_len;
        size_t low = 0;
        size_t high = count;
        char *prefix;

        if (destinations[i].kind == EXTRACTION_PATH_DIRECTORY)
            continue;
        path_len = strlen(path);
        if (path_len > SIZE_MAX - 2)
            return 1;
        prefix_len = path_len + 1;
        prefix = malloc(prefix_len + 1);
        if (!prefix)
            return -1;
        memcpy(prefix, path, path_len);
        prefix[path_len] = '/';
        prefix[prefix_len] = '\0';

        while (low < high) {
            size_t middle = low + (high - low) / 2;

            if (strcmp(destinations[middle].relative_path, prefix) < 0)
                low = middle + 1;
            else
                high = middle;
        }
        if (low < count &&
            strncmp(destinations[low].relative_path, prefix,
                    prefix_len) == 0) {
            free(prefix);
            return 1;
        }
        free(prefix);
    }
    return 0;
}

static int build_extraction_plan(const struct dlfrz_entry *entries,
                                 uint32_t count, const char *strtab,
                                 struct extraction_plan_entry **plan_out)
{
    struct extraction_plan_entry *plan = NULL;
    struct extraction_destination *destinations = NULL;
    size_t destination_count = 0;
    size_t destination_capacity;
    size_t allocation_size;
    int conflict;

    *plan_out = NULL;
    if (!size_multiply_checked((size_t)count, 2,
                               &destination_capacity) ||
        !size_multiply_checked((size_t)count, sizeof(*plan),
                               &allocation_size) ||
        !size_multiply_checked(destination_capacity, sizeof(*destinations),
                               &allocation_size)) {
        errno = EOVERFLOW;
        return -1;
    }
    plan = calloc(count, sizeof(*plan));
    destinations = calloc(destination_capacity, sizeof(*destinations));
    if (!plan || !destinations)
        goto fail;

    for (uint32_t i = 0; i < count; i++) {
        const char *name = strtab + entries[i].name_offset;
        size_t name_len = strlen(name);
        struct extraction_plan_entry *item = &plan[i];

        if ((entries[i].flags & DLFRZ_FLAG_DATA_NEGATIVE) != 0)
            continue;

        if ((entries[i].flags & DLFRZ_FLAG_DATA_DIRECTORY) != 0) {
            if (normalize_extraction_path(name, name_len,
                                          &item->relative_path) < 0 ||
                join_extraction_root(item->relative_path,
                                     &item->full_path) < 0)
                goto fail;
            item->kind = EXTRACTION_PATH_DIRECTORY;
            item->materialize = 1;
        } else if ((entries[i].flags & DLFRZ_FLAG_DATA_VIRTUAL) != 0) {
            /* Virtual placeholders carry identity only and have no
             * extraction-mode representation. */
            continue;
        } else {
            int use_full_path = name[0] == '/' &&
                (entries[i].flags & DLFRZ_FLAG_DLOPEN) != 0;

            if (use_full_path) {
                if (normalize_extraction_path(name, name_len,
                                              &item->relative_path) < 0)
                    goto fail;
            } else if (build_flat_relative_path(name,
                                                &item->relative_path) < 0) {
                goto fail;
            }
            if (join_extraction_root(item->relative_path,
                                     &item->full_path) < 0)
                goto fail;
            item->kind = EXTRACTION_PATH_FILE;
            item->materialize = 1;
            item->executable =
                (entries[i].flags &
                 (DLFRZ_FLAG_MAIN_EXE | DLFRZ_FLAG_INTERP)) != 0;

            if (use_full_path) {
                if (build_flat_relative_path(name,
                                             &item->alias_relative_path) < 0)
                    goto fail;
                if (strcmp(item->relative_path,
                           item->alias_relative_path) == 0) {
                    free(item->alias_relative_path);
                    item->alias_relative_path = NULL;
                } else if (join_extraction_root(item->alias_relative_path,
                                                &item->alias_full_path) < 0) {
                    goto fail;
                } else {
                    item->alias_materialize = 1;
                    item->alias_executable = item->executable;
                }
            }
        }

        destinations[destination_count].relative_path = item->relative_path;
        destinations[destination_count].kind = item->kind;
        destinations[destination_count].data_offset = entries[i].data_offset;
        destinations[destination_count].data_size = entries[i].data_size;
        destinations[destination_count].order = (size_t)i * 2;
        destinations[destination_count].materialize = &item->materialize;
        destinations[destination_count].executable = &item->executable;
        destination_count++;
        if (item->alias_relative_path) {
            destinations[destination_count].relative_path =
                item->alias_relative_path;
            destinations[destination_count].kind = EXTRACTION_PATH_FILE;
            destinations[destination_count].data_offset =
                entries[i].data_offset;
            destinations[destination_count].data_size = entries[i].data_size;
            destinations[destination_count].order = (size_t)i * 2 + 1;
            destinations[destination_count].materialize =
                &item->alias_materialize;
            destinations[destination_count].executable =
                &item->alias_executable;
            destination_count++;
        }
    }

    qsort(destinations, destination_count, sizeof(*destinations),
          extraction_destination_cmp);
    conflict = extraction_destinations_conflict(destinations,
                                                destination_count);
    if (conflict != 0) {
        if (conflict > 0)
            errno = EEXIST;
        goto fail;
    }

    free(destinations);
    *plan_out = plan;
    return 0;

fail:
    free(destinations);
    free_extraction_plan(plan, count);
    return -1;
}

static int bs_detect_secure_mode(char **envp)
{
    Elf64_auxv_t *auxv;

    if (!envp)
        return 1;
    while (*envp)
        envp++;
    auxv = (Elf64_auxv_t *)(envp + 1);
    for (size_t i = 0; i < 256; i++, auxv++) {
        if (auxv->a_type == AT_SECURE)
            return auxv->a_un.a_val != 0;
        if (auxv->a_type == AT_NULL)
            return 0;
    }
    /* A malformed initial stack must not enable environment controls. */
    return 1;
}

static int bs_env_enabled(const char *name)
{
    const char *value;

    if (g_bootstrap_secure_mode)
        return 0;
    value = getenv(name);
    return value && value[0] && value[0] != '0';
}

static int bs_execution_context_supported(void)
{
    /* Extraction relies on dynamic-loader environment controls which secure
     * execution ignores, while the direct loader does not yet claim the full
     * set-user-ID/set-group-ID loader contract.  Refuse the whole artifact
     * before selecting either path; silently falling through could load host
     * libraries or run a target with different privilege semantics. */
    return !g_bootstrap_secure_mode;
}

static int uint64_to_off_t(uint64_t value, off_t *out)
{
    off_t converted = (off_t)value;

    if (converted < 0 || (uint64_t)converted != value) {
        errno = EOVERFLOW;
        return -1;
    }
    *out = converted;
    return 0;
}

/* Read exactly one manifest-declared range without changing the shared file
 * offset.  Keep every individual request representable by ssize_t and reject
 * both premature EOF and offsets that the host ABI cannot express. */
static int full_pread(int fd, void *buffer, size_t size, uint64_t offset)
{
    unsigned char *out = buffer;
    size_t done = 0;

    while (done < size) {
        uint64_t current;
        off_t file_offset;
        size_t request = size - done;
        ssize_t len;

        if (done > UINT64_MAX - offset) {
            errno = EOVERFLOW;
            return -1;
        }
        current = offset + done;
        if (uint64_to_off_t(current, &file_offset) < 0)
            return -1;
        if (request > (size_t)SSIZE_MAX)
            request = (size_t)SSIZE_MAX;
        len = pread(fd, out + done, request, file_offset);

        if (len < 0 && errno == EINTR)
            continue;
        if (len < 0)
            return -1;
        if (len == 0) {
            errno = EIO;
            return -1;
        }
        done += (size_t)len;
    }
    return 0;
}

static int file_revision_matches(const struct stat *left,
                                 const struct stat *right)
{
    return left && right &&
           left->st_dev == right->st_dev &&
           left->st_ino == right->st_ino &&
           left->st_mode == right->st_mode &&
           left->st_uid == right->st_uid &&
           left->st_gid == right->st_gid &&
           left->st_size == right->st_size &&
           left->st_mtim.tv_sec == right->st_mtim.tv_sec &&
           left->st_mtim.tv_nsec == right->st_mtim.tv_nsec &&
           left->st_ctim.tv_sec == right->st_ctim.tv_sec &&
           left->st_ctim.tv_nsec == right->st_ctim.tv_nsec;
}

static int files_identical(const char *left, const char *right)
{
    int left_fd = -1, right_fd = -1;
    struct stat left_st, right_st;
    struct stat left_after, right_after;
    struct stat left_path, right_path;
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
        int left_rc = full_pread(left_fd, left_buf, chunk, (uint64_t)offset);
        int right_rc = full_pread(right_fd, right_buf, chunk,
                                  (uint64_t)offset);

        if (left_rc < 0 || right_rc < 0 ||
            memcmp(left_buf, right_buf, chunk) != 0)
            goto out;
        offset += (off_t)chunk;
    }
    /* Establish that each sampled descriptor stayed on one complete file
     * revision and that its pathname still names that inode.  The kernel
     * necessarily resolves a literal PT_INTERP pathname again during the
     * later exec, so this closes races during comparison but cannot make a
     * mutable system pathname descriptor-bound across execve(). */
    if (fstat(left_fd, &left_after) < 0 ||
        fstat(right_fd, &right_after) < 0 ||
        stat(left, &left_path) < 0 || stat(right, &right_path) < 0 ||
        !file_revision_matches(&left_st, &left_after) ||
        !file_revision_matches(&right_st, &right_after) ||
        !file_revision_matches(&left_after, &left_path) ||
        !file_revision_matches(&right_after, &right_path))
        goto out;
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

static int write_all(int fd, const void *buffer, size_t size)
{
    const unsigned char *bytes = buffer;
    size_t done = 0;

    while (done < size) {
        ssize_t written = write(fd, bytes + done, size - done);

        if (written < 0 && errno == EINTR)
            continue;
        if (written < 0)
            return -1;
        if (written == 0) {
            errno = EIO;
            return -1;
        }
        done += (size_t)written;
    }
    return 0;
}

static void unlink_extraction_file(int rootfd, const char *relative_path)
{
    int rc;

    do {
        rc = unlinkat(rootfd, relative_path, 0);
    } while (rc < 0 && errno == EINTR);
}

/* Linux closes the descriptor even when close reports EINTR, so retrying can
 * accidentally close a subsequently reused descriptor.  Call it exactly once
 * and treat any reported error as a failed extraction. */
static int finish_extraction_file(int rootfd, const char *relative_path,
                                  int fd)
{
    if (close(fd) == 0)
        return 0;

    int saved_errno = errno;
    unlink_extraction_file(rootfd, relative_path);
    errno = saved_errno;
    return -1;
}

static int abandon_extraction_file(int rootfd, const char *relative_path,
                                   int fd, int failure_errno)
{
    int close_errno = 0;

    if (close(fd) < 0)
        close_errno = errno;
    unlink_extraction_file(rootfd, relative_path);
    errno = failure_errno ? failure_errno :
            (close_errno ? close_errno : EIO);
    return -1;
}

static int extract(int srcfd, int rootfd, const char *relative_path,
                   uint64_t off, uint64_t sz, int exec)
{
    int dfd;

    if (ensure_relative_directories(rootfd, relative_path, 0) < 0)
        return -1;
    dfd = openat(rootfd, relative_path,
                 O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                 exec ? 0755 : 0644);
    if (dfd < 0)
        return -1;
    int chmod_rc;
    do {
        chmod_rc = fchmod(dfd, exec ? 0755 : 0644);
    } while (chmod_rc < 0 && errno == EINTR);
    if (chmod_rc < 0) {
        int saved_errno = errno;
        return abandon_extraction_file(rootfd, relative_path, dfd,
                                       saved_errno);
    }

    char buf[65536];
    uint64_t rem = sz;
    uint64_t source_offset = off;
    while (rem > 0) {
        size_t want = rem > sizeof(buf) ? sizeof(buf) : rem;
        if (full_pread(srcfd, buf, want, source_offset) < 0) {
            int saved_errno = errno;
            return abandon_extraction_file(rootfd, relative_path, dfd,
                                           saved_errno);
        }
        if (write_all(dfd, buf, want) < 0) {
            int saved_errno = errno;
            return abandon_extraction_file(rootfd, relative_path, dfd,
                                           saved_errno);
        }
        source_offset += want;
        rem -= want;
    }
    return finish_extraction_file(rootfd, relative_path, dfd);
}

/* ---- extract from a canonical mapped payload to a file ----------- */
static int extract_mem(const uint8_t *base, uint64_t base_foff, int rootfd,
                       const char *relative_path, uint64_t off, uint64_t sz,
                       int exec)
{
    int dfd;

    if (ensure_relative_directories(rootfd, relative_path, 0) < 0)
        return -1;
    dfd = openat(rootfd, relative_path,
                 O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                 exec ? 0755 : 0644);
    if (dfd < 0)
        return -1;
    int chmod_rc;
    do {
        chmod_rc = fchmod(dfd, exec ? 0755 : 0644);
    } while (chmod_rc < 0 && errno == EINTR);
    if (chmod_rc < 0) {
        int saved_errno = errno;
        return abandon_extraction_file(rootfd, relative_path, dfd,
                                       saved_errno);
    }
    const uint8_t *src = base + (off - base_foff);
    uint64_t rem = sz;
    while (rem > 0) {
        size_t want = rem > 65536 ? 65536 : rem;
        if (write_all(dfd, src, want) < 0) {
            int saved_errno = errno;
            return abandon_extraction_file(rootfd, relative_path, dfd,
                                           saved_errno);
        }
        src += want;
        rem -= want;
    }
    return finish_extraction_file(rootfd, relative_path, dfd);
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

struct payload_file_range {
    uint64_t offset;
    uint64_t size;
};

enum payload_control_range_index {
    PAYLOAD_CONTROL_STRTAB,
    PAYLOAD_CONTROL_MANIFEST,
    PAYLOAD_CONTROL_FOOTER,
    PAYLOAD_CONTROL_COUNT
};

/* Empty manifest entries occupy no payload bytes.  Nonempty entry aliases
 * are intentional (the same pinned ELF may satisfy multiple manifest roles),
 * but a partial overlap has no canonical owner.  Loader-control tables are
 * never aliases, even when two malformed ranges happen to be identical. */
static int payload_ranges_compatible(const struct payload_file_range *left,
                                     const struct payload_file_range *right,
                                     int allow_exact_alias)
{
    uint64_t left_end;
    uint64_t right_end;

    if (left->size == 0 || right->size == 0)
        return 1;
    if (!u64_add_checked(left->offset, left->size, &left_end) ||
        !u64_add_checked(right->offset, right->size, &right_end))
        return 0;
    if (left_end <= right->offset || right_end <= left->offset)
        return 1;
    return allow_exact_alias && left->offset == right->offset &&
           left->size == right->size;
}

static int payload_file_range_cmp(const void *left_pointer,
                                  const void *right_pointer)
{
    const struct payload_file_range *left = left_pointer;
    const struct payload_file_range *right = right_pointer;

    if (left->offset < right->offset)
        return -1;
    if (left->offset > right->offset)
        return 1;
    if (left->size < right->size)
        return -1;
    if (left->size > right->size)
        return 1;
    return 0;
}

static int payload_control_ranges(
    const struct dlfrz_footer *footer, uint64_t payload_offset,
    uint64_t payload_size,
    struct payload_file_range controls[PAYLOAD_CONTROL_COUNT])
{
    uint64_t footer_offset;
    uint64_t manifest_size;

    if (!footer || payload_size < sizeof(*footer) ||
        !u64_add_checked(payload_offset,
                         payload_size - sizeof(*footer), &footer_offset))
        return 0;
    manifest_size = (uint64_t)footer->num_entries *
                    sizeof(struct dlfrz_entry);
    controls[PAYLOAD_CONTROL_STRTAB] =
        (struct payload_file_range){footer->strtab_offset,
                                    footer->strtab_size};
    controls[PAYLOAD_CONTROL_MANIFEST] =
        (struct payload_file_range){footer->manifest_offset, manifest_size};
    controls[PAYLOAD_CONTROL_FOOTER] =
        (struct payload_file_range){footer_offset, sizeof(*footer)};

    for (size_t i = 0; i < PAYLOAD_CONTROL_COUNT; i++) {
        if (!payload_range_valid(controls[i].offset, controls[i].size,
                                 payload_offset, payload_size))
            return 0;
        for (size_t j = 0; j < i; j++)
            if (!payload_ranges_compatible(&controls[i], &controls[j], 0))
                return 0;
    }
    return 1;
}

static int payload_entry_ranges_valid(
    const struct dlfrz_footer *footer, const struct dlfrz_entry *entries,
    uint64_t payload_offset, uint64_t payload_size)
{
    struct payload_file_range controls[PAYLOAD_CONTROL_COUNT];
    struct payload_file_range *occupied;
    size_t occupied_count = 0;
    int valid = 0;

    if (!footer || !entries ||
        !payload_control_ranges(footer, payload_offset, payload_size,
                                controls))
        return 0;
    occupied = malloc((size_t)footer->num_entries * sizeof(*occupied));
    if (!occupied)
        return 0;

    for (uint32_t i = 0; i < footer->num_entries; i++) {
        struct payload_file_range range = {
            entries[i].data_offset, entries[i].data_size
        };

        if (range.size == 0)
            continue;
        if (!payload_range_valid(range.offset, range.size,
                                 payload_offset, payload_size))
            goto out;
        for (size_t c = 0; c < PAYLOAD_CONTROL_COUNT; c++)
            if (!payload_ranges_compatible(&range, &controls[c], 0))
                goto out;
        occupied[occupied_count++] = range;
    }

    qsort(occupied, occupied_count, sizeof(*occupied),
          payload_file_range_cmp);
    for (size_t i = 1; i < occupied_count; i++)
        if (!payload_ranges_compatible(
                &occupied[i - 1], &occupied[i], 1))
            goto out;
    valid = 1;

out:
    free(occupied);
    return valid;
}

static int direct_payload_ranges_valid(
    const struct dlfrz_footer *footer, const struct dlfrz_entry *entries,
    uint64_t payload_offset, uint64_t payload_size,
    uint64_t metadata_offset, uint64_t metadata_size,
    uint64_t fixup_offset, uint64_t fixup_size)
{
    struct payload_file_range controls[PAYLOAD_CONTROL_COUNT];
    struct payload_file_range direct[2] = {
        {metadata_offset, metadata_size},
        {fixup_offset, fixup_size}
    };

    if (!footer || !entries || metadata_size == 0 ||
        !payload_control_ranges(footer, payload_offset, payload_size,
                                controls))
        return 0;
    for (size_t d = 0; d < 2; d++) {
        if (direct[d].size == 0)
            continue;
        if (!payload_range_valid(direct[d].offset, direct[d].size,
                                 payload_offset, payload_size))
            return 0;
        for (size_t c = 0; c < PAYLOAD_CONTROL_COUNT; c++)
            if (!payload_ranges_compatible(&direct[d], &controls[c], 0))
                return 0;
        for (uint32_t i = 0; i < footer->num_entries; i++) {
            struct payload_file_range entry = {
                entries[i].data_offset, entries[i].data_size
            };

            if (!payload_ranges_compatible(&direct[d], &entry, 0))
                return 0;
        }
    }
    return payload_ranges_compatible(&direct[0], &direct[1], 0);
}

static int embedded_address_aligned(const void *base, uint64_t base_foff,
                                    uint64_t file_offset, size_t alignment)
{
    uintptr_t address = (uintptr_t)base;
    uint64_t relative;

    if (alignment == 0 || file_offset < base_foff)
        return 0;
    relative = file_offset - base_foff;
    if (relative > UINTPTR_MAX - address)
        return 0;
    return (address + (uintptr_t)relative) % alignment == 0;
}

#define BS_MAX_INITIAL_ENV_ENTRIES (1U << 20)
#define BS_MAX_AUXV_ENTRIES 256U
#define BS_MAX_MAPS_LINE 8192U
#define BS_MAX_MAPS_ENTRIES 131072U
#define BS_MAX_SMAPS_LINES (BS_MAX_MAPS_ENTRIES * 64ULL)

struct bs_live_phdr_table {
    const unsigned char *bytes;
    uintptr_t live_address;
    size_t count;
    size_t entsize;
};

static int bs_live_phdr_table_from_env(
    char **envp, struct bs_live_phdr_table *table)
{
    const unsigned char required = 1U | 2U | 4U;
    unsigned char seen = 0;
    size_t env_count;
    uintptr_t phdr_address = 0;
    size_t phdr_count = 0;
    size_t phdr_size = 0;
    int terminated = 0;

    if (!envp || !table)
        return 0;
    memset(table, 0, sizeof(*table));
    for (env_count = 0; env_count < BS_MAX_INITIAL_ENV_ENTRIES;
         env_count++) {
        if (!envp[env_count])
            break;
    }
    if (env_count == BS_MAX_INITIAL_ENV_ENTRIES)
        return 0;

    const unsigned char *auxv_bytes =
        (const unsigned char *)(envp + env_count + 1);
    for (size_t i = 0; i < BS_MAX_AUXV_ENTRIES; i++) {
        Elf64_auxv_t entry;

        memcpy(&entry, auxv_bytes + i * sizeof(entry), sizeof(entry));
        if (entry.a_type == AT_NULL) {
            terminated = 1;
            break;
        }
        if (entry.a_type == AT_PHDR) {
            if (seen & 1U || entry.a_un.a_val > UINTPTR_MAX)
                return 0;
            phdr_address = (uintptr_t)entry.a_un.a_val;
            seen |= 1U;
        } else if (entry.a_type == AT_PHNUM) {
            if (seen & 2U || entry.a_un.a_val > SIZE_MAX)
                return 0;
            phdr_count = (size_t)entry.a_un.a_val;
            seen |= 2U;
        } else if (entry.a_type == AT_PHENT) {
            if (seen & 4U || entry.a_un.a_val > SIZE_MAX)
                return 0;
            phdr_size = (size_t)entry.a_un.a_val;
            seen |= 4U;
        }
    }
    if (!terminated || seen != required || !phdr_address ||
        phdr_count == 0 || phdr_count > UINT16_MAX ||
        phdr_size != sizeof(Elf64_Phdr) ||
        phdr_count > (UINTPTR_MAX - phdr_address) / phdr_size)
        return 0;

    table->bytes = (const unsigned char *)phdr_address;
    table->live_address = phdr_address;
    table->count = phdr_count;
    table->entsize = phdr_size;
    return 1;
}

static int bs_live_phdr_read(const struct bs_live_phdr_table *table,
                             size_t index, Elf64_Phdr *phdr)
{
    size_t offset;
    uintptr_t bytes_address;

    if (!table || !phdr || !table->bytes ||
        table->entsize != sizeof(*phdr) || table->count == 0 ||
        table->count > UINT16_MAX || index >= table->count ||
        index > SIZE_MAX / table->entsize)
        return 0;
    bytes_address = (uintptr_t)table->bytes;
    if (table->count >
            (UINTPTR_MAX - bytes_address) / table->entsize)
        return 0;
    offset = index * table->entsize;
    memcpy(phdr, table->bytes + offset, sizeof(*phdr));
    return 1;
}

static int bs_live_phdr_table_size(const struct bs_live_phdr_table *table,
                                   uint64_t *size_out)
{
    if (!table || !size_out || !table->bytes || table->count == 0 ||
        table->count > UINT16_MAX ||
        table->entsize != sizeof(Elf64_Phdr) ||
        table->count > UINT64_MAX / table->entsize)
        return 0;
    *size_out = (uint64_t)table->count * table->entsize;
    return *size_out != 0;
}

static int bs_load_geometry_valid(const Elf64_Phdr *load)
{
    uint64_t alignment;

    if (!load || load->p_type != PT_LOAD ||
        load->p_filesz > load->p_memsz ||
        load->p_filesz > UINT64_MAX - load->p_offset ||
        load->p_memsz > UINT64_MAX - load->p_vaddr)
        return 0;
    alignment = load->p_align;
    if (alignment > 1) {
        if ((alignment & (alignment - 1)) != 0 ||
            (load->p_vaddr & (alignment - 1)) !=
                (load->p_offset & (alignment - 1)))
            return 0;
    }
    return 1;
}

static int bs_range_within_load_file(const Elf64_Phdr *load,
                                     uint64_t file_offset,
                                     uint64_t virtual_address,
                                     uint64_t size)
{
    uint64_t file_delta;
    uint64_t virtual_delta;

    if (!load || load->p_type != PT_LOAD || !(load->p_flags & PF_R) ||
        !bs_load_geometry_valid(load) ||
        file_offset < load->p_offset ||
        virtual_address < load->p_vaddr)
        return 0;
    file_delta = file_offset - load->p_offset;
    virtual_delta = virtual_address - load->p_vaddr;
    return file_delta == virtual_delta &&
           file_delta <= load->p_filesz &&
           size <= load->p_filesz - file_delta;
}

static int bs_phdr_segment_geometry_valid(const Elf64_Phdr *phdr,
                                          uint64_t table_size)
{
    uint64_t alignment;

    if (!phdr || phdr->p_type != PT_PHDR || !(phdr->p_flags & PF_R) ||
        phdr->p_filesz < table_size || phdr->p_memsz < table_size ||
        phdr->p_filesz > phdr->p_memsz ||
        phdr->p_filesz > UINT64_MAX - phdr->p_offset ||
        phdr->p_memsz > UINT64_MAX - phdr->p_vaddr)
        return 0;
    alignment = phdr->p_align;
    if (alignment > 1 &&
        ((alignment & (alignment - 1)) != 0 ||
         (phdr->p_vaddr & (alignment - 1)) !=
             (phdr->p_offset & (alignment - 1))))
        return 0;
    return 1;
}

/* Derive one load bias and prove that the live AT_PHDR table itself has one
 * readable file-backed PT_LOAD owner.  The mapped-payload compatibility path
 * may subsequently use p_memsz, but it must not derive an address from an
 * ambiguous or malformed PT_PHDR. */
static int bs_live_phdr_load_bias(const struct bs_live_phdr_table *table,
                                  uint64_t *load_bias_out)
{
    Elf64_Phdr phdr_segment;
    uint64_t table_size;
    uint64_t load_bias = 0;
    size_t phdr_segment_count = 0;
    size_t table_owner_count = 0;

    if (!table || !load_bias_out ||
        !bs_live_phdr_table_size(table, &table_size) ||
        table_size > UINTPTR_MAX - table->live_address)
        return 0;
    memset(&phdr_segment, 0, sizeof(phdr_segment));
    for (size_t i = 0; i < table->count; i++) {
        Elf64_Phdr phdr;

        if (!bs_live_phdr_read(table, i, &phdr))
            return 0;
        if (phdr.p_type == PT_LOAD && !bs_load_geometry_valid(&phdr))
            return 0;
        if (phdr.p_type == PT_PHDR) {
            phdr_segment = phdr;
            phdr_segment_count++;
        }
    }
    if (phdr_segment_count > 1)
        return 0;

    if (phdr_segment_count == 1) {
        if (!bs_phdr_segment_geometry_valid(&phdr_segment, table_size) ||
            phdr_segment.p_vaddr > table->live_address)
            return 0;
        load_bias = (uint64_t)table->live_address - phdr_segment.p_vaddr;
        if (phdr_segment.p_vaddr > UINT64_MAX - load_bias ||
            phdr_segment.p_vaddr + load_bias != table->live_address)
            return 0;

        for (size_t i = 0; i < table->count; i++) {
            Elf64_Phdr load;

            if (!bs_live_phdr_read(table, i, &load))
                return 0;
            if (bs_range_within_load_file(
                    &load, phdr_segment.p_offset,
                    phdr_segment.p_vaddr, table_size))
                table_owner_count++;
        }
    } else {
        uint64_t table_address = (uint64_t)table->live_address;

        /* Fixed-address executables commonly omit PT_PHDR.  Bias zero is
         * proven only when the live table lies in one readable file extent. */
        for (size_t i = 0; i < table->count; i++) {
            Elf64_Phdr load;

            if (!bs_live_phdr_read(table, i, &load))
                return 0;
            if (load.p_type != PT_LOAD || !(load.p_flags & PF_R) ||
                table_address < load.p_vaddr)
                continue;
            uint64_t delta = table_address - load.p_vaddr;
            if (delta <= load.p_filesz &&
                table_size <= load.p_filesz - delta)
                table_owner_count++;
        }
    }
    if (table_owner_count != 1)
        return 0;
    *load_bias_out = load_bias;
    return 1;
}

/* This is the compatibility predicate for using the live payload bytes as
 * the authority.  It intentionally uses p_memsz: a decompressor may replace
 * the original mappings yet still leave a valid, readable live payload. */
static int bs_mapped_range_is_readable(
    const struct bs_live_phdr_table *table,
    uint64_t start_value, uint64_t size_value)
{
    uint64_t load_bias;
    uint64_t end_value;

    if (!table || start_value > UINTPTR_MAX || size_value == 0 ||
        size_value > UINT64_MAX - start_value)
        return 0;
    end_value = start_value + size_value;
    if (!bs_live_phdr_load_bias(table, &load_bias))
        return 0;

    /* Fixed-address static executables need no bias and commonly omit
     * PT_PHDR.  Static PIEs provide PT_PHDR, allowing the same check after
     * relocation by the kernel. */
    for (size_t i = 0; i < table->count; i++) {
        Elf64_Phdr phdr;
        uint64_t segment_start;
        uint64_t segment_end;

        if (!bs_live_phdr_read(table, i, &phdr))
            return 0;
        if (phdr.p_type != PT_LOAD || !(phdr.p_flags & PF_R) ||
            phdr.p_memsz == 0 || !bs_load_geometry_valid(&phdr))
            continue;
        if (phdr.p_vaddr > UINT64_MAX - load_bias ||
            phdr.p_memsz > UINT64_MAX - (phdr.p_vaddr + load_bias))
            continue;
        segment_start = phdr.p_vaddr + load_bias;
        segment_end = segment_start + phdr.p_memsz;
        if (start_value >= segment_start && end_value <= segment_end)
            return 1;
    }
    return 0;
}

/* Prove that the live payload address is the exact translation of its file
 * offset through one readable, file-backed PT_LOAD.  This predicate does not
 * claim that the VMA still belongs to that file; /proc/self/smaps supplies the
 * second half of that proof before the optional source fd is retained. */
static int bs_mapped_payload_file_translation(
    const struct bs_live_phdr_table *table,
    uint64_t payload_vaddr, uint64_t payload_filesz,
    uint64_t payload_foff)
{
    uint64_t load_bias;
    size_t payload_owner_count = 0;

    if (!table || payload_vaddr > UINTPTR_MAX || payload_filesz == 0 ||
        payload_filesz > UINT64_MAX - payload_vaddr ||
        payload_filesz > UINT64_MAX - payload_foff ||
        !bs_live_phdr_load_bias(table, &load_bias))
        return 0;

    for (size_t i = 0; i < table->count; i++) {
        Elf64_Phdr load;
        uint64_t delta;
        uint64_t expected_address;

        if (!bs_live_phdr_read(table, i, &load))
            return 0;
        if (load.p_type != PT_LOAD || !(load.p_flags & PF_R) ||
            payload_foff < load.p_offset)
            continue;
        delta = payload_foff - load.p_offset;
        if (delta > load.p_filesz ||
            payload_filesz > load.p_filesz - delta ||
            load.p_vaddr > UINT64_MAX - load_bias ||
            delta > UINT64_MAX - (load.p_vaddr + load_bias))
            continue;
        expected_address = load.p_vaddr + load_bias + delta;
        if (payload_vaddr == expected_address)
            payload_owner_count++;
    }
    return payload_owner_count == 1;
}

struct bs_maps_entry {
    uint64_t start;
    uint64_t end;
    uint64_t file_offset;
    uint64_t dev_major;
    uint64_t dev_minor;
    uint64_t inode;
    int private_readonly;
};

static int bs_maps_space(unsigned char byte)
{
    return byte == ' ' || byte == '\t';
}

static int bs_maps_digit(unsigned char byte, unsigned base, unsigned *value)
{
    unsigned digit;

    if (byte >= '0' && byte <= '9')
        digit = (unsigned)(byte - '0');
    else if (byte >= 'a' && byte <= 'f')
        digit = (unsigned)(byte - 'a') + 10;
    else if (byte >= 'A' && byte <= 'F')
        digit = (unsigned)(byte - 'A') + 10;
    else
        return 0;
    if (digit >= base)
        return 0;
    *value = digit;
    return 1;
}

static int bs_maps_u64(const unsigned char **cursor,
                       const unsigned char *end, unsigned base,
                       uint64_t *value_out)
{
    const unsigned char *position = *cursor;
    uint64_t value = 0;
    size_t digits = 0;

    while (position < end) {
        unsigned digit;

        if (!bs_maps_digit(*position, base, &digit))
            break;
        if (value > (UINT64_MAX - digit) / base)
            return 0;
        value = value * base + digit;
        position++;
        digits++;
    }
    if (digits == 0)
        return 0;
    *cursor = position;
    *value_out = value;
    return 1;
}

static int bs_maps_spaces(const unsigned char **cursor,
                          const unsigned char *end)
{
    const unsigned char *position = *cursor;

    if (position == end || !bs_maps_space(*position))
        return 0;
    while (position < end && bs_maps_space(*position))
        position++;
    *cursor = position;
    return 1;
}

static int bs_parse_maps_entry(const unsigned char *line, size_t length,
                               struct bs_maps_entry *entry)
{
    const unsigned char *cursor = line;
    const unsigned char *end = line + length;

    if (!line || !entry ||
        !bs_maps_u64(&cursor, end, 16, &entry->start) ||
        cursor == end || *cursor++ != '-' ||
        !bs_maps_u64(&cursor, end, 16, &entry->end) ||
        !bs_maps_spaces(&cursor, end) || end - cursor < 4)
        return 0;
    entry->private_readonly =
        cursor[0] == 'r' && cursor[1] == '-' &&
        cursor[2] == '-' && cursor[3] == 'p';
    if ((cursor[0] != 'r' && cursor[0] != '-') ||
        (cursor[1] != 'w' && cursor[1] != '-') ||
        (cursor[2] != 'x' && cursor[2] != '-') ||
        (cursor[3] != 'p' && cursor[3] != 's'))
        return 0;
    cursor += 4;
    if (!bs_maps_spaces(&cursor, end) ||
        !bs_maps_u64(&cursor, end, 16, &entry->file_offset) ||
        !bs_maps_spaces(&cursor, end) ||
        !bs_maps_u64(&cursor, end, 16, &entry->dev_major) ||
        cursor == end || *cursor++ != ':' ||
        !bs_maps_u64(&cursor, end, 16, &entry->dev_minor) ||
        !bs_maps_spaces(&cursor, end) ||
        !bs_maps_u64(&cursor, end, 10, &entry->inode))
        return 0;
    if (cursor != end && !bs_maps_spaces(&cursor, end))
        return 0;
    if (entry->start > UINTPTR_MAX || entry->end > UINTPTR_MAX ||
        entry->start >= entry->end ||
        entry->end - entry->start > UINT64_MAX - entry->file_offset)
        return 0;
    return 1;
}

/* Return 1 for a line, 0 for clean EOF, and -1 for malformed or oversized
 * input.  Reading one byte at a time keeps a hostile synthetic stream from
 * making getline allocate without a bound; procfs maps lines are small. */
static int bs_read_maps_line(FILE *stream, unsigned char *line,
                             size_t capacity, size_t *length_out)
{
    size_t length = 0;

    if (!stream || !line || capacity == 0 || !length_out)
        return -1;
    for (;;) {
        int byte = fgetc(stream);

        if (byte == EOF) {
            if (ferror(stream))
                return -1;
            if (length == 0)
                return 0;
            *length_out = length;
            return 1;
        }
        if (byte == '\0' || length == capacity)
            return -1;
        if (byte == '\n') {
            *length_out = length;
            return 1;
        }
        line[length++] = (unsigned char)byte;
    }
}

struct bs_smaps_evidence {
    int have_header;
    int relevant;
    int have_anonymous;
    int have_swap;
    int have_vm_flags;
    int userfaultfd;
    uint64_t anonymous_kb;
    uint64_t swap_kb;
    struct bs_maps_entry entry;
};

static int bs_smaps_kb_field(const unsigned char *line, size_t length,
                             const char *field, uint64_t *value_out)
{
    const unsigned char *cursor = line;
    const unsigned char *end = line + length;
    size_t field_length = strlen(field);
    uint64_t value;

    if (!line || !field || !value_out || field_length > length ||
        memcmp(cursor, field, field_length) != 0)
        return 0;
    cursor += field_length;
    if (!bs_maps_spaces(&cursor, end) ||
        !bs_maps_u64(&cursor, end, 10, &value) ||
        !bs_maps_spaces(&cursor, end) || end - cursor < 2 ||
        cursor[0] != 'k' || cursor[1] != 'B')
        return 0;
    cursor += 2;
    while (cursor < end && bs_maps_space(*cursor))
        cursor++;
    if (cursor != end)
        return 0;
    *value_out = value;
    return 1;
}

static int bs_smaps_vm_flags(const unsigned char *line, size_t length,
                             int *userfaultfd_out)
{
    static const char field[] = "VmFlags:";
    static const char known[][2] = {
        {'r','d'}, {'w','r'}, {'e','x'}, {'s','h'}, {'m','r'}, {'m','w'},
        {'m','e'}, {'m','s'}, {'g','d'}, {'p','f'}, {'d','w'}, {'l','o'},
        {'i','o'}, {'s','r'}, {'r','r'}, {'d','c'}, {'d','e'}, {'a','c'},
        {'n','r'}, {'h','t'}, {'s','f'}, {'n','l'}, {'a','r'}, {'w','f'},
        {'d','d'}, {'s','d'}, {'m','m'}, {'h','g'}, {'n','h'}, {'m','g'},
        {'u','m'}, {'u','w'}, {'u','i'}, {'s','s'}, {'s','l'}, {'l','f'},
        {'d','p'},
    };
    const unsigned char *cursor = line;
    const unsigned char *end = line + length;
    int saw_flag = 0;
    int userfaultfd = 0;

    if (!line || !userfaultfd_out || length < sizeof(field) - 1 ||
        memcmp(cursor, field, sizeof(field) - 1) != 0)
        return 0;
    cursor += sizeof(field) - 1;
    while (cursor < end) {
        const unsigned char *token;

        if (!bs_maps_spaces(&cursor, end))
            return 0;
        if (cursor == end)
            break;
        token = cursor;
        while (cursor < end && !bs_maps_space(*cursor))
            cursor++;
        if (cursor - token != 2)
            return 0;
        size_t known_index;

        for (known_index = 0;
             known_index < sizeof(known) / sizeof(known[0]);
             known_index++)
            if (known[known_index][0] == token[0] &&
                known[known_index][1] == token[1])
                break;
        if (known_index == sizeof(known) / sizeof(known[0]))
            return 0;
        if (token[0] == 'u' &&
            (token[1] == 'm' || token[1] == 'w' || token[1] == 'i'))
            userfaultfd = 1;
        saw_flag = 1;
    }
    if (!saw_flag)
        return 0;
    *userfaultfd_out = userfaultfd;
    return 1;
}

static int bs_smaps_finish_relevant(
    const struct bs_smaps_evidence *evidence, uint64_t payload_end,
    uint64_t *cursor)
{
    if (!evidence->relevant)
        return 1;
    if (!evidence->have_anonymous || !evidence->have_swap ||
        !evidence->have_vm_flags || evidence->anonymous_kb != 0 ||
        evidence->swap_kb != 0 || evidence->userfaultfd)
        return 0;
    *cursor = evidence->entry.end < payload_end
        ? evidence->entry.end : payload_end;
    return 1;
}

/* smaps supplies the fact that exact file identity alone cannot: no page in
 * the live MAP_PRIVATE payload has been replaced by COW or swap state.  Every
 * required field is positive evidence.  Older, restricted, or malformed
 * procfs implementations simply decline the optional exact-source path. */
static int bs_payload_smaps_stream_matches(
    FILE *stream, const struct stat *executable,
    uint64_t payload_vaddr, uint64_t payload_filesz,
    uint64_t payload_foff)
{
    unsigned char line[BS_MAX_MAPS_LINE];
    struct bs_smaps_evidence evidence = {0};
    uint64_t payload_end;
    uint64_t cursor;
    uint64_t previous_end = 0;
    int have_previous = 0;

    if (!stream || !executable || executable->st_ino == 0 ||
        payload_vaddr > UINTPTR_MAX || payload_filesz == 0 ||
        !u64_add_checked(payload_vaddr, payload_filesz, &payload_end) ||
        payload_end > UINTPTR_MAX ||
        payload_filesz > UINT64_MAX - payload_foff)
        return 0;
    cursor = payload_vaddr;

    for (uint64_t count = 0; count < BS_MAX_SMAPS_LINES; count++) {
        struct bs_maps_entry entry;
        size_t length;
        int line_status = bs_read_maps_line(stream, line, sizeof(line),
                                            &length);

        if (line_status == 0) {
            if (!bs_smaps_finish_relevant(&evidence, payload_end, &cursor))
                return 0;
            return cursor == payload_end;
        }
        if (line_status < 0)
            return 0;

        size_t header_prefix = 0;
        unsigned ignored_digit;

        while (header_prefix < length &&
               bs_maps_digit(line[header_prefix], 16, &ignored_digit))
            header_prefix++;
        if (header_prefix != 0 && header_prefix < length &&
            line[header_prefix] == '-') {
            if (!bs_parse_maps_entry(line, length, &entry) ||
                (have_previous && entry.start < previous_end) ||
                !bs_smaps_finish_relevant(&evidence, payload_end, &cursor))
                return 0;
            if (cursor == payload_end)
                return 1;
            previous_end = entry.end;
            have_previous = 1;
            memset(&evidence, 0, sizeof(evidence));
            evidence.have_header = 1;
            evidence.entry = entry;

            if (entry.end <= payload_vaddr || entry.start >= payload_end)
                continue;
            if (entry.start > cursor || !entry.private_readonly ||
                entry.dev_major != (uint64_t)major(executable->st_dev) ||
                entry.dev_minor != (uint64_t)minor(executable->st_dev) ||
                entry.inode != (uint64_t)executable->st_ino)
                return 0;

            uint64_t map_delta = cursor - entry.start;
            uint64_t payload_delta = cursor - payload_vaddr;
            uint64_t map_file_offset;
            uint64_t payload_file_offset;

            if (!u64_add_checked(entry.file_offset, map_delta,
                                 &map_file_offset) ||
                !u64_add_checked(payload_foff, payload_delta,
                                 &payload_file_offset) ||
                map_file_offset != payload_file_offset)
                return 0;
            evidence.relevant = 1;
            continue;
        }

        if (!evidence.have_header || !evidence.relevant)
            continue;
        if (length >= sizeof("Anonymous:") - 1 &&
            memcmp(line, "Anonymous:", sizeof("Anonymous:") - 1) == 0) {
            if (evidence.have_anonymous ||
                !bs_smaps_kb_field(line, length, "Anonymous:",
                                   &evidence.anonymous_kb))
                return 0;
            evidence.have_anonymous = 1;
        } else if (length >= sizeof("Swap:") - 1 &&
                   memcmp(line, "Swap:", sizeof("Swap:") - 1) == 0) {
            if (evidence.have_swap ||
                !bs_smaps_kb_field(line, length, "Swap:",
                                   &evidence.swap_kb))
                return 0;
            evidence.have_swap = 1;
        } else if (length >= sizeof("VmFlags:") - 1 &&
                   memcmp(line, "VmFlags:", sizeof("VmFlags:") - 1) == 0) {
            if (evidence.have_vm_flags ||
                !bs_smaps_vm_flags(line, length, &evidence.userfaultfd))
                return 0;
            evidence.have_vm_flags = 1;
        }
    }
    return 0;
}

struct bs_proc_self_context {
    int root_fd;
    int self_fd;
    dev_t device;
};

static void bs_proc_self_context_close(struct bs_proc_self_context *context)
{
    if (!context)
        return;
    if (context->self_fd >= 0)
        close(context->self_fd);
    if (context->root_fd >= 0)
        close(context->root_fd);
    context->root_fd = -1;
    context->self_fd = -1;
    context->device = 0;
}

static int bs_fd_is_procfs(int fd)
{
    struct statfs filesystem;

    return fd >= 0 && fstatfs(fd, &filesystem) == 0 &&
           (unsigned long)filesystem.f_type ==
               (unsigned long)PROC_SUPER_MAGIC;
}

static int bs_proc_entry_status(int fd, dev_t device, mode_t type,
                                struct stat *status_out)
{
    struct stat status;

    if (fd < 0 || fstat(fd, &status) < 0 ||
        (status.st_mode & S_IFMT) != type || status.st_dev != device ||
        !bs_fd_is_procfs(fd))
        return 0;
    if (status_out)
        *status_out = status;
    return 1;
}

static int bs_proc_pid_component(const char *component, size_t length)
{
    if (!component || length == 0 || component[0] == '0')
        return 0;
    for (size_t i = 0; i < length; i++)
        if (component[i] < '0' || component[i] > '9')
            return 0;
    return 1;
}

/* Pin one genuine procfs mount and prove that its `self` magic link resolves
 * to the same process directory as its bounded numeric target.  Subsequent
 * entry opens stay relative to that pinned directory, so a fake /proc tree
 * cannot become payload authority. */
static int bs_proc_self_context_open_at(
    const char *proc_root, struct bs_proc_self_context *context)
{
    char pid_component[32];
    struct stat root_status;
    struct stat self_link_status;
    struct stat self_status;
    struct stat pid_status;
    int self_link_fd = -1;
    int pid_fd = -1;
    ssize_t pid_length;
    int saved_errno = EINVAL;

    if (!proc_root || !context) {
        errno = EINVAL;
        return -1;
    }
    context->root_fd = -1;
    context->self_fd = -1;
    context->device = 0;

    context->root_fd = open(proc_root, O_PATH | O_DIRECTORY | O_CLOEXEC |
                                       O_NOFOLLOW);
    if (context->root_fd < 0) {
        saved_errno = errno ? errno : EIO;
        goto fail;
    }
    if (fstat(context->root_fd, &root_status) < 0) {
        saved_errno = errno ? errno : EIO;
        goto fail;
    }
    if (!S_ISDIR(root_status.st_mode)) {
        saved_errno = ENOTDIR;
        goto fail;
    }
    errno = 0;
    if (!bs_fd_is_procfs(context->root_fd)) {
        saved_errno = errno ? errno : ENODEV;
        goto fail;
    }
    context->device = root_status.st_dev;

    self_link_fd = openat(context->root_fd, "self",
                          O_PATH | O_NOFOLLOW | O_CLOEXEC);
    if (self_link_fd < 0) {
        saved_errno = errno ? errno : EIO;
        goto fail;
    }
    errno = 0;
    if (!bs_proc_entry_status(self_link_fd, context->device, S_IFLNK,
                              &self_link_status)) {
        saved_errno = errno ? errno : ESTALE;
        goto fail;
    }
    pid_length = readlinkat(context->root_fd, "self", pid_component,
                            sizeof(pid_component));
    if (pid_length < 0) {
        saved_errno = errno ? errno : EIO;
        goto fail;
    }
    if (pid_length == 0 || (size_t)pid_length >= sizeof(pid_component) ||
        !bs_proc_pid_component(pid_component, (size_t)pid_length)) {
        saved_errno = EINVAL;
        goto fail;
    }
    pid_component[pid_length] = '\0';

    context->self_fd = openat(context->root_fd, "self",
                              O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (context->self_fd < 0) {
        saved_errno = errno ? errno : EIO;
        goto fail;
    }
    pid_fd = openat(context->root_fd, pid_component,
                    O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (pid_fd < 0) {
        saved_errno = errno ? errno : EIO;
        goto fail;
    }
    errno = 0;
    if (!bs_proc_entry_status(context->self_fd, context->device, S_IFDIR,
                              &self_status)) {
        saved_errno = errno ? errno : ESTALE;
        goto fail;
    }
    errno = 0;
    if (!bs_proc_entry_status(pid_fd, context->device, S_IFDIR,
                              &pid_status)) {
        saved_errno = errno ? errno : ESTALE;
        goto fail;
    }
    if (self_status.st_dev != pid_status.st_dev ||
        self_status.st_ino != pid_status.st_ino) {
        saved_errno = ESTALE;
        goto fail;
    }

    close(pid_fd);
    close(self_link_fd);
    return 0;

fail:
    if (pid_fd >= 0)
        close(pid_fd);
    if (self_link_fd >= 0)
        close(self_link_fd);
    bs_proc_self_context_close(context);
    errno = saved_errno;
    return -1;
}

static int bs_proc_self_executable_open(
    const struct bs_proc_self_context *context)
{
    struct stat link_status;
    struct stat link_after_status;
    struct stat executable_status;
    int link_fd = -1;
    int link_after_fd = -1;
    int executable_fd = -1;
    int saved_errno = EINVAL;

    if (!context || context->root_fd < 0 || context->self_fd < 0) {
        errno = EINVAL;
        return -1;
    }
    link_fd = openat(context->self_fd, "exe",
                     O_PATH | O_NOFOLLOW | O_CLOEXEC);
    if (link_fd < 0) {
        saved_errno = errno ? errno : EIO;
        goto fail;
    }
    errno = 0;
    if (!bs_proc_entry_status(link_fd, context->device, S_IFLNK,
                              &link_status)) {
        saved_errno = errno ? errno : ESTALE;
        goto fail;
    }
    executable_fd = openat(context->self_fd, "exe", O_RDONLY | O_CLOEXEC);
    if (executable_fd < 0) {
        saved_errno = errno ? errno : EIO;
        goto fail;
    }
    if (fstat(executable_fd, &executable_status) < 0) {
        saved_errno = errno ? errno : EIO;
        goto fail;
    }
    if (!S_ISREG(executable_status.st_mode) ||
        executable_status.st_ino == 0) {
        saved_errno = ESTALE;
        goto fail;
    }

    /* Procfs entries cannot normally be replaced, but verifying the pinned
     * link again makes mount manipulation fail closed rather than silently
     * changing which executable the followed open names. */
    link_after_fd = openat(context->self_fd, "exe",
                           O_PATH | O_NOFOLLOW | O_CLOEXEC);
    if (link_after_fd < 0) {
        saved_errno = errno ? errno : EIO;
        goto fail;
    }
    errno = 0;
    if (!bs_proc_entry_status(link_after_fd, context->device, S_IFLNK,
                              &link_after_status)) {
        saved_errno = errno ? errno : ESTALE;
        goto fail;
    }
    if (link_status.st_dev != link_after_status.st_dev ||
        link_status.st_ino != link_after_status.st_ino) {
        saved_errno = ESTALE;
        goto fail;
    }

    close(link_after_fd);
    close(link_fd);
    return executable_fd;

fail:
    if (link_after_fd >= 0)
        close(link_after_fd);
    if (link_fd >= 0)
        close(link_fd);
    if (executable_fd >= 0)
        close(executable_fd);
    errno = saved_errno;
    return -1;
}

static int bs_verified_proc_self_executable_open_at(const char *proc_root)
{
    struct bs_proc_self_context context;
    int executable_fd;
    int saved_errno;

    if (bs_proc_self_context_open_at(proc_root, &context) < 0)
        return -1;
    executable_fd = bs_proc_self_executable_open(&context);
    saved_errno = errno;
    bs_proc_self_context_close(&context);
    errno = saved_errno;
    return executable_fd;
}

static int bs_open_file_backed_payload(
    uint64_t payload_vaddr, uint64_t payload_filesz,
    uint64_t payload_foff)
{
    struct bs_proc_self_context context;
    struct stat executable;
    struct stat smaps_status;
    FILE *smaps = NULL;
    int executable_fd = -1;
    int smaps_fd = -1;
    int matched = 0;

    if (bs_proc_self_context_open_at("/proc", &context) < 0)
        return -1;
    executable_fd = bs_proc_self_executable_open(&context);
    if (executable_fd < 0 || fstat(executable_fd, &executable) < 0 ||
        !S_ISREG(executable.st_mode) || executable.st_size < 0 ||
        executable.st_ino == 0 ||
        payload_foff > (uint64_t)executable.st_size ||
        payload_filesz > (uint64_t)executable.st_size - payload_foff)
        goto out;
    smaps_fd = openat(context.self_fd, "smaps",
                      O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (!bs_proc_entry_status(smaps_fd, context.device, S_IFREG,
                              &smaps_status))
        goto out;
    smaps = fdopen(smaps_fd, "r");
    if (!smaps)
        goto out;
    smaps_fd = -1;
    matched = bs_payload_smaps_stream_matches(
        smaps, &executable, payload_vaddr, payload_filesz, payload_foff);
    if (fclose(smaps) < 0)
        matched = 0;
    smaps = NULL;
    if (!matched)
        goto out;

    bs_proc_self_context_close(&context);
    return executable_fd;

out:
    if (smaps)
        fclose(smaps);
    if (smaps_fd >= 0)
        close(smaps_fd);
    if (executable_fd >= 0)
        close(executable_fd);
    bs_proc_self_context_close(&context);
    return -1;
}

static int payload_descriptor_numbers_valid(uint64_t payload_vaddr,
                                            uint64_t payload_filesz,
                                            uint64_t payload_foff)
{
    return payload_vaddr != 0 && payload_foff != 0 &&
           payload_filesz >= sizeof(struct dlfrz_footer) &&
           payload_vaddr <= UINTPTR_MAX &&
           payload_vaddr % _Alignof(Elf64_Ehdr) == 0 &&
           payload_foff % _Alignof(Elf64_Ehdr) == 0 &&
           payload_filesz <= UINTPTR_MAX - (uintptr_t)payload_vaddr &&
           payload_filesz <= UINT64_MAX - payload_foff;
}

static int embedded_name_valid(const char *name)
{
    const char *base;

    if (!name || !name[0])
        return 0;
    base = bs_basename(name);
    return base[0] && strcmp(base, ".") != 0 && strcmp(base, "..") != 0;
}

enum manifest_string_role {
    MANIFEST_STRING_NAME,
    MANIFEST_STRING_LOGICAL_NAME,
    MANIFEST_STRING_DLOPEN_REQUEST,
};

struct manifest_string_ref {
    uint32_t offset;
    uint32_t entry_index;
    unsigned char role;
};

static int manifest_string_ref_compare(const void *left_pointer,
                                       const void *right_pointer)
{
    const struct manifest_string_ref *left = left_pointer;
    const struct manifest_string_ref *right = right_pointer;

    if (left->offset < right->offset)
        return -1;
    if (left->offset > right->offset)
        return 1;
    if (left->entry_index < right->entry_index)
        return -1;
    if (left->entry_index > right->entry_index)
        return 1;
    return (int)left->role - (int)right->role;
}

/* Manifest strings are emitted as complete, consecutive NUL-terminated
 * records.  Requiring every referenced offset to identify a record start
 * both removes ambiguous suffix identities and lets validation inspect each
 * distinct string once.  Without this canonical form, many entries can all
 * point into one long string and amplify a small artifact into O(N * L)
 * startup work. */
static int manifest_strings_are_valid(
    const struct dlfrz_footer *footer,
    const struct dlfrz_entry *entries, const char *strtab,
    struct manifest_string_ref *refs, size_t ref_count)
{
    size_t begin = 0;

    if (!footer || !entries || !strtab || !refs || ref_count == 0 ||
        strtab[footer->strtab_size - 1] != '\0')
        return 0;
    qsort(refs, ref_count, sizeof(*refs), manifest_string_ref_compare);

    while (begin < ref_count) {
        uint32_t offset = refs[begin].offset;
        const char *value;
        const char *terminator;
        size_t end = begin + 1;
        int nonempty;
        int has_slash;
        int valid_embedded_name;

        while (end < ref_count && refs[end].offset == offset)
            end++;
        if ((uint64_t)offset >= footer->strtab_size ||
            (offset != 0 && strtab[offset - 1] != '\0'))
            return 0;
        value = strtab + offset;
        terminator = memchr(value, '\0',
                            footer->strtab_size - (uint64_t)offset);
        if (!terminator)
            return 0;
        nonempty = terminator != value;
        has_slash = memchr(value, '/', (size_t)(terminator - value)) != NULL;
        valid_embedded_name = nonempty && embedded_name_valid(value);

        for (size_t i = begin; i < end; i++) {
            const struct dlfrz_entry *entry =
                &entries[refs[i].entry_index];
            uint32_t flags = entry->flags;

            switch ((enum manifest_string_role)refs[i].role) {
            case MANIFEST_STRING_NAME:
                if (!nonempty ||
                    ((flags & DLFRZ_FLAG_DATA) && value[0] != '/') ||
                    (!(flags & (DLFRZ_FLAG_DATA |
                                DLFRZ_FLAG_NEEDED_PATHFUL)) &&
                     !valid_embedded_name) ||
                    ((flags & DLFRZ_FLAG_NEEDED_PATHFUL) && !has_slash))
                    return 0;
                break;
            case MANIFEST_STRING_LOGICAL_NAME:
                if (!(flags & DLFRZ_FLAG_SHLIB) || !nonempty)
                    return 0;
                break;
            case MANIFEST_STRING_DLOPEN_REQUEST:
                if (!nonempty ||
                    !dlfrz_manifest_entry_flags_canonical(
                        flags, 1, has_slash))
                    return 0;
                break;
            default:
                return 0;
            }
        }
        begin = end;
    }
    return 1;
}

static int manifest_is_valid(const struct dlfrz_footer *footer,
                             const struct dlfrz_entry *entries,
                             const char *strtab,
                             uint64_t payload_offset,
                             uint64_t payload_size)
{
    uint32_t main_count = 0;
    uint32_t interp_count = 0;
    struct manifest_string_ref *refs = NULL;
    size_t ref_capacity;
    size_t ref_count = 0;
    int result = 0;

    if (!footer->strtab_size || footer->strtab_size > SIZE_MAX ||
        !payload_entry_ranges_valid(footer, entries,
                                    payload_offset, payload_size))
        return 0;

    ref_capacity = (size_t)footer->num_entries * 3;
    if (ref_capacity == 0)
        return 0;
    refs = malloc(ref_capacity * sizeof(*refs));
    if (!refs)
        return 0;

    for (uint32_t i = 0; i < footer->num_entries; i++) {
        uint32_t flags = entries[i].flags;
        uint32_t data_state = flags & (DLFRZ_FLAG_DATA_VIRTUAL |
                                       DLFRZ_FLAG_DATA_NEGATIVE |
                                       DLFRZ_FLAG_DATA_DIRECTORY);

        if (entries[i].name_offset >= footer->strtab_size ||
            !dlfrz_manifest_entry_timestamps_canonical(&entries[i]))
            goto out;
        refs[ref_count++] = (struct manifest_string_ref) {
            entries[i].name_offset, i, MANIFEST_STRING_NAME
        };
        if (entries[i].logical_name_offset != 0) {
            if ((flags & DLFRZ_FLAG_SHLIB) == 0 ||
                entries[i].logical_name_offset >= footer->strtab_size)
                goto out;
            refs[ref_count++] = (struct manifest_string_ref) {
                entries[i].logical_name_offset, i,
                MANIFEST_STRING_LOGICAL_NAME
            };
        }
        if (entries[i].dlopen_request_offset != 0) {
            if (entries[i].dlopen_request_offset >= footer->strtab_size)
                goto out;
            refs[ref_count++] = (struct manifest_string_ref) {
                entries[i].dlopen_request_offset, i,
                MANIFEST_STRING_DLOPEN_REQUEST
            };
        } else if (!dlfrz_manifest_entry_flags_canonical(flags, 0, 0)) {
            goto out;
        }
        if ((data_state != 0)
                 ? (entries[i].data_offset != 0 ||
                    entries[i].data_size != 0)
                 : !payload_range_valid(entries[i].data_offset,
                                        entries[i].data_size,
                                        payload_offset, payload_size))
            goto out;
        if (entries[i].flags & DLFRZ_FLAG_MAIN_EXE)
            main_count++;
        if (entries[i].flags & DLFRZ_FLAG_INTERP)
            interp_count++;
    }
    result = main_count == 1 && interp_count <= 1 &&
             manifest_strings_are_valid(
                 footer, entries, strtab, refs, ref_count);

out:
    free(refs);
    return result;
}

static int direct_source_alias_role(uint32_t flags)
{
    uint32_t role = flags & (DLFRZ_FLAG_MAIN_EXE |
                             DLFRZ_FLAG_INTERP |
                             DLFRZ_FLAG_SHLIB |
                             DLFRZ_FLAG_DATA);

    return role == DLFRZ_FLAG_INTERP || role == DLFRZ_FLAG_SHLIB;
}

static int direct_object_source_alias(const struct dlfrz_entry *entries,
                                      uint32_t left, uint32_t right)
{
    return entries && direct_source_alias_role(entries[left].flags) &&
           direct_source_alias_role(entries[right].flags) &&
           entries[left].data_size != 0 &&
           entries[left].data_offset == entries[right].data_offset &&
           entries[left].data_size == entries[right].data_size;
}

static int direct_alias_geometry_matches(
    const struct dlfrz_lib_meta *left,
    const struct dlfrz_lib_meta *right)
{
    return left->base_addr == right->base_addr &&
           left->vaddr_lo == right->vaddr_lo &&
           left->vaddr_hi == right->vaddr_hi &&
           left->entry == right->entry &&
           left->phdr_file_off == right->phdr_file_off &&
           left->phdr_off == right->phdr_off &&
           left->phdr_num == right->phdr_num &&
           left->phdr_entsz == right->phdr_entsz &&
           ((left->flags ^ right->flags) & DLFRZ_FLAG_NEEDS_RTLD) == 0;
}

static int direct_entry_is_startup_mapped(
    const struct dlfrz_entry *entry,
    const struct dlfrz_lib_meta *meta)
{
    if (entry->flags & (DLFRZ_FLAG_INTERP | DLFRZ_FLAG_DATA))
        return 0;
    return !(entry->flags & DLFRZ_FLAG_DLOPEN) ||
           (meta->flags & DLFRZ_FLAG_DLOPEN_EARLY);
}

/* Exact source aliases may legitimately describe different lifecycle roles:
 * a startup DT_NEEDED object can also have one or more lazy/early dlopen
 * request aliases.  The startup object is always the relocation owner in
 * that case, independent of manifest order.  Two ordinary startup entries,
 * however, have equal ownership priority.  Require their prelink state and
 * fixup slice to agree so reordering a hostile manifest cannot select a
 * different interpretation of the shared mapped bytes.  DLOPEN entries are
 * already required above to carry no prelink state or fixups. */
static int direct_alias_runtime_state_matches(
    const struct dlfrz_lib_meta *left,
    const struct dlfrz_lib_meta *right)
{
    if ((left->flags | right->flags) & DLFRZ_FLAG_DLOPEN)
        return 1;
    return ((left->flags ^ right->flags) &
            (DLFRZ_FLAG_PRELINKED | DLFRZ_FLAG_RUNTIME_SCAN)) == 0 &&
           left->runtime_fixup_off == right->runtime_fixup_off &&
           left->runtime_fixup_count == right->runtime_fixup_count;
}

struct direct_source_ref {
    uint64_t data_offset;
    uint64_t data_size;
    uint32_t entry_index;
};

struct direct_reserved_interval {
    uint64_t lo;
    uint64_t hi;
};

struct direct_elf_summary {
    uint64_t tls_memsz;
    uint64_t tls_align;
    uint64_t reserved_lo;
    uint64_t reserved_hi;
};

struct direct_tls_event {
    uint64_t memsz;
    uint64_t align;
    uint32_t owner_index;
    int owner_priority;
};

static int direct_source_ref_cmp(const void *left_pointer,
                                 const void *right_pointer)
{
    const struct direct_source_ref *left = left_pointer;
    const struct direct_source_ref *right = right_pointer;

    if (left->data_offset < right->data_offset)
        return -1;
    if (left->data_offset > right->data_offset)
        return 1;
    if (left->data_size < right->data_size)
        return -1;
    if (left->data_size > right->data_size)
        return 1;
    if (left->entry_index < right->entry_index)
        return -1;
    if (left->entry_index > right->entry_index)
        return 1;
    return 0;
}

static int direct_reserved_interval_cmp(const void *left_pointer,
                                        const void *right_pointer)
{
    const struct direct_reserved_interval *left = left_pointer;
    const struct direct_reserved_interval *right = right_pointer;

    if (left->lo < right->lo)
        return -1;
    if (left->lo > right->lo)
        return 1;
    if (left->hi < right->hi)
        return -1;
    if (left->hi > right->hi)
        return 1;
    return 0;
}

static int direct_tls_event_cmp(const void *left_pointer,
                                const void *right_pointer)
{
    const struct direct_tls_event *left = left_pointer;
    const struct direct_tls_event *right = right_pointer;

    if (left->owner_priority < right->owner_priority)
        return -1;
    if (left->owner_priority > right->owner_priority)
        return 1;
    if (left->owner_index < right->owner_index)
        return -1;
    if (left->owner_index > right->owner_index)
        return 1;
    return 0;
}

static int direct_startup_owner_priority(
    const struct dlfrz_lib_meta *meta)
{
    if (meta->flags & DLFRZ_FLAG_MAIN_EXE)
        return 0;
    if (meta->flags & DLFRZ_FLAG_DLOPEN)
        return 2;
    return 1;
}

/* Keep this ordering identical to dl_manifest_startup_owner(): the main
 * object, then an ordinary startup identity, then an early dlopen identity;
 * manifest order breaks ties. */
static uint32_t direct_source_group_startup_owner(
    const struct direct_source_ref *refs, size_t begin, size_t end,
    const struct dlfrz_entry *entries,
    const struct dlfrz_lib_meta *metas)
{
    uint32_t owner = UINT32_MAX;
    int owner_priority = INT_MAX;

    for (size_t i = begin; i < end; i++) {
        uint32_t index = refs[i].entry_index;
        int priority;

        if (!direct_entry_is_startup_mapped(&entries[index], &metas[index]))
            continue;
        priority = direct_startup_owner_priority(&metas[index]);
        if (owner == UINT32_MAX || priority < owner_priority ||
            (priority == owner_priority && index < owner)) {
            owner = index;
            owner_priority = priority;
        }
    }
    return owner;
}

static int direct_elf_metadata_is_valid(
    const uint8_t *mem, uint64_t mem_foff,
    const struct dlfrz_entry *entry,
    const struct dlfrz_lib_meta *meta,
    uint64_t page_size, struct direct_elf_summary *summary)
{
    if (!mem || !entry || !meta || !summary ||
        page_size == 0 || (page_size & (page_size - 1)) != 0)
        return 0;
    if (entry->data_offset < mem_foff ||
        !embedded_address_aligned(mem, mem_foff, entry->data_offset,
                                  _Alignof(Elf64_Ehdr)) ||
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
            (ehdr->e_ident[EI_OSABI] != ELFOSABI_NONE &&
             ehdr->e_ident[EI_OSABI] != ELFOSABI_LINUX) ||
            ehdr->e_ident[EI_ABIVERSION] != 0 ||
            ehdr->e_version != EV_CURRENT ||
            ehdr->e_flags != 0 ||
            ehdr->e_machine != expected_machine ||
            (ehdr->e_type != ET_DYN && ehdr->e_type != ET_EXEC) ||
            (ehdr->e_type == ET_EXEC &&
             ((entry->flags & DLFRZ_FLAG_MAIN_EXE) == 0 ||
              meta->base_addr != 0)) ||
            (ehdr->e_type == ET_DYN && meta->base_addr == 0) ||
            ehdr->e_ehsize != sizeof(*ehdr) ||
            ehdr->e_phentsize != sizeof(Elf64_Phdr) ||
            ehdr->e_phnum == 0 || ehdr->e_phnum == PN_XNUM ||
            meta->phdr_num != ehdr->e_phnum ||
            meta->phdr_entsz != ehdr->e_phentsize ||
            ehdr->e_phoff > entry->data_size ||
            (uint64_t)ehdr->e_phnum >
                (entry->data_size - ehdr->e_phoff) / sizeof(Elf64_Phdr))
            return 0;
        for (size_t ident = EI_PAD; ident < EI_NIDENT; ident++)
            if (ehdr->e_ident[ident] != 0)
                return 0;

        /* e_phoff is not required to have Elf64_Phdr alignment.  Consume
         * the bounded file table as bytes and copy each entry into aligned
         * local storage before interpreting it. */
        const uint8_t *phdrs = elf + ehdr->e_phoff;
        uint64_t lo = UINT64_MAX;
        uint64_t hi = 0;
        uint64_t phdr_vaddr = UINT64_MAX;
        uint64_t tls_memsz = 0;
        uint64_t tls_align = 1;
        uint16_t tls_count = 0;
        uint16_t dynamic_count = 0;
        uint16_t gnu_stack_count = 0;
        uint16_t phdr_count = 0;
        int executable_stack = 0;
        int entry_is_executable = 0;
        int phdr_translation_ambiguous = 0;
        int phdr_translation_readable = 0;
        int saw_load_header = 0;
        /* Older GCC data-flow analysis does not reliably correlate the
         * presence guards with the whole-structure assignments below.  Keep
         * the inactive states defined as well; they are never consumed, but
         * doing so makes that invariant explicit to every supported compiler. */
        Elf64_Phdr tls_phdr = {0};
        int have_tls_phdr = 0;
        Elf64_Phdr dynamic_phdr = {0};
        int have_dynamic_phdr = 0;
        Elf64_Phdr self_phdr = {0};
        int have_self_phdr = 0;
        uint64_t phdr_file_end;

        if (!u64_add_checked(
                ehdr->e_phoff,
                (uint64_t)ehdr->e_phnum * sizeof(Elf64_Phdr),
                &phdr_file_end))
            return 0;

        for (uint16_t p = 0; p < ehdr->e_phnum; p++) {
            Elf64_Phdr ph_storage;
            const Elf64_Phdr *ph = &ph_storage;

            memcpy(&ph_storage, phdrs + (size_t)p * ehdr->e_phentsize,
                   sizeof(ph_storage));

            if (ph->p_type == PT_LOAD && ph->p_align > 1) {
                if ((ph->p_align & (ph->p_align - 1)) != 0 ||
                    (ph->p_vaddr & (ph->p_align - 1)) !=
                        (ph->p_offset & (ph->p_align - 1)))
                    return 0;
                /* A zero-sized PT_LOAD maps no pages and imposes no load
                 * bias alignment requirement. */
                if (ph->p_memsz != 0 &&
                    (meta->base_addr & (ph->p_align - 1)) != 0)
                    return 0;
            }
            if (ph->p_type == PT_PHDR) {
                if (++phdr_count != 1 || saw_load_header)
                    return 0;
                self_phdr = *ph;
                have_self_phdr = 1;
            }
            if (ph->p_type == PT_LOAD)
                saw_load_header = 1;
            if (ph->p_type == PT_TLS) {
                if (++tls_count != 1 ||
                    (ph->p_align > 1 &&
                     (ph->p_align & (ph->p_align - 1)) != 0))
                    return 0;
                tls_memsz = ph->p_memsz;
                tls_align = ph->p_align ? ph->p_align : 1;
                tls_phdr = *ph;
                have_tls_phdr = 1;
            }
            if (ph->p_type == PT_DYNAMIC) {
                if (++dynamic_count != 1)
                    return 0;
                dynamic_phdr = *ph;
                have_dynamic_phdr = 1;
            }
            if (ph->p_type == PT_GNU_STACK) {
                if (++gnu_stack_count != 1)
                    return 0;
                executable_stack = (ph->p_flags & PF_X) != 0;
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

            if (ph->p_memsz == 0)
                continue;

            if ((entry->flags & DLFRZ_FLAG_MAIN_EXE) &&
                (ph->p_flags & PF_X) != 0 &&
                meta->entry >= ph->p_vaddr &&
                meta->entry - ph->p_vaddr < ph->p_filesz)
                entry_is_executable = 1;

            if (ph->p_vaddr < lo)
                lo = ph->p_vaddr;
            if (ph->p_vaddr + ph->p_memsz > hi)
                hi = ph->p_vaddr + ph->p_memsz;
            if (ehdr->e_phoff >= ph->p_offset &&
                phdr_file_end - ph->p_offset <= ph->p_filesz) {
                uint64_t candidate;

                if (!u64_add_checked(
                        ph->p_vaddr, ehdr->e_phoff - ph->p_offset,
                        &candidate))
                    return 0;
                if (phdr_vaddr != UINT64_MAX && phdr_vaddr != candidate)
                    phdr_translation_ambiguous = 1;
                else
                    phdr_vaddr = candidate;
                if (ph->p_flags & PF_R)
                    phdr_translation_readable = 1;
            }
        }

        if (!dlfrz_load_pages_do_not_overlap_bytes(
                phdrs, ehdr->e_phnum, ehdr->e_phentsize, page_size))
            return 0;
        if (have_dynamic_phdr &&
            !dlfrz_segment_is_contained_by_load_bytes(
                phdrs, ehdr->e_phnum, ehdr->e_phentsize,
                &dynamic_phdr))
            return 0;

        if (have_tls_phdr) {
            if ((tls_phdr.p_vaddr & (tls_align - 1)) !=
                (tls_phdr.p_offset & (tls_align - 1)))
                return 0;
            if (tls_phdr.p_filesz != 0) {
                int template_contained = 0;

                for (uint16_t p = 0; p < ehdr->e_phnum; p++) {
                    Elf64_Phdr load_storage;
                    const Elf64_Phdr *load = &load_storage;
                    uint64_t delta;

                    memcpy(&load_storage,
                           phdrs + (size_t)p * ehdr->e_phentsize,
                           sizeof(load_storage));

                    if (load->p_type != PT_LOAD ||
                        tls_phdr.p_vaddr < load->p_vaddr ||
                        tls_phdr.p_offset < load->p_offset)
                        continue;
                    delta = tls_phdr.p_vaddr - load->p_vaddr;
                    if (tls_phdr.p_offset - load->p_offset != delta ||
                        delta > load->p_filesz ||
                        tls_phdr.p_filesz > load->p_filesz - delta ||
                        delta > load->p_memsz ||
                        tls_phdr.p_filesz > load->p_memsz - delta)
                        continue;
                    template_contained = 1;
                    break;
                }
                if (!template_contained)
                    return 0;
            }
        }

        int phdr_has_canonical_mapping =
            phdr_vaddr != UINT64_MAX && phdr_translation_readable &&
            phdr_vaddr < DLFRZ_PHDR_EXTERNAL &&
            phdr_vaddr % _Alignof(Elf64_Phdr) == 0;
        int phdr_is_external = meta->phdr_off == DLFRZ_PHDR_EXTERNAL;

        if (lo >= hi || phdr_translation_ambiguous ||
            (have_self_phdr &&
             (!phdr_has_canonical_mapping ||
              self_phdr.p_offset != ehdr->e_phoff ||
              self_phdr.p_vaddr != phdr_vaddr ||
              self_phdr.p_filesz !=
                  (uint64_t)ehdr->e_phnum * sizeof(Elf64_Phdr) ||
              self_phdr.p_memsz !=
                  (uint64_t)ehdr->e_phnum * sizeof(Elf64_Phdr) ||
              !(self_phdr.p_flags & PF_R) ||
              (self_phdr.p_align > 1 &&
               ((self_phdr.p_align & (self_phdr.p_align - 1)) != 0 ||
                (self_phdr.p_vaddr & (self_phdr.p_align - 1)) !=
                    (self_phdr.p_offset &
                     (self_phdr.p_align - 1)))))) ||
            meta->vaddr_lo != lo || meta->vaddr_hi != hi ||
            meta->entry != ehdr->e_entry ||
            (phdr_has_canonical_mapping
                 ? (phdr_is_external || meta->phdr_file_off != 0 ||
                    meta->phdr_off != phdr_vaddr)
                 : (!phdr_is_external ||
                    meta->phdr_file_off != ehdr->e_phoff)) ||
            ((entry->flags & DLFRZ_FLAG_MAIN_EXE) &&
             !entry_is_executable) ||
            gnu_stack_count != 1 || executable_stack ||
            (meta->base_addr & (page_size - 1)) != 0 ||
            hi > UINT64_MAX - (page_size - 1) ||
            meta->base_addr >
                UINT64_MAX - ((hi + page_size - 1) & ~(page_size - 1)) ||
            meta->base_addr +
                ((hi + page_size - 1) & ~(page_size - 1)) >
                UINT64_MAX - 4 * page_size)
            return 0;

    summary->tls_memsz = tls_count != 0 ? tls_memsz : 0;
    summary->tls_align = tls_align;
    summary->reserved_lo = meta->base_addr +
                           (lo & ~(page_size - 1));
    summary->reserved_hi = meta->base_addr +
                           ((hi + page_size - 1) & ~(page_size - 1)) +
                           4 * page_size;
    return 1;
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
                                     DLFRZ_FLAG_DATA |
                                     DLFRZ_FLAG_DLOPEN_PATHFUL |
                                     DLFRZ_FLAG_NEEDED_PATHFUL;
    const uint32_t metadata_flag_mask = entry_type_mask |
                                        DLFRZ_FLAG_PRELINKED |
                                        DLFRZ_FLAG_NEEDS_RTLD |
                                        DLFRZ_FLAG_RUNTIME_SCAN |
                                        DLFRZ_FLAG_DLOPEN_EARLY |
                                        DLFRZ_FLAG_DLOPEN_ROOT;
    struct direct_source_ref *refs = NULL;
    struct direct_reserved_interval *intervals = NULL;
    struct direct_tls_event *tls_events = NULL;
    size_t source_count = 0;
    size_t interval_count = 0;
    size_t tls_event_count = 0;
    uint32_t mapped_group_count = 0;
    long page_size_long;
    uint64_t page_size;
#if defined(__aarch64__)
    /* Both supported AArch64 TLS variants reserve two words above TP. */
    uint64_t total_tls = 16;
#else
    uint64_t total_tls = 0;
#endif
    int valid = 0;

    if (!mem || !metas || !entries || num_entries == 0)
        return 0;
    page_size_long = sysconf(_SC_PAGESIZE);
    if (page_size_long <= 0 ||
        ((uint64_t)page_size_long & ((uint64_t)page_size_long - 1)) != 0)
        return 0;
    page_size = (uint64_t)page_size_long;

    /* Validate role-specific state for every manifest identity before
     * collapsing shared immutable ELF sources.  DATA entries deliberately
     * remain outside the mapped-object view and may be high-cardinality. */
    for (uint32_t i = 0; i < num_entries; i++) {
        const struct dlfrz_entry *entry = &entries[i];
        const struct dlfrz_lib_meta *meta = &metas[i];

        if ((entry->flags & DLFRZ_FLAG_INTERP_KERNEL_ONLY) != 0 ||
            (meta->flags & ~metadata_flag_mask) != 0 ||
            meta->_reserved != 0 ||
            (meta->flags & entry_type_mask) !=
                (entry->flags & entry_type_mask) ||
            ((meta->flags & (DLFRZ_FLAG_DLOPEN_EARLY |
                             DLFRZ_FLAG_DLOPEN_ROOT)) != 0 &&
             (meta->flags & (DLFRZ_FLAG_DLOPEN | DLFRZ_FLAG_SHLIB)) !=
                 (DLFRZ_FLAG_DLOPEN | DLFRZ_FLAG_SHLIB)) ||
            (((meta->flags & DLFRZ_FLAG_DLOPEN_ROOT) != 0) !=
             ((meta->flags & DLFRZ_FLAG_DLOPEN) != 0 &&
              entry->dlopen_request_offset != 0)) ||
            ((meta->flags & DLFRZ_FLAG_PRELINKED) != 0 &&
             (meta->flags & (DLFRZ_FLAG_INTERP |
                             DLFRZ_FLAG_DLOPEN |
                             DLFRZ_FLAG_DATA)) != 0) ||
            (((meta->flags & DLFRZ_FLAG_RUNTIME_SCAN) != 0) !=
             ((meta->flags & DLFRZ_FLAG_PRELINKED) != 0 &&
              meta->runtime_fixup_count != 0)) ||
            ((meta->flags & DLFRZ_FLAG_PRELINKED) == 0 &&
             (meta->runtime_fixup_off != 0 ||
              meta->runtime_fixup_count != 0)) ||
            (meta->runtime_fixup_count == 0 &&
             meta->runtime_fixup_off != 0) ||
            ((meta->flags & DLFRZ_FLAG_DLOPEN) != 0 &&
             (((meta->flags & (DLFRZ_FLAG_PRELINKED |
                               DLFRZ_FLAG_RUNTIME_SCAN)) != 0) ||
              meta->runtime_fixup_off != 0 ||
              meta->runtime_fixup_count != 0)) ||
            meta->runtime_fixup_off > runtime_fixup_count ||
            meta->runtime_fixup_count >
                runtime_fixup_count - meta->runtime_fixup_off)
            goto out;

        if ((entry->flags & DLFRZ_FLAG_DATA) != 0) {
            if (meta->flags != DLFRZ_FLAG_DATA ||
                meta->base_addr != 0 ||
                meta->vaddr_lo != 0 || meta->vaddr_hi != 0 ||
                meta->entry != 0 || meta->phdr_file_off != 0 ||
                meta->phdr_off != 0 ||
                meta->phdr_num != 0 || meta->phdr_entsz != 0 ||
                meta->runtime_fixup_off != 0 ||
                meta->runtime_fixup_count != 0)
                goto out;
            if (entry->data_size != 0)
                source_count++;
            continue;
        }

        source_count++;
    }
    if (source_count == 0)
        goto out;

    refs = malloc(source_count * sizeof(*refs));
    intervals = malloc(source_count * sizeof(*intervals));
    tls_events = malloc(source_count * sizeof(*tls_events));
    if (!refs || !intervals || !tls_events)
        goto out;
    {
        size_t ref_count = 0;

        for (uint32_t i = 0; i < num_entries; i++) {
            if ((entries[i].flags & DLFRZ_FLAG_DATA) &&
                entries[i].data_size == 0)
                continue;
            refs[ref_count++] = (struct direct_source_ref) {
                entries[i].data_offset, entries[i].data_size, i
            };
        }
        if (ref_count != source_count)
            goto out;
    }

    qsort(refs, source_count, sizeof(*refs), direct_source_ref_cmp);
    for (size_t begin = 0; begin < source_count;) {
        size_t end = begin + 1;
        uint32_t reference = refs[begin].entry_index;
        uint32_t ordinary_reference = UINT32_MAX;
        uint32_t owner;
        uint32_t representative;
        int dlopen_early_state = -1;
        struct direct_elf_summary summary;

        while (end < source_count &&
               refs[end].data_offset == refs[begin].data_offset &&
               refs[end].data_size == refs[begin].data_size)
            end++;

        /* One musl file may serve as both PT_INTERP and libc SHLIB.  Exact
         * nonempty ranges may otherwise alias only SHLIB identities; MAIN,
         * DATA, combined roles, and all unrelated kinds remain distinct. */
        if (end - begin > 1) {
            for (size_t i = begin + 1; i < end; i++)
                if (!direct_object_source_alias(
                        entries, reference, refs[i].entry_index))
                    goto out;
        }

        /* A nonempty regular DATA entry participates above only so exact
         * aliasing with an ELF role is rejected.  It is not an ELF object and
         * has no reserved virtual-address interval of its own. */
        if (entries[reference].flags & DLFRZ_FLAG_DATA) {
            begin = end;
            continue;
        }

        for (size_t i = begin; i < end; i++) {
            uint32_t index = refs[i].entry_index;
            const struct dlfrz_lib_meta *meta = &metas[index];

            if (!direct_alias_geometry_matches(&metas[reference], meta))
                goto out;
            if (meta->flags & DLFRZ_FLAG_INTERP) {
                continue;
            } else if ((meta->flags & DLFRZ_FLAG_DLOPEN) == 0) {
                if (ordinary_reference != UINT32_MAX &&
                    !direct_alias_runtime_state_matches(
                        &metas[ordinary_reference], meta))
                    goto out;
                ordinary_reference = index;
            } else {
                int early =
                    (meta->flags & DLFRZ_FLAG_DLOPEN_EARLY) != 0;

                if (dlopen_early_state >= 0 &&
                    dlopen_early_state != early)
                    goto out;
                dlopen_early_state = early;
            }
        }

        owner = direct_source_group_startup_owner(
            refs, begin, end, entries, metas);
        representative = owner != UINT32_MAX ? owner : reference;
        if ((entries[representative].flags & DLFRZ_FLAG_INTERP) == 0 &&
            ++mapped_group_count > DLFRZ_DIRECT_MAX_OBJECTS)
            goto out;
        if (!direct_elf_metadata_is_valid(
                mem, mem_foff, &entries[representative],
                &metas[representative], page_size, &summary))
            goto out;

        intervals[interval_count++] =
            (struct direct_reserved_interval) {
                summary.reserved_lo, summary.reserved_hi
            };
        if (owner != UINT32_MAX && summary.tls_memsz != 0) {
            tls_events[tls_event_count++] = (struct direct_tls_event) {
                summary.tls_memsz, summary.tls_align, owner,
                direct_startup_owner_priority(&metas[owner])
            };
        }
        begin = end;
    }

    qsort(intervals, interval_count, sizeof(*intervals),
          direct_reserved_interval_cmp);
    for (size_t i = 1; i < interval_count; i++)
        if (intervals[i].lo < intervals[i - 1].hi)
            goto out;

    /* Match the loader's startup object order when checking aggregate TLS:
     * main, ordinary objects, then promoted dlopen closures, with manifest
     * order inside each class. */
    qsort(tls_events, tls_event_count, sizeof(*tls_events),
          direct_tls_event_cmp);
    for (size_t i = 0; i < tls_event_count; i++) {
        uint64_t next_tls;

#if defined(__aarch64__)
        if (!u64_align_up_checked(total_tls, tls_events[i].align,
                                  &next_tls) ||
            !u64_add_checked(next_tls, tls_events[i].memsz, &total_tls))
            goto out;
#else
        if (!u64_add_checked(total_tls, tls_events[i].memsz, &next_tls) ||
            !u64_align_up_checked(next_tls, tls_events[i].align,
                                  &total_tls))
            goto out;
#endif
        if (total_tls > INT64_MAX)
            goto out;
    }

    valid = 1;
out:
    free(tls_events);
    free(intervals);
    free(refs);
    return valid;
}

/* A contained proof has fixed overhead (one clone/reap, a bounded procfs VMA
 * check, and the prospective remap syscalls).  Below this amount, anonymous
 * copy is generally cheaper and avoids adding a process to tiny launches. */
#ifndef BS_MREMAP_MIN_STARTUP_BYTES
#define BS_MREMAP_MIN_STARTUP_BYTES (UINT64_C(4) * 1024 * 1024)
#endif
#define BS_MREMAP_WAIT_CLONE UINT32_C(0x80000000)

#ifdef DLFREEZE_BOOTSTRAP_FILEBACK_GATE
static size_t g_bs_mremap_clone_attempts;
#endif

enum bs_mremap_probe_status {
    /* Nonzero, uncommon values cannot be confused with an unmodified wait
     * status or with ordinary program exit conventions. */
    BS_MREMAP_PROBE_READY = 72,
    BS_MREMAP_PROBE_DECLINED = 73,
    BS_MREMAP_PROBE_READY_WITH_COOKIE = 74,
    BS_MREMAP_PROBE_COOKIE_ONLY = 75
};

struct bs_mremap_range {
    uintptr_t source;
    uintptr_t target;
    size_t length;
    uint64_t file_offset;
};

/* Re-derive exactly the complete, entry-owned page prefix map_object may
 * transfer for one PT_LOAD.  Returning zero means that the segment remains
 * on the bounded copy path; malformed/overflowing geometry returns -1. */
static int bs_startup_mremap_range(
    const uint8_t *mem, uint64_t mem_foff,
    const struct dlfrz_entry *entry,
    const struct dlfrz_lib_meta *meta,
    const Elf64_Phdr *load, uint64_t page_size,
    struct bs_mremap_range *range)
{
    uint64_t page_mask;
    uint64_t page_delta;
    uint64_t page_offset;
    uint64_t page_vaddr;
    uint64_t map_input;
    uint64_t map_length;
    uint64_t available;
    uint64_t entry_delta;
    uint64_t source_delta;
    uint64_t source_value;
    uint64_t target_value;
    uint64_t source_end;
    uint64_t target_end;
    uint64_t file_offset;

    if (!mem || !entry || !meta || !load || !range ||
        page_size == 0 || (page_size & (page_size - 1)) != 0)
        return -1;
    if (load->p_type != PT_LOAD || load->p_memsz == 0 ||
        load->p_filesz == 0)
        return 0;
    if (load->p_offset > entry->data_size ||
        load->p_filesz > entry->data_size - load->p_offset ||
        load->p_filesz > load->p_memsz ||
        entry->data_offset < mem_foff)
        return -1;

    page_mask = page_size - 1;
    page_delta = load->p_vaddr & page_mask;
    if (page_delta != (load->p_offset & page_mask))
        return 0;
    page_offset = load->p_offset & ~page_mask;
    page_vaddr = load->p_vaddr & ~page_mask;
    if (!u64_add_checked(page_delta, load->p_filesz, &map_input) ||
        !u64_align_up_checked(map_input, page_size, &map_length) ||
        page_offset > entry->data_size)
        return -1;
    available = entry->data_size - page_offset;
    if (map_length > available)
        map_length = available & ~page_mask;
    if (map_length <= page_delta)
        return 0;
    if (map_length > SIZE_MAX)
        return -1;

    entry_delta = entry->data_offset - mem_foff;
    if (!u64_add_checked(entry_delta, page_offset, &source_delta) ||
        source_delta > UINTPTR_MAX ||
        (uintptr_t)mem > UINTPTR_MAX - (uintptr_t)source_delta)
        return -1;
    source_value = (uint64_t)((uintptr_t)mem + (uintptr_t)source_delta);
    if (!u64_add_checked(meta->base_addr, page_vaddr, &target_value) ||
        source_value > UINTPTR_MAX || target_value > UINTPTR_MAX ||
        (source_value & page_mask) != 0 ||
        (target_value & page_mask) != 0 ||
        !u64_add_checked(source_value, map_length, &source_end) ||
        !u64_add_checked(target_value, map_length, &target_end) ||
        source_end > UINTPTR_MAX || target_end > UINTPTR_MAX)
        return -1;
    if (source_value < target_end && target_value < source_end)
        return 0;
    if (!u64_add_checked(entry->data_offset, page_offset, &file_offset) ||
        map_length > UINT64_MAX - file_offset)
        return -1;

    range->source = (uintptr_t)source_value;
    range->target = (uintptr_t)target_value;
    range->length = (size_t)map_length;
    range->file_offset = file_offset;
    return 1;
}

struct bs_startup_mremap_plan {
    /* Loader order is semantic when two targets use the same source page. */
    struct bs_mremap_range *ranges;
    /* A separately sorted copy drives non-overlapping target reservations
     * and the single-pass smaps proof. */
    struct bs_mremap_range *targets;
    size_t count;
    uint64_t total_bytes;
    int kernel_premap;
};

static int bs_kernel_premap_admit(
    const struct bs_live_phdr_table *live,
    uint64_t table_address, uint64_t table_count,
    uint64_t payload_offset, uint64_t payload_size,
    const struct dlfrz_lib_meta *metas, size_t n)
{
    Elf64_Phdr ph[DLFRZ_PREMAP_MAX_PHDRS];
    uint64_t payload_end;
#if defined(__aarch64__)
    const uint64_t page = 65536;
#else
    const uint64_t page = 4096;
#endif
    if (!table_address && !table_count) return 1;
    if (!live || live->live_address != table_address ||
        live->count != table_count || table_count > DLFRZ_PREMAP_MAX_PHDRS ||
        !u64_add_checked(payload_offset, payload_size, &payload_end))
        return 0;
    for (size_t i = 0; i < table_count; i++)
        if (!bs_live_phdr_read(live, i, &ph[i])) return 0;
    if (!table_count || ph[0].p_offset > payload_offset ||
        payload_offset - ph[0].p_offset != page ||
        table_address < DLFRZ_PREMAP_LO ||
        table_address >= DLFRZ_PREMAP_HI ||
        !dlfrz_premap_headers_valid(ph, table_count, table_address,
                                    payload_end, page)) return 0;
    size_t count = 0;
    for (size_t i = 1; i < table_count; i++) {
        const Elf64_Phdr *p = &ph[i];
        if (p->p_type != PT_LOAD || p->p_paddr == p->p_vaddr) continue;
        if (p->p_offset < payload_offset || p->p_offset > payload_end ||
            p->p_filesz > payload_end - p->p_offset) return 0;
        g_bs_premaps[count++] = (struct dlfrz_premap_range){
            p->p_vaddr, p->p_paddr, p->p_filesz, p->p_offset};
    }
    /* Authenticate ownership against every manifest reservation, including
     * lazy ranges and guards, before any unmap or optional fixed syscall. */
    for (size_t i = 0; i < n; i++) {
        uint64_t lo, hi;
        if (metas[i].flags & DLFRZ_FLAG_DATA) continue;
        if (!u64_add_checked(metas[i].base_addr,
                             metas[i].vaddr_lo & ~(page - 1), &lo) ||
            !u64_align_up_checked(metas[i].vaddr_hi, page, &hi) ||
            !u64_add_checked(hi, metas[i].base_addr, &hi) ||
            !u64_add_checked(hi, 4 * page, &hi)) return 0;
        if (lo < UINT64_C(0x40000000) && hi > DLFRZ_PREMAP_LO) return 0;
    }
    g_bs_premap_count = count;
    return count != 0;
}

/* Select only transfers independently derived from admitted input ELFs.
 * Each whole kernel stage has one consumer; boundary padding is trimmed
 * after the child proof, never transferred into an object or its guards. */
static int bs_kernel_premap_select(struct bs_startup_mremap_plan *plan)
{
    size_t count = 0;
    uint64_t bytes = 0;
    memset(g_bs_premap_selected, 0, sizeof(g_bs_premap_selected));
    for (size_t i = 0; i < plan->count; i++) {
        struct bs_mremap_range r = plan->ranges[i];
        for (size_t j = 0; j < g_bs_premap_count; j++) {
            const struct dlfrz_premap_range *s = &g_bs_premaps[j];
            uint64_t delta;
            if (g_bs_premap_selected[j].length || r.target < s->target)
                continue;
            delta = r.target - s->target;
            if (delta > s->length || r.length > s->length - delta ||
                r.file_offset < s->file_offset ||
                r.file_offset - s->file_offset != delta) continue;
            r.source = (uintptr_t)(s->source + delta);
            g_bs_premap_selected[j] = (struct dlfrz_premap_range){
                r.source, r.target, r.length, r.file_offset};
            plan->ranges[count] = r;
            plan->targets[count++] = r;
            bytes += r.length;
            break;
        }
    }
    plan->count = count;
    plan->total_bytes = bytes;
    plan->kernel_premap = 1;
    return count != 0;
}

/* Called before handoff even when the optional proof declined. Unmap only
 * still-owned intervals; after trimming, the loader owns the exact survivors. */
static int bs_kernel_premap_finish(int ready)
{
    struct dlfrz_premap_range kept[DLFRZ_PREMAP_MAX_PHDRS];
    size_t count = 0;
    for (size_t i = 0; i < g_bs_premap_count; i++) {
        const struct dlfrz_premap_range *s = &g_bs_premaps[i];
        const struct dlfrz_premap_range *r = &g_bs_premap_selected[i];
        uint64_t prefix = ready && r->length ? r->source - s->source : s->length;
        uint64_t suffix = ready && r->length ?
            s->length - prefix - r->length : 0;
        if (prefix && munmap((void *)(uintptr_t)s->source, (size_t)prefix) < 0)
            return 0;
        if (suffix && munmap((void *)(uintptr_t)(r->source + r->length),
                             (size_t)suffix) < 0) return 0;
        if (ready && r->length) kept[count++] = *r;
    }
    g_bs_premap_count = 0;
    return !ready || (count && loader_install_kernel_premap(kept, count) == 0);
}

static void bs_startup_mremap_plan_destroy(
    struct bs_startup_mremap_plan *plan)
{
    if (!plan)
        return;
    free(plan->targets);
    free(plan->ranges);
    memset(plan, 0, sizeof(*plan));
}

/* Scan one representative for every exact startup-source alias group.
 * direct_metadata_is_valid() has already authenticated the same records, but
 * retain complete local bounds checks so this optional proof cannot become
 * authority if call ordering changes later.  A NULL output prices the vector;
 * the second parent-side pass fills it once for the disposable child. */
static int bs_startup_mremap_collect(
    const uint8_t *mem, uint64_t mem_foff,
    const struct dlfrz_lib_meta *metas,
    const struct dlfrz_entry *entries,
    uint32_t num_entries, uint64_t page_size,
    struct bs_mremap_range *ranges, size_t range_capacity,
    size_t *range_count_out, uint64_t *total_bytes_out)
{
    uint64_t total = 0;
    size_t range_count = 0;

    if (!mem || !metas || !entries || num_entries == 0 ||
        page_size == 0 || (page_size & (page_size - 1)) != 0)
        return 0;
    for (uint32_t i = 0; i < num_entries; i++) {
        const struct dlfrz_entry *entry = &entries[i];
        const struct dlfrz_lib_meta *meta = &metas[i];
        const Elf64_Ehdr *ehdr;
        uint64_t entry_delta;
        int duplicate = 0;

        if (!direct_entry_is_startup_mapped(entry, meta))
            continue;
        for (uint32_t previous = 0; previous < i; previous++) {
            if (!direct_entry_is_startup_mapped(
                    &entries[previous], &metas[previous]))
                continue;
            if (entries[previous].data_offset == entry->data_offset &&
                entries[previous].data_size == entry->data_size) {
                duplicate = 1;
                break;
            }
        }
        if (duplicate)
            continue;
        if (entry->data_offset < mem_foff ||
            entry->data_offset - mem_foff > SIZE_MAX ||
            entry->data_size < sizeof(*ehdr))
            return 0;
        entry_delta = entry->data_offset - mem_foff;
        if (entry_delta > UINTPTR_MAX ||
            (uintptr_t)mem > UINTPTR_MAX - (uintptr_t)entry_delta)
            return 0;
        ehdr = (const Elf64_Ehdr *)
            ((uintptr_t)mem + (uintptr_t)entry_delta);
        if (ehdr->e_phentsize != sizeof(Elf64_Phdr) ||
            ehdr->e_phnum == 0 || ehdr->e_phnum == PN_XNUM ||
            ehdr->e_phoff > entry->data_size ||
            (uint64_t)ehdr->e_phnum >
                (entry->data_size - ehdr->e_phoff) /
                    sizeof(Elf64_Phdr))
            return 0;

        for (uint16_t p = 0; p < ehdr->e_phnum; p++) {
            Elf64_Phdr load;
            struct bs_mremap_range range;
            int eligible;

            memcpy(&load,
                   (const uint8_t *)ehdr + ehdr->e_phoff +
                       (size_t)p * sizeof(load),
                   sizeof(load));
            eligible = bs_startup_mremap_range(
                mem, mem_foff, entry, meta, &load, page_size, &range);
            if (eligible < 0)
                return 0;
            if (!eligible)
                continue;
            if (total > UINT64_MAX - range.length ||
                range_count == SIZE_MAX ||
                (ranges && range_count >= range_capacity))
                return 0;
            total += range.length;
            if (ranges)
                ranges[range_count] = range;
            range_count++;
        }
    }
    if (range_count_out)
        *range_count_out = range_count;
    if (total_bytes_out)
        *total_bytes_out = total;
    return range_count != 0;
}

static int bs_mremap_target_cmp(const void *left_pointer,
                                const void *right_pointer)
{
    const struct bs_mremap_range *left = left_pointer;
    const struct bs_mremap_range *right = right_pointer;

    if (left->target < right->target)
        return -1;
    if (left->target > right->target)
        return 1;
    if (left->length < right->length)
        return -1;
    if (left->length > right->length)
        return 1;
    return 0;
}

static int bs_mremap_source_cmp(const void *left_pointer,
                                const void *right_pointer)
{
    const struct bs_mremap_range *left = left_pointer;
    const struct bs_mremap_range *right = right_pointer;

    if (left->source < right->source)
        return -1;
    if (left->source > right->source)
        return 1;
    if (left->length < right->length)
        return -1;
    if (left->length > right->length)
        return 1;
    return 0;
}

static int bs_startup_mremap_plan_build(
    const uint8_t *mem, uint64_t mem_foff,
    const struct dlfrz_lib_meta *metas,
    const struct dlfrz_entry *entries,
    uint32_t num_entries, uint64_t page_size,
    struct bs_startup_mremap_plan *plan)
{
    struct bs_mremap_range *sources = NULL;
    size_t count = 0;
    size_t filled_count = 0;
    uint64_t total = 0;
    uint64_t filled_total = 0;
    int valid = 0;

    if (!plan)
        return 0;
    memset(plan, 0, sizeof(*plan));
    if (!bs_startup_mremap_collect(
            mem, mem_foff, metas, entries, num_entries, page_size,
            NULL, 0, &count, &total) ||
        count > SIZE_MAX / sizeof(*plan->ranges))
        return 0;
    plan->ranges = malloc(count * sizeof(*plan->ranges));
    plan->targets = malloc(count * sizeof(*plan->targets));
    sources = malloc(count * sizeof(*sources));
    if (!plan->ranges || !plan->targets || !sources)
        goto out;
    if (!bs_startup_mremap_collect(
            mem, mem_foff, metas, entries, num_entries, page_size,
            plan->ranges, count, &filled_count, &filled_total) ||
        filled_count != count || filled_total != total)
        goto out;
    memcpy(plan->targets, plan->ranges, count * sizeof(*plan->targets));
    memcpy(sources, plan->ranges, count * sizeof(*sources));
    qsort(plan->targets, count, sizeof(*plan->targets),
          bs_mremap_target_cmp);
    qsort(sources, count, sizeof(*sources), bs_mremap_source_cmp);

    /* The loader's ordinary object reservations have already been checked,
     * but the proof remains independently fail-closed.  Overlapping target
     * transfers would make their final backing order-dependent; a target
     * which aliases any source could destroy a later proof input. */
    for (size_t i = 1; i < count; i++) {
        uint64_t previous_end;

        if (!u64_add_checked(
                (uint64_t)plan->targets[i - 1].target,
                plan->targets[i - 1].length, &previous_end) ||
            previous_end > UINTPTR_MAX ||
            (uint64_t)plan->targets[i].target < previous_end)
            goto out;
    }
    {
        size_t source_index = 0;
        size_t target_index = 0;

        while (source_index < count && target_index < count) {
            uint64_t source_end;
            uint64_t target_end;

            if (!u64_add_checked(
                    (uint64_t)sources[source_index].source,
                    sources[source_index].length, &source_end) ||
                !u64_add_checked(
                    (uint64_t)plan->targets[target_index].target,
                    plan->targets[target_index].length, &target_end) ||
                source_end > UINTPTR_MAX || target_end > UINTPTR_MAX)
                goto out;
            if (source_end <=
                    (uint64_t)plan->targets[target_index].target) {
                source_index++;
            } else if (target_end <=
                           (uint64_t)sources[source_index].source) {
                target_index++;
            } else {
                goto out;
            }
        }
    }
    plan->count = count;
    plan->total_bytes = total;
    valid = 1;
out:
    free(sources);
    if (!valid)
        bs_startup_mremap_plan_destroy(plan);
    return valid;
}

static int bs_startup_mremap_plan_matches_payload(
    const struct bs_startup_mremap_plan *plan,
    uint64_t payload_vaddr, uint64_t payload_filesz,
    uint64_t payload_foff)
{
    uint64_t payload_end;

    if (!plan || !plan->ranges || plan->count == 0 ||
        payload_vaddr > UINTPTR_MAX || payload_filesz == 0 ||
        !u64_add_checked(payload_vaddr, payload_filesz, &payload_end) ||
        payload_end > UINTPTR_MAX ||
        payload_filesz > UINT64_MAX - payload_foff)
        return 0;
    for (size_t i = 0; i < plan->count; i++) {
        const struct bs_mremap_range *range = &plan->ranges[i];
        uint64_t source_end;
        uint64_t expected_file_offset;

        if ((uint64_t)range->source < payload_vaddr ||
            !u64_add_checked((uint64_t)range->source, range->length,
                             &source_end) ||
            source_end > payload_end ||
            !u64_add_checked(payload_foff,
                             (uint64_t)range->source - payload_vaddr,
                             &expected_file_offset) ||
            expected_file_offset != range->file_offset)
            return 0;
    }
    return 1;
}

static int bs_mremap_targets_finish_vma(
    const struct bs_smaps_evidence *evidence,
    const struct bs_startup_mremap_plan *plan,
    size_t *range_index, uint64_t *cursor)
{
    const struct bs_maps_entry *entry = &evidence->entry;

    if (!evidence->relevant)
        return 1;
    if (!evidence->have_anonymous || !evidence->have_swap ||
        !evidence->have_vm_flags || evidence->anonymous_kb != 0 ||
        evidence->swap_kb != 0 || evidence->userfaultfd)
        return 0;

    while (*range_index < plan->count && entry->end > *cursor) {
        const struct bs_mremap_range *range =
            &plan->targets[*range_index];
        uint64_t range_end;
        uint64_t overlap_start;
        uint64_t overlap_end;
        uint64_t actual_file_offset;
        uint64_t expected_file_offset;

        if (!u64_add_checked((uint64_t)range->target, range->length,
                             &range_end))
            return 0;
        overlap_start = *cursor;
        if (overlap_start < (uint64_t)range->target)
            overlap_start = (uint64_t)range->target;
        if (entry->end <= overlap_start)
            break;
        if (entry->start > overlap_start ||
            !u64_add_checked(entry->file_offset,
                             overlap_start - entry->start,
                             &actual_file_offset) ||
            !u64_add_checked(range->file_offset,
                             overlap_start - (uint64_t)range->target,
                             &expected_file_offset) ||
            actual_file_offset != expected_file_offset)
            return 0;
        overlap_end = entry->end < range_end ? entry->end : range_end;
        if (overlap_end <= overlap_start)
            return 0;
        *cursor = overlap_end;
        if (*cursor != range_end)
            break;
        (*range_index)++;
        if (*range_index < plan->count)
            *cursor = (uint64_t)plan->targets[*range_index].target;
    }
    return 1;
}

/* DONTUNMAP itself creates exact child-only target VMAs.  Proving those
 * mappings avoids treating unrelated captured DATA pages in the source
 * payload as startup authority while still detecting COW, swap, userfaultfd,
 * wrong-file, and wrong-offset state in every byte the loader may transfer. */
static int bs_mremap_targets_smaps_stream_matches(
    FILE *stream, const struct stat *executable,
    const struct bs_startup_mremap_plan *plan)
{
    unsigned char line[BS_MAX_MAPS_LINE];
    struct bs_smaps_evidence evidence = {0};
    size_t range_index = 0;
    uint64_t cursor;
    uint64_t previous_end = 0;
    int have_previous = 0;

    if (!stream || !executable || executable->st_ino == 0 || !plan ||
        !plan->targets || plan->count == 0)
        return 0;
    cursor = (uint64_t)plan->targets[0].target;

    for (uint64_t count = 0; count < BS_MAX_SMAPS_LINES; count++) {
        struct bs_maps_entry entry;
        size_t length;
        int line_status = bs_read_maps_line(stream, line, sizeof(line),
                                            &length);

        if (line_status == 0) {
            if (!bs_mremap_targets_finish_vma(
                    &evidence, plan, &range_index, &cursor))
                return 0;
            return range_index == plan->count;
        }
        if (line_status < 0)
            return 0;

        size_t header_prefix = 0;
        unsigned ignored_digit;

        while (header_prefix < length &&
               bs_maps_digit(line[header_prefix], 16, &ignored_digit))
            header_prefix++;
        if (header_prefix != 0 && header_prefix < length &&
            line[header_prefix] == '-') {
            if (!bs_parse_maps_entry(line, length, &entry) ||
                (have_previous && entry.start < previous_end) ||
                !bs_mremap_targets_finish_vma(
                    &evidence, plan, &range_index, &cursor))
                return 0;
            if (range_index == plan->count)
                return 1;
            previous_end = entry.end;
            have_previous = 1;
            memset(&evidence, 0, sizeof(evidence));
            evidence.have_header = 1;
            evidence.entry = entry;

            if (entry.end <= cursor)
                continue;
            if (entry.start > cursor || !entry.private_readonly ||
                entry.dev_major != (uint64_t)major(executable->st_dev) ||
                entry.dev_minor != (uint64_t)minor(executable->st_dev) ||
                entry.inode != (uint64_t)executable->st_ino)
                return 0;
            evidence.relevant = 1;
            continue;
        }

        if (!evidence.have_header || !evidence.relevant)
            continue;
        if (length >= sizeof("Anonymous:") - 1 &&
            memcmp(line, "Anonymous:", sizeof("Anonymous:") - 1) == 0) {
            if (evidence.have_anonymous ||
                !bs_smaps_kb_field(line, length, "Anonymous:",
                                   &evidence.anonymous_kb))
                return 0;
            evidence.have_anonymous = 1;
        } else if (length >= sizeof("Swap:") - 1 &&
                   memcmp(line, "Swap:", sizeof("Swap:") - 1) == 0) {
            if (evidence.have_swap ||
                !bs_smaps_kb_field(line, length, "Swap:",
                                   &evidence.swap_kb))
                return 0;
            evidence.have_swap = 1;
        } else if (length >= sizeof("VmFlags:") - 1 &&
                   memcmp(line, "VmFlags:", sizeof("VmFlags:") - 1) == 0) {
            if (evidence.have_vm_flags ||
                !bs_smaps_vm_flags(line, length, &evidence.userfaultfd))
                return 0;
            evidence.have_vm_flags = 1;
        }
    }
    return 0;
}

static int bs_startup_mremap_target_unions(
    const struct bs_startup_mremap_plan *plan, int reserve)
{
    int valid = 1;

    if (!plan || !plan->targets || plan->count == 0)
        return 0;
    for (size_t begin = 0; begin < plan->count;) {
        uintptr_t start = plan->targets[begin].target;
        uint64_t end_value;
        size_t next = begin + 1;
        size_t union_length;

        if (!u64_add_checked((uint64_t)start,
                             plan->targets[begin].length, &end_value) ||
            end_value > UINTPTR_MAX)
            return 0;
        while (next < plan->count &&
               (uint64_t)plan->targets[next].target == end_value) {
            if (!u64_add_checked(
                    (uint64_t)plan->targets[next].target,
                    plan->targets[next].length, &end_value) ||
                end_value > UINTPTR_MAX)
                return 0;
            next++;
        }
        if (end_value < (uint64_t)start ||
            end_value - (uint64_t)start > SIZE_MAX)
            return 0;
        union_length = (size_t)(end_value - (uint64_t)start);
        if (reserve) {
            void *mapping = mmap(
                (void *)start, union_length, PROT_NONE,
                MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);

            if (mapping != (void *)start)
                return 0;
        } else if (munmap((void *)start, union_length) < 0) {
            valid = 0;
        }
        begin = next;
    }
    return valid;
}

static int bs_startup_mremap_transfer_batch(
    const struct bs_startup_mremap_plan *plan)
{
#if defined(SYS_mremap)
    if (!plan || !plan->ranges || plan->count == 0)
        return 0;
    for (size_t i = 0; i < plan->count; i++) {
        const struct bs_mremap_range *range = &plan->ranges[i];
        void *moved = (void *)syscall(
            SYS_mremap, (void *)range->source,
            range->length, range->length,
            MREMAP_MAYMOVE | MREMAP_FIXED |
                (plan->kernel_premap ? 0 : MREMAP_DONTUNMAP),
            (void *)range->target);

        if (moved != (void *)range->target)
            return 0;
    }
    return 1;
#else
    (void)plan;
    return 0;
#endif
}

/* Reuse the bounded smaps grammar, but require a positively observed wf
 * flag for the complete anonymous cookie page.  Checking the kernel's VMA
 * state also rejects a SIGSYS handler which resumes an unexecuted madvise
 * with an apparent success return. */
static int bs_runtime_fork_cookie_smaps_matches(
    FILE *stream, uintptr_t cookie, size_t page_size)
{
    unsigned char line[BS_MAX_MAPS_LINE];
    uint64_t cookie_end;
    uint64_t previous_end = 0;
    int relevant = 0;
    int have_flags = 0;

    if (!stream || cookie == 0 || page_size < sizeof(uint32_t) ||
        !u64_add_checked(cookie, page_size, &cookie_end))
        return 0;
    for (uint64_t count = 0; count < BS_MAX_SMAPS_LINES; count++) {
        struct bs_maps_entry entry;
        size_t length;
        size_t prefix = 0;
        unsigned digit;
        int status = bs_read_maps_line(stream, line, sizeof(line), &length);

        if (status == 0)
            return relevant && have_flags;
        if (status < 0)
            return 0;
        while (prefix < length && bs_maps_digit(line[prefix], 16, &digit))
            prefix++;
        if (prefix != 0 && prefix < length && line[prefix] == '-') {
            if (!bs_parse_maps_entry(line, length, &entry) ||
                entry.start < previous_end)
                return 0;
            if (relevant)
                return have_flags;
            previous_end = entry.end;
            if (entry.end <= cookie)
                continue;
            if (entry.start > cookie || entry.end < cookie_end ||
                entry.inode != 0 || entry.dev_major != 0 ||
                entry.dev_minor != 0 || entry.file_offset != 0)
                return 0;
            relevant = 1;
        } else if (relevant && length >= sizeof("VmFlags:") - 1 &&
                   memcmp(line, "VmFlags:", sizeof("VmFlags:") - 1) == 0) {
            const unsigned char *cursor = line + sizeof("VmFlags:") - 1;
            const unsigned char *end = line + length;
            int userfaultfd = 0;
            unsigned flags = 0;

            if (have_flags ||
                !bs_smaps_vm_flags(line, length, &userfaultfd) ||
                userfaultfd)
                return 0;
            while (cursor < end) {
                if (!bs_maps_spaces(&cursor, end))
                    return 0;
                if (cursor == end)
                    break;
                /* The complete grammar was validated above. */
                if (cursor[0] == 'w' && cursor[1] == 'f')
                    flags |= 1U;
                else if (cursor[0] == 'r' && cursor[1] == 'd')
                    flags |= 2U;
                else if (cursor[0] == 'w' && cursor[1] == 'r')
                    flags |= 4U;
                else if ((cursor[0] == 's' && cursor[1] == 'h') ||
                         (cursor[0] == 'e' && cursor[1] == 'x') ||
                         (cursor[0] == 'd' && cursor[1] == 'c') ||
                         (cursor[0] == 'i' && cursor[1] == 'o') ||
                         (cursor[0] == 'p' && cursor[1] == 'f'))
                    return 0;
                cursor += 2;
            }
            if (flags != 7U)
                return 0;
            have_flags = 1;
        }
    }
    return 0;
}

/* This exact helper runs first in the already-required disposable startup
 * probe and only then in its parent, under the inherited startup policy.
 * No target resolver, constructor, or thread callback can run between them.
 * Keep madvise and the authenticated verification together: neither its
 * return value nor a child-only VMA flag establishes the parent's cookie. */
static int bs_runtime_fork_cookie_establish(
    volatile uint32_t *cookie, size_t page_size)
{
    struct bs_proc_self_context context = {.root_fd = -1, .self_fd = -1};
    struct stat status;
    FILE *stream = NULL;
    int fd = -1;
    int ready = 0;

    if (!cookie || syscall(SYS_madvise, (void *)cookie, page_size,
                            MADV_WIPEONFORK) != 0 ||
        bs_proc_self_context_open_at("/proc", &context) < 0)
        goto out;
    fd = openat(context.self_fd, "smaps", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (!bs_proc_entry_status(fd, context.device, S_IFREG, &status))
        goto out;
    stream = fdopen(fd, "r");
    if (!stream)
        goto out;
    fd = -1;
    ready = bs_runtime_fork_cookie_smaps_matches(
        stream, (uintptr_t)cookie, page_size);
    if (fclose(stream) != 0)
        ready = 0;
    stream = NULL;
out:
    if (stream)
        fclose(stream);
    if (fd >= 0)
        close(fd);
    bs_proc_self_context_close(&context);
    return ready;
}

/* The remap plan contains only eligible file-page prefixes.  Its endpoints
 * can lie inside noneligible LOAD pages, BSS, guard pages, or the assigned
 * range of a dormant dlopen object.  Derive the conservative full manifest
 * envelope, including all four loader-owned trailing pages, before choosing
 * any address for state which must survive every later object mapping. */
static int bs_runtime_fork_cookie_envelope(
    const struct dlfrz_lib_meta *metas, uint32_t num_entries,
    size_t page_size, uint64_t *lo_out, uint64_t *hi_out)
{
    uint64_t lo = UINT64_MAX;
    uint64_t hi = 0;

    if (!metas || num_entries == 0 || page_size < sizeof(uint32_t) ||
        (page_size & (page_size - 1)) != 0 || page_size > UINT64_MAX / 4)
        return 0;
    for (uint32_t i = 0; i < num_entries; i++) {
        uint64_t start, aligned_hi, end;

        if (metas[i].flags & DLFRZ_FLAG_DATA)
            continue;
        if (metas[i].vaddr_hi <= metas[i].vaddr_lo ||
            !u64_add_checked(metas[i].base_addr,
                             metas[i].vaddr_lo & ~(uint64_t)(page_size - 1),
                             &start) ||
            !u64_align_up_checked(metas[i].vaddr_hi, page_size, &aligned_hi) ||
            !u64_add_checked(metas[i].base_addr, aligned_hi, &end) ||
            !u64_add_checked(end, 4 * page_size, &end) ||
            end > UINTPTR_MAX)
            return 0;
        if (start < lo)
            lo = start;
        if (end > hi)
            hi = end;
    }
    if (hi <= lo)
        return 0;
    *lo_out = lo;
    *hi_out = hi;
    return 1;
}

/* mmap may ignore a nonfixed hint.  Positively check its actual result and
 * decline this optional state if both attempts land in the manifest span. */
static volatile uint32_t *bs_runtime_fork_cookie_allocate(
    const struct dlfrz_lib_meta *metas, uint32_t num_entries, size_t page_size)
{
    uintptr_t hints[2];
    uint64_t lo, hi;

    if (!bs_runtime_fork_cookie_envelope(metas, num_entries, page_size,
                                         &lo, &hi))
        return NULL;
    hints[0] = lo > page_size ? (uintptr_t)(lo - page_size) : 0;
    hints[1] = (uintptr_t)hi;
    for (size_t attempt = 0; attempt < 2; attempt++) {
        void *mapping = mmap((void *)hints[attempt], page_size,
                              PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        uint64_t mapping_end;

        if (mapping == MAP_FAILED)
            continue;
        if (!mapping || !u64_add_checked((uintptr_t)mapping, page_size,
                                         &mapping_end)) {
            munmap(mapping, page_size);
            continue;
        }
        if ((uint64_t)(uintptr_t)mapping >= hi || mapping_end <= lo) {
            *(volatile uint32_t *)mapping = DLFRZ_RUNTIME_FORK_COOKIE;
            return mapping;
        }
        munmap(mapping, page_size);
    }
    return NULL;
}

static void bs_startup_mremap_probe_child(
    const struct bs_startup_mremap_plan *plan,
    int source_fd, int exact_clean_source,
    uint64_t payload_vaddr, uint64_t payload_filesz,
    uint64_t payload_foff, volatile uint32_t *runtime_fork_cookie,
    size_t page_size) __attribute__((noreturn));
static void bs_startup_mremap_probe_child(
    const struct bs_startup_mremap_plan *plan,
    int source_fd, int exact_clean_source,
    uint64_t payload_vaddr, uint64_t payload_filesz,
    uint64_t payload_foff, volatile uint32_t *runtime_fork_cookie,
    size_t page_size)
{
    struct bs_proc_self_context context = {
        .root_fd = -1,
        .self_fd = -1,
    };
    struct stat executable;
    struct stat smaps_status;
    FILE *smaps = NULL;
    int executable_fd = -1;
    int smaps_fd = -1;
    int targets_reserved = 0;
    int ready = 0;
    int cookie_ready = 0;

    if (runtime_fork_cookie)
        cookie_ready = bs_runtime_fork_cookie_establish(
            runtime_fork_cookie, page_size);

    if (!plan || !plan->ranges || !plan->targets || plan->count == 0 ||
        bs_proc_self_context_open_at("/proc", &context) < 0)
        goto out;
    if (exact_clean_source) {
        if (source_fd < 0 || fstat(source_fd, &executable) < 0)
            goto out;
    } else {
        if (!plan->kernel_premap && !bs_startup_mremap_plan_matches_payload(
                plan, payload_vaddr, payload_filesz, payload_foff))
            goto out;
        executable_fd = bs_proc_self_executable_open(&context);
        if (executable_fd < 0 || fstat(executable_fd, &executable) < 0)
            goto out;
    }
    if (!S_ISREG(executable.st_mode) || executable.st_size < 0 ||
        executable.st_ino == 0)
        goto out;
    for (size_t i = 0; i < plan->count; i++) {
        if (plan->ranges[i].file_offset >
                (uint64_t)executable.st_size ||
            plan->ranges[i].length >
                (uint64_t)executable.st_size -
                    plan->ranges[i].file_offset)
            goto out;
    }

    /* Close every descriptor for the transfer's backing file before the
     * first mremap.  The pinned proc directory is retained only to inspect
     * the child after the complete batch has materialized. */
    if (source_fd >= 0) {
        if (close(source_fd) != 0)
            goto out;
        source_fd = -1;
    }
    if (executable_fd >= 0) {
        if (close(executable_fd) != 0)
            goto out;
        executable_fd = -1;
    }
    if (!bs_startup_mremap_target_unions(plan, 1))
        goto out;
    targets_reserved = 1;
    if (!bs_startup_mremap_transfer_batch(plan))
        goto out;

    smaps_fd = openat(context.self_fd, "smaps",
                      O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (!bs_proc_entry_status(smaps_fd, context.device, S_IFREG,
                              &smaps_status))
        goto out;
    smaps = fdopen(smaps_fd, "r");
    if (!smaps)
        goto out;
    smaps_fd = -1;
    if (plan->kernel_premap) {
        /* Authenticate BOTH aliases in one smaps pass. A dirty/reconstructed
         * canonical payload is not interchangeable with a clean stage.
         * Proving both exact file translations avoids faulting every page
         * merely to compare equal bytes. */
        struct bs_mremap_range evidence[2 * DLFRZ_PREMAP_MAX_PHDRS];
        struct bs_startup_mremap_plan proof = *plan;
        if (plan->count > DLFRZ_PREMAP_MAX_PHDRS) goto out;
        for (size_t i = 0; i < plan->count; i++) {
            const struct bs_mremap_range *r = &plan->ranges[i];
            if (r->file_offset < payload_foff ||
                r->file_offset - payload_foff > payload_filesz ||
                r->length > payload_filesz - (r->file_offset - payload_foff))
                goto out;
            evidence[2 * i] = *r;
            evidence[2 * i + 1] = *r;
            evidence[2 * i + 1].target = (uintptr_t)(payload_vaddr +
                r->file_offset - payload_foff);
        }
        proof.count *= 2;
        proof.targets = evidence;
        qsort(evidence, proof.count, sizeof(*evidence), bs_mremap_target_cmp);
        /* Shared source pages are allowed in the loader plan; union exact
         * same-file translations before feeding the non-overlapping proof. */
        size_t merged = 0;
        for (size_t i = 0; i < proof.count; i++) {
            struct bs_mremap_range *r = &evidence[i];
            if (merged && r->target < evidence[merged - 1].target +
                                     evidence[merged - 1].length) {
                struct bs_mremap_range *prev = &evidence[merged - 1];
                uint64_t delta = r->target - prev->target;
                if (r->file_offset < prev->file_offset ||
                    r->file_offset - prev->file_offset != delta) goto out;
                if (delta + r->length > prev->length)
                    prev->length = (size_t)(delta + r->length);
            } else {
                evidence[merged++] = *r;
            }
        }
        proof.count = merged;
        ready = bs_mremap_targets_smaps_stream_matches(smaps, &executable, &proof);
    } else {
        ready = bs_mremap_targets_smaps_stream_matches(smaps, &executable, plan);
    }
    if (fclose(smaps) < 0)
        ready = 0;
    smaps = NULL;

out:
    if (smaps)
        fclose(smaps);
    if (smaps_fd >= 0)
        close(smaps_fd);
    if (targets_reserved &&
        !bs_startup_mremap_target_unions(plan, 0))
        ready = 0;
    if (executable_fd >= 0)
        close(executable_fd);
    if (source_fd >= 0)
        close(source_fd);
    bs_proc_self_context_close(&context);
    _exit(cookie_ready
        ? (ready ? BS_MREMAP_PROBE_READY_WITH_COOKIE
                 : BS_MREMAP_PROBE_COOKIE_ONLY)
        : (ready ? BS_MREMAP_PROBE_READY : BS_MREMAP_PROBE_DECLINED));
}

/* Return one only when a sufficiently large plan passed in a disposable
 * signal-zero clone.  The clone exercises the complete transfer batch, then
 * establishes clean file provenance for exactly the resulting target ranges
 * without faulting payload pages.  Missing procfs and ENOSYS/EINVAL/EPERM are
 * ordinary optimization misses in the parent; fatal policy outcomes after
 * clone are contained by the child.
 *
 * As with the bootstrap's other contained probes, containment begins only
 * after clone returns: a policy which kills clone or the parent's wait4
 * remains fatal, while an errno denial declines the optimization.
 * DLFREEZE_NO_FORK skips this complete optional boundary before allocating a
 * plan or touching procfs, so launchers with restrictive inherited policies
 * have a syscall-safe copy fallback.  A seccomp user-notification supervisor
 * must otherwise service clone, child probes, and wait4 just as it must
 * service ordinary startup syscalls; deliberately unanswered notifications
 * are outside the in-process loader's bounded-progress contract. */
static int bs_startup_mremap_source_ready(
    const uint8_t *mem, uint64_t mem_foff,
    const struct dlfrz_lib_meta *metas,
    const struct dlfrz_entry *entries,
    uint32_t num_entries, int source_fd, int exact_clean_source,
    uint64_t payload_vaddr, uint64_t payload_filesz,
    uint64_t payload_foff, volatile uint32_t **runtime_fork_cookie_out)
{
    if (runtime_fork_cookie_out)
        *runtime_fork_cookie_out = NULL;
    if (bs_env_enabled("DLFREEZE_NO_FORK"))
        return 0;
#if defined(SYS_clone) && defined(SYS_wait4) && defined(SYS_mremap)
    long page_value = sysconf(_SC_PAGESIZE);
    struct bs_startup_mremap_plan plan;
    int child_status = -1;
    long child;
    long waited;
    volatile uint32_t *runtime_fork_cookie = NULL;
    int ready = 0;

    if (page_value <= 0 ||
        ((uint64_t)page_value & ((uint64_t)page_value - 1)) != 0 ||
        !bs_startup_mremap_plan_build(
            mem, mem_foff, metas, entries, num_entries,
            (uint64_t)page_value, &plan))
        return 0;
    if (g_bs_premap_count) {
        if (!bs_kernel_premap_select(&plan)) {
            bs_startup_mremap_plan_destroy(&plan);
            return 0;
        }
        qsort(plan.targets, plan.count, sizeof(*plan.targets),
               bs_mremap_target_cmp);
    }
    if (plan.total_bytes < BS_MREMAP_MIN_STARTUP_BYTES ||
        (!exact_clean_source &&
         !plan.kernel_premap &&
         !bs_startup_mremap_plan_matches_payload(
             &plan, payload_vaddr, payload_filesz, payload_foff))) {
        bs_startup_mremap_plan_destroy(&plan);
        return 0;
    }
    if (runtime_fork_cookie_out)
        runtime_fork_cookie = bs_runtime_fork_cookie_allocate(
            metas, num_entries, (size_t)page_value);
#ifdef DLFREEZE_BOOTSTRAP_FILEBACK_GATE
    g_bs_mremap_clone_attempts++;
#endif
    child = syscall(SYS_clone, 0, 0, 0, 0, 0);
    if (child < 0) {
        if (runtime_fork_cookie)
            munmap((void *)runtime_fork_cookie, (size_t)page_value);
        bs_startup_mremap_plan_destroy(&plan);
        return 0;
    }
    if (child == 0)
        bs_startup_mremap_probe_child(
            &plan, source_fd, exact_clean_source,
            payload_vaddr, payload_filesz, payload_foff,
            runtime_fork_cookie, (size_t)page_value);

    do {
        waited = syscall(SYS_wait4, child, &child_status,
                         (int)BS_MREMAP_WAIT_CLONE, NULL);
    } while (waited < 0 && errno == EINTR);
    bs_startup_mremap_plan_destroy(&plan);
    if (waited == child && WIFEXITED(child_status)) {
        int result = WEXITSTATUS(child_status);

        ready = result == BS_MREMAP_PROBE_READY ||
                result == BS_MREMAP_PROBE_READY_WITH_COOKIE;
        if (runtime_fork_cookie &&
            (result == BS_MREMAP_PROBE_READY_WITH_COOKIE ||
             result == BS_MREMAP_PROBE_COOKIE_ONLY) &&
            *runtime_fork_cookie == DLFRZ_RUNTIME_FORK_COOKIE &&
            bs_runtime_fork_cookie_establish(
                runtime_fork_cookie, (size_t)page_value)) {
            *runtime_fork_cookie_out = runtime_fork_cookie;
            runtime_fork_cookie = NULL;
        }
    }
    if (runtime_fork_cookie)
        munmap((void *)runtime_fork_cookie, (size_t)page_value);
    return ready;
#else
    (void)mem;
    (void)mem_foff;
    (void)metas;
    (void)entries;
    (void)num_entries;
    (void)source_fd;
    (void)exact_clean_source;
    (void)payload_vaddr;
    (void)payload_filesz;
    (void)payload_foff;
    return 0;
#endif
}

enum extraction_fallback_refusal {
    EXTRACTION_FALLBACK_ALLOWED = 0,
    EXTRACTION_REFUSE_DATA,
    EXTRACTION_REFUSE_PATHFUL_DLOPEN,
    EXTRACTION_REFUSE_PATHFUL_NEEDED,
    EXTRACTION_REFUSE_LOGICAL_NAME,
};

/* Extraction relocates every object beneath one private root.  A distinct
 * first-open name is therefore direct-only, except when the manifest proves
 * that the same nonempty payload is both PT_INTERP and SHLIB and the SHLIB's
 * logical-name record is exactly the interpreter's name record.  That object
 * is already present as the launched interpreter; its dependency spelling is
 * merely an additional lookup alias.  Compare offsets and payload ranges so
 * this remains linear even for adversarially large shared strings. */
static int manifest_has_unextractable_logical_names(
    const struct dlfrz_entry *entries, uint32_t count)
{
    uint32_t interp_index = UINT32_MAX;

    if (!entries)
        return 1;
    for (uint32_t i = 0; i < count; i++) {
        if ((entries[i].flags & DLFRZ_FLAG_INTERP) != 0) {
            interp_index = i;
            break;
        }
    }
    for (uint32_t i = 0; i < count; i++) {
        if (entries[i].logical_name_offset == 0)
            continue;
        if (interp_index == UINT32_MAX || entries[i].data_size == 0 ||
            entries[i].logical_name_offset !=
                entries[interp_index].name_offset ||
            entries[i].data_offset != entries[interp_index].data_offset ||
            entries[i].data_size != entries[interp_index].data_size)
            return 1;
    }
    return 0;
}

/* Direct startup only needs a supervisor while a failure before target
 * handoff can still be retried through extraction.  This one classification
 * drives both process selection and refusal diagnostics so a newly
 * direct-only manifest class cannot accidentally retain one behavior without
 * the other. */
static enum extraction_fallback_refusal classify_extraction_fallback(
    int has_data_entries, int has_pathful_dlopen_entries,
    int has_pathful_needed_entries,
    int has_distinct_logical_names)
{
    if (has_data_entries)
        return EXTRACTION_REFUSE_DATA;
    if (has_pathful_dlopen_entries)
        return EXTRACTION_REFUSE_PATHFUL_DLOPEN;
    if (has_pathful_needed_entries)
        return EXTRACTION_REFUSE_PATHFUL_NEEDED;
    if (has_distinct_logical_names)
        return EXTRACTION_REFUSE_LOGICAL_NAME;
    return EXTRACTION_FALLBACK_ALLOWED;
}

static void report_extraction_fallback_refusal(
    enum extraction_fallback_refusal refusal)
{
    switch (refusal) {
    case EXTRACTION_REFUSE_DATA:
        fprintf(stderr,
                "dlfreeze: refusing extraction fallback for a captured-file "
                "artifact\n");
        break;
    case EXTRACTION_REFUSE_PATHFUL_DLOPEN:
        fprintf(stderr,
                "dlfreeze: refusing extraction fallback for a pathful traced "
                "dlopen artifact\n");
        break;
    case EXTRACTION_REFUSE_PATHFUL_NEEDED:
        fprintf(stderr,
                "dlfreeze: refusing extraction fallback for an artifact "
                "with pathful DT_NEEDED entries\n");
        break;
    case EXTRACTION_REFUSE_LOGICAL_NAME:
        fprintf(stderr,
                "dlfreeze: refusing extraction fallback for an artifact "
                "with separate logical load names\n");
        break;
    case EXTRACTION_FALLBACK_ALLOWED:
        break;
    }
}

/* ---- main -------------------------------------------------------- */
int main(int argc, char **argv)
{
    g_bootstrap_secure_mode = bs_detect_secure_mode(environ);
    if (!bs_execution_context_supported()) {
        fprintf(stderr,
                "dlfreeze-bootstrap: AT_SECURE execution is unsupported\n");
        return 127;
    }

    /* Force a relocation from live code to the reserved payload note. */
    __asm__ volatile("" : : "r"(dlfrz_payload_note) : "memory");

    /* Snapshot the packer-patched descriptor once.  Validate its live range
     * against the kernel-provided program headers before dereferencing it. */
    const uint64_t loader_payload_vaddr = g_loader_info.payload_vaddr;
    const uint64_t loader_payload_filesz = g_loader_info.payload_filesz;
    const uint64_t loader_payload_foff = g_loader_info.payload_foff;
    const int loader_descriptor_present = loader_payload_vaddr != 0 ||
        loader_payload_filesz != 0 || loader_payload_foff != 0;
    const int loader_descriptor_numeric_valid =
        payload_descriptor_numbers_valid(loader_payload_vaddr,
                                         loader_payload_filesz,
                                         loader_payload_foff);

    /* 1. Prefer the mapped payload.  Every current artifact carries it in a
     * dedicated readable PT_LOAD, so direct startup does not require procfs.
     * Reopen /proc/self/exe only for compatibility with older/unpatched
     * layouts whose mapped descriptor cannot be validated. */
    int sfd = -1;
    struct stat st;
    struct dlfrz_footer ft;
    int from_memory = 0;
    const uint8_t *mem_base = NULL;
    uint32_t source_flags = 0;
    struct bs_live_phdr_table live_phdrs;
    int have_live_phdrs;
    int mapped_payload_file_backed = 0;

    memset(&st, 0, sizeof(st));
    have_live_phdrs = bs_live_phdr_table_from_env(environ, &live_phdrs);
    if (loader_descriptor_numeric_valid && have_live_phdrs &&
        bs_mapped_range_is_readable(&live_phdrs, loader_payload_vaddr,
                                    loader_payload_filesz)) {
        mem_base = (const uint8_t *)(uintptr_t)loader_payload_vaddr;
        const uint8_t *footer_ptr =
            mem_base + loader_payload_filesz - sizeof(ft);
        memcpy(&ft, footer_ptr, sizeof(ft));
        if (memcmp(ft.magic, DLFRZ_MAGIC, 8) == 0) {
            from_memory = 1;
            mapped_payload_file_backed =
                bs_mapped_payload_file_translation(
                    &live_phdrs, loader_payload_vaddr,
                    loader_payload_filesz, loader_payload_foff);
        }
    }
    if (!from_memory) {
        /* Legacy descriptor-less artifacts require procfs for correctness,
         * not acceleration.  Admit that authority only through a pinned,
         * positively identified procfs process directory. */
        sfd = bs_verified_proc_self_executable_open_at("/proc");
        if (sfd < 0) {
            perror("/proc/self/exe");
            return 127;
        }
        if (fstat(sfd, &st) < 0) {
            perror("fstat"); close(sfd); return 127;
        }
        if (!S_ISREG(st.st_mode) || st.st_size < 0) {
            errno = EINVAL;
            perror("fstat"); close(sfd); return 127;
        }
        if (st.st_size < (off_t)sizeof(ft) ||
            full_pread(sfd, &ft, sizeof(ft),
                       (uint64_t)st.st_size - sizeof(ft)) < 0 ||
            memcmp(ft.magic, DLFRZ_MAGIC, 8) != 0) {
            fprintf(stderr, "dlfreeze-bootstrap: no embedded payload\n");
            close(sfd); return 127;
        }
    }

    if (ft.version != DLFRZ_VERSION) {
        fprintf(stderr, "dlfreeze-bootstrap: unsupported version %u\n", ft.version);
        close(sfd); return 127;
    }

    uint64_t payload_offset = 0;
    uint64_t payload_size = (uint64_t)st.st_size;
    if (from_memory) {
        payload_offset = loader_payload_foff;
        payload_size = loader_payload_filesz;
    } else if (loader_descriptor_present) {
        uint64_t file_size = (uint64_t)st.st_size;
        uint64_t footer_offset = file_size - sizeof(ft);

        if (!loader_descriptor_numeric_valid ||
            loader_payload_foff > file_size ||
            loader_payload_filesz > file_size - loader_payload_foff ||
            !payload_range_valid(footer_offset, sizeof(ft),
                                 loader_payload_foff,
                                 loader_payload_filesz)) {
            fprintf(stderr,
                    "dlfreeze-bootstrap: invalid payload descriptor\n");
            close(sfd); return 127;
        }
        payload_offset = loader_payload_foff;
        payload_size = loader_payload_filesz;
    }
    {
        struct payload_file_range controls[PAYLOAD_CONTROL_COUNT];

        if (ft.num_entries == 0 || ft.strtab_size == 0 ||
            ft.strtab_size > SIZE_MAX ||
            !payload_control_ranges(&ft, payload_offset, payload_size,
                                    controls)) {
            fprintf(stderr, "dlfreeze-bootstrap: invalid payload layout\n");
            close(sfd); return 127;
        }
    }

    /* 3. read string table */
    char *strtab = malloc(ft.strtab_size);
    if (!strtab) {
        fprintf(stderr, "dlfreeze-bootstrap: cannot read strtab\n");
        close(sfd); return 127;
    }
    if (from_memory) {
        memcpy(strtab,
               mem_base + (ft.strtab_offset - loader_payload_foff),
               ft.strtab_size);
    } else {
        if (full_pread(sfd, strtab, (size_t)ft.strtab_size,
                       ft.strtab_offset) < 0) {
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
               mem_base + (ft.manifest_offset - loader_payload_foff),
               msz);
    } else {
        if (full_pread(sfd, ent, msz, ft.manifest_offset) < 0) {
            fprintf(stderr, "dlfreeze-bootstrap: cannot read manifest\n");
            free(ent); free(strtab); close(sfd); return 127;
        }
    }

    if (!manifest_is_valid(&ft, ent, strtab, payload_offset, payload_size)) {
        fprintf(stderr, "dlfreeze-bootstrap: invalid manifest\n");
        free(ent); free(strtab); close(sfd); return 127;
    }

    int has_data_entries = 0;
    int has_shlib_entries = 0;
    int has_kernel_only_interpreter = 0;
    int has_pathful_dlopen_entries = 0;
    int has_pathful_needed_entries = 0;
    int has_unextractable_logical_names;
    for (uint32_t i = 0; i < ft.num_entries; i++) {
        if (ent[i].flags & DLFRZ_FLAG_DATA) {
            has_data_entries = 1;
        }
        if (ent[i].flags & DLFRZ_FLAG_SHLIB)
            has_shlib_entries = 1;
        if (ent[i].flags & DLFRZ_FLAG_INTERP_KERNEL_ONLY)
            has_kernel_only_interpreter = 1;
        if ((ent[i].flags & DLFRZ_FLAG_DLOPEN_PATHFUL) != 0)
            has_pathful_dlopen_entries = 1;
        if ((ent[i].flags & DLFRZ_FLAG_NEEDED_PATHFUL) != 0)
            has_pathful_needed_entries = 1;
    }
    has_unextractable_logical_names =
        manifest_has_unextractable_logical_names(ent, ft.num_entries);

    /* 5. check for direct-load metadata in footer pad[0..7] */
    uint64_t meta_off = 0;
    uint64_t fixup_off = 0;
    uint64_t fixup_count = 0;
    memcpy(&meta_off, ft.pad, sizeof(meta_off));
    memcpy(&fixup_off, ft.pad + 8, sizeof(fixup_off));
    memcpy(&fixup_count, ft.pad + 16, sizeof(fixup_count));
    if ((meta_off == 0 && (fixup_off != 0 || fixup_count != 0)) ||
        (meta_off != 0 &&
         meta_off % _Alignof(struct dlfrz_lib_meta) != 0) ||
        ((fixup_off == 0) != (fixup_count == 0)) ||
        (fixup_off != 0 && fixup_off % _Alignof(uint32_t) != 0)) {
        fprintf(stderr,
                "dlfreeze-bootstrap: non-canonical direct-load metadata\n");
        free(ent); free(strtab); close(sfd); return 127;
    }
    if (meta_off != 0) {
        /* Direct-load mode: try in a child first when the manifest remains
         * extraction-representable.  Prelink writes only explicit-addend
         * RELA RELATIVE destinations; native relocation overwrites those,
         * while implicit-addend RELR is deliberately replayed only in the
         * direct child's private mapping. */
        size_t metasz = ft.num_entries * sizeof(struct dlfrz_lib_meta);
        uint64_t fixup_size = 0;

        if (fixup_count != 0 && fixup_count <= UINT32_MAX)
            fixup_size = fixup_count * sizeof(uint32_t);
        if (!payload_range_valid(meta_off, metasz,
                                 payload_offset, payload_size) ||
            fixup_count > UINT32_MAX ||
            (fixup_count != 0 &&
             (fixup_off == 0 || fixup_count > UINT64_MAX / sizeof(uint32_t) ||
              !payload_range_valid(fixup_off,
                                   fixup_count * sizeof(uint32_t),
                                   payload_offset, payload_size))) ||
            !direct_payload_ranges_valid(
                &ft, ent, payload_offset, payload_size,
                meta_off, metasz, fixup_off, fixup_size)) {
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
                   mem_base + (meta_off - loader_payload_foff),
                   metasz);
        } else {
            if (full_pread(sfd, metas, metasz, meta_off) < 0) {
                fprintf(stderr, "dlfreeze-bootstrap: cannot read lib_meta\n");
                free(metas); free(ent); free(strtab); close(sfd);
                return 127;
            }
        }

        /* Set up mem/mem_foff for the loader.  A current mapped payload stays
         * authoritative until an optional exact clean file alias is proven
         * inside the supervised direct child below.  The compatibility map
         * is itself a newly created clean alias of its verified source fd. */
        const uint8_t *ldr_mem;
        uint64_t ldr_mem_foff;
        int ldr_srcfd;

        if (from_memory) {
            ldr_mem = mem_base;
            ldr_mem_foff = loader_payload_foff;
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
            source_flags |= DLFRZ_SOURCE_EXACT_CLEAN_FILE;
        }

        const uint32_t *runtime_fixups = NULL;
        uint32_t runtime_fixup_count = 0;
        if (fixup_off != 0 && fixup_count != 0) {
            if (!embedded_address_aligned(ldr_mem, ldr_mem_foff, fixup_off,
                                          _Alignof(uint32_t))) {
                fprintf(stderr,
                        "dlfreeze-bootstrap: unaligned runtime fixup table\n");
                if (from_memory == 0 && ldr_mem_foff == 0)
                    munmap((void *)ldr_mem, st.st_size);
                free(metas); free(ent); free(strtab); close(sfd);
                return 127;
            }
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

        /* A live PT_LOAD translation identifies the kernel's intended file
         * source.  A disposable clone exercises the complete prospective
         * DONTUNMAP batch, then the hardened procfs verifier proves exact
         * clean file provenance only for the resulting startup target VMAs.
         * Unrelated captured DATA state cannot disable the optimization;
         * uncertainty in any selected page is still an ordinary miss and the
         * portable bounded-copy path stays authoritative.  A compatibility
         * mapping already has its source fd and uses the ordinary exact-file
         * mmap path instead. */
        volatile uint32_t *runtime_fork_cookie = NULL;
        if (!bs_kernel_premap_admit(
                have_live_phdrs ? &live_phdrs : NULL,
                g_premap_info.phdr_vaddr, g_premap_info.phdr_count,
                loader_payload_foff, loader_payload_filesz,
                metas, ft.num_entries)) {
            fprintf(stderr, "dlfreeze-bootstrap: invalid kernel pre-map layout\n");
            return 127;
        }
        const int kernel_premap = g_bs_premap_count != 0;
        int transfer_ready = 0;
        if (from_memory && mapped_payload_file_backed &&
            bs_startup_mremap_source_ready(
                ldr_mem, ldr_mem_foff, metas, ent, ft.num_entries,
                -1, 0, loader_payload_vaddr, loader_payload_filesz,
                loader_payload_foff, &runtime_fork_cookie))
            transfer_ready = 1;
        if (kernel_premap && !bs_kernel_premap_finish(transfer_ready)) {
            fprintf(stderr, "dlfreeze-bootstrap: cannot release kernel staging\n");
            return 127;
        }
        if (transfer_ready)
            source_flags |= kernel_premap ? DLFRZ_SOURCE_KERNEL_PREMAP :
                                           DLFRZ_SOURCE_MREMAP_DONTUNMAP;
        if (kernel_premap && bs_debug_enabled())
            fprintf(stderr, "dlfreeze-bootstrap: kernel pre-map %s\n",
                    transfer_ready ? "ready" : "copy fallback");

        const enum extraction_fallback_refusal fallback_refusal =
            classify_extraction_fallback(
                has_data_entries, has_pathful_dlopen_entries,
                has_pathful_needed_entries,
                has_unextractable_logical_names);
        const int direct_only_payload =
            fallback_refusal != EXTRACTION_FALLBACK_ALLOWED;

        /* Direct loading normally replaces this bootstrap in the original
         * process.  Besides preserving PID/signal/job-control semantics,
         * that is required for process-associated state which survives exec
         * but not fork, including POSIX record locks.  A clean,
         * extraction-representable artifact may explicitly opt into the
         * speculative supervisor which retries an early loader refusal.
         * DLFREEZE_NO_FORK remains a backwards-compatible override when
         * both controls are present. */
        const int supervised_fallback =
            !direct_only_payload &&
            bs_env_enabled("DLFREEZE_SUPERVISED_FALLBACK") &&
            !bs_env_enabled("DLFREEZE_NO_FORK");
        if (!supervised_fallback) {
            int loader_srcfd = ldr_srcfd;

            /* loader_run owns a nonnegative source fd.  Clear the bootstrap
             * alias before transfer so a late loader failure cannot make a
             * reused descriptor number get closed a second time. */
            ldr_srcfd = -1;
            if (loader_srcfd == sfd)
                sfd = -1;
            loader_run(ldr_mem, ldr_mem_foff, loader_srcfd, source_flags,
                       runtime_fork_cookie, metas, ent, strtab,
                       ft.num_entries, runtime_fixups, runtime_fixup_count,
                       -1,
                       argc, argv, environ);
            if (direct_only_payload)
                report_extraction_fallback_refusal(fallback_refusal);
            if (bs_debug_enabled())
                fprintf(stderr, "dlfreeze-bootstrap: in-process loader failed\n");
            close(sfd);
            return 127;
        }

        /* Run direct-load in a child so clean-payload failures before
         * application handoff can fall back without duplicated effects. */
        int handoff_pipe[2];
        if (pipe2(handoff_pipe, O_CLOEXEC) < 0) {
            /* This pipe belongs only to the optional speculative direct
             * attempt.  A sandbox or older syscall allowlist may reject
             * pipe2 even though the established extraction fork/exec path is
             * usable.  No target code or direct-loader mutation has run yet,
             * so release the direct-only view and take that compatibility
             * path instead of turning a recoverable optimization miss into a
             * fatal launch failure. */
            if (bs_debug_enabled())
                fprintf(stderr,
                        "dlfreeze-bootstrap: cannot create optional direct "
                        "handoff pipe; using extraction: %s\n",
                        strerror(errno));
            if (from_memory == 0 && ldr_mem_foff == 0)
                munmap((void *)ldr_mem, st.st_size);
            free(metas);
            goto extraction_fallback;
        }
        sigset_t forward_set, old_mask;
        struct sigaction old_forward_actions[FORWARD_SIGNAL_CAPACITY];
        struct sigaction old_sigchld_action;
        build_forward_signal_set(&forward_set);
        sigaddset(&forward_set, SIGCHLD);
        if (sigprocmask(SIG_BLOCK, &forward_set, &old_mask) < 0) {
            perror("sigprocmask");
            close(handoff_pipe[0]); close(handoff_pipe[1]);
            if (from_memory == 0 && ldr_mem_foff == 0)
                munmap((void *)ldr_mem, st.st_size);
            free(metas); free(ent); free(strtab); close(sfd);
            return 127;
        }
        if (install_waitable_sigchld(&old_sigchld_action) < 0) {
            perror("sigaction");
            sigprocmask(SIG_SETMASK, &old_mask, NULL);
            close(handoff_pipe[0]); close(handoff_pipe[1]);
            if (from_memory == 0 && ldr_mem_foff == 0)
                munmap((void *)ldr_mem, st.st_size);
            free(metas); free(ent); free(strtab); close(sfd);
            return 127;
        }
        pid_t lpid = fork();
        if (lpid < 0) {
            perror("fork");
            restore_inherited_sigchld(&old_sigchld_action);
            sigprocmask(SIG_SETMASK, &old_mask, NULL);
            close(handoff_pipe[0]); close(handoff_pipe[1]);
            if (from_memory == 0 && ldr_mem_foff == 0)
                munmap((void *)ldr_mem, st.st_size);
            free(metas); free(ent); free(strtab); close(sfd);
            return 127;
        }

        if (lpid == 0) {
            uint32_t child_source_flags = source_flags;
            int child_srcfd = ldr_srcfd;
            int loader_result;

            /* The optional supervisor fork consumes the first wipe before
             * loader_run owns the page.  Rearm only the proven zero child
             * state, still before any target callback can observe it. */
            if (runtime_fork_cookie) {
                if (*runtime_fork_cookie == 0)
                    *runtime_fork_cookie = DLFRZ_RUNTIME_FORK_COOKIE;
                else
                    runtime_fork_cookie = NULL;
            }

            if (restore_inherited_sigchld(&old_sigchld_action) < 0)
                _exit(127);
            if (sigprocmask(SIG_SETMASK, &old_mask, NULL) < 0)
                _exit(127);
            close(handoff_pipe[0]);

            /* This is optional acceleration, so every syscall needed to
             * establish it runs only after a supervisor boundary exists.
             * An inherited seccomp RET_KILL/TRAP therefore kills this clean
             * direct attempt and lets the parent use extraction fallback.
             * Strict/direct-only in-process paths never make these probes. */
            if (from_memory && mapped_payload_file_backed) {
                child_srcfd = bs_open_file_backed_payload(
                    loader_payload_vaddr, loader_payload_filesz,
                    loader_payload_foff);
                if (child_srcfd >= 0)
                    child_source_flags |= DLFRZ_SOURCE_EXACT_CLEAN_FILE;
            }
            /* loader_run() does NOT return on success */
            loader_result = loader_run(
                ldr_mem, ldr_mem_foff, child_srcfd, child_source_flags,
                runtime_fork_cookie, metas, ent, strtab,
                ft.num_entries, runtime_fixups, runtime_fixup_count,
                handoff_pipe[1], argc, argv, environ);
            close(handoff_pipe[1]);
            if (bs_debug_enabled())
                fprintf(stderr, "dlfreeze-bootstrap: in-process loader failed\n");
            _exit(loader_result == DLFRZ_LOADER_RUN_TERMINAL_REFUSAL
                ? DLFRZ_LOADER_CHILD_TERMINAL_REFUSAL
                : 127);
        }

        close(handoff_pipe[1]);
        g_child = lpid;
        g_forwarded_signal = 0;
        if (install_forward_signal_handlers(old_forward_actions) < 0) {
            perror("sigaction");
            kill(lpid, SIGKILL);
            while (waitpid(lpid, NULL, 0) < 0 && errno == EINTR) {}
            g_child = -1;
            restore_inherited_sigchld(&old_sigchld_action);
            sigprocmask(SIG_SETMASK, &old_mask, NULL);
            close(handoff_pipe[0]);
            if (from_memory == 0 && ldr_mem_foff == 0)
                munmap((void *)ldr_mem, st.st_size);
            free(metas); free(ent); free(strtab); close(sfd);
            return 127;
        }
        sigprocmask(SIG_SETMASK, &old_mask, NULL);

        int lst = 0;
        int wait_failed = wait_for_supervised_child(lpid, &lst,
                                                    &forward_set) < 0;

        sigprocmask(SIG_BLOCK, &forward_set, NULL);
        int direct_interrupted = g_forwarded_signal != 0;
        g_child = -1;
        restore_forward_signal_handlers(old_forward_actions);
        restore_inherited_sigchld(&old_sigchld_action);
        sigprocmask(SIG_SETMASK, &old_mask, NULL);

        if (wait_failed) {
            perror("waitpid");
            close(handoff_pipe[0]);
            if (from_memory == 0 && ldr_mem_foff == 0)
                munmap((void *)ldr_mem, st.st_size);
            free(metas); free(ent); free(strtab); close(sfd);
            return 127;
        }

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
        int terminal_exit = !application_started && WIFEXITED(lst) &&
            WEXITSTATUS(lst) == DLFRZ_LOADER_CHILD_TERMINAL_REFUSAL;

        if (from_memory == 0 && ldr_mem_foff == 0)
            munmap((void *)ldr_mem, st.st_size);

        free(metas);

        if (terminal_refusal || terminal_exit) {
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
        if (fallback_refusal != EXTRACTION_FALLBACK_ALLOWED) {
            report_extraction_fallback_refusal(fallback_refusal);
            free(ent); free(strtab); close(sfd);
            return 127;
        }
    }

extraction_fallback:
    ;
    /* DATA entries describe an in-memory filesystem overlay, including
     * negative lookups.  Pathful dynamic-load requests and unrepresented
     * logical names likewise have exact identity/$ORIGIN semantics that a
     * temporary extraction prefix cannot retain. */
    enum extraction_fallback_refusal fallback_refusal =
        classify_extraction_fallback(
            has_data_entries, has_pathful_dlopen_entries,
            has_pathful_needed_entries, has_unextractable_logical_names);
    if (fallback_refusal != EXTRACTION_FALLBACK_ALLOWED) {
        report_extraction_fallback_refusal(fallback_refusal);
        free(ent); free(strtab); close(sfd);
        return 127;
    }

    /* 6. create a bound workdir for extraction fallback. */
    if (make_workdir(g_tmpdir, sizeof(g_tmpdir)) < 0) {
        perror("dlfreeze-bootstrap: temporary extraction directory");
        free(ent); free(strtab); close(sfd);
        return 127;
    }

    /* 7. Build and validate the complete destination set before creating any
     * payload files.  This prevents basename aliases or normalized paths from
     * silently overwriting an earlier manifest entry. */
    struct extraction_plan_entry *extraction_plan = NULL;
    char *exe_path = NULL;
    char *interp_path = NULL;
    char *system_interp_path = NULL;
    int extraction_failed = 0;

    if (build_extraction_plan(ent, ft.num_entries, strtab,
                              &extraction_plan) < 0) {
        fprintf(stderr,
                "dlfreeze-bootstrap: invalid or conflicting extraction paths\n");
        cleanup_workdir();
        free(ent); free(strtab); close(sfd);
        return 127;
    }

    for (uint32_t i = 0; i < ft.num_entries; i++) {
        const char *name = strtab + ent[i].name_offset;
        struct extraction_plan_entry *item = &extraction_plan[i];

        if (item->kind == EXTRACTION_PATH_NONE)
            continue;

        if (item->kind == EXTRACTION_PATH_DIRECTORY) {
            if (item->materialize &&
                ensure_relative_directories(g_tmpdir_fd,
                                            item->relative_path, 1) < 0) {
                fprintf(stderr, "dlfreeze-bootstrap: mkdir failed: %s\n",
                        item->full_path);
                extraction_failed = 1;
                break;
            }
            continue;
        }

        int rc = 0;

        if (item->materialize) {
            if (from_memory) {
                rc = extract_mem(mem_base, loader_payload_foff, g_tmpdir_fd,
                                 item->relative_path, ent[i].data_offset,
                                 ent[i].data_size, item->executable);
            } else {
                rc = extract(sfd, g_tmpdir_fd, item->relative_path,
                             ent[i].data_offset, ent[i].data_size,
                             item->executable);
            }
            if (rc < 0) {
                fprintf(stderr,
                        "dlfreeze-bootstrap: extract failed: %s\n", name);
                extraction_failed = 1;
                break;
            }
        }

        if (item->alias_relative_path && item->alias_materialize) {
            /* Hard links also share mode bits.  If destination coalescing
             * promoted only the alias to executable, materialize an
             * independent copy rather than changing the primary's mode. */
            if (item->alias_executable != item->executable ||
                linkat(g_tmpdir_fd, item->relative_path, g_tmpdir_fd,
                       item->alias_relative_path, 0) < 0) {
                if (from_memory) {
                    rc = extract_mem(mem_base, loader_payload_foff,
                                     g_tmpdir_fd, item->alias_relative_path,
                                     ent[i].data_offset, ent[i].data_size,
                                     item->alias_executable);
                } else {
                    rc = extract(sfd, g_tmpdir_fd, item->alias_relative_path,
                                 ent[i].data_offset, ent[i].data_size,
                                 item->alias_executable);
                }
                if (rc < 0) {
                    fprintf(stderr,
                            "dlfreeze-bootstrap: extract alias failed: %s\n",
                            item->alias_full_path);
                    extraction_failed = 1;
                    break;
                }
            }
        }

        if (ent[i].flags & DLFRZ_FLAG_MAIN_EXE) {
            exe_path = strdup(item->full_path);
            if (!exe_path) {
                extraction_failed = 1;
                break;
            }
        }
        if (ent[i].flags & DLFRZ_FLAG_INTERP) {
            interp_path = strdup(item->full_path);
            system_interp_path = strdup(name);
            if (!interp_path || !system_interp_path) {
                extraction_failed = 1;
                break;
            }
        }
    }
    free_extraction_plan(extraction_plan, ft.num_entries);
    free(ent); free(strtab); close(sfd);

    if (extraction_failed || !exe_path) {
        if (!extraction_failed)
            fprintf(stderr,
                    "dlfreeze-bootstrap: no main executable in payload\n");
        cleanup_workdir();
        free(exe_path);
        free(interp_path); free(system_interp_path);
        return 127;
    }
    if (!exe_path[0]) {
        fprintf(stderr, "dlfreeze-bootstrap: no main executable in payload\n");
        cleanup_workdir();
        free(exe_path);
        free(interp_path); free(system_interp_path);
        return 127;
    }

    /* 8. Build argv for the real program.  Prefer normal kernel PT_INTERP
     * startup when the target has a byte-identical interpreter.  Besides
     * preserving normal /proc/self/exe and self-reexec behavior, this avoids
     * relying on libc-specific command-line options.  If the interpreter is
     * absent or differs, launch the executable through the bundled copy so
     * the bundled libc and loader remain a matched pair. */
    int launcher_available = interp_path != NULL;
    int kernel_interp_available = !launcher_available ||
        (system_interp_path && system_interp_path[0] == '/' &&
         access(system_interp_path, X_OK) == 0);
    int use_interp_launcher = launcher_available &&
        !(kernel_interp_available &&
          files_identical(system_interp_path, interp_path));

    /* Executing an ELF interpreter as `interpreter program` is a loader CLI
     * convention, not part of the generic ELF PT_INTERP ABI.  An unknown
     * dependency-free interpreter is useful in extraction mode only while
     * the original byte-identical pathname remains available for ordinary
     * kernel startup. */
    if (has_kernel_only_interpreter && use_interp_launcher) {
        fprintf(stderr,
                "dlfreeze-bootstrap: original interpreter is unavailable "
                "or differs; bundled launcher ABI is unknown\n");
        cleanup_workdir();
        free(exe_path);
        free(interp_path); free(system_interp_path);
        return 127;
    }

    /* Build the kernel and explicit-interpreter argv variants. */
    char **direct_nav = calloc((size_t)argc + 1, sizeof(char *));
    if (!direct_nav) {
        cleanup_workdir();
        free(exe_path);
        free(interp_path); free(system_interp_path);
        return 127;
    }
    /* execve(2) treats argv[0] as caller-owned process state.  Preserve the
     * spelling used to invoke the frozen artifact, including an explicitly
     * empty value, instead of substituting the pack-time target name. */
    direct_nav[0] = argc > 0 ? argv[0] : NULL;
    for (int i = 1; i < argc; i++)
        direct_nav[i] = argv[i];

    char **launcher_nav = NULL;
    if (launcher_available) {
        launcher_nav = calloc((size_t)argc + 2, sizeof(char *));
        if (!launcher_nav) {
            free(direct_nav);
            cleanup_workdir();
            free(exe_path);
            free(interp_path); free(system_interp_path);
            return 127;
        }
        launcher_nav[0] = interp_path;
        launcher_nav[1] = exe_path;
        for (int i = 1; i < argc; i++)
            launcher_nav[i + 1] = argv[i];
    }

    char **nav = use_interp_launcher ? launcher_nav : direct_nav;

    /* 9. Expose extracted shared objects to the native loader.  With no
     * SHLIB entries there is nothing in the extraction root for a loader to
     * find, so preserve the caller's exact LD_LIBRARY_PATH. */
    if (has_shlib_entries) {
        const char *oldlp = getenv("LD_LIBRARY_PATH");
        size_t root_len = strlen(g_tmpdir);
        size_t oldlp_len = oldlp && oldlp[0] ? strlen(oldlp) : 0;
        size_t lp_size = 0;
        char *lp = NULL;

        if (oldlp_len &&
            size_add_checked(root_len, 1, &lp_size) &&
            size_add_checked(lp_size, oldlp_len, &lp_size) &&
            size_add_checked(lp_size, 1, &lp_size)) {
            lp = malloc(lp_size);
            if (lp) {
                memcpy(lp, g_tmpdir, root_len);
                lp[root_len] = ':';
                memcpy(lp + root_len + 1, oldlp, oldlp_len + 1);
            }
        } else if (!oldlp_len) {
            lp = strdup(g_tmpdir);
        } else {
            errno = EOVERFLOW;
        }
        if (!lp || setenv("LD_LIBRARY_PATH", lp, 1) < 0) {
            perror("setenv");
            free(lp);
            cleanup_workdir();
            free(direct_nav); free(launcher_nav);
            free(exe_path);
            free(interp_path); free(system_interp_path);
            return 127;
        }
        free(lp);
    }

    /* 10. fork→exec, parent waits + cleans up.  Block forwarded signals
     * across fork so only the parent installs the supervisor handlers; caught
     * dispositions inherited before exec would otherwise consume a terminal
     * stop in the child during the fork/exec window. */
    sigset_t forward_set, old_mask;
    struct sigaction old_forward_actions[FORWARD_SIGNAL_CAPACITY];
    struct sigaction old_sigchld_action;
    build_forward_signal_set(&forward_set);
    sigaddset(&forward_set, SIGCHLD);
    if (sigprocmask(SIG_BLOCK, &forward_set, &old_mask) < 0) {
        perror("sigprocmask");
        cleanup_workdir();
        free(direct_nav); free(launcher_nav);
        free(exe_path);
        free(interp_path); free(system_interp_path);
        return 127;
    }
    if (install_waitable_sigchld(&old_sigchld_action) < 0) {
        perror("sigaction");
        sigprocmask(SIG_SETMASK, &old_mask, NULL);
        cleanup_workdir();
        free(direct_nav); free(launcher_nav);
        free(exe_path);
        free(interp_path); free(system_interp_path);
        return 127;
    }
    int status = 0;
    g_child = fork();
    if (g_child < 0) {
        restore_inherited_sigchld(&old_sigchld_action);
        sigprocmask(SIG_SETMASK, &old_mask, NULL);
        perror("fork"); cleanup_workdir();
        free(direct_nav); free(launcher_nav);
        free(exe_path);
        free(interp_path); free(system_interp_path);
        return 127;
    }

    if (g_child == 0) {
        if (restore_inherited_sigchld(&old_sigchld_action) < 0)
            _exit(127);
        if (sigprocmask(SIG_SETMASK, &old_mask, NULL) < 0)
            _exit(127);
        if (use_interp_launcher)
            execve(interp_path, nav, environ);
        else
            execve(exe_path, nav, environ);
        perror("execve");
        _exit(127);
    }

    pid_t child = g_child;
    g_forwarded_signal = 0;
    if (install_forward_signal_handlers(old_forward_actions) < 0) {
        perror("sigaction");
        kill(child, SIGKILL);
        while (waitpid(child, NULL, 0) < 0 && errno == EINTR) {}
        g_child = -1;
        restore_inherited_sigchld(&old_sigchld_action);
        sigprocmask(SIG_SETMASK, &old_mask, NULL);
        cleanup_workdir();
        free(direct_nav); free(launcher_nav);
        free(exe_path);
        free(interp_path); free(system_interp_path);
        return 127;
    }
    sigprocmask(SIG_SETMASK, &old_mask, NULL);

    int wait_failed = wait_for_supervised_child(child, &status,
                                                &forward_set) < 0;

    sigprocmask(SIG_BLOCK, &forward_set, NULL);
    g_child = -1;
    restore_forward_signal_handlers(old_forward_actions);
    restore_inherited_sigchld(&old_sigchld_action);
    sigprocmask(SIG_SETMASK, &old_mask, NULL);

    cleanup_workdir();
    free(direct_nav);
    free(launcher_nav);
    free(exe_path);
    free(interp_path); free(system_interp_path);

    if (wait_failed) {
        perror("waitpid");
        return 127;
    }

    if (WIFEXITED(status))
        return WEXITSTATUS(status);
    if (WIFSIGNALED(status))
        reraise_child_signal(WTERMSIG(status));
    return 127;
}
