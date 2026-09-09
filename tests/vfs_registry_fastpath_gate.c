/* Deterministic empty-registry fast-path and publication gate. */
#include <pthread.h>
#include <sys/wait.h>

#define DLFREEZE_SYMBOL_LOOKUP_COMPLEXITY_GATE 1
#include "../src/loader.c"

#define HOST_ITERATIONS 256U
#define STREAM_COUNT 96U

static unsigned int g_stub_readdir_calls;
static unsigned int g_stub_closedir_calls;
static unsigned int g_stub_rewinddir_calls;
static unsigned int g_stub_telldir_calls;
static unsigned int g_stub_seekdir_calls;
static unsigned int g_stub_dirfd_calls;
static unsigned int g_stub_fdopendir_calls;
static struct dirent g_stub_dirent;
static int g_errno_stub_fd = -1;
static int g_errno_stub_saw_input;

static void *stub_readdir(void *dirp)
{
    (void)dirp;
    g_stub_readdir_calls++;
    return &g_stub_dirent;
}

static int stub_closedir(void *dirp)
{
    (void)dirp;
    g_stub_closedir_calls++;
    return 17;
}

static void stub_rewinddir(void *dirp)
{
    (void)dirp;
    g_stub_rewinddir_calls++;
}

static long stub_telldir(void *dirp)
{
    (void)dirp;
    g_stub_telldir_calls++;
    return 23;
}

static void stub_seekdir(void *dirp, long position)
{
    (void)dirp;
    (void)position;
    g_stub_seekdir_calls++;
}

static int stub_dirfd(void *dirp)
{
    (void)dirp;
    g_stub_dirfd_calls++;
    return 29;
}

static void *stub_fdopendir(int fd)
{
    (void)fd;
    g_stub_fdopendir_calls++;
    return &g_stub_dirent;
}

static int errno_stub_fileno(void *stream)
{
    (void)stream;
    errno = EILSEQ;
    return g_errno_stub_fd;
}

static int errno_stub_fclose(void *stream)
{
    (void)stream;
    g_errno_stub_saw_input = errno == EDOM;
    if (g_errno_stub_fd >= 0)
        (void)arch_raw_syscall1(SYS_close, g_errno_stub_fd);
    errno = EUCLEAN;
    return 0;
}

static int make_memfd(size_t size)
{
    int fd = (int)syscall(SYS_memfd_create, "dlfreeze-vfs-gate",
                          MFD_CLOEXEC | MFD_ALLOW_SEALING);

    if (fd < 0 || ftruncate(fd, (off_t)size) != 0) {
        if (fd >= 0)
            close(fd);
        return -1;
    }
    return fd;
}

static void initialize_gate(void)
{
    /* The shared complexity macro exposes counters used by this gate and a
     * few symbol-query helpers exercised by a different focused fixture. */
    (void)symbol_lookup_query_init_known_key;
    (void)defined_symbol_version;
    (void)needed_symbol_version;
    runtime_loader_lock_initialize();
    runtime_atomic_store32(&g_vfs_registry_presence, 0);
    memset((void *)g_vfs_fd_hint_counts, 0,
           sizeof(g_vfs_fd_hint_counts));
    memset((void *)g_vfs_dir_handle_hint_counts, 0,
           sizeof(g_vfs_dir_handle_hint_counts));
    runtime_atomic_store32(&g_vfs_fd_hints_saturated, 0);
    runtime_atomic_store32(&g_vfs_dir_handle_hints_saturated, 0);
    g_runtime_loader_lock_acquisitions = 0;
    g_vfs_regular_fd_identity_probes = 0;
    g_vfs_dup_destination_hint_reservations = 0;
    g_vfs_dup_destination_hint_misses = 0;
    g_page_size = (size_t)sysconf(_SC_PAGESIZE);
    g_target_tls_active = 1;
    g_target_errno_ready = 1;
    g_real_errno_location = __errno_location;
    g_real_readdir = stub_readdir;
    g_real_closedir = stub_closedir;
    g_real_rewinddir = stub_rewinddir;
    g_real_telldir = stub_telldir;
    g_real_seekdir = stub_seekdir;
    g_real_dirfd = stub_dirfd;
    g_real_fdopendir = stub_fdopendir;
}

static int empty_registry_gate(void)
{
    void *sentinel = &g_stub_dirent;
    char byte;
    char mapped[PATH_MAX];
    struct stat status;
    uint64_t acquisitions;
    int host_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);

    if (host_fd < 0 ||
        runtime_atomic_load32(&g_vfs_registry_presence) != 0)
        return 0;
    acquisitions = g_runtime_loader_lock_acquisitions;
    for (unsigned int iteration = 0;
         iteration < HOST_ITERATIONS; iteration++) {
        int duplicate = (int)syscall(SYS_dup, host_fd);

        if (duplicate < 0 || vfs_fstat(host_fd, &status) != 0 ||
            vfs_fcntl(host_fd, F_GETFD, 0) < 0 ||
            vfs_close(duplicate) != 0)
            goto fail;
    }
    if (vfs_fstatat(host_fd, "", &status, AT_EMPTY_PATH) != 0 ||
        vfs_readlinkat(host_fd, "", &byte, sizeof(byte)) != -1 ||
        lookup_vfs_dirfd(host_fd, mapped, sizeof(mapped)) != 0 ||
        vfs_fdopendir(host_fd) != sentinel ||
        vfs_readdir(sentinel) != &g_stub_dirent ||
        vfs_telldir(sentinel) != 23 ||
        vfs_dirfd(sentinel) != 29)
        goto fail;
    vfs_rewinddir(sentinel);
    vfs_seekdir(sentinel, 7);
    if (vfs_closedir(sentinel) != 17 ||
        g_stub_fdopendir_calls != 1 || g_stub_readdir_calls != 1 ||
        g_stub_telldir_calls != 1 || g_stub_dirfd_calls != 1 ||
        g_stub_rewinddir_calls != 1 || g_stub_seekdir_calls != 1 ||
        g_stub_closedir_calls != 1 ||
        g_runtime_loader_lock_acquisitions != acquisitions) {
        goto fail;
    }
    close(host_fd);
    return 1;

fail:
    close(host_fd);
    return 0;
}

static int mapped_fd_gate(void)
{
    struct vfs_entry entry;
    struct stat status;
    uint64_t acquisitions;
    uint64_t reservations;
    int fd = make_memfd(3);
    int duplicate = -1;

    if (fd < 0)
        return 0;
    memset(&entry, 0, sizeof(entry));
    entry.size = 3;
    entry.inode = 71;
    if (remember_vfs_regular_fd(fd, &entry) != 0 ||
        !vfs_registry_may_have(VFS_REGISTRY_REGULAR_FD_MAPS))
        goto fail;
    acquisitions = g_runtime_loader_lock_acquisitions;
    if (vfs_fstat(fd, &status) != 0 ||
        status.st_dev != VFS_SYNTHETIC_DEVICE || status.st_ino != 71 ||
        g_runtime_loader_lock_acquisitions != acquisitions + 1)
        goto fail;
    duplicate = open("/dev/null", O_RDONLY | O_CLOEXEC);
    reservations = g_vfs_dup_destination_hint_reservations;
    if (duplicate < 0 || vfs_dup2(fd, duplicate) != duplicate ||
        g_vfs_dup_destination_hint_reservations != reservations + 1 ||
        g_vfs_dup_destination_hint_misses != 0 ||
        g_vfs_regular_fd_map_count != 2 ||
        vfs_fstat(duplicate, &status) != 0 || status.st_ino != 71)
        goto fail;
    if (vfs_close(duplicate) != 0 || vfs_close(fd) != 0 ||
        g_vfs_regular_fd_map_count != 0 ||
        vfs_registry_may_have(VFS_REGISTRY_REGULAR_FD_MAPS))
        return 0;
    acquisitions = g_runtime_loader_lock_acquisitions;
    fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (fd < 0 || vfs_fstat(fd, &status) != 0 || vfs_close(fd) != 0 ||
        g_runtime_loader_lock_acquisitions != acquisitions)
        return 0;
    return 1;

fail:
    if (duplicate >= 0)
        vfs_close(duplicate);
    if (fd >= 0)
        vfs_close(fd);
    return 0;
}

static int unrelated_fd_hint_gate(void)
{
    struct vfs_entry entry;
    struct stat status;
    runtime_loader_lock_token token;
    uint64_t acquisitions;
    int mapped_fd = make_memfd(5);
    int host_fd = -1;

    if (mapped_fd < 0)
        return 0;
    memset(&entry, 0, sizeof(entry));
    entry.size = 5;
    entry.inode = 74;
    if (remember_vfs_regular_fd(mapped_fd, &entry) != 0)
        goto fail;
    host_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    while (host_fd >= 0 &&
           vfs_fd_hint_bucket(host_fd) ==
               vfs_fd_hint_bucket(mapped_fd)) {
        int replacement = (int)syscall(
            SYS_fcntl, host_fd, F_DUPFD_CLOEXEC, host_fd + 1);

        close(host_fd);
        host_fd = replacement;
    }
    if (host_fd < 0)
        goto fail;

    acquisitions = g_runtime_loader_lock_acquisitions;
    for (unsigned int iteration = 0;
         iteration < HOST_ITERATIONS; iteration++) {
        int duplicate = (int)syscall(SYS_dup, host_fd);

        if (duplicate < 0 ||
            vfs_fd_hint_bucket(duplicate) ==
                vfs_fd_hint_bucket(mapped_fd) ||
            vfs_fstat(host_fd, &status) != 0 ||
            vfs_close(duplicate) != 0)
            goto fail;
    }
    if (g_runtime_loader_lock_acquisitions != acquisitions)
        goto fail;

    /* A collision is deliberately only a false positive.  Model a transient
     * reservation in the host fd's bucket: exact lookup still falls through
     * correctly, at the cost of one lock acquisition. */
    token = vfs_dirfd_lock();
    vfs_fd_hint_add_locked(host_fd + (int)VFS_FD_HINT_BUCKET_COUNT);
    vfs_dirfd_unlock(token);
    acquisitions = g_runtime_loader_lock_acquisitions;
    if (vfs_fstat(host_fd, &status) != 0 ||
        g_runtime_loader_lock_acquisitions != acquisitions + 1)
        goto fail_reserved;
    token = vfs_dirfd_lock();
    vfs_fd_hint_remove_locked(
        host_fd + (int)VFS_FD_HINT_BUCKET_COUNT);
    vfs_dirfd_unlock(token);

    if (vfs_close(host_fd) != 0 || vfs_close(mapped_fd) != 0)
        return 0;
    return 1;

fail_reserved:
    token = vfs_dirfd_lock();
    vfs_fd_hint_remove_locked(
        host_fd + (int)VFS_FD_HINT_BUCKET_COUNT);
    vfs_dirfd_unlock(token);
fail:
    if (host_fd >= 0)
        vfs_close(host_fd);
    if (mapped_fd >= 0)
        vfs_close(mapped_fd);
    return 0;
}

static int recursive_publication_gate(void)
{
    struct vfs_entry entry;
    struct stat status;
    runtime_loader_lock_token outer;
    uint64_t acquisitions;
    int fd = make_memfd(1);

    if (fd < 0)
        return 0;
    memset(&entry, 0, sizeof(entry));
    entry.size = 1;
    entry.inode = 72;
    outer = runtime_loader_lock_acquire();
    if (remember_vfs_regular_fd(fd, &entry) != 0 ||
        vfs_close(fd) != 0 || g_vfs_regular_fd_map_count != 0 ||
        !vfs_registry_may_have(VFS_REGISTRY_REGULAR_FD_MAPS)) {
        runtime_loader_lock_release(outer);
        return 0;
    }
    runtime_loader_lock_release(outer);
    if (vfs_registry_may_have(VFS_REGISTRY_REGULAR_FD_MAPS))
        return 0;
    fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return 0;
    acquisitions = g_runtime_loader_lock_acquisitions;
    if (vfs_fstat(fd, &status) != 0 || vfs_close(fd) != 0 ||
        g_runtime_loader_lock_acquisitions != acquisitions)
        return 0;
    return 1;
}

static int dir_handle_gate(void)
{
    struct vfs_dir_handle *handle = vfs_alloc_dir_handle();
    void *noncolliding = (void *)(uintptr_t)UINT64_C(0x10000);
    void *colliding = NULL;
    runtime_loader_lock_token token;
    uint64_t acquisitions;

    if (!handle)
        return 0;
    handle->fd_compat = -1;
    token = vfs_dirfd_lock();
    vfs_register_dir_handle_locked(handle);
    vfs_dirfd_unlock(token);
    if (!vfs_registry_may_have(VFS_REGISTRY_DIR_HANDLES))
        return 0;
    while (vfs_dir_handle_hint_bucket(noncolliding) ==
           vfs_dir_handle_hint_bucket(handle))
        noncolliding = (void *)((uintptr_t)noncolliding + 16U);
    acquisitions = g_runtime_loader_lock_acquisitions;
    if (vfs_readdir(noncolliding) != &g_stub_dirent ||
        vfs_telldir(noncolliding) != 23 ||
        vfs_dirfd(noncolliding) != 29 ||
        g_runtime_loader_lock_acquisitions != acquisitions)
        return 0;

    for (uintptr_t candidate = UINT64_C(0x20000);
         candidate < UINT64_C(0x2000000); candidate += 16U) {
        void *pointer = (void *)candidate;

        if (pointer != (void *)handle &&
            vfs_dir_handle_hint_bucket(pointer) ==
                vfs_dir_handle_hint_bucket(handle)) {
            colliding = pointer;
            break;
        }
    }
    if (!colliding)
        return 0;
    acquisitions = g_runtime_loader_lock_acquisitions;
    if (vfs_readdir(colliding) != &g_stub_dirent ||
        g_runtime_loader_lock_acquisitions != acquisitions + 1)
        return 0;
    acquisitions = g_runtime_loader_lock_acquisitions;
    vfs_rewinddir(handle);
    if (g_runtime_loader_lock_acquisitions != acquisitions + 1 ||
        vfs_closedir(handle) != 0 ||
        vfs_registry_may_have(VFS_REGISTRY_DIR_HANDLES))
        return 0;
    return 1;
}

static int fclose_cleanup_gate(void)
{
    struct vfs_entry entries[STREAM_COUNT];
    void *streams[STREAM_COUNT];
    uint64_t probes;

    memset(entries, 0, sizeof(entries));
    memset(streams, 0, sizeof(streams));
    g_real_fileno = (fileno_fn)fileno;
    g_real_fclose = (fclose_fn)fclose;
    for (size_t index = 0; index < STREAM_COUNT; index++) {
        int fd = make_memfd(index + 1);

        entries[index].size = index + 1;
        entries[index].inode = (ino_t)(1000 + index);
        if (fd < 0 || remember_vfs_regular_fd(fd, &entries[index]) != 0)
            return 0;
        streams[index] = fdopen(fd, "r");
        if (!streams[index])
            return 0;
    }
    probes = g_vfs_regular_fd_identity_probes;
    for (size_t index = 0; index < STREAM_COUNT; index++)
        if (vfs_fclose(streams[index]) != 0)
            return 0;
    if (g_vfs_regular_fd_map_count != 0 ||
        vfs_registry_may_have(VFS_REGISTRY_REGULAR_FD_MAPS) ||
        g_vfs_regular_fd_identity_probes - probes != STREAM_COUNT)
        return 0;

    /* fileno is an implementation detail of the wrapper and must not change
     * the errno value observed by the exact target fclose implementation. */
    g_errno_stub_fd = make_memfd(1);
    entries[0].size = 1;
    entries[0].inode = 2000;
    if (g_errno_stub_fd < 0 ||
        remember_vfs_regular_fd(g_errno_stub_fd, &entries[0]) != 0)
        return 0;
    g_real_fileno = errno_stub_fileno;
    g_real_fclose = errno_stub_fclose;
    errno = EDOM;
    if (vfs_fclose(&entries[0]) != 0 || !g_errno_stub_saw_input ||
        errno != EUCLEAN || g_vfs_regular_fd_map_count != 0 ||
        vfs_registry_may_have(VFS_REGISTRY_REGULAR_FD_MAPS))
        return 0;
    g_errno_stub_fd = -1;

    /* A libc without an exported POSIX fileno remains admissible and uses
     * the conservative full-registry cleanup after fclose. */
    g_errno_stub_fd = make_memfd(2);
    entries[0].size = 2;
    entries[0].inode = 2001;
    if (g_errno_stub_fd < 0 ||
        remember_vfs_regular_fd(g_errno_stub_fd, &entries[0]) != 0)
        return 0;
    g_real_fileno = NULL;
    errno = EDOM;
    if (vfs_fclose(&entries[0]) != 0 || errno != EUCLEAN ||
        g_vfs_regular_fd_map_count != 0 ||
        vfs_registry_may_have(VFS_REGISTRY_REGULAR_FD_MAPS))
        return 0;
    g_errno_stub_fd = -1;
    return 1;
}

static int fork_snapshot_gate(void)
{
    struct vfs_entry entry;
    pid_t child;
    int status;
    int fd = make_memfd(4);

    if (fd < 0)
        return 0;
    memset(&entry, 0, sizeof(entry));
    entry.size = 4;
    entry.inode = 73;
    if (remember_vfs_regular_fd(fd, &entry) != 0)
        return 0;
    child = fork();
    if (child == 0) {
        struct stat child_status;

        if (!vfs_registry_may_have(VFS_REGISTRY_REGULAR_FD_MAPS) ||
            vfs_fstat(fd, &child_status) != 0 ||
            child_status.st_dev != VFS_SYNTHETIC_DEVICE ||
            child_status.st_ino != 73 || vfs_close(fd) != 0 ||
            vfs_registry_may_have(VFS_REGISTRY_REGULAR_FD_MAPS))
            _exit(1);
        _exit(0);
    }
    if (child < 0 || waitpid(child, &status, 0) != child ||
        !WIFEXITED(status) || WEXITSTATUS(status) != 0 ||
        !vfs_registry_may_have(VFS_REGISTRY_REGULAR_FD_MAPS) ||
        vfs_close(fd) != 0)
        return 0;
    return !vfs_registry_may_have(VFS_REGISTRY_REGULAR_FD_MAPS);
}

int main(void)
{
    initialize_gate();
    if (!empty_registry_gate())
        return 1;
    if (!mapped_fd_gate())
        return 2;
    if (!unrelated_fd_hint_gate())
        return 3;
    if (!recursive_publication_gate())
        return 4;
    if (!dir_handle_gate())
        return 5;
    if (!fclose_cleanup_gate())
        return 6;
    if (!fork_snapshot_gate())
        return 7;
    return 0;
}
