/*
 * dlfreeze trace helper — LD_PRELOAD library.
 *
 * Logs dlopen() results to $DLFREEZE_TRACE_FILE and successful file /
 * directory opens to $DLFREEZE_FILE_TRACE_FILE.  File tracing avoids the
 * external strace dependency for -t -f capture.
 */
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <link.h>
#include <pthread.h>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/syscall.h>

#ifndef O_TMPFILE
#define O_TMPFILE 020000000
#endif

static int g_dlopen_trace_fd = -1;
static int g_file_trace_fd = -1;

static void *(*real_dlopen)(const char *, int);
static int (*real_open)(const char *, int, ...);
static int (*real_open64)(const char *, int, ...);
static int (*real_openat)(int, const char *, int, ...);
static int (*real_openat64)(int, const char *, int, ...);
static FILE *(*real_fopen)(const char *, const char *);
static FILE *(*real_fopen64)(const char *, const char *);
static DIR *(*real_opendir)(const char *);

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static __thread int g_trace_depth;

#define PRELOAD_TRACE_READY "#DLFREEZE_PRELOAD_TRACE_V1"

static int open_needs_mode(int flags)
{
    return (flags & O_CREAT) || ((flags & O_TMPFILE) == O_TMPFILE);
}

static void resolve_symbols(void)
{
    if (real_dlopen && real_open && real_openat && real_fopen && real_opendir)
        return;

    g_trace_depth++;
    if (!real_dlopen)
        real_dlopen = dlsym(RTLD_NEXT, "dlopen");
    if (!real_open)
        real_open = dlsym(RTLD_NEXT, "open");
    if (!real_open64)
        real_open64 = dlsym(RTLD_NEXT, "open64");
    if (!real_openat)
        real_openat = dlsym(RTLD_NEXT, "openat");
    if (!real_openat64)
        real_openat64 = dlsym(RTLD_NEXT, "openat64");
    if (!real_fopen)
        real_fopen = dlsym(RTLD_NEXT, "fopen");
    if (!real_fopen64)
        real_fopen64 = dlsym(RTLD_NEXT, "fopen64");
    if (!real_opendir)
        real_opendir = dlsym(RTLD_NEXT, "opendir");
    g_trace_depth--;
}

static int open_trace_fd(const char *path)
{
    if (!path || !path[0])
        return -1;

    return (int)syscall(SYS_openat, AT_FDCWD, path,
                        O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
}

static void close_trace_fd(int *fd)
{
    if (*fd >= 0) {
        syscall(SYS_close, *fd);
        *fd = -1;
    }
}

static int build_path(int dirfd, const char *path, char *out, size_t out_sz)
{
    char base[PATH_MAX];

    if (!path || !path[0] || !out || out_sz == 0)
        return 0;

    if (path[0] == '/') {
        if (strlen(path) >= out_sz)
            return 0;
        strcpy(out, path);
        return 1;
    }

    if (dirfd == AT_FDCWD) {
        if (!getcwd(base, sizeof(base)))
            return 0;
    } else {
        char proc_path[64];
        ssize_t len;

        snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", dirfd);
        len = readlink(proc_path, base, sizeof(base) - 1);
        if (len < 0)
            return 0;
        base[len] = '\0';
    }

    return snprintf(out, out_sz, "%s/%s", base, path) < (int)out_sz;
}

static void canonicalize_path(char *path, size_t path_sz)
{
    char resolved[PATH_MAX];

    if (!path || !path[0])
        return;

    g_trace_depth++;
    if (realpath(path, resolved)) {
        snprintf(path, path_sz, "%s", resolved);
    }
    g_trace_depth--;
}

static void write_trace_line(int fd, const char *prefix, const char *path)
{
    int saved_errno = errno;

    if (fd < 0 || !path || !path[0])
        return;

    pthread_mutex_lock(&g_lock);
    if (prefix && prefix[0])
        syscall(SYS_write, fd, prefix, strlen(prefix));
    syscall(SYS_write, fd, path, strlen(path));
    syscall(SYS_write, fd, "\n", 1);
    pthread_mutex_unlock(&g_lock);

    errno = saved_errno;
}

static void trace_path_kind(int dirfd, const char *path, int is_dir)
{
    char resolved[PATH_MAX];

    if (g_trace_depth || g_file_trace_fd < 0)
        return;

    if (!build_path(dirfd, path, resolved, sizeof(resolved)))
        return;

    canonicalize_path(resolved, sizeof(resolved));
    write_trace_line(g_file_trace_fd, is_dir ? "D " : "F ", resolved);
}

/* Record a failed file-open (path not found) so the packer can embed a
 * negative VFS entry.  We deliberately do NOT call canonicalize_path here
 * because realpath(3) fails for non-existent paths. */
static void trace_failed_path(int dirfd, const char *path)
{
    char resolved[PATH_MAX];
    int saved_errno = errno;

    if (g_trace_depth || g_file_trace_fd < 0)
        return;

    if (!build_path(dirfd, path, resolved, sizeof(resolved)))
        return;

    /* Only record absolute paths; relative-without-dirfd would need cwd
     * normalisation which is error-prone for non-existent entries. */
    if (resolved[0] != '/')
        return;

    write_trace_line(g_file_trace_fd, "N ", resolved);
    errno = saved_errno;
}

static void trace_fd_result(int fd, int dirfd, const char *path)
{
    struct stat st;

    if (fd < 0 || g_trace_depth || g_file_trace_fd < 0 || !path || !path[0])
        return;

    if (fstat(fd, &st) != 0)
        return;
    if (!S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode))
        return;

    trace_path_kind(dirfd, path, S_ISDIR(st.st_mode));
}

__attribute__((constructor))
static void dlfreeze_trace_init(void)
{
    resolve_symbols();
    g_dlopen_trace_fd = open_trace_fd(getenv("DLFREEZE_TRACE_FILE"));
    g_file_trace_fd = open_trace_fd(getenv("DLFREEZE_FILE_TRACE_FILE"));
    write_trace_line(g_dlopen_trace_fd, "", PRELOAD_TRACE_READY);
    write_trace_line(g_file_trace_fd, "", PRELOAD_TRACE_READY);
}

__attribute__((destructor))
static void dlfreeze_trace_fini(void)
{
    close_trace_fd(&g_dlopen_trace_fd);
    close_trace_fd(&g_file_trace_fd);
}

void *dlopen(const char *filename, int flags)
{
    void *h;

    resolve_symbols();
    h = real_dlopen ? real_dlopen(filename, flags) : NULL;

    if (h && filename && g_dlopen_trace_fd >= 0) {
        struct link_map *lm = NULL;

        if (dlinfo(h, RTLD_DI_LINKMAP, &lm) == 0 &&
            lm && lm->l_name && lm->l_name[0]) {
            char resolved[PATH_MAX];

            snprintf(resolved, sizeof(resolved), "%s", lm->l_name);
            canonicalize_path(resolved, sizeof(resolved));
            write_trace_line(g_dlopen_trace_fd, "", resolved);
        }
    }

    return h;
}

int open(const char *path, int flags, ...)
{
    mode_t mode = 0;
    int fd;

    if (open_needs_mode(flags)) {
        va_list ap;

        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }

    resolve_symbols();
    if (!real_open) {
        errno = ENOSYS;
        return -1;
    }

    fd = open_needs_mode(flags) ? real_open(path, flags, mode)
                                : real_open(path, flags);
    trace_fd_result(fd, AT_FDCWD, path);
    if (fd < 0 && path[0] == '/')
        trace_failed_path(AT_FDCWD, path);
    return fd;
}

int open64(const char *path, int flags, ...)
{
    mode_t mode = 0;
    int fd;

    if (open_needs_mode(flags)) {
        va_list ap;

        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }

    resolve_symbols();
    if (!real_open64 && !real_open) {
        errno = ENOSYS;
        return -1;
    }

    if (real_open64)
        fd = open_needs_mode(flags) ? real_open64(path, flags, mode)
                                    : real_open64(path, flags);
    else
        fd = open_needs_mode(flags) ? real_open(path, flags, mode)
                                    : real_open(path, flags);

    trace_fd_result(fd, AT_FDCWD, path);
    if (fd < 0 && path[0] == '/')
        trace_failed_path(AT_FDCWD, path);
    return fd;
}

int openat(int dirfd, const char *path, int flags, ...)
{
    mode_t mode = 0;
    int fd;

    if (open_needs_mode(flags)) {
        va_list ap;

        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }

    resolve_symbols();
    if (!real_openat) {
        errno = ENOSYS;
        return -1;
    }

    fd = open_needs_mode(flags) ? real_openat(dirfd, path, flags, mode)
                                : real_openat(dirfd, path, flags);
    trace_fd_result(fd, dirfd, path);
    if (fd < 0) {
        char resolved[PATH_MAX];
        if (build_path(dirfd, path, resolved, sizeof(resolved)) &&
            resolved[0] == '/')
            trace_failed_path(dirfd, path);
    }
    return fd;
}

int openat64(int dirfd, const char *path, int flags, ...)
{
    mode_t mode = 0;
    int fd;

    if (open_needs_mode(flags)) {
        va_list ap;

        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }

    resolve_symbols();
    if (!real_openat64 && !real_openat) {
        errno = ENOSYS;
        return -1;
    }

    if (real_openat64)
        fd = open_needs_mode(flags) ? real_openat64(dirfd, path, flags, mode)
                                    : real_openat64(dirfd, path, flags);
    else
        fd = open_needs_mode(flags) ? real_openat(dirfd, path, flags, mode)
                                    : real_openat(dirfd, path, flags);

    trace_fd_result(fd, dirfd, path);
    if (fd < 0) {
        char resolved[PATH_MAX];
        if (build_path(dirfd, path, resolved, sizeof(resolved)) &&
            resolved[0] == '/')
            trace_failed_path(dirfd, path);
    }
    return fd;
}

FILE *fopen(const char *path, const char *mode)
{
    FILE *fp;

    resolve_symbols();
    if (!real_fopen) {
        errno = ENOSYS;
        return NULL;
    }

    fp = real_fopen(path, mode);
    if (fp)
        trace_fd_result(fileno(fp), AT_FDCWD, path);
    return fp;
}

FILE *fopen64(const char *path, const char *mode)
{
    FILE *fp;

    resolve_symbols();
    if (!real_fopen64 && !real_fopen) {
        errno = ENOSYS;
        return NULL;
    }

    fp = real_fopen64 ? real_fopen64(path, mode) : real_fopen(path, mode);
    if (fp)
        trace_fd_result(fileno(fp), AT_FDCWD, path);
    return fp;
}

DIR *opendir(const char *path)
{
    DIR *dir;

    resolve_symbols();
    if (!real_opendir) {
        errno = ENOSYS;
        return NULL;
    }

    dir = real_opendir(path);
    if (dir)
        trace_path_kind(AT_FDCWD, path, 1);
    return dir;
}
