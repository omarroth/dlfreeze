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

#if defined(__GLIBC__)
#define DLFREEZE_HAVE_GLIBC_STAT_ALIASES 1
#else
#define DLFREEZE_HAVE_GLIBC_STAT_ALIASES 0
#endif

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
static int (*real_stat)(const char *, struct stat *);
#if DLFREEZE_HAVE_GLIBC_STAT_ALIASES
static int (*real_stat64)(const char *, struct stat64 *);
#endif
static int (*real_lstat)(const char *, struct stat *);
#if DLFREEZE_HAVE_GLIBC_STAT_ALIASES
static int (*real_lstat64)(const char *, struct stat64 *);
#endif
static int (*real_fstatat)(int, const char *, struct stat *, int);
#if DLFREEZE_HAVE_GLIBC_STAT_ALIASES
static int (*real_fstatat64)(int, const char *, struct stat64 *, int);
static int (*real_xstat)(int, const char *, struct stat *);
static int (*real_xstat64)(int, const char *, struct stat64 *);
static int (*real_lxstat)(int, const char *, struct stat *);
static int (*real_lxstat64)(int, const char *, struct stat64 *);
static int (*real_fxstatat)(int, int, const char *, struct stat *, int);
static int (*real_fxstatat64)(int, int, const char *, struct stat64 *, int);
#endif
static int (*real_access)(const char *, int);
static int (*real_faccessat)(int, const char *, int, int);

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static __thread int g_trace_depth;
static int g_symbols_resolved;

#define PRELOAD_TRACE_READY "#DLFREEZE_PRELOAD_TRACE_V1"

static int open_needs_mode(int flags)
{
    return (flags & O_CREAT) || ((flags & O_TMPFILE) == O_TMPFILE);
}

static int is_absolute_path(const char *path)
{
    return path && path[0] == '/';
}

static void resolve_symbols(void)
{
    if (g_symbols_resolved)
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
    if (!real_stat)
        real_stat = dlsym(RTLD_NEXT, "stat");
#if DLFREEZE_HAVE_GLIBC_STAT_ALIASES
    if (!real_stat64)
        real_stat64 = dlsym(RTLD_NEXT, "stat64");
#endif
    if (!real_lstat)
        real_lstat = dlsym(RTLD_NEXT, "lstat");
#if DLFREEZE_HAVE_GLIBC_STAT_ALIASES
    if (!real_lstat64)
        real_lstat64 = dlsym(RTLD_NEXT, "lstat64");
#endif
    if (!real_fstatat)
        real_fstatat = dlsym(RTLD_NEXT, "fstatat");
#if DLFREEZE_HAVE_GLIBC_STAT_ALIASES
    if (!real_fstatat64)
        real_fstatat64 = dlsym(RTLD_NEXT, "fstatat64");
    if (!real_xstat)
        real_xstat = dlsym(RTLD_NEXT, "__xstat");
    if (!real_xstat64)
        real_xstat64 = dlsym(RTLD_NEXT, "__xstat64");
    if (!real_lxstat)
        real_lxstat = dlsym(RTLD_NEXT, "__lxstat");
    if (!real_lxstat64)
        real_lxstat64 = dlsym(RTLD_NEXT, "__lxstat64");
    if (!real_fxstatat)
        real_fxstatat = dlsym(RTLD_NEXT, "__fxstatat");
    if (!real_fxstatat64)
        real_fxstatat64 = dlsym(RTLD_NEXT, "__fxstatat64");
#endif
    if (!real_access)
        real_access = dlsym(RTLD_NEXT, "access");
    if (!real_faccessat)
        real_faccessat = dlsym(RTLD_NEXT, "faccessat");
    g_symbols_resolved = 1;
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

static void trace_stat_result(int rc, int dirfd, const char *path,
                              const struct stat *st)
{
    int saved_errno = errno;

    if (rc == 0 && st && (S_ISREG(st->st_mode) || S_ISDIR(st->st_mode))) {
        trace_path_kind(dirfd, path, S_ISDIR(st->st_mode));
    } else if (rc < 0 && (saved_errno == ENOENT || saved_errno == ENOTDIR)) {
        trace_failed_path(dirfd, path);
    }

    errno = saved_errno;
}

#if DLFREEZE_HAVE_GLIBC_STAT_ALIASES
static void trace_stat64_result(int rc, int dirfd, const char *path,
                                const struct stat64 *st)
{
    int saved_errno = errno;

    if (rc == 0 && st && (S_ISREG(st->st_mode) || S_ISDIR(st->st_mode))) {
        trace_path_kind(dirfd, path, S_ISDIR(st->st_mode));
    } else if (rc < 0 && (saved_errno == ENOENT || saved_errno == ENOTDIR)) {
        trace_failed_path(dirfd, path);
    }

    errno = saved_errno;
}
#endif

static void trace_access_result(int rc, int dirfd, const char *path, int flags)
{
    int saved_errno = errno;

    if (rc == 0 && real_fstatat) {
        struct stat st;

        g_trace_depth++;
        if (real_fstatat(dirfd, path, &st, flags) == 0 &&
            (S_ISREG(st.st_mode) || S_ISDIR(st.st_mode))) {
            g_trace_depth--;
            trace_path_kind(dirfd, path, S_ISDIR(st.st_mode));
        } else {
            g_trace_depth--;
        }
    } else if (rc < 0 && (saved_errno == ENOENT || saved_errno == ENOTDIR)) {
        trace_failed_path(dirfd, path);
    }

    errno = saved_errno;
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

    if (h && filename && (g_dlopen_trace_fd >= 0 || g_file_trace_fd >= 0)) {
        struct link_map *lm = NULL;

        if (dlinfo(h, RTLD_DI_LINKMAP, &lm) == 0 &&
            lm && lm->l_name && lm->l_name[0]) {
            char resolved[PATH_MAX];

            snprintf(resolved, sizeof(resolved), "%s", lm->l_name);
            canonicalize_path(resolved, sizeof(resolved));
            if (g_dlopen_trace_fd >= 0)
                write_trace_line(g_dlopen_trace_fd, "", resolved);
            /* Also record in the file trace.  Some libcs open dlopen()
             * targets internally and bypass the interposed open() family,
             * so the successful link-map path is the authoritative record. */
            if (g_file_trace_fd >= 0 && resolved[0] == '/')
                write_trace_line(g_file_trace_fd, "F ", resolved);
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
    if (fd < 0 && is_absolute_path(path))
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
    if (fd < 0 && is_absolute_path(path))
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

int stat(const char *path, struct stat *buf)
{
    int rc;

    resolve_symbols();
    if (!real_stat) {
        errno = ENOSYS;
        return -1;
    }

    rc = real_stat(path, buf);
    trace_stat_result(rc, AT_FDCWD, path, buf);
    return rc;
}

#if DLFREEZE_HAVE_GLIBC_STAT_ALIASES
int stat64(const char *path, struct stat64 *buf)
{
    int rc;

    resolve_symbols();
    if (!real_stat64) {
        errno = ENOSYS;
        return -1;
    }

    rc = real_stat64(path, buf);
    trace_stat64_result(rc, AT_FDCWD, path, buf);
    return rc;
}
#endif

int lstat(const char *path, struct stat *buf)
{
    int rc;

    resolve_symbols();
    if (!real_lstat) {
        errno = ENOSYS;
        return -1;
    }

    rc = real_lstat(path, buf);
    trace_stat_result(rc, AT_FDCWD, path, buf);
    return rc;
}

#if DLFREEZE_HAVE_GLIBC_STAT_ALIASES
int lstat64(const char *path, struct stat64 *buf)
{
    int rc;

    resolve_symbols();
    if (!real_lstat64) {
        errno = ENOSYS;
        return -1;
    }

    rc = real_lstat64(path, buf);
    trace_stat64_result(rc, AT_FDCWD, path, buf);
    return rc;
}
#endif

int fstatat(int dirfd, const char *path, struct stat *buf, int flags)
{
    int rc;

    resolve_symbols();
    if (!real_fstatat) {
        errno = ENOSYS;
        return -1;
    }

    rc = real_fstatat(dirfd, path, buf, flags);
    trace_stat_result(rc, dirfd, path, buf);
    return rc;
}

#if DLFREEZE_HAVE_GLIBC_STAT_ALIASES
int fstatat64(int dirfd, const char *path, struct stat64 *buf, int flags)
{
    int rc;

    resolve_symbols();
    if (!real_fstatat64) {
        errno = ENOSYS;
        return -1;
    }

    rc = real_fstatat64(dirfd, path, buf, flags);
    trace_stat64_result(rc, dirfd, path, buf);
    return rc;
}

int __xstat(int version, const char *path, struct stat *buf)
{
    int rc;

    resolve_symbols();
    if (!real_xstat) {
        errno = ENOSYS;
        return -1;
    }

    rc = real_xstat(version, path, buf);
    trace_stat_result(rc, AT_FDCWD, path, buf);
    return rc;
}

int __xstat64(int version, const char *path, struct stat64 *buf)
{
    int rc;

    resolve_symbols();
    if (!real_xstat64) {
        errno = ENOSYS;
        return -1;
    }

    rc = real_xstat64(version, path, buf);
    trace_stat64_result(rc, AT_FDCWD, path, buf);
    return rc;
}

int __lxstat(int version, const char *path, struct stat *buf)
{
    int rc;

    resolve_symbols();
    if (!real_lxstat) {
        errno = ENOSYS;
        return -1;
    }

    rc = real_lxstat(version, path, buf);
    trace_stat_result(rc, AT_FDCWD, path, buf);
    return rc;
}

int __lxstat64(int version, const char *path, struct stat64 *buf)
{
    int rc;

    resolve_symbols();
    if (!real_lxstat64) {
        errno = ENOSYS;
        return -1;
    }

    rc = real_lxstat64(version, path, buf);
    trace_stat64_result(rc, AT_FDCWD, path, buf);
    return rc;
}

int __fxstatat(int version, int dirfd, const char *path,
               struct stat *buf, int flags)
{
    int rc;

    resolve_symbols();
    if (!real_fxstatat) {
        errno = ENOSYS;
        return -1;
    }

    rc = real_fxstatat(version, dirfd, path, buf, flags);
    trace_stat_result(rc, dirfd, path, buf);
    return rc;
}

int __fxstatat64(int version, int dirfd, const char *path,
                 struct stat64 *buf, int flags)
{
    int rc;

    resolve_symbols();
    if (!real_fxstatat64) {
        errno = ENOSYS;
        return -1;
    }

    rc = real_fxstatat64(version, dirfd, path, buf, flags);
    trace_stat64_result(rc, dirfd, path, buf);
    return rc;
}
#endif

int access(const char *path, int mode)
{
    int rc;

    resolve_symbols();
    if (!real_access) {
        errno = ENOSYS;
        return -1;
    }

    rc = real_access(path, mode);
    trace_access_result(rc, AT_FDCWD, path, 0);
    return rc;
}

int faccessat(int dirfd, const char *path, int mode, int flags)
{
    int rc;

    resolve_symbols();
    if (!real_faccessat) {
        errno = ENOSYS;
        return -1;
    }

    rc = real_faccessat(dirfd, path, mode, flags);
    trace_access_result(rc, dirfd, path,
                        (flags & AT_SYMLINK_NOFOLLOW) ? AT_SYMLINK_NOFOLLOW : 0);
    return rc;
}
