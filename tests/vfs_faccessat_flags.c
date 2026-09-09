#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef SYS_faccessat2
#if defined(__x86_64__) || defined(__aarch64__)
#define SYS_faccessat2 439
#endif
#endif

/* Keep this regression buildable with minimal musl sysroots that do not ship
 * Linux UAPI headers.  These are stable seccomp/classic-BPF ABI values. */
struct syscall_filter {
    uint16_t code;
    uint8_t jt;
    uint8_t jf;
    uint32_t k;
};

struct syscall_filter_program {
    unsigned short len;
    struct syscall_filter *filter;
};

#define FILTER_STMT(code_, k_) \
    { (uint16_t)(code_), 0, 0, (uint32_t)(k_) }
#define FILTER_JUMP(code_, k_, jt_, jf_) \
    { (uint16_t)(code_), (uint8_t)(jt_), (uint8_t)(jf_), (uint32_t)(k_) }
#define FILTER_LOAD_SYSCALL_NR 0x20
#define FILTER_JUMP_EQUAL      0x15
#define FILTER_RETURN          0x06
#define SECCOMP_FILTER_MODE    2
#define SECCOMP_ALLOW          0x7fff0000U
#define SECCOMP_ERRNO          0x00050000U

static int install_dispatch_filter(void)
{
    struct syscall_filter filter[] = {
        FILTER_STMT(FILTER_LOAD_SYSCALL_NR, 0),
        FILTER_JUMP(FILTER_JUMP_EQUAL, SYS_faccessat, 0, 1),
        FILTER_STMT(FILTER_RETURN, SECCOMP_ERRNO | EIO),
        FILTER_JUMP(FILTER_JUMP_EQUAL, SYS_faccessat2, 0, 1),
        FILTER_STMT(FILTER_RETURN, SECCOMP_ERRNO | EBUSY),
        FILTER_STMT(FILTER_RETURN, SECCOMP_ALLOW),
    };
    struct syscall_filter_program program = {
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
        return -1;
    return prctl(PR_SET_SECCOMP, SECCOMP_FILTER_MODE, &program);
}

static int install_enosys_filter(void)
{
    struct syscall_filter filter[] = {
        FILTER_STMT(FILTER_LOAD_SYSCALL_NR, 0),
        FILTER_JUMP(FILTER_JUMP_EQUAL, SYS_faccessat2, 0, 1),
        FILTER_STMT(FILTER_RETURN, SECCOMP_ERRNO | ENOSYS),
        FILTER_STMT(FILTER_RETURN, SECCOMP_ALLOW),
    };
    struct syscall_filter_program program = {
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
        return -1;
    return prctl(PR_SET_SECCOMP, SECCOMP_FILTER_MODE, &program);
}

static int check_dispatch(const char *regular, const char *dangling)
{
    if (install_dispatch_filter() < 0)
        return 77;

    errno = 0;
    if (faccessat(AT_FDCWD, regular, F_OK, 0) != -1 || errno != EIO)
        return 10;
    errno = 0;
    if (faccessat(AT_FDCWD, regular, R_OK, AT_EACCESS) != -1 ||
        errno != EBUSY)
        return 11;
    errno = 0;
    if (faccessat(AT_FDCWD, dangling, F_OK, AT_SYMLINK_NOFOLLOW) != -1 ||
        errno != EBUSY)
        return 12;
    return 0;
}

static int check_enosys(const char *regular, const char *dangling)
{
    if (install_enosys_filter() < 0)
        return 77;

    /* faccessat2 being absent must not disable the exact legacy case. */
    if (faccessat(AT_FDCWD, regular, F_OK, 0) != 0)
        return 20;

    /* On ENOSYS the interposer must delegate to the admitted target libc,
     * whose compatibility path preserves both effective-ID and nofollow
     * semantics on the supported glibc and musl runtimes. */
    if (faccessat(AT_FDCWD, regular, R_OK, AT_EACCESS) != 0)
        return 21;
    if (faccessat(AT_FDCWD, dangling, F_OK, AT_SYMLINK_NOFOLLOW) != 0)
        return 22;
    return 0;
}

static int run_child(int (*check)(const char *, const char *),
                     const char *regular, const char *dangling)
{
    int status;
    pid_t pid = fork();

    if (pid < 0)
        return 90;
    if (pid == 0)
        _exit(check(regular, dangling));
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR)
            return 91;
    }
    if (!WIFEXITED(status))
        return 92;
    return WEXITSTATUS(status);
}

int main(int argc, char **argv)
{
    char byte;
    int fd;
    int dispatch_status;
    int enosys_status;
    int kernel_has_faccessat2 = 1;

    if (argc != 5)
        return 2;

    fd = open(argv[1], O_RDONLY);
    if (fd < 0 || read(fd, &byte, 1) != 1)
        return 3;
    close(fd);

    if (strcmp(argv[4], "trace") == 0) {
        puts("vfs-faccessat-trace-ok");
        return 0;
    }
    if (strcmp(argv[4], "frozen") != 0)
        return 4;

    /* Captured regular files implement the same accepted flag set without
     * consulting a same-named host path. */
    if (faccessat(AT_FDCWD, argv[1], R_OK, 0) != 0 ||
        faccessat(AT_FDCWD, argv[1], R_OK, AT_EACCESS) != 0 ||
        faccessat(AT_FDCWD, argv[1], F_OK, AT_SYMLINK_NOFOLLOW) != 0)
        return 5;
    errno = 0;
    if (faccessat(AT_FDCWD, argv[1], F_OK, 0x40000000) != -1 ||
        errno != EINVAL)
        return 6;

    /* The legacy syscall follows a dangling link.  faccessat2 with
     * AT_SYMLINK_NOFOLLOW checks the link itself. */
    if (faccessat(AT_FDCWD, argv[2], F_OK, 0) != 0)
        return 7;
    errno = 0;
    if (faccessat(AT_FDCWD, argv[3], F_OK, 0) != -1 || errno != ENOENT)
        return 8;

    errno = 0;
    if (faccessat(AT_FDCWD, argv[2], R_OK, AT_EACCESS) != 0) {
        if (errno != EOPNOTSUPP)
            return 9;
        kernel_has_faccessat2 = 0;
    }
    errno = 0;
    if (faccessat(AT_FDCWD, argv[3], F_OK, AT_SYMLINK_NOFOLLOW) != 0) {
        if (errno != EOPNOTSUPP || kernel_has_faccessat2)
            return 13;
    } else if (!kernel_has_faccessat2) {
        return 14;
    }

    dispatch_status = run_child(check_dispatch, argv[2], argv[3]);
    enosys_status = run_child(check_enosys, argv[2], argv[3]);
    if (dispatch_status != 0 && dispatch_status != 77)
        return dispatch_status;
    if (enosys_status != 0 && enosys_status != 77)
        return enosys_status;
    if ((dispatch_status == 77) != (enosys_status == 77))
        return 15;

    printf("vfs-faccessat-ok:kernel=%s,seccomp=%s\n",
           kernel_has_faccessat2 ? "faccessat2" : "unsupported",
           dispatch_status == 0 ? "verified" : "unavailable");
    return 0;
}
