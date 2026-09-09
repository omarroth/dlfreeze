#define _GNU_SOURCE

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

/* Keep the fixture buildable in minimal musl sysroots without Linux UAPI
 * headers.  These constants and structures are stable classic-BPF/seccomp
 * ABI, and the production implementation does not depend on them. */
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
#define FILTER_LOAD_ARGUMENT   0x20
#define FILTER_ALU_AND         0x54
#define FILTER_JUMP_EQUAL      0x15
#define FILTER_RETURN          0x06
#define SECCOMP_FILTER_MODE    2
#define SECCOMP_ALLOW          0x7fff0000U
#define SECCOMP_ERRNO          0x00050000U
#define SECCOMP_NR_OFFSET      0
#define SECCOMP_ARG_OFFSET(n_) (16 + 8 * (n_))

enum fallback_filter {
    FILTER_MEMFD_ENOSYS,
    FILTER_PROC_REOPEN_DENIED,
};

struct worker_args {
    const char *data_path;
    int failed;
};

static int install_filter(enum fallback_filter kind)
{
    struct syscall_filter memfd_filter[] = {
        FILTER_STMT(FILTER_LOAD_SYSCALL_NR, SECCOMP_NR_OFFSET),
        FILTER_JUMP(FILTER_JUMP_EQUAL, SYS_memfd_create, 0, 1),
        FILTER_STMT(FILTER_RETURN, SECCOMP_ERRNO | ENOSYS),
        FILTER_STMT(FILTER_RETURN, SECCOMP_ALLOW),
    };
    struct syscall_filter proc_filter[] = {
        FILTER_STMT(FILTER_LOAD_SYSCALL_NR, SECCOMP_NR_OFFSET),
        FILTER_JUMP(FILTER_JUMP_EQUAL, SYS_openat, 0, 6),
        FILTER_STMT(FILTER_LOAD_ARGUMENT, SECCOMP_ARG_OFFSET(0)),
        FILTER_JUMP(FILTER_JUMP_EQUAL, (uint32_t)AT_FDCWD, 0, 4),
        FILTER_STMT(FILTER_LOAD_ARGUMENT, SECCOMP_ARG_OFFSET(2)),
        FILTER_STMT(FILTER_ALU_AND, O_DIRECTORY),
        FILTER_JUMP(FILTER_JUMP_EQUAL, 0, 0, 1),
        FILTER_STMT(FILTER_RETURN, SECCOMP_ERRNO | EACCES),
        FILTER_STMT(FILTER_RETURN, SECCOMP_ALLOW),
    };
    struct syscall_filter_program program;

    if (kind == FILTER_MEMFD_ENOSYS) {
        program.len = (unsigned short)(sizeof(memfd_filter) /
                                       sizeof(memfd_filter[0]));
        program.filter = memfd_filter;
    } else {
        program.len = (unsigned short)(sizeof(proc_filter) /
                                       sizeof(proc_filter[0]));
        program.filter = proc_filter;
    }
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
        return -1;
    return prctl(PR_SET_SECCOMP, SECCOMP_FILTER_MODE, &program);
}

static int count_backing_names(const char *directory)
{
    static const char prefix[] = ".dlfreeze-";
    DIR *stream = opendir(directory);
    struct dirent *entry;
    int count = 0;

    if (!stream)
        return -1;
    errno = 0;
    while ((entry = readdir(stream)) != NULL) {
        if (strncmp(entry->d_name, prefix, sizeof(prefix) - 1) == 0)
            count++;
    }
    if (errno != 0 || closedir(stream) != 0)
        return -1;
    return count;
}

static int check_data_descriptor(const char *path)
{
    static const char expected[] = "captured-fallback-data\n";
    struct stat status;
    unsigned char *mapping = MAP_FAILED;
    char bytes[sizeof(expected)] = {0};
    FILE *stream = NULL;
    int duplicate = -1;
    int fd = -1;
    int result = 0;

    fd = open(path, O_RDONLY | O_CLOEXEC | O_APPEND | O_NONBLOCK);
    if (fd < 0 || fcntl(fd, F_GETFL) < 0 ||
        (fcntl(fd, F_GETFL) & (O_ACCMODE | O_APPEND | O_NONBLOCK)) !=
            (O_RDONLY | O_APPEND | O_NONBLOCK) ||
        (fcntl(fd, F_GETFD) & FD_CLOEXEC) == 0 ||
        fstat(fd, &status) < 0 || !S_ISREG(status.st_mode) ||
        (status.st_mode & 0777) != 0444 ||
        status.st_size != (off_t)(sizeof(expected) - 1) ||
        read(fd, bytes, 1) != 1 || bytes[0] != expected[0] ||
        lseek(fd, 0, SEEK_SET) != 0 ||
        pread(fd, bytes, sizeof(expected) - 1, 0) !=
            (ssize_t)(sizeof(expected) - 1) ||
        memcmp(bytes, expected, sizeof(expected) - 1) != 0 ||
        lseek(fd, 0, SEEK_CUR) != 0)
        goto out;
    errno = 0;
    if (write(fd, "x", 1) >= 0 || errno != EBADF)
        goto out;
    mapping = mmap(NULL, sizeof(expected) - 1, PROT_READ,
                   MAP_PRIVATE, fd, 0);
    if (mapping == MAP_FAILED ||
        memcmp(mapping, expected, sizeof(expected) - 1) != 0)
        goto out;
    duplicate = dup(fd);
    if (duplicate < 0 || (fcntl(duplicate, F_GETFD) & FD_CLOEXEC) != 0 ||
        (fcntl(duplicate, F_GETFL) & (O_ACCMODE | O_APPEND | O_NONBLOCK)) !=
            (O_RDONLY | O_APPEND | O_NONBLOCK))
        goto out;

    stream = fopen(path, "re");
    if (!stream || (fcntl(fileno(stream), F_GETFD) & FD_CLOEXEC) == 0 ||
        fgetc(stream) != expected[0])
        goto out;
#ifdef O_PATH
    {
        int path_fd = open(path, O_PATH | O_CLOEXEC);

        if (path_fd < 0 || (fcntl(path_fd, F_GETFL) & O_PATH) != O_PATH ||
            (fcntl(path_fd, F_GETFD) & FD_CLOEXEC) == 0 ||
            fstat(path_fd, &status) < 0) {
            if (path_fd >= 0)
                close(path_fd);
            goto out;
        }
        errno = 0;
        if (read(path_fd, bytes, 1) >= 0 || errno != EBADF) {
            close(path_fd);
            goto out;
        }
        close(path_fd);
    }
#endif
    result = 1;

out:
    if (stream)
        fclose(stream);
    if (duplicate >= 0)
        close(duplicate);
    if (mapping != MAP_FAILED)
        munmap(mapping, sizeof(expected) - 1);
    if (fd >= 0)
        close(fd);
    return result;
}

static int check_elf_descriptor(const char *path)
{
    unsigned char magic[4];
    void *mapping = MAP_FAILED;
    struct stat status;
    int fd = -1;
    int result = 0;

    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0 || fstat(fd, &status) < 0 || !S_ISREG(status.st_mode) ||
        (status.st_mode & 0777) != 0555 ||
        read(fd, magic, sizeof(magic)) != (ssize_t)sizeof(magic) ||
        memcmp(magic, "\177ELF", sizeof(magic)) != 0)
        goto out;
    mapping = mmap(NULL, 1, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0);
    if (mapping == MAP_FAILED)
        goto out;
    result = 1;

out:
    if (mapping != MAP_FAILED)
        munmap(mapping, 1);
    if (fd >= 0)
        close(fd);
    return result;
}

static void *worker(void *opaque)
{
    struct worker_args *args = opaque;

    for (int iteration = 0; iteration < 16; iteration++) {
        if (!check_data_descriptor(args->data_path)) {
            __atomic_store_n(&args->failed, 1, __ATOMIC_RELAXED);
            break;
        }
    }
    return NULL;
}

static int exercise_fallback(enum fallback_filter kind,
                             const char *data_path, const char *elf_path,
                             const char *tmpdir)
{
    enum { WORKER_COUNT = 6 };
    pthread_t workers[WORKER_COUNT];
    struct worker_args args = {data_path, 0};
    int before;
    int after;

    before = count_backing_names(tmpdir);
    if (before < 0 || install_filter(kind) < 0)
        return 77;
    /* The loader must keep using the immutable startup snapshot, not a
     * target-libc environment buffer which the application can replace. */
    if (setenv("TMPDIR", "/dlfreeze-nonexistent-tmpdir", 1) < 0)
        return 10;
    if (!check_data_descriptor(data_path) ||
        !check_elf_descriptor(elf_path))
        return 11;
    for (size_t i = 0; i < WORKER_COUNT; i++) {
        if (pthread_create(&workers[i], NULL, worker, &args) != 0)
            return 12;
    }
    for (size_t i = 0; i < WORKER_COUNT; i++) {
        if (pthread_join(workers[i], NULL) != 0)
            return 13;
    }
    if (__atomic_load_n(&args.failed, __ATOMIC_RELAXED) != 0)
        return 14;
    after = count_backing_names(tmpdir);
    if (after < 0 || after != before)
        return 15;
    return 0;
}

static int run_fallback_child(enum fallback_filter kind,
                              const char *data_path, const char *elf_path,
                              const char *tmpdir)
{
    int status;
    pid_t child = fork();

    if (child < 0)
        return 90;
    if (child == 0)
        _exit(exercise_fallback(kind, data_path, elf_path, tmpdir));
    while (waitpid(child, &status, 0) < 0) {
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
    int memfd_status;
    int proc_status;

    if (argc != 5)
        return 2;
    fd = open(argv[1], O_RDONLY);
    if (fd < 0 || read(fd, &byte, 1) != 1 || close(fd) != 0)
        return 3;
    if (strcmp(argv[4], "trace") == 0) {
        puts("vfs-backing-fallback-trace-ok");
        return 0;
    }
    if (strcmp(argv[4], "frozen") != 0 ||
        !getenv("TMPDIR") || strcmp(getenv("TMPDIR"), argv[3]) != 0)
        return 4;

    memfd_status = run_fallback_child(
        FILTER_MEMFD_ENOSYS, argv[1], argv[2], argv[3]);
    proc_status = run_fallback_child(
        FILTER_PROC_REOPEN_DENIED, argv[1], argv[2], argv[3]);
    if (memfd_status == 77 || proc_status == 77) {
        puts("vfs-backing-fallback-ok:seccomp-unavailable");
        return 0;
    }
    if (memfd_status != 0 || proc_status != 0) {
        fprintf(stderr, "fallback status: memfd=%d proc=%d\n",
                memfd_status, proc_status);
        return 5;
    }
    puts("vfs-backing-fallback-ok:verified");
    return 0;
}
