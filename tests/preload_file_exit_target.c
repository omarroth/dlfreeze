#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

static int find_file_trace_fd(void)
{
    const char *identity = getenv("DLFREEZE_FILE_TRACE_IDENTITY");
    unsigned long long device, inode, type, rdevice;
    struct stat status;
    char extra;

    if (!identity ||
        sscanf(identity, "%16llx:%16llx:%16llx:%16llx%c",
               &device, &inode, &type, &rdevice, &extra) != 4)
        return -1;
    for (int fd = 3; fd < 1024; fd++) {
        if (fstat(fd, &status) == 0 &&
            (unsigned long long)status.st_dev == device &&
            (unsigned long long)status.st_ino == inode &&
            (unsigned long long)(status.st_mode & S_IFMT) == type &&
            (unsigned long long)status.st_rdev == rdevice)
            return fd;
    }
    return -1;
}

static int write_operation_record(int fd, char kind,
                                  unsigned long long attempt)
{
    char record[64];
    int length;

    length = snprintf(record, sizeof(record), "%c %016llx %016llx\n",
                      kind, (unsigned long long)getpid(), attempt);
    return length == 36 &&
        syscall(SYS_write, fd, record, (size_t)length) == (ssize_t)length;
}

static int inject_operation_record(const char *mode)
{
    static const unsigned long long attempt = 0xfedcba9876543210ULL;
    int fd = find_file_trace_fd();

    if (fd < 0)
        return 0;
    if (strcmp(mode, "orphan-w") == 0)
        return write_operation_record(fd, 'W', attempt);
    if (strcmp(mode, "duplicate-v") == 0)
        return write_operation_record(fd, 'V', attempt) &&
            write_operation_record(fd, 'V', attempt);
    if (strcmp(mode, "mismatched-v-k") == 0)
        return write_operation_record(fd, 'V', attempt) &&
            write_operation_record(fd, 'K', attempt);
    if (strcmp(mode, "dangling-v") == 0)
        return write_operation_record(fd, 'V', attempt);
    return 0;
}

int main(int argc, char **argv)
{
    int fd;

    if (argc != 2 && argc != 3)
        return 2;
    fd = open(argv[1], O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return 3;
    if (close(fd) != 0)
        return 5;
    if (argc == 3)
        return inject_operation_record(argv[2]) ? 0 : 6;
    return 4;
}
