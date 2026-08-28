#define _GNU_SOURCE
#include <fcntl.h>
#include <unistd.h>

__attribute__((noinline))
static int runtime_flags(int selector, int extra)
{
    return (selector ? O_RDONLY : O_WRONLY) | extra | O_CLOEXEC;
}

int main(int argc, char **argv)
{
    char byte;
    int directory;
    int fd;

    if (argc != 4)
        return 2;
    fd = open(argv[1], runtime_flags(argc, 0));
    if (fd < 0 || read(fd, &byte, 1) != 1 || close(fd) != 0)
        return 3;

    directory = open(argv[2], runtime_flags(argc, O_DIRECTORY));
    if (directory < 0)
        return 4;
    fd = openat(directory, argv[3], runtime_flags(argc, 0));
    if (fd < 0 || read(fd, &byte, 1) != 1 || close(fd) != 0)
        return 5;
    return close(directory) != 0;
}
