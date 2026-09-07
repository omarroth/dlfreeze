#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    char byte;
    int dirfd;
    int fd;

    if (argc != 2)
        return 2;
    dirfd = open(argv[1], O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dirfd < 0)
        return 3;
    fd = openat(dirfd, "input.txt", O_RDONLY | O_CLOEXEC);
    if (fd < 0 || read(fd, &byte, 1) != 1 || byte != 'B')
        return 4;
    if (close(fd) != 0 || close(dirfd) != 0)
        return 5;
    puts("dirfd-replacement-ok");
    return 0;
}
