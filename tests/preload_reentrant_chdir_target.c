#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    char cwd[PATH_MAX];
    char byte;
    int fd;

    if (argc != 3)
        return 2;
    if (chdir(argv[1]) != 0 || !getcwd(cwd, sizeof(cwd)) ||
        strcmp(cwd, argv[1]) != 0)
        return 3;
    fd = open(argv[2], O_RDONLY | O_CLOEXEC);
    if (fd < 0 || read(fd, &byte, 1) != 1)
        return 4;
    if (close(fd) != 0)
        return 5;
    puts("reentrant-chdir-ok");
    return 0;
}
