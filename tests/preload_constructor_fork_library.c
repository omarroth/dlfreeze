#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <sys/types.h>
#include <unistd.h>

static pid_t constructor_child_pid = -1;
static int constructor_is_child;

__attribute__((constructor)) static void fork_from_constructor(void)
{
    constructor_child_pid = fork();
    if (constructor_child_pid == 0)
        constructor_is_child = 1;
}

pid_t preload_constructor_child_pid(void)
{
    return constructor_child_pid;
}

int preload_constructor_is_child(void)
{
    return constructor_is_child;
}
