#include <errno.h>
#include <unistd.h>

extern int dlfrz_runtime_truncate_ready_fd;
extern int dlfrz_runtime_truncate_release_fd;

static int transfer_byte(int fd, char *byte, int writing)
{
    ssize_t result;

    do {
        result = writing ? write(fd, byte, 1) : read(fd, byte, 1);
    } while (result < 0 && errno == EINTR);
    return result == 1 ? 0 : -1;
}

__attribute__((constructor))
static void runtime_truncate_constructor(void)
{
    char byte = 'R';

    if (dlfrz_runtime_truncate_ready_fd < 0 ||
        dlfrz_runtime_truncate_release_fd < 0 ||
        transfer_byte(dlfrz_runtime_truncate_ready_fd, &byte, 1) < 0 ||
        transfer_byte(dlfrz_runtime_truncate_release_fd, &byte, 0) < 0)
        _exit(101);
}

int dlfrz_runtime_truncate_value(void)
{
    return 73;
}
