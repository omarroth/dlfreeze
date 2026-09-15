#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

typedef int (*private_open_fn)(const char *, int, ...);

struct open_request {
    private_open_fn function;
    const char *path;
    int result;
};

static void *open_from_thread(void *opaque)
{
    struct open_request *request = opaque;
    char buffer[64];
    ssize_t count;
    int fd;

    request->result = 3;
    fd = request->function(request->path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return NULL;
    count = read(fd, buffer, sizeof(buffer) - 1);
    if (count < 0 || close(fd) < 0) {
        request->result = 4;
        return NULL;
    }
    buffer[count] = '\0';
    request->result = strcmp(buffer, "private-open-snapshot\n") == 0
        ? 0 : 5;
    return NULL;
}

int main(int argc, char **argv)
{
    private_open_fn private_open;
    struct open_request request;
    pthread_t thread;

    if (argc != 2)
        return 2;
    private_open = (private_open_fn)dlvsym(
        RTLD_DEFAULT, "__open64_nocancel", "GLIBC_PRIVATE");
    if (!private_open) {
        puts("glibc-private-open-unavailable");
        return 77;
    }
    request.function = private_open;
    request.path = argv[1];
    request.result = 6;
    if (pthread_create(&thread, NULL, open_from_thread, &request) != 0 ||
        pthread_join(thread, NULL) != 0)
        return 6;
    if (request.result != 0)
        return request.result;
    puts("vfs-glibc-private-open-ok");
    return 0;
}
