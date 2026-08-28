#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

/* Keep the private compatibility hooks internal in production while testing
 * that their unsupported paths neither touch an opaque target record nor run
 * a callback outside glibc's real exception region.  Dead-section elimination
 * discards the rest of the direct loader from this small helper. */
#include "../src/loader.c"

enum exception_entry {
    EXCEPTION_CREATE,
    EXCEPTION_CREATE_FORMAT,
    EXCEPTION_FREE,
    SIGNAL_EXCEPTION,
    CATCH_EXCEPTION,
    EXCEPTION_ENTRY_COUNT
};

static void must_not_operate(void *argument)
{
    (void)argument;
    _exit(86);
}

static int wait_for_fail_closed(pid_t child)
{
    int status;

    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR)
            return 0;
    }
    return WIFEXITED(status) && WEXITSTATUS(status) == 127;
}

static int run_entry(enum exception_entry entry, void *opaque)
{
    pid_t child = fork();

    if (child < 0)
        return 0;
    if (child == 0) {
        (void)close(STDERR_FILENO);
        switch (entry) {
        case EXCEPTION_CREATE:
            stub_dl_exception_create(opaque, "object", "error");
        case EXCEPTION_CREATE_FORMAT:
            stub_dl_exception_create_format(
                opaque, "object", "error %s", "detail");
        case EXCEPTION_FREE:
            stub_dl_exception_free(opaque);
        case SIGNAL_EXCEPTION:
            stub_dl_signal_exception(1, opaque, NULL);
        case CATCH_EXCEPTION:
            stub_dl_catch_exception(opaque, must_not_operate, opaque);
        case EXCEPTION_ENTRY_COUNT:
            break;
        }
        _exit(99);
    }
    return wait_for_fail_closed(child);
}

int main(void)
{
    long page_size = sysconf(_SC_PAGESIZE);
    void *opaque;
    int ok = 1;

    if (page_size <= 0)
        return 1;
    opaque = mmap(NULL, (size_t)page_size, PROT_NONE,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (opaque == MAP_FAILED)
        return 1;

    for (int entry = 0; entry < EXCEPTION_ENTRY_COUNT; entry++) {
        if (!run_entry((enum exception_entry)entry, opaque)) {
            fprintf(stderr, "private exception entry %d did not fail closed\n",
                    entry);
            ok = 0;
        }
    }
    if (munmap(opaque, (size_t)page_size) < 0)
        ok = 0;
    return ok ? 0 : 1;
}
