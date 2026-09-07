#define _GNU_SOURCE

#include <elf.h>
#include <fcntl.h>
#include <link.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/auxv.h>
#include <sys/wait.h>
#include <unistd.h>

struct main_query {
    uintptr_t address;
    const Elf64_Phdr *phdr;
    Elf64_Half phnum;
    int matches;
};

static int find_main(struct dl_phdr_info *info, size_t size, void *opaque)
{
    struct main_query *query = opaque;

    (void)size;
    for (Elf64_Half i = 0; i < info->dlpi_phnum; i++) {
        const Elf64_Phdr *ph = &info->dlpi_phdr[i];
        uintptr_t start;

        if (ph->p_type != PT_LOAD || ph->p_memsz == 0 ||
            ph->p_vaddr > UINTPTR_MAX - info->dlpi_addr)
            continue;
        start = info->dlpi_addr + ph->p_vaddr;
        if (query->address < start ||
            query->address - start >= ph->p_memsz)
            continue;
        query->matches++;
        query->phdr = info->dlpi_phdr;
        query->phnum = info->dlpi_phnum;
        break;
    }
    return 0;
}

static int header_view_is_read_only(const Elf64_Phdr *phdr)
{
    pid_t child = fork();
    int status;

    if (child < 0)
        return 0;
    if (child == 0) {
        int nullfd = open("/dev/null", O_WRONLY | O_CLOEXEC);
        volatile unsigned char *byte =
            (volatile unsigned char *)(uintptr_t)phdr;

        if (nullfd >= 0) {
            if (nullfd != STDERR_FILENO) {
                (void)dup2(nullfd, STDERR_FILENO);
                (void)close(nullfd);
            }
        }
        *byte = *byte;
        _exit(0);
    }
    return waitpid(child, &status, 0) == child && WIFSIGNALED(status) &&
           (WTERMSIG(status) == SIGSEGV || WTERMSIG(status) == SIGBUS);
}

int main(void)
{
    struct main_query query = { .address = (uintptr_t)&main };

    if (dl_iterate_phdr(find_main, &query) != 0 || query.matches != 1 ||
        !query.phdr || query.phnum == 0 ||
        (uintptr_t)query.phdr % _Alignof(Elf64_Phdr) != 0 ||
        getauxval(AT_PHDR) != (uintptr_t)query.phdr ||
        getauxval(AT_PHNUM) != query.phnum ||
        !header_view_is_read_only(query.phdr))
        return 1;
    puts("external-main-ok");
    return 0;
}
