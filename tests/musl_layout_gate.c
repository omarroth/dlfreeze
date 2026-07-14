#include "common.h"
#include "musl_layout.h"

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

static int range_fits(size_t offset, size_t length, size_t size)
{
    return offset <= size && length <= size - offset;
}

static int patch_version_identity(uint8_t *elf, size_t elf_size)
{
    const struct dlfrz_musl_layout *layout;
    uint16_t machine;
    char version[8];
    int length;

    if (elf_size < EI_NIDENT || memcmp(elf, ELFMAG, SELFMAG) != 0 ||
        elf[EI_CLASS] != ELFCLASS64 || elf[EI_DATA] != ELFDATA2LSB)
        return -1;
    if (elf_size < sizeof(Elf64_Ehdr))
        return -1;
    machine = ((const Elf64_Ehdr *)elf)->e_machine;
    layout = dlfrz_musl_layout_lookup(machine, elf, elf_size);
    if (!layout)
        return -1;

    length = snprintf(version, sizeof(version), "%u.%u.%u",
                      layout->major, layout->minor, layout->patch);
    if (length <= 0 || (size_t)length + 1 > sizeof(version) ||
        (size_t)length + 1 > elf_size)
        return -1;
    for (size_t i = 0; i <= elf_size - ((size_t)length + 1); i++) {
        if (memcmp(elf + i, version, (size_t)length + 1) != 0)
            continue;
        /* Preserve the byte count so the copied loader remains runnable,
         * while changing its exact release identity to an unknown one. */
        elf[i] = elf[i] == '9' ? '8' : '9';
        return 0;
    }
    return -1;
}

static int patch_frozen_interp(uint8_t *map, size_t size)
{
    struct dlfrz_footer *footer;
    struct dlfrz_entry *entries;
    size_t entries_size;

    if (size < sizeof(struct dlfrz_footer))
        return -1;
    footer = (struct dlfrz_footer *)(map + size - sizeof(*footer));
    if (memcmp(footer->magic, DLFRZ_MAGIC, sizeof(footer->magic)) != 0 ||
        footer->version != DLFRZ_VERSION)
        return -1;
    entries_size = (size_t)footer->num_entries * sizeof(struct dlfrz_entry);
    if (!range_fits((size_t)footer->manifest_offset, entries_size, size))
        return -1;
    entries = (struct dlfrz_entry *)(map + footer->manifest_offset);

    for (uint32_t i = 0; i < footer->num_entries; i++) {
        if (!(entries[i].flags & DLFRZ_FLAG_INTERP) ||
            !range_fits((size_t)entries[i].data_offset,
                        (size_t)entries[i].data_size, size))
            continue;
        return patch_version_identity(map + entries[i].data_offset,
                                      (size_t)entries[i].data_size);
    }
    return -1;
}

static int patch_file(const char *path, int frozen)
{
    struct stat st;
    uint8_t *map;
    int fd;
    int rc;

    fd = open(path, O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        perror(path);
        return 1;
    }
    if (fstat(fd, &st) < 0 || st.st_size <= 0) {
        perror("fstat");
        close(fd);
        return 1;
    }
    map = mmap(NULL, (size_t)st.st_size, PROT_READ | PROT_WRITE,
               MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) {
        perror("mmap");
        close(fd);
        return 1;
    }
    rc = frozen ? patch_frozen_interp(map, (size_t)st.st_size)
                : patch_version_identity(map, (size_t)st.st_size);
    if (rc == 0 && msync(map, (size_t)st.st_size, MS_SYNC) < 0) {
        perror("msync");
        rc = -1;
    }
    munmap(map, (size_t)st.st_size);
    close(fd);
    if (rc != 0)
        fprintf(stderr, "%s: could not patch musl release identity\n", path);
    return rc != 0;
}

static int profile_matches(uint16_t machine, const char *image,
                           size_t image_size,
                           unsigned int patch, size_t pthread_size,
                           size_t tid_offset)
{
    const struct dlfrz_musl_layout *layout = dlfrz_musl_layout_lookup(
        machine, (const uint8_t *)image, image_size);

    return layout && layout->major == 1 && layout->minor == 2 &&
           layout->patch == patch && layout->pthread_size == pthread_size &&
           layout->thread_tid == tid_offset;
}

static int selftest(void)
{
    static const char x86_119[] =
        "musl libc (x86_64)\0Version %s\0Dynamic Program Loader\0"
        "1.1.19\0";
    static const char x86_124[] =
        "musl libc (x86_64)\0Version %s\0Dynamic Program Loader\0"
        "1.1.24\0";
    static const char x86_122[] =
        "musl libc (x86_64)\0Version %s\0Dynamic Program Loader\0"
        "1.2.2\0";
    static const char x86_126[] =
        "musl libc (x86_64)\0Version %s\0Dynamic Program Loader\0"
        "1.2.6\0";
    static const char arm_123[] =
        "musl libc (aarch64)\0Version %s\0Dynamic Program Loader\0"
        "1.2.3\0";
    static const char arm_125[] =
        "musl libc (aarch64)\0Version %s\0Dynamic Program Loader\0"
        "1.2.5\0";
    static const char unknown[] =
        "musl libc (x86_64)\0Version %s\0Dynamic Program Loader\0"
        "1.2.99\0";
    static const char missing_banner[] =
        "musl libc (x86_64)\0Version %s\0not the loader banner\0"
        "1.2.6\0";
    static const char non_standalone[] =
        "musl libc (x86_64)\0Version %s\0Dynamic Program Loader\0"
        "1.2.6-downstream\0";
    static const char ambiguous[] =
        "musl libc (x86_64)\0Version %s\0Dynamic Program Loader\0"
        "1.2.5\0"
        "1.2.6\0";
    const struct dlfrz_musl_layout *layout;

    layout = dlfrz_musl_layout_lookup(
        EM_X86_64, (const uint8_t *)x86_119, sizeof(x86_119));
    if (!layout || layout->patch != 19 || layout->pthread_size != 280 ||
        layout->thread_tid != 56 || layout->thread_errno != 68 ||
        layout->libc_flag_width != 4)
        return 1;
    layout = dlfrz_musl_layout_lookup(
        EM_X86_64, (const uint8_t *)x86_124, sizeof(x86_124));
    if (!layout || layout->patch != 24 || layout->pthread_size != 224 ||
        layout->thread_errno != 60 || layout->detach_initial != 2)
        return 1;
    if (!profile_matches(EM_X86_64, x86_122, sizeof(x86_122), 2, 200, 48) ||
        !profile_matches(EM_X86_64, x86_126, sizeof(x86_126), 6, 200, 48) ||
        !profile_matches(EM_AARCH64, arm_123, sizeof(arm_123), 3, 200, 32) ||
        !profile_matches(EM_AARCH64, arm_125, sizeof(arm_125), 5, 200, 32) ||
        dlfrz_musl_layout_lookup(EM_X86_64,
                                 (const uint8_t *)unknown,
                                 sizeof(unknown)) ||
        dlfrz_musl_layout_lookup(EM_X86_64,
                                 (const uint8_t *)missing_banner,
                                 sizeof(missing_banner)) ||
        dlfrz_musl_layout_lookup(EM_X86_64,
                                 (const uint8_t *)non_standalone,
                                 sizeof(non_standalone)) ||
        dlfrz_musl_layout_lookup(EM_X86_64,
                                 (const uint8_t *)ambiguous,
                                 sizeof(ambiguous)) ||
        dlfrz_musl_layout_lookup(EM_386,
                                 (const uint8_t *)x86_126,
                                 sizeof(x86_126)))
        return 1;
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "--selftest") == 0)
        return selftest();
    if (argc == 3 && strcmp(argv[1], "--elf") == 0)
        return patch_file(argv[2], 0);
    if (argc == 3 && strcmp(argv[1], "--frozen") == 0)
        return patch_file(argv[2], 1);
    fprintf(stderr, "usage: %s --selftest | --elf FILE | --frozen FILE\n",
            argv[0]);
    return 2;
}
