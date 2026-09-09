#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <sys/sysmacros.h>
#include <sys/wait.h>

#define DLFREEZE_FILEBACK_GATE 1
#include "../src/loader.c"

enum gate_mutation {
    GATE_SOURCE_CLEAN,
    GATE_SOURCE_COW_FILE_BYTES,
    GATE_SOURCE_COW_PAGE_TAIL,
    GATE_SOURCE_COW_PARTIAL_PREFIX,
    GATE_SOURCE_COW_PARTIAL_BOUNDARY,
    GATE_STACK_EXECUTABLE,
    GATE_FILEBACK_MAP_FAILURE,
    GATE_FILEBACK_RESTORE_FAILURE,
};

static FILE *gate_temporary_file(void)
{
    const char *directory = getenv("TMPDIR");
    char path[PATH_MAX];
    int fd;
    FILE *file;

    if (!directory || directory[0] != '/')
        directory = "/tmp";
    if (snprintf(path, sizeof(path),
                 "%s/dlfreeze-loader-gate.XXXXXX", directory) >=
        (int)sizeof(path)) {
        errno = ENAMETOOLONG;
        return NULL;
    }
    fd = mkstemp(path);
    if (fd < 0)
        return NULL;
    if (unlink(path) < 0) {
        int saved_errno = errno;

        close(fd);
        errno = saved_errno;
        return NULL;
    }
    file = fdopen(fd, "w+b");
    if (!file) {
        int saved_errno = errno;

        close(fd);
        errno = saved_errno;
    }
    return file;
}

static void reset_fileback_counters(void)
{
    g_fileback_map_attempts = 0;
    g_fileback_map_accepts = 0;
    g_fileback_forced_map_errno = 0;
    g_fileback_forced_restore_errno = 0;
    g_mremap_attempts = 0;
    g_mremap_accepts = 0;
    g_mremap_forced_errno = 0;
    g_mremap_force_attempt = 0;
    g_executable_probe_forced_munmap_errno = 0;
    g_startup_mremap_disabled = 0;
}

static int gate_mapping_permissions(const void *address,
                                    char permissions[5])
{
    FILE *maps = fopen("/proc/self/maps", "r");
    char line[1024];
    uintptr_t needle = (uintptr_t)address;
    int found = 0;

    if (!maps)
        return 0;
    while (fgets(line, sizeof(line), maps)) {
        unsigned long long start;
        unsigned long long end;
        char parsed[5] = {0};

        if (sscanf(line, "%llx-%llx %4s", &start, &end, parsed) != 3)
            continue;
        if (needle < start || needle >= end)
            continue;
        memcpy(permissions, parsed, sizeof(parsed));
        found = 1;
        break;
    }
    fclose(maps);
    return found;
}

static int gate_mapping_file_identity(const void *address,
                                      const struct stat *expected,
                                      uint64_t expected_offset)
{
    FILE *maps = fopen("/proc/self/maps", "r");
    char line[1024];
    uintptr_t needle = (uintptr_t)address;
    int matched = 0;

    if (!maps || !expected)
        return 0;
    while (fgets(line, sizeof(line), maps)) {
        unsigned long long start;
        unsigned long long end;
        unsigned long long offset;
        unsigned long long inode;
        unsigned device_major;
        unsigned device_minor;
        char permissions[5];

        if (sscanf(line, "%llx-%llx %4s %llx %x:%x %llu",
                   &start, &end, permissions, &offset,
                   &device_major, &device_minor, &inode) != 7)
            continue;
        if (needle < start || needle >= end)
            continue;
        matched = offset == expected_offset &&
                  device_major == major(expected->st_dev) &&
                  device_minor == minor(expected->st_dev) &&
                  inode == (uint64_t)expected->st_ino;
        break;
    }
    fclose(maps);
    return matched;
}


static int gate_map_case(const char *label, enum gate_mutation mutation,
                         uint32_t source_flags, uint32_t flags,
                         int embedded_eof,
                         int expected_result,
                         size_t expected_attempts,
                         int expected_fileback,
                         const char *expected_permissions)
{
    long page_value = sysconf(_SC_PAGESIZE);
    size_t page;
    uint64_t payload_file_offset;
    size_t container_size;
    size_t segment_file_size;
    const size_t in_file_mutation = 512;
    size_t tail_mutation;
    FILE *container = NULL;
    unsigned char *container_map = MAP_FAILED;
    unsigned char *source = MAP_FAILED;
    unsigned char *reservation = MAP_FAILED;
    size_t reservation_size;
    struct dlfrz_entry entry = {0};
    struct dlfrz_lib_meta meta = {0};
    struct loaded_obj object = {0};
    Elf64_Ehdr *ehdr;
    Elf64_Phdr *phdr;
    char permissions[5] = {0};
    struct stat source_status;
    int map_result;
    int ok = 0;

    if (page_value <= 0 || (uint64_t)page_value > SIZE_MAX)
        return 0;
    page = (size_t)page_value;
    if ((page & (page - 1)) != 0)
        return 0;
    g_page_size = page;
    payload_file_offset = 2 * page;
    container_size = 4 * page;
    segment_file_size = page / 2;
    tail_mutation = 3 * page / 4;
    reservation_size = 5 * page;
    container = gate_temporary_file();
    if (!container || ftruncate(fileno(container), container_size) < 0)
        goto out;
    container_map = mmap(NULL, container_size, PROT_READ | PROT_WRITE,
                         MAP_SHARED, fileno(container), 0);
    if (container_map == MAP_FAILED)
        goto out;
    memset(container_map, 0, container_size);
    memset(container_map + payload_file_offset, 0x5a, page);
    ehdr = (Elf64_Ehdr *)(container_map + payload_file_offset);
    phdr = (Elf64_Phdr *)((unsigned char *)ehdr + sizeof(*ehdr));
    memset(ehdr, 0, sizeof(*ehdr));
    memcpy(ehdr->e_ident, ELFMAG, SELFMAG);
    ehdr->e_type = ET_DYN;
    ehdr->e_phoff = sizeof(*ehdr);
    ehdr->e_phnum = 2;
    ehdr->e_phentsize = sizeof(*phdr);
    memset(phdr, 0, 2 * sizeof(*phdr));
    phdr[0].p_type = PT_LOAD;
    phdr[0].p_flags = flags;
    phdr[0].p_offset = 0;
    phdr[0].p_vaddr = 0;
    phdr[0].p_filesz = segment_file_size;
    phdr[0].p_memsz = page;
    phdr[0].p_align = page;
    phdr[1].p_type = PT_GNU_STACK;
    phdr[1].p_flags = PF_R | PF_W;
    if (mutation == GATE_STACK_EXECUTABLE)
        phdr[1].p_flags |= PF_X;
    if (msync(container_map, container_size, MS_SYNC) < 0 ||
        munmap(container_map, container_size) < 0)
        goto out;
    container_map = MAP_FAILED;

    source = mmap(NULL, page, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE, fileno(container),
                  (off_t)payload_file_offset);
    if (source == MAP_FAILED)
        goto out;
    if (mutation == GATE_SOURCE_COW_FILE_BYTES)
        source[in_file_mutation] ^= 0xff;
    else if (mutation == GATE_SOURCE_COW_PAGE_TAIL)
        source[tail_mutation] ^= 0xff;

    reservation = mmap(NULL, reservation_size, PROT_NONE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (reservation == MAP_FAILED)
        goto out;

    entry.data_offset = payload_file_offset;
    entry.data_size = embedded_eof ? page / 2 : page;
    meta.base_addr = (uint64_t)(uintptr_t)reservation;
    meta.vaddr_lo = 0;
    meta.vaddr_hi = page;
    meta.phdr_num = 2;
    meta.phdr_entsz = sizeof(Elf64_Phdr);
    meta.flags = LDR_FLAG_SHLIB;
    object.runtime_reservation = reservation;
    object.runtime_reservation_size = reservation_size;
    if (flags & PF_R) {
        meta.phdr_off = sizeof(Elf64_Ehdr);
        meta.phdr_file_off = 0;
    } else {
        meta.phdr_off = DLFRZ_PHDR_EXTERNAL;
        meta.phdr_file_off = sizeof(Elf64_Ehdr);
    }

    reset_fileback_counters();
    if (mutation == GATE_FILEBACK_MAP_FAILURE)
        g_fileback_forced_map_errno = EIO;
    else if (mutation == GATE_FILEBACK_RESTORE_FAILURE) {
        g_fileback_forced_map_errno = EIO;
        g_fileback_forced_restore_errno = ENOMEM;
    }
    map_result = map_object(source, payload_file_offset, fileno(container),
                            source_flags,
                            &meta, &entry, &object, 1);
    if ((map_result == 0) != !!expected_result ||
        g_fileback_map_attempts != expected_attempts ||
        g_fileback_map_accepts != (size_t)expected_fileback) {
        fprintf(stderr,
                "%s: result=%d attempts=%zu accepts=%zu\n",
                label, map_result, g_fileback_map_attempts,
                g_fileback_map_accepts);
        goto out;
    }
    if (!expected_result) {
        ok = 1;
        goto out;
    }
    if (expected_permissions &&
        (!gate_mapping_permissions(reservation, permissions) ||
         memcmp(permissions, expected_permissions, 4) != 0)) {
        fprintf(stderr, "%s: permissions=%.4s expected=%.4s\n",
                label, permissions, expected_permissions);
        goto out;
    }
    if (fstat(fileno(container), &source_status) < 0)
        goto out;
    if (!!gate_mapping_file_identity(
            reservation, &source_status, payload_file_offset) !=
        !!expected_fileback) {
        fprintf(stderr, "%s: target provenance differs\n", label);
        goto out;
    }
    if (expected_permissions && expected_permissions[0] != 'r') {
        int final_prot = 0;

        if (flags & PF_R)
            final_prot |= PROT_READ;
        if (flags & PF_W)
            final_prot |= PROT_WRITE;
        if (flags & PF_X)
            final_prot |= PROT_EXEC;
        if (mprotect(reservation, page, PROT_READ) < 0 ||
            reservation[in_file_mutation] != source[in_file_mutation] ||
            reservation[tail_mutation] != 0 ||
            mprotect(reservation, page, final_prot) < 0) {
            fprintf(stderr, "%s: unreadable segment bytes/BSS differ\n",
                    label);
            goto out;
        }
    }
    if (expected_permissions && expected_permissions[0] == 'r') {
        if (reservation[in_file_mutation] != source[in_file_mutation]) {
            fprintf(stderr, "%s: authoritative file byte differs\n", label);
            goto out;
        }
        if (reservation[tail_mutation] != 0) {
            fprintf(stderr, "%s: zero-fill tail was not anonymous zero\n",
                    label);
            goto out;
        }
    }
    ok = 1;

out:
    if (object.runtime_phdr_mapping && object.runtime_phdr_mapping_size)
        (void)munmap(object.runtime_phdr_mapping,
                     object.runtime_phdr_mapping_size);
    if (reservation != MAP_FAILED)
        (void)munmap(reservation, reservation_size);
    if (source != MAP_FAILED)
        (void)munmap(source, page);
    if (container_map != MAP_FAILED)
        (void)munmap(container_map, container_size);
    if (container)
        fclose(container);
    return ok;
}

/* Exercise the common packed-ELF geometry in which the final PT_LOAD ends
 * inside the entry's last source page.  The complete prefix pages may retain
 * container provenance, but the boundary page must remain anonymous: mapping
 * that page from the container would expose bytes owned by the next entry. */
static int gate_partial_eof_case(const char *label,
                                 enum gate_mutation mutation,
                                 uint32_t source_flags, uint32_t flags,
                                 int nonzero_page_delta,
                                 int expected_fileback,
                                 const char *expected_permissions)
{
    long page_value = sysconf(_SC_PAGESIZE);
    size_t page;
    uint64_t payload_file_offset;
    size_t container_size;
    size_t entry_size;
    size_t segment_file_size;
    size_t segment_memory_size;
    size_t page_delta;
    size_t prefix_byte;
    size_t boundary_byte;
    size_t bss_byte;
    size_t next_entry_byte;
    FILE *container = NULL;
    unsigned char *container_map = MAP_FAILED;
    unsigned char *source = MAP_FAILED;
    unsigned char *reservation = MAP_FAILED;
    size_t reservation_size;
    struct dlfrz_entry entry = {0};
    struct dlfrz_lib_meta meta = {0};
    struct loaded_obj object = {0};
    Elf64_Ehdr *ehdr;
    Elf64_Phdr *phdr;
    struct stat source_status;
    char prefix_permissions[5] = {0};
    char boundary_permissions[5] = {0};
    int map_result;
    int ok = 0;

    if (page_value <= 0 || (uint64_t)page_value > SIZE_MAX)
        return 0;
    page = (size_t)page_value;
    if ((page & (page - 1)) != 0 || page < 1024)
        return 0;
    g_page_size = page;

    page_delta = nonzero_page_delta ? page / 4 : 0;
    payload_file_offset = 2 * page;
    entry_size = 2 * page + page / 2;
    segment_file_size = 2 * page + page / 4;
    segment_memory_size = 3 * page - page_delta;
    container_size = 6 * page;
    reservation_size = 7 * page;
    prefix_byte = page + page / 3;
    boundary_byte = 2 * page + page / 8;
    bss_byte = page_delta + segment_file_size + page / 8;
    next_entry_byte = entry_size + 16;

    container = gate_temporary_file();
    if (!container || ftruncate(fileno(container), container_size) < 0)
        goto out;
    container_map = mmap(NULL, container_size, PROT_READ | PROT_WRITE,
                         MAP_SHARED, fileno(container), 0);
    if (container_map == MAP_FAILED)
        goto out;
    memset(container_map, 0, container_size);
    memset(container_map + payload_file_offset, 0x5a,
           segment_memory_size);
    /* These bytes model the following packed entry. */
    memset(container_map + payload_file_offset + entry_size, 0xa5,
           segment_memory_size - entry_size);

    ehdr = (Elf64_Ehdr *)(container_map + payload_file_offset);
    phdr = (Elf64_Phdr *)((unsigned char *)ehdr + sizeof(*ehdr));
    memset(ehdr, 0, sizeof(*ehdr));
    memcpy(ehdr->e_ident, ELFMAG, SELFMAG);
    ehdr->e_type = ET_DYN;
    ehdr->e_phoff = sizeof(*ehdr);
    ehdr->e_phnum = 2;
    ehdr->e_phentsize = sizeof(*phdr);
    memset(phdr, 0, 2 * sizeof(*phdr));
    phdr[0].p_type = PT_LOAD;
    phdr[0].p_flags = flags;
    phdr[0].p_offset = page_delta;
    phdr[0].p_vaddr = page_delta;
    phdr[0].p_filesz = segment_file_size;
    phdr[0].p_memsz = segment_memory_size;
    phdr[0].p_align = page;
    phdr[1].p_type = PT_GNU_STACK;
    phdr[1].p_flags = PF_R | PF_W;
    if (msync(container_map, container_size, MS_SYNC) < 0 ||
        munmap(container_map, container_size) < 0)
        goto out;
    container_map = MAP_FAILED;

    source = mmap(NULL, segment_memory_size, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE, fileno(container),
                  (off_t)payload_file_offset);
    if (source == MAP_FAILED)
        goto out;
    if (mutation == GATE_SOURCE_COW_PARTIAL_PREFIX)
        source[prefix_byte] ^= 0xff;
    else if (mutation == GATE_SOURCE_COW_PARTIAL_BOUNDARY)
        source[boundary_byte] ^= 0xff;

    reservation = mmap(NULL, reservation_size, PROT_NONE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (reservation == MAP_FAILED)
        goto out;

    entry.data_offset = payload_file_offset;
    entry.data_size = entry_size;
    meta.base_addr = (uint64_t)(uintptr_t)reservation;
    meta.vaddr_lo = page_delta;
    meta.vaddr_hi = page_delta + segment_memory_size;
    meta.phdr_num = 2;
    meta.phdr_entsz = sizeof(Elf64_Phdr);
    meta.flags = LDR_FLAG_SHLIB;
    object.runtime_reservation = reservation;
    object.runtime_reservation_size = reservation_size;
    if (page_delta == 0 && (flags & PF_R)) {
        meta.phdr_off = sizeof(Elf64_Ehdr);
        meta.phdr_file_off = 0;
    } else {
        meta.phdr_off = DLFRZ_PHDR_EXTERNAL;
        meta.phdr_file_off = sizeof(Elf64_Ehdr);
    }

    reset_fileback_counters();
    map_result = map_object(source, payload_file_offset, fileno(container),
                            source_flags, &meta, &entry, &object, 1);
    if (map_result < 0 ||
        g_fileback_map_attempts != (size_t)expected_fileback ||
        g_fileback_map_accepts != (size_t)expected_fileback) {
        fprintf(stderr,
                "%s: result=%d attempts=%zu accepts=%zu\n",
                label, map_result, g_fileback_map_attempts,
                g_fileback_map_accepts);
        goto out;
    }
    if (!gate_mapping_permissions(reservation, prefix_permissions) ||
        !gate_mapping_permissions(reservation + 2 * page,
                                  boundary_permissions) ||
        memcmp(prefix_permissions, expected_permissions, 4) != 0 ||
        memcmp(boundary_permissions, expected_permissions, 4) != 0) {
        fprintf(stderr, "%s: prefix=%.4s boundary=%.4s expected=%.4s\n",
                label, prefix_permissions, boundary_permissions,
                expected_permissions);
        goto out;
    }
    if (fstat(fileno(container), &source_status) < 0)
        goto out;
    if (!!gate_mapping_file_identity(
            reservation, &source_status, payload_file_offset) !=
            !!expected_fileback) {
        fprintf(stderr, "%s: complete-prefix provenance differs\n", label);
        goto out;
    }
    if (gate_mapping_file_identity(reservation + 2 * page,
                                   &source_status,
                                   payload_file_offset + 2 * page)) {
        fprintf(stderr, "%s: boundary page exposed container provenance\n",
                label);
        goto out;
    }
    if (reservation[prefix_byte] != source[prefix_byte] ||
        reservation[boundary_byte] != source[boundary_byte] ||
        reservation[bss_byte] != 0 ||
        reservation[next_entry_byte] != 0) {
        fprintf(stderr,
                "%s: prefix/tail bytes, BSS, or next-entry isolation differ\n",
                label);
        goto out;
    }
    ok = 1;

out:
    if (object.runtime_phdr_mapping && object.runtime_phdr_mapping_size)
        (void)munmap(object.runtime_phdr_mapping,
                     object.runtime_phdr_mapping_size);
    if (reservation != MAP_FAILED)
        (void)munmap(reservation, reservation_size);
    if (source != MAP_FAILED)
        (void)munmap(source, segment_memory_size);
    if (container_map != MAP_FAILED)
        (void)munmap(container_map, container_size);
    if (container)
        fclose(container);
    return ok;
}

static int gate_lazy_exact_case(const char *label, uint32_t phdr_flags,
                                const char *expected_permissions)
{
    long page_value = sysconf(_SC_PAGESIZE);
    size_t page;
    uint64_t payload_file_offset;
    size_t container_size;
    size_t reservation_size;
    size_t data_byte;
    size_t tail_byte;
    FILE *container = NULL;
    unsigned char *container_map = MAP_FAILED;
    unsigned char *source = MAP_FAILED;
    void *hole = MAP_FAILED;
    struct dlfrz_entry entry = {0};
    struct dlfrz_lib_meta meta = {0};
    struct loaded_obj object = {0};
    Elf64_Ehdr *ehdr;
    Elf64_Phdr *phdr;
    int original_fd = -1;
    int reused_fd = -1;
    int map_result;
    int ok = 0;

    if (page_value <= 0 || (uint64_t)page_value > SIZE_MAX)
        return 0;
    page = (size_t)page_value;
    if ((page & (page - 1)) != 0 || page < 1024)
        return 0;
    g_page_size = page;
    payload_file_offset = 2 * page;
    container_size = 4 * page;
    reservation_size = 5 * page;
    data_byte = page / 3;
    tail_byte = 3 * page / 4;

    container = gate_temporary_file();
    if (!container || ftruncate(fileno(container), container_size) < 0)
        goto out;
    original_fd = fileno(container);
    container_map = mmap(NULL, container_size, PROT_READ | PROT_WRITE,
                         MAP_SHARED, original_fd, 0);
    if (container_map == MAP_FAILED)
        goto out;
    memset(container_map, 0, container_size);
    memset(container_map + payload_file_offset, 0x5a, page);
    ehdr = (Elf64_Ehdr *)(container_map + payload_file_offset);
    phdr = (Elf64_Phdr *)((unsigned char *)ehdr + sizeof(*ehdr));
    memset(ehdr, 0, sizeof(*ehdr));
    memcpy(ehdr->e_ident, ELFMAG, SELFMAG);
    ehdr->e_type = ET_DYN;
    ehdr->e_phoff = sizeof(*ehdr);
    ehdr->e_phnum = 2;
    ehdr->e_phentsize = sizeof(*phdr);
    memset(phdr, 0, 2 * sizeof(*phdr));
    phdr[0].p_type = PT_LOAD;
    phdr[0].p_flags = phdr_flags;
    phdr[0].p_filesz = page / 2;
    phdr[0].p_memsz = page;
    phdr[0].p_align = page;
    phdr[1].p_type = PT_GNU_STACK;
    phdr[1].p_flags = PF_R | PF_W;
    if (msync(container_map, container_size, MS_SYNC) < 0 ||
        munmap(container_map, container_size) < 0)
        goto out;
    container_map = MAP_FAILED;

    source = mmap(NULL, page, PROT_READ, MAP_PRIVATE, original_fd,
                  (off_t)payload_file_offset);
    if (source == MAP_FAILED)
        goto out;
    if (fclose(container) < 0)
        goto out;
    container = NULL;
    reused_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (reused_fd < 0)
        goto out;
    if (reused_fd != original_fd) {
        if (dup2(reused_fd, original_fd) != original_fd)
            goto out;
        close(reused_fd);
        reused_fd = original_fd;
    }

    hole = mmap(NULL, reservation_size, PROT_NONE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (hole == MAP_FAILED || munmap(hole, reservation_size) < 0)
        goto out;
    entry.data_offset = payload_file_offset;
    entry.data_size = page;
    meta.base_addr = (uint64_t)(uintptr_t)hole;
    meta.vaddr_lo = 0;
    meta.vaddr_hi = page;
    meta.phdr_num = 2;
    meta.phdr_entsz = sizeof(Elf64_Phdr);
    meta.flags = LDR_FLAG_SHLIB;
    if (phdr_flags & PF_R) {
        meta.phdr_off = sizeof(Elf64_Ehdr);
        meta.phdr_file_off = 0;
    } else {
        meta.phdr_off = DLFRZ_PHDR_EXTERNAL;
        meta.phdr_file_off = sizeof(Elf64_Ehdr);
    }

    reset_fileback_counters();
    map_result = map_object(
        source, payload_file_offset, -1,
        DLFRZ_SOURCE_EXACT_CLEAN_FILE,
        &meta, &entry, &object, 0);
    if (map_result < 0) {
        fprintf(stderr, "%s: lazy map failed\n", label);
        goto out;
    }
    if (g_fileback_map_attempts != 0 || g_fileback_map_accepts != 0) {
        fprintf(stderr, "%s: lazy copy unexpectedly used source fd\n", label);
        goto out;
    }
    {
        char target_permissions[5] = {0};

        if (!gate_mapping_permissions(
                (void *)(uintptr_t)meta.base_addr, target_permissions) ||
            memcmp(target_permissions, expected_permissions, 4) != 0)
            goto out;
    }
    if (source[data_byte] != 0x5a || source[tail_byte] != 0x5a)
        goto out;
    if ((phdr_flags & (PF_R | PF_W)) == (PF_R | PF_W)) {
        unsigned char *target = (unsigned char *)(uintptr_t)meta.base_addr;

        if (target[data_byte] != 0x5a || target[tail_byte] != 0)
            goto out;
        target[data_byte] ^= 0xff;
        if (source[data_byte] != 0x5a)
            goto out;
    }
    {
        char guard_permissions[5] = {0};

        if (!gate_mapping_permissions(
                (const unsigned char *)(uintptr_t)meta.base_addr + page,
                guard_permissions) ||
            memcmp(guard_permissions, "---p", 4) != 0)
            goto out;
    }
    ok = 1;

out:
    if (object.runtime_phdr_mapping && object.runtime_phdr_mapping_size)
        munmap(object.runtime_phdr_mapping,
               object.runtime_phdr_mapping_size);
    if (object.runtime_reservation && object.runtime_reservation_size)
        munmap(object.runtime_reservation,
               object.runtime_reservation_size);
    if (hole != MAP_FAILED && !object.runtime_reservation)
        (void)munmap(hole, reservation_size);
    if (source != MAP_FAILED)
        munmap(source, page);
    if (container_map != MAP_FAILED)
        munmap(container_map, container_size);
    if (container)
        fclose(container);
    if (reused_fd >= 0)
        close(reused_fd);
    return ok;
}

/* Exercise both fdless success and the first-syscall refusal transaction.
 * The latter must rebuild the destination, disable later attempts, and copy
 * both segments without damaging the retained source mapping. */
static int gate_mremap_case(const char *label, int forced_errno,
                            size_t force_attempt,
                            size_t expected_attempts,
                            size_t expected_accepts,
                            int expected_first_fileback,
                            int expected_second_fileback)
{
    long page_value = sysconf(_SC_PAGESIZE);
    size_t page;
    size_t container_size;
    size_t reservation_size;
    FILE *container = NULL;
    unsigned char *populate = MAP_FAILED;
    unsigned char *source = MAP_FAILED;
    unsigned char *reservation = MAP_FAILED;
    struct dlfrz_entry entry = {0};
    struct dlfrz_lib_meta meta = {0};
    struct loaded_obj object = {0};
    Elf64_Ehdr *ehdr;
    Elf64_Phdr *phdr;
    struct stat status;
    int map_result;
    int ok = 0;

    if (page_value <= 0 || (uint64_t)page_value > SIZE_MAX)
        return 0;
    page = (size_t)page_value;
    if ((page & (page - 1)) != 0 || page < 1024)
        return 0;
    g_page_size = page;
    container_size = 2 * page;
    reservation_size = 7 * page;
    container = gate_temporary_file();
    if (!container || ftruncate(fileno(container), container_size) < 0)
        goto out;
    populate = mmap(NULL, container_size, PROT_READ | PROT_WRITE,
                    MAP_SHARED, fileno(container), 0);
    if (populate == MAP_FAILED)
        goto out;
    memset(populate, 0x5a, page);
    memset(populate + page, 0x5b, page);
    ehdr = (Elf64_Ehdr *)populate;
    phdr = (Elf64_Phdr *)(populate + sizeof(*ehdr));
    memset(ehdr, 0, sizeof(*ehdr));
    memcpy(ehdr->e_ident, ELFMAG, SELFMAG);
    ehdr->e_type = ET_DYN;
    ehdr->e_phoff = sizeof(*ehdr);
    ehdr->e_phnum = 3;
    ehdr->e_phentsize = sizeof(*phdr);
    memset(phdr, 0, 3 * sizeof(*phdr));
    phdr[0].p_type = PT_LOAD;
    phdr[0].p_flags = PF_R;
    phdr[0].p_filesz = page;
    phdr[0].p_memsz = page;
    phdr[0].p_align = page;
    phdr[1].p_type = PT_LOAD;
    phdr[1].p_flags = PF_R | PF_W;
    phdr[1].p_offset = page;
    phdr[1].p_vaddr = 2 * page;
    phdr[1].p_filesz = page / 2;
    phdr[1].p_memsz = page;
    phdr[1].p_align = page;
    phdr[2].p_type = PT_GNU_STACK;
    phdr[2].p_flags = PF_R | PF_W;
    if (msync(populate, container_size, MS_SYNC) < 0 ||
        munmap(populate, container_size) < 0)
        goto out;
    populate = MAP_FAILED;
    source = mmap(NULL, container_size, PROT_READ, MAP_PRIVATE,
                  fileno(container), 0);
    if (source == MAP_FAILED || fstat(fileno(container), &status) < 0)
        goto out;
    if (fclose(container) < 0)
        goto out;
    container = NULL;

    reservation = mmap(NULL, reservation_size, PROT_NONE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (reservation == MAP_FAILED)
        goto out;
    entry.data_size = container_size;
    entry.flags = LDR_FLAG_SHLIB;
    meta.base_addr = (uint64_t)(uintptr_t)reservation;
    meta.vaddr_hi = 3 * page;
    meta.phdr_off = sizeof(*ehdr);
    meta.phdr_num = 3;
    meta.phdr_entsz = sizeof(*phdr);
    meta.flags = LDR_FLAG_SHLIB;
    object.runtime_reservation = reservation;
    object.runtime_reservation_size = reservation_size;

    reset_fileback_counters();
    g_mremap_forced_errno = forced_errno;
    g_mremap_force_attempt = force_attempt;
    map_result = map_object(
        source, 0, -1, DLFRZ_SOURCE_MREMAP_DONTUNMAP,
        &meta, &entry, &object, 1);
    g_mremap_forced_errno = 0;
    g_mremap_force_attempt = 0;
    if (map_result < 0 ||
        g_mremap_attempts != expected_attempts ||
        g_mremap_accepts != expected_accepts ||
        g_fileback_map_attempts != 0 || g_fileback_map_accepts != 0) {
        fprintf(stderr,
                "%s: result=%d mremap=%zu/%zu fileback=%zu/%zu\n",
                label, map_result, g_mremap_accepts, g_mremap_attempts,
                g_fileback_map_accepts, g_fileback_map_attempts);
        goto out;
    }
    if (!!gate_mapping_file_identity(reservation, &status, 0) !=
            !!expected_first_fileback ||
        !!gate_mapping_file_identity(
            reservation + 2 * page, &status, page) !=
            !!expected_second_fileback) {
        fprintf(stderr, "%s: target provenance differs\n", label);
        goto out;
    }
    if (reservation[page / 2] != source[page / 2] ||
        reservation[2 * page + page / 3] != source[page + page / 3] ||
        reservation[2 * page + 3 * page / 4] != 0 ||
        source[page + 3 * page / 4] != 0x5b) {
        fprintf(stderr, "%s: source, file bytes, or BSS tail differ\n",
                label);
        goto out;
    }
    ok = 1;

out:
    g_mremap_forced_errno = 0;
    g_mremap_force_attempt = 0;
    if (object.runtime_phdr_mapping && object.runtime_phdr_mapping_size)
        (void)munmap(object.runtime_phdr_mapping,
                     object.runtime_phdr_mapping_size);
    if (reservation != MAP_FAILED)
        (void)munmap(reservation, reservation_size);
    if (source != MAP_FAILED)
        (void)munmap(source, container_size);
    if (populate != MAP_FAILED)
        (void)munmap(populate, container_size);
    if (container)
        fclose(container);
    return ok;
}


static int gate_kernel_premap_transfer(int forced_errno)
{
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    FILE *file = gate_temporary_file();
    unsigned char *source = MAP_FAILED, *target = MAP_FAILED;
    void *stage = MAP_FAILED, *replacement = MAP_FAILED;
    struct dlfrz_premap_range ranges[2];
    int ok = 0;
    if (!file || !page || ftruncate(fileno(file), 2 * page) < 0) goto out;
    source = mmap(NULL, 2 * page, PROT_READ | PROT_WRITE, MAP_SHARED,
                   fileno(file), 0);
    if (source == MAP_FAILED) goto out;
    memset(source, 0x5a, 2 * page);
    if (msync(source, 2 * page, MS_SYNC) < 0) goto out;
    stage = mmap((void *)(uintptr_t)DLFRZ_PREMAP_LO, 2 * page, PROT_READ,
                  MAP_PRIVATE | MAP_FIXED_NOREPLACE, fileno(file), 0);
    target = mmap(NULL, page, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (stage == MAP_FAILED || target == MAP_FAILED) goto out;
    ranges[0] = (struct dlfrz_premap_range){(uintptr_t)stage, (uintptr_t)target,
                                          page, 0};
    ranges[1] = (struct dlfrz_premap_range){(uintptr_t)stage + page,
                                          (uintptr_t)target + page, page, page};
    if (loader_install_kernel_premap(ranges, 2) < 0 ||
        !loader_source_contract_is_valid(-1, DLFRZ_SOURCE_KERNEL_PREMAP)) goto out;
    reset_fileback_counters();
    g_mremap_forced_errno = forced_errno;
    int result = map_mapped_payload_segment(source, target, page);
    g_mremap_forced_errno = 0;
    if (result != (forced_errno ? 0 : 1) || g_mremap_attempts != 1 ||
        g_kernel_premaps[0].length != 0) goto out;
    if (mprotect(target, page, PROT_READ | PROT_WRITE) < 0) goto out;
    if (forced_errno) memcpy(target, source, page);
    if (memcmp(target, source, page)) goto out;
    target[0] = 0xa5;
    if (source[0] != 0x5a) goto out;
    if (map_mapped_payload_segment(source, target, page) != 0 ||
        g_mremap_attempts != 1) goto out;
    replacement = mmap(stage, page, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (replacement != stage) goto out;
    *(unsigned char *)replacement = 0xa5;
    g_frozen_srcfd = -1;
    g_frozen_source_flags = DLFRZ_SOURCE_KERNEL_PREMAP;
    release_frozen_source_fd_after_tls();
    if (g_kernel_premap_count || g_frozen_source_flags ||
        *(unsigned char *)replacement != 0xa5) goto out;
    /* The unused second stage was released, without touching the new owner
     * of the consumed first stage's old address. */
    unsigned char resident;
    if (mincore((char *)stage + page, page, &resident) == 0) goto out;
    ok = 1;
out:
    g_mremap_forced_errno = 0;
    release_kernel_premaps();
    if (replacement != MAP_FAILED) munmap(replacement, page);
    if (stage != MAP_FAILED) munmap(stage, 2 * page);
    if (target != MAP_FAILED) munmap(target, page);
    if (source != MAP_FAILED) munmap(source, 2 * page);
    if (file) fclose(file);
    return ok;
}

static int gate_fd_lifecycle(void)
{
    int fd = open("/dev/null", O_RDONLY | O_CLOEXEC);

    if (fd < 0)
        return 0;
    g_frozen_srcfd = fd;
    g_frozen_source_flags = DLFRZ_SOURCE_EXACT_CLEAN_FILE |
                            DLFRZ_SOURCE_MREMAP_DONTUNMAP;
    g_startup_mremap_disabled = 0;
    if (g_frozen_srcfd != fd)
        return 0;
    release_frozen_source_fd_after_tls();
    if (g_frozen_srcfd != -1 ||
        (g_frozen_source_flags & DLFRZ_SOURCE_MREMAP_DONTUNMAP) != 0 ||
        !g_startup_mremap_disabled)
        return 0;
    errno = 0;
    if (fcntl(fd, F_GETFD) != -1 || errno != EBADF)
        return 0;
    return 1;
}

static int gate_source_contract(void)
{
    return loader_source_contract_is_valid(-1, 0) &&
           loader_source_contract_is_valid(
               -1, DLFRZ_SOURCE_MREMAP_DONTUNMAP) &&
           loader_source_contract_is_valid(7,
               DLFRZ_SOURCE_EXACT_CLEAN_FILE) &&
           loader_source_contract_is_valid(
               7, DLFRZ_SOURCE_EXACT_CLEAN_FILE |
                  DLFRZ_SOURCE_MREMAP_DONTUNMAP) &&
           !loader_source_contract_is_valid(
               -1, DLFRZ_SOURCE_EXACT_CLEAN_FILE) &&
           !loader_source_contract_is_valid(7, 1U << 31) &&
           !loader_source_contract_is_valid(
               7, DLFRZ_SOURCE_EXACT_CLEAN_FILE | (1U << 31));
}

static int gate_forced_probe_cleanup_child(int fd, int runtime_probe)
{
    pid_t child = fork();
    int status;

    if (child < 0)
        return 0;
    if (child == 0) {
        struct dlfrz_gnu_property_profile profile = {0};
        Elf64_Phdr phdr = {0};

        g_loader_diagnostics_suppressed = 1;
        g_executable_probe_forced_munmap_errno = EACCES;
        if (runtime_probe) {
            phdr.p_type = PT_LOAD;
            phdr.p_flags = PF_R | PF_X;
            phdr.p_filesz = 1;
            phdr.p_memsz = 1;
            (void)runtime_probe_file_mapping_policy(fd, &phdr, &profile);
        } else {
            (void)vfs_validate_executable_backing(fd, 1, 0555);
        }
        _exit(99);
    }
    do {
        if (waitpid(child, &status, 0) >= 0)
            break;
    } while (errno == EINTR);
    return WIFEXITED(status) && WEXITSTATUS(status) == 127;
}

static int gate_executable_probe_cleanup_is_terminal(void)
{
    struct dlfrz_gnu_property_profile profile = {0};
    Elf64_Phdr phdr = {0};
    int fd = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
    int ok;

    if (fd < 0)
        return 0;
    phdr.p_type = PT_LOAD;
    phdr.p_flags = PF_R | PF_X;
    phdr.p_filesz = 1;
    phdr.p_memsz = 1;
    g_executable_probe_forced_munmap_errno = 0;
    ok = vfs_validate_executable_backing(fd, 1, 0555) == 0 &&
         runtime_probe_file_mapping_policy(fd, &phdr, &profile) == 0 &&
         gate_forced_probe_cleanup_child(fd, 0) &&
         gate_forced_probe_cleanup_child(fd, 1);
    close(fd);
    return ok;
}

static unsigned int gate_vfs_temp_seen_stages;
static int gate_vfs_temp_hook_failed;
static mode_t gate_vfs_temp_final_mode;
static int gate_vfs_temp_replace_private;
static struct stat gate_vfs_temp_renamed_writer_status;
static const char gate_vfs_temp_renamed_leaf[] =
    ".dlfreeze-renamed-writer";

static void gate_vfs_temp_stage(
    int dirfd, const char *leaf, int writer_fd, int served_fd,
    enum vfs_temp_gate_stage stage)
{
    struct stat path_status;
    struct stat served_status;
    struct stat writer_status;
    mode_t expected_mode = stage == VFS_TEMP_GATE_UNLINKED_FINAL ?
        gate_vfs_temp_final_mode : (S_IRUSR | S_IWUSR);
    unsigned int bit = 1U << (unsigned int)stage;
    int path_error = 0;
    int path_result;

    errno = 0;
    path_result = fstatat(
        dirfd, leaf, &path_status, AT_SYMLINK_NOFOLLOW);
    if (path_result < 0)
        path_error = errno;
    if ((gate_vfs_temp_seen_stages & bit) != 0 ||
        fstat(writer_fd, &writer_status) < 0 ||
        fstat(served_fd, &served_status) < 0 ||
        !vfs_stat_identity_equal(&writer_status, &served_status) ||
        (writer_status.st_mode & 07777) != expected_mode ||
        (served_status.st_mode & 07777) != expected_mode) {
        gate_vfs_temp_hook_failed = 1;
    } else if (stage == VFS_TEMP_GATE_PRIVATE_NAME) {
        if (path_result < 0 ||
            !vfs_stat_identity_equal(&writer_status, &path_status) ||
            (path_status.st_mode & 07777) != expected_mode)
            gate_vfs_temp_hook_failed = 1;
        if (gate_vfs_temp_replace_private &&
            !gate_vfs_temp_hook_failed) {
            int replacement_fd;

            gate_vfs_temp_renamed_writer_status = writer_status;
            if (renameat(dirfd, leaf, dirfd,
                         gate_vfs_temp_renamed_leaf) < 0) {
                gate_vfs_temp_hook_failed = 1;
            } else {
                replacement_fd = openat(
                    dirfd, leaf,
                    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                    S_IRUSR | S_IWUSR);
                if (replacement_fd < 0) {
                    gate_vfs_temp_hook_failed = 1;
                } else {
                    if (fchmod(replacement_fd,
                               S_IRUSR | S_IWUSR) < 0)
                        gate_vfs_temp_hook_failed = 1;
                    close(replacement_fd);
                }
            }
        }
    } else if (path_result == 0 || path_error != ENOENT ||
               writer_status.st_nlink != 0 ||
               served_status.st_nlink != 0) {
        gate_vfs_temp_hook_failed = 1;
    }
    gate_vfs_temp_seen_stages |= bit;
}

static int gate_vfs_temp_directory(char path[PATH_MAX])
{
    const char *candidates[] = { getenv("TMPDIR"), "/tmp" };

    for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]);
         i++) {
        int length;

        if (!candidates[i] || candidates[i][0] != '/')
            continue;
        length = snprintf(path, PATH_MAX,
                          "%s/dlfreeze-vfs-private-XXXXXX",
                          candidates[i]);
        if (length <= 0 || length >= PATH_MAX)
            continue;
        if (mkdtemp(path))
            return 1;
    }
    return 0;
}

static int gate_vfs_temp_one(const char *directory, mode_t mode)
{
    static const unsigned char bytes[] = "\177ELFprivate-fallback";
    struct stat status;
    unsigned char copy[sizeof(bytes) - 1];
    void *mapping = MAP_FAILED;
    int fd = -1;
    int ok = 0;

    gate_vfs_temp_seen_stages = 0;
    gate_vfs_temp_hook_failed = 0;
    gate_vfs_temp_final_mode = mode;
    g_vfs_temp_stage_hook = gate_vfs_temp_stage;
    fd = vfs_serve_bytes_temp_dir(
        directory, bytes, sizeof(bytes) - 1,
        O_RDONLY | O_CLOEXEC, mode);
    g_vfs_temp_stage_hook = NULL;
    if (fd < 0 || gate_vfs_temp_hook_failed ||
        gate_vfs_temp_seen_stages !=
            ((1U << VFS_TEMP_GATE_PRIVATE_NAME) |
             (1U << VFS_TEMP_GATE_UNLINKED_PRIVATE) |
             (1U << VFS_TEMP_GATE_UNLINKED_FINAL)) ||
        fstat(fd, &status) < 0 ||
        (status.st_mode & 07777) != mode ||
        pread(fd, copy, sizeof(copy), 0) != (ssize_t)sizeof(copy) ||
        memcmp(copy, bytes, sizeof(copy)) != 0)
        goto out;
    if ((mode & 0111) != 0) {
        mapping = mmap(NULL, 1, PROT_READ | PROT_EXEC,
                       MAP_PRIVATE, fd, 0);
        if (mapping == MAP_FAILED)
            goto out;
    }
    ok = 1;

out:
    if (mapping != MAP_FAILED)
        munmap(mapping, 1);
    if (fd >= 0)
        close(fd);
    return ok;
}

static int gate_vfs_temp_publication(void)
{
    static const unsigned char bytes[] = "private-fallback";
    char directory[PATH_MAX];
    char renamed_path[PATH_MAX];
    struct stat renamed_status;
    int failed_fd;
    int renamed_length = -1;

    if (!gate_vfs_temp_directory(directory))
        return 0;
    renamed_length = snprintf(
        renamed_path, sizeof(renamed_path), "%s/%s",
        directory, gate_vfs_temp_renamed_leaf);
    if (renamed_length <= 0 ||
        (size_t)renamed_length >= sizeof(renamed_path))
        goto fail;
    if (g_page_size == 0) {
        long page = sysconf(_SC_PAGESIZE);

        if (page <= 0 || (uint64_t)page > SIZE_MAX)
            goto fail;
        g_page_size = (size_t)page;
    }
    g_vfs_hash_key[0] = UINT64_C(0x79a35b40cf1268ed);
    g_vfs_hash_key[1] = UINT64_C(0x1c8ef462a73590bd);
    g_vfs_hash_key_ready = 1;
    g_vfs_temp_nonce = 0;

    /* Creation needs only write/search permission.  The fallback must not
     * add an unrelated directory-read requirement when opening its dirfd. */
    if (chmod(directory, 0300) < 0)
        goto fail;
    if (!gate_vfs_temp_one(directory, 0444) ||
        !gate_vfs_temp_one(directory, 0555))
        goto fail;

    gate_vfs_temp_seen_stages = 0;
    gate_vfs_temp_hook_failed = 0;
    gate_vfs_temp_final_mode = 0444;
    g_vfs_temp_stage_hook = gate_vfs_temp_stage;
    g_vfs_temp_forced_unlink_errno = EACCES;
    g_loader_errno = 0;
    failed_fd = vfs_serve_bytes_temp_dir(
        directory, bytes, sizeof(bytes) - 1,
        O_RDONLY | O_CLOEXEC, 0444);
    g_vfs_temp_stage_hook = NULL;
    g_vfs_temp_forced_unlink_errno = 0;
    if (failed_fd >= 0) {
        close(failed_fd);
        goto fail;
    }
    if (loader_errno_value() != EACCES || gate_vfs_temp_hook_failed ||
        gate_vfs_temp_seen_stages !=
            (1U << VFS_TEMP_GATE_PRIVATE_NAME))
        goto fail;

    /* Replacing the private pathname immediately before unlink must not make
     * the original inode public under its renamed alias.  The fallback must
     * fail before raising permissions and scrub that surviving inode to 000. */
    gate_vfs_temp_seen_stages = 0;
    gate_vfs_temp_hook_failed = 0;
    gate_vfs_temp_final_mode = 0555;
    gate_vfs_temp_replace_private = 1;
    g_vfs_temp_stage_hook = gate_vfs_temp_stage;
    g_loader_errno = 0;
    failed_fd = vfs_serve_bytes_temp_dir(
        directory, bytes, sizeof(bytes) - 1,
        O_RDONLY | O_CLOEXEC, 0555);
    g_vfs_temp_stage_hook = NULL;
    gate_vfs_temp_replace_private = 0;
    if (failed_fd >= 0) {
        close(failed_fd);
        goto fail;
    }
    if (loader_errno_value() != EIO || gate_vfs_temp_hook_failed ||
        gate_vfs_temp_seen_stages !=
            (1U << VFS_TEMP_GATE_PRIVATE_NAME) ||
        stat(renamed_path, &renamed_status) < 0 ||
        !vfs_stat_identity_equal(
            &gate_vfs_temp_renamed_writer_status, &renamed_status) ||
        renamed_status.st_nlink != 1 ||
        (renamed_status.st_mode & 07777) != 0 ||
        unlink(renamed_path) < 0)
        goto fail;
    if (chmod(directory, 0700) < 0)
        goto fail;
    return rmdir(directory) == 0;

fail:
    g_vfs_temp_stage_hook = NULL;
    g_vfs_temp_forced_unlink_errno = 0;
    gate_vfs_temp_replace_private = 0;
    if (renamed_length > 0 &&
        (size_t)renamed_length < sizeof(renamed_path))
        (void)unlink(renamed_path);
    (void)chmod(directory, 0700);
    (void)rmdir(directory);
    return 0;
}

int main(void)
{
    if (!gate_source_contract())
        return 1;
    if (!gate_kernel_premap_transfer(0) ||
        !gate_kernel_premap_transfer(ENOSYS) ||
        !gate_kernel_premap_transfer(EPERM))
        return 25;
    if (!gate_executable_probe_cleanup_is_terminal())
        return 24;
    if (!gate_map_case("clean nonzero-mem_foff file map",
                       GATE_SOURCE_CLEAN, 0, PF_R | PF_W, 0,
                       1, 0, 0, "rw-p"))
        return 2;
    if (!gate_map_case("exact startup maps pinned file",
                       GATE_SOURCE_CLEAN,
                       DLFRZ_SOURCE_EXACT_CLEAN_FILE,
                       PF_R | PF_W, 0,
                       1, 1, 1, "rw-p"))
        return 3;
    if (!gate_map_case("COW mutation inside p_filesz",
                       GATE_SOURCE_COW_FILE_BYTES, 0, PF_R | PF_W, 0,
                       1, 0, 0, "rw-p"))
        return 4;
    if (!gate_map_case("COW mutation in page-rounded tail",
                       GATE_SOURCE_COW_PAGE_TAIL, 0, PF_R | PF_W, 0,
                       1, 0, 0, "rw-p"))
        return 5;
    if (!gate_map_case("embedded EOF declines rounded mmap",
                       GATE_SOURCE_CLEAN, 0, PF_R | PF_W, 1,
                       1, 0, 0, "rw-p"))
        return 6;
    if (!gate_partial_eof_case("embedded EOF maps complete prefix",
                               GATE_SOURCE_CLEAN,
                               DLFRZ_SOURCE_EXACT_CLEAN_FILE,
                               PF_R | PF_X, 0, 1, "r-xp"))
        return 7;
    if (!gate_partial_eof_case("unproven EOF copies COW boundary",
                               GATE_SOURCE_COW_PARTIAL_BOUNDARY, 0,
                               PF_R | PF_W, 0, 0, "rw-p"))
        return 8;
    if (!gate_partial_eof_case("unproven EOF copies COW prefix",
                               GATE_SOURCE_COW_PARTIAL_PREFIX, 0,
                               PF_R | PF_W, 0, 0, "rw-p"))
        return 9;
    if (!gate_partial_eof_case("nonzero-delta EOF maps complete prefix",
                               GATE_SOURCE_CLEAN,
                               DLFRZ_SOURCE_EXACT_CLEAN_FILE,
                               PF_R | PF_W, 1, 1, "rw-p"))
        return 10;
    if (!gate_map_case("PF_X temporary-read mapping",
                       GATE_SOURCE_CLEAN,
                       DLFRZ_SOURCE_EXACT_CLEAN_FILE,
                       PF_X, 0, 1, 1, 1, "--xp"))
        return 11;
    if (!gate_map_case("PF_NONE temporary-read mapping",
                       GATE_SOURCE_CLEAN,
                       DLFRZ_SOURCE_EXACT_CLEAN_FILE,
                       0, 0, 1, 1, 1, "---p"))
        return 12;
    if (!gate_map_case("failed MAP_FIXED restores anonymous copy target",
                       GATE_FILEBACK_MAP_FAILURE,
                       DLFRZ_SOURCE_EXACT_CLEAN_FILE,
                       PF_R | PF_W, 0, 1, 1, 0, "rw-p"))
        return 22;
    if (!gate_map_case("failed MAP_FIXED restoration fails closed",
                       GATE_FILEBACK_RESTORE_FAILURE,
                       DLFRZ_SOURCE_EXACT_CLEAN_FILE,
                       PF_R | PF_W, 0, 0, 1, 0, NULL))
        return 23;
    if (!gate_lazy_exact_case("lazy exact fd-independent copy",
                              PF_R | PF_W, "rw-p"))
        return 13;
    if (!gate_lazy_exact_case("lazy exact PF_X copy", PF_X, "--xp"))
        return 14;
    if (!gate_lazy_exact_case("lazy exact PF_NONE copy", 0, "---p"))
        return 15;
    if (!gate_mremap_case("fdless mapped-payload transfer", 0, 0,
                          2, 2, 1, 1))
        return 16;
    if (!gate_mremap_case("first mremap refusal copies all ranges", EPERM, 1,
                          1, 0, 0, 0))
        return 17;
    if (!gate_mremap_case("later mremap refusal preserves prior transfer",
                          EPERM, 2, 2, 1, 1, 0))
        return 18;
    if (!gate_fd_lifecycle())
        return 19;
    if (!gate_map_case("executable PT_GNU_STACK is rejected",
                       GATE_STACK_EXECUTABLE, 0, PF_R | PF_W, 0,
                       0, 0, 0, NULL))
        return 20;
    if (!gate_vfs_temp_publication())
        return 21;
    return 0;
}
