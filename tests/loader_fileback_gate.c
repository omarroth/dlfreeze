#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <sys/sysmacros.h>

#define DLFREEZE_FILEBACK_GATE 1
#include "../src/loader.c"

enum gate_mutation {
    GATE_SOURCE_CLEAN,
    GATE_SOURCE_COW_FILE_BYTES,
    GATE_SOURCE_COW_PAGE_TAIL,
    GATE_SOURCE_COW_PARTIAL_PREFIX,
    GATE_SOURCE_COW_PARTIAL_BOUNDARY,
};

static void reset_fileback_counters(void)
{
    g_fileback_map_attempts = 0;
    g_fileback_map_accepts = 0;
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
    container = tmpfile();
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
    ehdr->e_phnum = 1;
    ehdr->e_phentsize = sizeof(*phdr);
    memset(phdr, 0, sizeof(*phdr));
    phdr->p_type = PT_LOAD;
    phdr->p_flags = flags;
    phdr->p_offset = 0;
    phdr->p_vaddr = 0;
    phdr->p_filesz = segment_file_size;
    phdr->p_memsz = page;
    phdr->p_align = page;
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
    meta.phdr_num = 1;
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

    container = tmpfile();
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
    ehdr->e_phnum = 1;
    ehdr->e_phentsize = sizeof(*phdr);
    memset(phdr, 0, sizeof(*phdr));
    phdr->p_type = PT_LOAD;
    phdr->p_flags = flags;
    phdr->p_offset = page_delta;
    phdr->p_vaddr = page_delta;
    phdr->p_filesz = segment_file_size;
    phdr->p_memsz = segment_memory_size;
    phdr->p_align = page;
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
    meta.phdr_num = 1;
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

    container = tmpfile();
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
    ehdr->e_phnum = 1;
    ehdr->e_phentsize = sizeof(*phdr);
    memset(phdr, 0, sizeof(*phdr));
    phdr->p_type = PT_LOAD;
    phdr->p_flags = phdr_flags;
    phdr->p_filesz = page / 2;
    phdr->p_memsz = page;
    phdr->p_align = page;
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
    meta.phdr_num = 1;
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


static int gate_fd_lifecycle(void)
{
    int fd = open("/dev/null", O_RDONLY | O_CLOEXEC);

    if (fd < 0)
        return 0;
    g_frozen_srcfd = fd;
    if (g_frozen_srcfd != fd)
        return 0;
    release_frozen_source_fd_after_tls();
    if (g_frozen_srcfd != -1)
        return 0;
    errno = 0;
    if (fcntl(fd, F_GETFD) != -1 || errno != EBADF)
        return 0;
    return 1;
}

static int gate_source_contract(void)
{
    return loader_source_contract_is_valid(-1, 0) &&
           loader_source_contract_is_valid(7,
               DLFRZ_SOURCE_EXACT_CLEAN_FILE) &&
           !loader_source_contract_is_valid(
               -1, DLFRZ_SOURCE_EXACT_CLEAN_FILE) &&
           !loader_source_contract_is_valid(7, 1U << 31) &&
           !loader_source_contract_is_valid(
               7, DLFRZ_SOURCE_EXACT_CLEAN_FILE | (1U << 31));
}

int main(void)
{
    if (!gate_source_contract())
        return 1;
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
    if (!gate_lazy_exact_case("lazy exact fd-independent copy",
                              PF_R | PF_W, "rw-p"))
        return 13;
    if (!gate_lazy_exact_case("lazy exact PF_X copy", PF_X, "--xp"))
        return 14;
    if (!gate_lazy_exact_case("lazy exact PF_NONE copy", 0, "---p"))
        return 15;
    if (!gate_fd_lifecycle())
        return 16;
    return 0;
}
