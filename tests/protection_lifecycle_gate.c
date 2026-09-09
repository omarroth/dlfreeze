#include <sys/resource.h>
#include <sys/wait.h>

/* Count only this gate's loader-owned mprotect calls. */
#define DLFREEZE_PROTECTION_LIFECYCLE_GATE 1
#include "../src/loader.c"

static void silence_expected_fault_diagnostic(void)
{
    int fd = open("/dev/null", O_WRONLY | O_CLOEXEC);

    if (fd >= 0) {
        (void)dup2(fd, STDERR_FILENO);
        close(fd);
    }
}

static int child_write_faults(volatile unsigned char *address)
{
    int status = 0;
    pid_t child = fork();

    if (child < 0)
        return 0;
    if (child == 0) {
        silence_expected_fault_diagnostic();
        *address ^= UINT8_C(0xff);
        _exit(0);
    }
    if (waitpid(child, &status, 0) != child)
        return 0;
    return WIFSIGNALED(status) &&
           (WTERMSIG(status) == SIGSEGV || WTERMSIG(status) == SIGBUS);
}

static int child_store_succeeds(volatile unsigned char *address)
{
    int status = 0;
    pid_t child = fork();

    if (child < 0)
        return 0;
    if (child == 0) {
        *address = UINT8_C(0x4d);
        _exit(0);
    }
    if (waitpid(child, &status, 0) != child)
        return 0;
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static int child_read_faults(volatile const unsigned char *address)
{
    int status = 0;
    pid_t child = fork();

    if (child < 0)
        return 0;
    if (child == 0) {
        silence_expected_fault_diagnostic();
        volatile unsigned char value = *address;

        (void)value;
        _exit(0);
    }
    if (waitpid(child, &status, 0) != child)
        return 0;
    return WIFSIGNALED(status) &&
           (WTERMSIG(status) == SIGSEGV || WTERMSIG(status) == SIGBUS);
}

static int mapping_has_protection(const void *address, size_t length,
                                  int expected_prot)
{
    uintptr_t cursor = (uintptr_t)address;
    uintptr_t limit;
    FILE *maps;
    char line[512];

    if (length == 0 || cursor > UINTPTR_MAX - length)
        return 0;
    limit = cursor + length;
    maps = fopen("/proc/self/maps", "r");
    if (!maps)
        return 0;

    while (cursor < limit && fgets(line, sizeof(line), maps)) {
        unsigned long long raw_start;
        unsigned long long raw_end;
        uintptr_t start;
        uintptr_t end;
        char perms[5];
        int actual_prot = 0;

        if (sscanf(line, "%llx-%llx %4s", &raw_start, &raw_end, perms) != 3 ||
            raw_start > UINTPTR_MAX || raw_end > UINTPTR_MAX)
            continue;
        start = (uintptr_t)raw_start;
        end = (uintptr_t)raw_end;
        if (end <= cursor)
            continue;
        if (start > cursor || end <= start)
            break;
        if (perms[0] == 'r')
            actual_prot |= PROT_READ;
        if (perms[1] == 'w')
            actual_prot |= PROT_WRITE;
        if (perms[2] == 'x')
            actual_prot |= PROT_EXEC;
        if (actual_prot != expected_prot)
            break;
        cursor = end < limit ? end : limit;
    }
    fclose(maps);
    return cursor == limit;
}

static void *map_aligned_reservation(size_t length, size_t alignment)
{
    void *whole;
    uintptr_t raw;
    uintptr_t aligned;
    size_t total;
    size_t prefix;
    size_t suffix;

    if (length == 0 || alignment == 0 ||
        (alignment & (alignment - 1)) != 0 ||
        length > SIZE_MAX - alignment)
        return MAP_FAILED;
    total = length + alignment;
    whole = mmap(NULL, total, PROT_NONE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (whole == MAP_FAILED)
        return MAP_FAILED;
    raw = (uintptr_t)whole;
    if (raw > UINTPTR_MAX - (alignment - 1)) {
        munmap(whole, total);
        return MAP_FAILED;
    }
    aligned = (raw + alignment - 1) & ~(uintptr_t)(alignment - 1);
    prefix = (size_t)(aligned - raw);
    suffix = total - prefix - length;
    if ((prefix != 0 && munmap(whole, prefix) != 0) ||
        (suffix != 0 &&
         munmap((void *)(aligned + length), suffix) != 0)) {
        if (prefix == 0)
            munmap(whole, total);
        else
            munmap((void *)aligned, length + suffix);
        return MAP_FAILED;
    }
    return (void *)aligned;
}

/* Range admission is deliberately two-pass: a bad later header must not
 * leave an earlier PT_LOAD writable. */
static int run_anonymous_malformed_gate(size_t page_size)
{
    const size_t reservation_size = 4 * page_size;
    unsigned char *target = MAP_FAILED;
    Elf64_Phdr phdr[2] = {0};
    int result = 1;

    target = map_aligned_reservation(reservation_size, page_size);
    if (target == MAP_FAILED || (uintptr_t)target == 0)
        return 2;
    g_page_size = page_size;
    phdr[0].p_type = PT_LOAD;
    phdr[0].p_filesz = 1;
    phdr[0].p_memsz = page_size;
    phdr[1].p_type = PT_LOAD;
    phdr[1].p_filesz = 1;
    phdr[1].p_memsz = page_size;

    /* The first range is valid, but relocating the second wraps. */
    phdr[0].p_vaddr = 0;
    phdr[1].p_vaddr = UINT64_MAX - (uintptr_t)target + 1;
    g_loader_mprotect_calls = 0;
    if (make_anonymous_load_runs_writable(
            (uintptr_t)target, phdr, 2) == 0 ||
        g_loader_mprotect_calls != 0 ||
        !mapping_has_protection(target, reservation_size, PROT_NONE)) {
        result = 3;
        goto out;
    }

    /* Both ranges are representable, but the later header descends. */
    phdr[0].p_vaddr = 2 * page_size;
    phdr[1].p_vaddr = 0;
    g_loader_mprotect_calls = 0;
    if (make_anonymous_load_runs_writable(
            (uintptr_t)target, phdr, 2) == 0 ||
        g_loader_mprotect_calls != 0 ||
        !mapping_has_protection(target, reservation_size, PROT_NONE)) {
        result = 4;
        goto out;
    }
    result = 0;

out:
    if (target != MAP_FAILED)
        munmap(target, reservation_size);
    return result;
}

/* Startup reservations are a batch transaction.  A collision for a later
 * object must release every earlier interval and clear its ownership record. */
static int run_reservation_transaction_gate(size_t page_size)
{
    const size_t object_size = 5 * page_size;
    const size_t total_size = 2 * object_size;
    unsigned char *region = MAP_FAILED;
    void *probe = MAP_FAILED;
    struct dlfrz_lib_meta metas[2] = {0};
    struct loaded_obj objects[2] = {0};
    const int indices[2] = {0, 1};
    int first_is_hole = 0;
    int second_is_mapped = 0;
    int result = 1;

    region = map_aligned_reservation(total_size, page_size);
    if (region == MAP_FAILED)
        return 2;
    second_is_mapped = 1;
    if (munmap(region, object_size) < 0) {
        result = 3;
        goto out;
    }
    first_is_hole = 1;
    g_page_size = page_size;
    for (size_t i = 0; i < 2; i++) {
        metas[i].base_addr = (uintptr_t)region + i * object_size;
        metas[i].vaddr_lo = 0;
        metas[i].vaddr_hi = page_size;
    }

    if (reserve_address_range(metas, indices, objects, 2) == 0 ||
        objects[0].runtime_reservation ||
        objects[0].runtime_reservation_size ||
        objects[1].runtime_reservation ||
        objects[1].runtime_reservation_size) {
        result = 4;
        goto out;
    }
    probe = mmap(region, object_size, PROT_NONE,
                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
                 -1, 0);
    if (probe != region) {
        if (probe != MAP_FAILED)
            munmap(probe, object_size);
        probe = MAP_FAILED;
        result = 5;
        goto out;
    }
    first_is_hole = 0;
    result = 0;

out:
    if (probe != MAP_FAILED)
        munmap(probe, object_size);
    else if (!first_is_hole)
        munmap(region, object_size);
    if (second_is_mapped)
        munmap(region + object_size, object_size);
    return result;
}

/* Exercise the anonymous-copy batching path with page-adjacent file-backed
 * segments whose final permissions all differ.  The fourth PT_LOAD is pure
 * BSS and a real hole separates it from the file-bearing population run. */
static int run_anonymous_edge_case(size_t page_size)
{
    const size_t source_size = 4 * page_size;
    const size_t reservation_size = 10 * page_size;
    const size_t partial_filesz = page_size / 2 + 37;
    const size_t partial_memsz = page_size + 211;
    const size_t write_filesz = 73;
    const size_t rwx_filesz = 97;
    unsigned char *source = MAP_FAILED;
    unsigned char *target = MAP_FAILED;
    Elf64_Ehdr *ehdr;
    Elf64_Phdr *phdr;
    struct dlfrz_entry entry = {0};
    struct dlfrz_lib_meta meta = {0};
    struct loaded_obj object = {0};
    int result = 1;

    g_page_size = page_size;
    source = mmap(NULL, source_size, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    target = map_aligned_reservation(reservation_size, page_size);
    if (source == MAP_FAILED || target == MAP_FAILED ||
        (uintptr_t)target < page_size) {
        result = 2;
        goto out;
    }

    memset(source, 0, source_size);
    ehdr = (Elf64_Ehdr *)source;
    phdr = (Elf64_Phdr *)(source + sizeof(*ehdr));
    memcpy(ehdr->e_ident, ELFMAG, SELFMAG);
    ehdr->e_phoff = sizeof(*ehdr);
    ehdr->e_phnum = 5;
    ehdr->e_phentsize = sizeof(*phdr);

    /* A read-only, partially file-backed segment spans two pages. */
    phdr[0].p_type = PT_LOAD;
    phdr[0].p_flags = PF_R;
    phdr[0].p_offset = page_size;
    phdr[0].p_vaddr = page_size;
    phdr[0].p_filesz = partial_filesz;
    phdr[0].p_memsz = partial_memsz;
    phdr[0].p_align = page_size;

    /* These two file-bearing pages are adjacent to the first segment and
     * therefore share its temporary RW population run despite ending with
     * distinct W-only and RWX permissions. */
    phdr[1].p_type = PT_LOAD;
    phdr[1].p_flags = PF_W;
    phdr[1].p_offset = 2 * page_size;
    phdr[1].p_vaddr = 3 * page_size;
    phdr[1].p_filesz = write_filesz;
    phdr[1].p_memsz = page_size;
    phdr[1].p_align = page_size;

    phdr[2].p_type = PT_LOAD;
    phdr[2].p_flags = PF_R | PF_W | PF_X;
    phdr[2].p_offset = 3 * page_size;
    phdr[2].p_vaddr = 4 * page_size;
    phdr[2].p_filesz = rwx_filesz;
    phdr[2].p_memsz = page_size;
    phdr[2].p_align = page_size;

    /* Page five is deliberately absent.  A pure-BSS RW segment follows it
     * and must be transitioned only during final protection, never folded
     * into the file-bearing population run across the hole. */
    phdr[3].p_type = PT_LOAD;
    phdr[3].p_flags = PF_R | PF_W;
    phdr[3].p_vaddr = 6 * page_size;
    phdr[3].p_memsz = page_size;
    phdr[3].p_align = page_size;

    phdr[4].p_type = PT_GNU_STACK;
    phdr[4].p_flags = PF_R | PF_W;

    memset(source + page_size, 0xa5, partial_filesz);
    memset(source + 2 * page_size, 0xb6, write_filesz);
    memset(source + 3 * page_size, 0xc7, rwx_filesz);

    entry.data_size = source_size;
    /* target is the exact reservation start.  Keep a nonzero vaddr_lo by
     * placing the ELF load bias one page below it, as a real ET_DYN mapping
     * may do.  Six load/hole pages are followed by all four guard pages. */
    meta.base_addr = (uintptr_t)target - page_size;
    meta.vaddr_lo = page_size;
    meta.vaddr_hi = 7 * page_size;
    meta.phdr_off = DLFRZ_PHDR_EXTERNAL;
    meta.phdr_file_off = sizeof(*ehdr);
    meta.phdr_num = ehdr->e_phnum;
    meta.phdr_entsz = sizeof(*phdr);
    meta.flags = DLFRZ_FLAG_SHLIB;
    object.runtime_reservation = target;
    object.runtime_reservation_size = reservation_size;

    {
        struct dlfrz_lib_meta bad_meta = meta;
        int bad_result;

        /* A caller cannot authorize a larger/smaller image by making its
         * reservation record agree with forged metadata: the copied PT_LOAD
         * authority must independently reproduce the exact extent. */
        bad_meta.vaddr_hi -= page_size;
        object.runtime_reservation_size -= page_size;
        g_loader_mprotect_calls = 0;
        bad_result = map_object(source, 0, -1, 0, &bad_meta, &entry,
                                &object, 1);
        object.runtime_reservation_size = reservation_size;
        if (bad_result == 0 ||
            g_loader_mprotect_calls != 0 ||
            !mapping_has_protection(
                target, reservation_size, PROT_NONE)) {
            result = 3;
            goto out;
        }

        /* Conversely, exact ELF metadata cannot grant access without an
         * exact ownership record for the load interval plus four guards. */
        object.runtime_reservation_size -= page_size;
        g_loader_mprotect_calls = 0;
        bad_result = map_object(source, 0, -1, 0, &meta, &entry,
                                &object, 1);
        object.runtime_reservation_size = reservation_size;
        if (bad_result == 0 ||
            g_loader_mprotect_calls != 0 ||
            !mapping_has_protection(
                target, reservation_size, PROT_NONE)) {
            result = 4;
            goto out;
        }
    }

    g_loader_mprotect_calls = 0;
    if (map_object(source, 0, -1, 0, &meta, &entry, &object, 1) < 0) {
        result = 5;
        goto out;
    }

    /* One temporary RW run covers all three adjacent file-bearing loads;
     * four final PT_LOAD transitions and the PHDR snapshot add five calls. */
    if (g_loader_mprotect_calls != 6) {
        result = 6;
        goto out;
    }
    if (!mapping_has_protection(target, 2 * page_size, PROT_READ) ||
        !mapping_has_protection(target + 2 * page_size, page_size,
                                PROT_WRITE) ||
        !mapping_has_protection(target + 3 * page_size, page_size,
                                PROT_READ | PROT_WRITE | PROT_EXEC) ||
        !mapping_has_protection(target + 4 * page_size, page_size,
                                PROT_NONE) ||
        !mapping_has_protection(target + 5 * page_size, page_size,
                                PROT_READ | PROT_WRITE) ||
        !mapping_has_protection(target + 6 * page_size, 4 * page_size,
                                PROT_NONE)) {
        result = 7;
        goto out;
    }
    if (!child_read_faults(target + 4 * page_size) ||
        !child_read_faults(target + 6 * page_size) ||
        !child_store_succeeds(target + 2 * page_size) ||
        !child_store_succeeds(target + 3 * page_size) ||
        !child_store_succeeds(target + 5 * page_size) ||
        !child_write_faults(target)) {
        result = 8;
        goto out;
    }
    for (size_t i = 0; i < partial_filesz; i++) {
        if (target[i] != 0xa5) {
            result = 9;
            goto out;
        }
    }
    /* The partial file/BSS page tail, the following full BSS portion, and
     * the pure-BSS PT_LOAD all come from the fresh anonymous reservation. */
    for (size_t i = partial_filesz; i < 2 * page_size; i++) {
        if (target[i] != 0) {
            result = 10;
            goto out;
        }
    }
    for (size_t i = 0; i < rwx_filesz; i++) {
        if (target[3 * page_size + i] != 0xc7) {
            result = 11;
            goto out;
        }
    }
    for (size_t i = rwx_filesz; i < page_size; i++) {
        if (target[3 * page_size + i] != 0) {
            result = 12;
            goto out;
        }
    }
    for (size_t i = 0; i < page_size; i++) {
        if (target[5 * page_size + i] != 0) {
            result = 13;
            goto out;
        }
    }
    result = 0;

out:
    if (object.runtime_reservation || object.runtime_phdr_mapping) {
        dl_release_runtime_mapping(&object);
        target = MAP_FAILED;
    }
    if (target != MAP_FAILED)
        munmap(target, reservation_size);
    if (source != MAP_FAILED)
        munmap(source, source_size);
    return result;
}

int main(void)
{
    const struct rlimit no_core = {0, 0};
    long page_size_long = sysconf(_SC_PAGESIZE);
    size_t page_size;
    size_t source_size;
    size_t reservation_size;
    size_t data_filesz;
    unsigned char *source = MAP_FAILED;
    unsigned char *target = MAP_FAILED;
    Elf64_Ehdr *ehdr;
    Elf64_Phdr *phdr;
    struct dlfrz_entry entry = {0};
    struct dlfrz_lib_meta meta = {0};
    struct loaded_obj object = {0};
    int result = 1;

    if (setrlimit(RLIMIT_CORE, &no_core) != 0)
        return 2;
    if (page_size_long < 4096 || page_size_long > 65536 ||
        (page_size_long & (page_size_long - 1)) != 0)
        return 3;
    page_size = (size_t)page_size_long;
    source_size = 3 * page_size;
    reservation_size = 9 * page_size;
    data_filesz = page_size / 2 + 37;
    g_page_size = page_size;

    source = mmap(NULL, source_size, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    target = mmap(NULL, reservation_size, PROT_NONE,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (source == MAP_FAILED || target == MAP_FAILED) {
        result = 4;
        goto out;
    }
    memset(source, 0x5a, source_size);
    memset(source + page_size, 0x6b, page_size);
    memset(source + 2 * page_size, 0x3c, data_filesz);

    ehdr = (Elf64_Ehdr *)source;
    phdr = (Elf64_Phdr *)(source + sizeof(*ehdr));
    memset(ehdr, 0, sizeof(*ehdr));
    memset(phdr, 0, 5 * sizeof(*phdr));
    memcpy(ehdr->e_ident, ELFMAG, SELFMAG);
    ehdr->e_phoff = sizeof(*ehdr);
    ehdr->e_phnum = 5;
    ehdr->e_phentsize = sizeof(*phdr);

    phdr[0].p_type = PT_LOAD;
    phdr[0].p_flags = PF_R;
    phdr[0].p_offset = 0;
    phdr[0].p_vaddr = 0;
    phdr[0].p_filesz = page_size;
    phdr[0].p_memsz = page_size;
    phdr[0].p_align = page_size;

    phdr[1].p_type = PT_LOAD;
    phdr[1].p_flags = PF_R | PF_X;
    phdr[1].p_offset = page_size;
    phdr[1].p_vaddr = page_size;
    phdr[1].p_filesz = page_size;
    phdr[1].p_memsz = page_size;
    phdr[1].p_align = page_size;

    phdr[2].p_type = PT_LOAD;
    phdr[2].p_flags = PF_R | PF_W;
    phdr[2].p_offset = 2 * page_size;
    phdr[2].p_vaddr = 3 * page_size;
    phdr[2].p_filesz = data_filesz;
    phdr[2].p_memsz = 2 * page_size;
    phdr[2].p_align = page_size;

    phdr[3].p_type = PT_GNU_RELRO;
    phdr[3].p_flags = PF_R;
    phdr[3].p_vaddr = 3 * page_size;
    phdr[3].p_memsz = page_size;
    phdr[3].p_align = page_size;

    phdr[4].p_type = PT_GNU_STACK;
    phdr[4].p_flags = PF_R | PF_W;

    entry.data_size = source_size;
    meta.base_addr = (uintptr_t)target;
    meta.vaddr_lo = 0;
    meta.vaddr_hi = 5 * page_size;
    meta.phdr_off = sizeof(*ehdr);
    meta.phdr_num = ehdr->e_phnum;
    meta.phdr_entsz = sizeof(*phdr);
    meta.flags = DLFRZ_FLAG_SHLIB;
    object.runtime_reservation = target;
    object.runtime_reservation_size = reservation_size;

    /* Force the anonymous-copy producer.  It must restore the first PT_LOAD
     * to PF_R, expose both data/BSS pages as PF_W, and zero the complete BSS
     * before protect_object is ever called. */
    g_loader_mprotect_calls = 0;
    if (map_object(source, 0, -1, 0, &meta, &entry, &object, 1) < 0) {
        result = 5;
        goto out;
    }
    /* The adjacent R/RX pages use one writable population run; the data/BSS
     * pair uses the second.  Finalizing R, RX, and the PHDR snapshot adds
     * three calls, while the already-final RW segment needs no transition. */
    if (g_loader_mprotect_calls != 5 ||
        !child_write_faults(target) ||
        !child_write_faults(target + page_size) ||
        target[page_size - 1] != 0x5a ||
        target[2 * page_size - 1] != 0x6b) {
        result = 6;
        goto out;
    }
    /* The one-page hole separating executable and writable runs must never
     * become readable as a side effect of coalescing. */
    if (!child_read_faults(target + 2 * page_size)) {
        result = 7;
        goto out;
    }
    for (size_t i = 0; i < data_filesz; i++) {
        if (target[3 * page_size + i] != 0x3c) {
            result = 8;
            goto out;
        }
    }
    for (size_t i = data_filesz; i < 2 * page_size; i++) {
        if (target[3 * page_size + i] != 0) {
            result = 9;
            goto out;
        }
    }

    /* RELRO remains writable through relocation time. */
    target[3 * page_size + 8] = 0x71;
    target[4 * page_size + 8] = 0x72;

    g_loader_mprotect_calls = 0;
    if (protect_object(&object, &meta) < 0 ||
        g_loader_mprotect_calls != 1) {
        result = 10;
        goto out;
    }

    /* Sealing changes only the complete RELRO page.  PT_LOAD permissions
     * remain producer-owned and the following ordinary data page stays RW. */
    if (!child_write_faults(target + 3 * page_size + 8) ||
        !child_write_faults(target) ||
        target[4 * page_size + 8] != 0x72) {
        result = 11;
        goto out;
    }
    target[4 * page_size + 8] = 0x73;
    if (target[4 * page_size + 8] != 0x73)
        result = 12;
    else
        result = 0;

out:
    if (object.runtime_reservation || object.runtime_phdr_mapping) {
        dl_release_runtime_mapping(&object);
        target = MAP_FAILED;
    }
    if (target != MAP_FAILED)
        munmap(target, reservation_size);
    if (source != MAP_FAILED)
        munmap(source, source_size);
    if (result != 0)
        return result;

    result = run_anonymous_edge_case(page_size);
    if (result != 0)
        return 20 + result;

    /* A 64-KiB target page is a valid loader contract even when this host
     * kernel uses 4-KiB pages.  An explicitly aligned reservation makes the
     * larger geometry safe to exercise without relying on mmap placement. */
    if (page_size < 65536) {
        result = run_anonymous_edge_case(65536);
        if (result != 0)
            return 40 + result;
    }
    result = run_anonymous_malformed_gate(page_size);
    if (result != 0)
        return 60 + result;
    result = run_reservation_transaction_gate(page_size);
    if (result != 0)
        return 70 + result;
    return 0;
}
