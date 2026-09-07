#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#define main dlfreeze_embedded_bootstrap_main
#include "../src/bootstrap.c"
#undef main

static int expect_value(const char *label, int actual, int expected)
{
    if (!!actual == !!expected)
        return 1;
    fprintf(stderr, "%s: got %d, expected %d\n",
            label, !!actual, !!expected);
    return 0;
}

static struct bs_live_phdr_table phdr_view(Elf64_Phdr *phdrs, size_t count)
{
    struct bs_live_phdr_table view = {
        .bytes = (const unsigned char *)phdrs,
        .live_address = (uintptr_t)phdrs,
        .count = count,
        .entsize = sizeof(*phdrs),
    };

    return view;
}

static void fixed_phdrs(Elf64_Phdr phdrs[3],
                        struct bs_live_phdr_table *view,
                        uint64_t *payload_vaddr,
                        uint64_t *payload_foff)
{
    const uint64_t table_address = (uint64_t)(uintptr_t)phdrs;
    const uint64_t table_delta = 0x100;
    const uint64_t payload_delta = 0x1000;

    memset(phdrs, 0, 3 * sizeof(*phdrs));
    *view = phdr_view(phdrs, 2);
    phdrs[0].p_type = PT_LOAD;
    phdrs[0].p_flags = PF_R;
    phdrs[0].p_offset = 0x2000;
    phdrs[0].p_vaddr = table_address - table_delta;
    phdrs[0].p_filesz = 0x4000;
    phdrs[0].p_memsz = 0x5000;
    phdrs[0].p_align = 1;
    *payload_vaddr = phdrs[0].p_vaddr + payload_delta;
    *payload_foff = phdrs[0].p_offset + payload_delta;
}

static void pie_phdrs(Elf64_Phdr phdrs[3],
                      struct bs_live_phdr_table *view,
                      uint64_t *payload_vaddr,
                      uint64_t *payload_foff)
{
    uint64_t load_bias;

    memset(phdrs, 0, 3 * sizeof(*phdrs));
    *view = phdr_view(phdrs, 2);
    phdrs[0].p_type = PT_LOAD;
    phdrs[0].p_flags = PF_R;
    phdrs[0].p_offset = 0;
    phdrs[0].p_vaddr = 0x1000;
    phdrs[0].p_filesz = 0x9000;
    phdrs[0].p_memsz = 0xa000;
    phdrs[0].p_align = 0x1000;
    phdrs[1].p_type = PT_PHDR;
    phdrs[1].p_flags = PF_R;
    phdrs[1].p_offset = 0x100;
    phdrs[1].p_vaddr = 0x1100;
    phdrs[1].p_filesz = 2 * sizeof(*phdrs);
    phdrs[1].p_memsz = phdrs[1].p_filesz;

    load_bias = (uint64_t)view->live_address - phdrs[1].p_vaddr;
    *payload_foff = 0x5000;
    *payload_vaddr = load_bias + phdrs[0].p_vaddr + *payload_foff;
}

static int phdr_translation_gate(void)
{
    Elf64_Phdr phdrs[3];
    struct bs_live_phdr_table view;
    uint64_t payload_vaddr;
    uint64_t payload_foff;
    const uint64_t payload_size = 0x800;
    int ok = 1;

    fixed_phdrs(phdrs, &view, &payload_vaddr, &payload_foff);
    ok &= expect_value(
        "fixed executable exact translation",
        bs_mapped_payload_file_translation(
            &view, payload_vaddr, payload_size, payload_foff), 1);
    ok &= expect_value(
        "fixed executable mapped readability",
        bs_mapped_range_is_readable(&view, payload_vaddr, payload_size), 1);

    pie_phdrs(phdrs, &view, &payload_vaddr, &payload_foff);
    ok &= expect_value(
        "PIE exact PT_PHDR load bias",
        bs_mapped_payload_file_translation(
            &view, payload_vaddr, payload_size, payload_foff), 1);
    ok &= expect_value(
        "PIE mapped readability",
        bs_mapped_range_is_readable(&view, payload_vaddr, payload_size), 1);

    ok &= expect_value(
        "wrong live payload address",
        bs_mapped_payload_file_translation(
            &view, payload_vaddr + 1, payload_size, payload_foff), 0);
    ok &= expect_value(
        "wrong payload file offset",
        bs_mapped_payload_file_translation(
            &view, payload_vaddr, payload_size, payload_foff + 1), 0);

    pie_phdrs(phdrs, &view, &payload_vaddr, &payload_foff);
    view.live_address++;
    ok &= expect_value(
        "wrong load bias",
        bs_mapped_payload_file_translation(
            &view, payload_vaddr, payload_size, payload_foff), 0);

    pie_phdrs(phdrs, &view, &payload_vaddr, &payload_foff);
    phdrs[1].p_offset++;
    ok &= expect_value(
        "PT_PHDR offset disagrees with owning LOAD",
        bs_mapped_payload_file_translation(
            &view, payload_vaddr, payload_size, payload_foff), 0);
    ok &= expect_value(
        "misowned PT_PHDR cannot authorize mapped footer read",
        bs_mapped_range_is_readable(
            &view, payload_vaddr, payload_size), 0);

    fixed_phdrs(phdrs, &view, &payload_vaddr, &payload_foff);
    phdrs[0].p_filesz = payload_foff - phdrs[0].p_offset +
                        payload_size - 1;
    ok &= expect_value(
        "payload extends beyond p_filesz",
        bs_mapped_payload_file_translation(
            &view, payload_vaddr, payload_size, payload_foff), 0);
    ok &= expect_value(
        "mem-only payload remains mapped compatibility authority",
        bs_mapped_range_is_readable(&view, payload_vaddr, payload_size), 1);

    fixed_phdrs(phdrs, &view, &payload_vaddr, &payload_foff);
    phdrs[0].p_flags = PF_W;
    ok &= expect_value(
        "non-readable payload LOAD",
        bs_mapped_payload_file_translation(
            &view, payload_vaddr, payload_size, payload_foff), 0);

    fixed_phdrs(phdrs, &view, &payload_vaddr, &payload_foff);
    phdrs[0].p_filesz = phdrs[0].p_memsz + 1;
    ok &= expect_value(
        "p_filesz exceeds p_memsz",
        bs_mapped_payload_file_translation(
            &view, payload_vaddr, payload_size, payload_foff), 0);

    fixed_phdrs(phdrs, &view, &payload_vaddr, &payload_foff);
    phdrs[0].p_offset = UINT64_MAX - 0x10;
    phdrs[0].p_filesz = 0x20;
    phdrs[0].p_memsz = 0x20;
    ok &= expect_value(
        "overflowing LOAD file extent",
        bs_mapped_payload_file_translation(
            &view, payload_vaddr, payload_size, payload_foff), 0);

    fixed_phdrs(phdrs, &view, &payload_vaddr, &payload_foff);
    phdrs[0].p_align = 3;
    ok &= expect_value(
        "non-power-of-two LOAD alignment",
        bs_mapped_payload_file_translation(
            &view, payload_vaddr, payload_size, payload_foff), 0);

    fixed_phdrs(phdrs, &view, &payload_vaddr, &payload_foff);
    view.count = 3;
    phdrs[2].p_type = PT_LOAD;
    phdrs[2].p_flags = PF_R;
    phdrs[2].p_offset = payload_foff;
    phdrs[2].p_vaddr = payload_vaddr;
    phdrs[2].p_filesz = payload_size;
    phdrs[2].p_memsz = payload_size;
    phdrs[2].p_align = 1;
    ok &= expect_value(
        "ambiguous overlapping payload LOADs",
        bs_mapped_payload_file_translation(
            &view, payload_vaddr, payload_size, payload_foff), 0);

    pie_phdrs(phdrs, &view, &payload_vaddr, &payload_foff);
    view.count = 3;
    phdrs[1].p_filesz = view.count * sizeof(*phdrs);
    phdrs[1].p_memsz = phdrs[1].p_filesz;
    phdrs[2] = phdrs[1];
    ok &= expect_value(
        "duplicate PT_PHDR",
        bs_mapped_payload_file_translation(
            &view, payload_vaddr, payload_size, payload_foff), 0);
    ok &= expect_value(
        "duplicate PT_PHDR cannot authorize mapped footer read",
        bs_mapped_range_is_readable(
            &view, payload_vaddr, payload_size), 0);

    pie_phdrs(phdrs, &view, &payload_vaddr, &payload_foff);
    phdrs[1].p_filesz = sizeof(*phdrs);
    phdrs[1].p_memsz = phdrs[1].p_filesz;
    ok &= expect_value(
        "undersized PT_PHDR cannot authorize mapped footer read",
        bs_mapped_range_is_readable(
            &view, payload_vaddr, payload_size), 0);

    fixed_phdrs(phdrs, &view, &payload_vaddr, &payload_foff);
    view.entsize--;
    ok &= expect_value(
        "malformed program-header stride",
        bs_mapped_payload_file_translation(
            &view, payload_vaddr, payload_size, payload_foff), 0);
    return ok;
}

struct synthetic_initial_stack {
    char *environment[2];
    Elf64_auxv_t auxiliary[BS_MAX_AUXV_ENTRIES];
};

static void initialize_auxv(struct synthetic_initial_stack *stack,
                            Elf64_Phdr *phdrs, size_t phdr_count)
{
    memset(stack, 0, sizeof(*stack));
    stack->environment[0] = (char *)"X=1";
    stack->auxiliary[0].a_type = AT_PHDR;
    stack->auxiliary[0].a_un.a_val = (uintptr_t)phdrs;
    stack->auxiliary[1].a_type = AT_PHNUM;
    stack->auxiliary[1].a_un.a_val = phdr_count;
    stack->auxiliary[2].a_type = AT_PHENT;
    stack->auxiliary[2].a_un.a_val = sizeof(*phdrs);
    stack->auxiliary[3].a_type = AT_NULL;
}

static int auxv_gate(void)
{
    struct synthetic_initial_stack stack;
    struct bs_live_phdr_table view;
    Elf64_Phdr phdrs[2] = {{0}};
    int ok = 1;

    initialize_auxv(&stack, phdrs, 2);
    ok &= expect_value(
        "bounded auxv program-header view",
        bs_live_phdr_table_from_env(stack.environment, &view), 1);
    if (view.bytes != (const unsigned char *)phdrs || view.count != 2 ||
        view.entsize != sizeof(*phdrs)) {
        fprintf(stderr, "auxv view did not preserve exact geometry\n");
        ok = 0;
    }

    initialize_auxv(&stack, phdrs, 2);
    stack.auxiliary[3] = stack.auxiliary[0];
    stack.auxiliary[4].a_type = AT_NULL;
    ok &= expect_value(
        "duplicate AT_PHDR",
        bs_live_phdr_table_from_env(stack.environment, &view), 0);

    initialize_auxv(&stack, phdrs, 2);
    stack.auxiliary[2].a_un.a_val--;
    ok &= expect_value(
        "wrong AT_PHENT",
        bs_live_phdr_table_from_env(stack.environment, &view), 0);

    memset(&stack, 0, sizeof(stack));
    stack.environment[0] = (char *)"X=1";
    for (size_t i = 0; i < BS_MAX_AUXV_ENTRIES; i++) {
        stack.auxiliary[i].a_type = AT_PAGESZ;
        stack.auxiliary[i].a_un.a_val = 4096;
    }
    ok &= expect_value(
        "unterminated bounded auxv",
        bs_live_phdr_table_from_env(stack.environment, &view), 0);
    return ok;
}

static int smaps_match_bytes(const void *bytes, size_t size,
                             const struct stat *executable,
                             uint64_t payload_vaddr,
                             uint64_t payload_filesz,
                             uint64_t payload_foff)
{
    FILE *stream = fmemopen((void *)bytes, size, "r");
    int result;

    if (!stream)
        return 0;
    result = bs_payload_smaps_stream_matches(
        stream, executable, payload_vaddr, payload_filesz, payload_foff);
    fclose(stream);
    return result;
}

static int smaps_match_text(const char *text, const struct stat *executable,
                            uint64_t payload_vaddr,
                            uint64_t payload_filesz,
                            uint64_t payload_foff)
{
    return smaps_match_bytes(text, strlen(text), executable,
                             payload_vaddr, payload_filesz, payload_foff);
}

static int smaps_gate(void)
{
    const uint64_t payload_vaddr = 0x4100;
    const uint64_t payload_filesz = 0x1800;
    const uint64_t payload_foff = 0x2100;
    struct stat executable = {0};
    char exact[1024];
    char split[2048];
    char altered[2048];
    int ok = 1;

    executable.st_dev = makedev(8, 3);
    executable.st_ino = 1234567;
    snprintf(exact, sizeof(exact),
             "4000-6000 r--p 2000 %x:%x %llu /frozen image\n"
             "Size:                  8 kB\n"
             "Private_Dirty:         0 kB\n"
             "Anonymous:             0 kB\n"
             "Swap:                  0 kB\n"
             "VmFlags: rd mr mw me sd\n",
             major(executable.st_dev), minor(executable.st_dev),
             (unsigned long long)executable.st_ino);
    ok &= expect_value(
        "one exact clean smaps VMA",
        smaps_match_text(exact, &executable, payload_vaddr,
                         payload_filesz, payload_foff), 1);

    snprintf(split, sizeof(split),
             "4000-5000 r--p 2000 %x:%x %llu /frozen\n"
             "Private_Dirty: 0 kB\nAnonymous: 0 kB\nSwap: 0 kB\n"
             "VmFlags: rd mr mw me\n"
             "5000-7000 r--p 3000 %x:%x %llu /frozen\n"
             "Private_Dirty: 0 kB\nAnonymous: 0 kB\nSwap: 0 kB\n"
             "VmFlags: rd mr mw me\n",
             major(executable.st_dev), minor(executable.st_dev),
             (unsigned long long)executable.st_ino,
             major(executable.st_dev), minor(executable.st_dev),
             (unsigned long long)executable.st_ino);
    ok &= expect_value(
        "adjacent clean smaps VMAs require per-VMA evidence",
        smaps_match_text(split, &executable, payload_vaddr,
                         payload_filesz, payload_foff), 1);

#define EXPECT_SMAPS_REJECT(label, old_text, new_text) do {                 \
        size_t old_length = strlen(old_text);                               \
        const char *position = strstr(exact, old_text);                     \
        if (!position || old_length != strlen(new_text))                    \
            return 0;                                                       \
        memcpy(altered, exact, strlen(exact) + 1);                          \
        memcpy(altered + (position - exact), new_text, old_length);         \
        ok &= expect_value(label,                                            \
            smaps_match_text(altered, &executable, payload_vaddr,           \
                             payload_filesz, payload_foff), 0);              \
    } while (0)

    EXPECT_SMAPS_REJECT("COW Anonymous evidence", "Anonymous:             0",
                        "Anonymous:             4");
    EXPECT_SMAPS_REJECT("swapped COW evidence", "Swap:                  0",
                        "Swap:                  4");
    EXPECT_SMAPS_REJECT("userfaultfd missing registration", "me sd",
                        "me um");
    EXPECT_SMAPS_REJECT("userfaultfd write-protect registration", "me sd",
                        "me uw");
    EXPECT_SMAPS_REJECT("userfaultfd minor registration", "me sd",
                        "me ui");
    EXPECT_SMAPS_REJECT("unknown future VmFlags token", "me sd",
                        "me zz");

    memcpy(altered, exact, strlen(exact) + 1);
    {
        char *dirty = strstr(altered, "Private_Dirty:         0");

        if (!dirty)
            return 0;
        dirty[strlen("Private_Dirty:         ")] = '4';
    }
    ok &= expect_value(
        "file page-cache dirty accounting is not COW evidence",
        smaps_match_text(altered, &executable, payload_vaddr,
                         payload_filesz, payload_foff), 1);

    memcpy(altered, exact, strlen(exact) + 1);
    {
        char *vmflags = strstr(altered, "VmFlags:");

        if (!vmflags)
            return 0;
        memcpy(vmflags, "NoFlags:", sizeof("NoFlags:") - 1);
    }
    ok &= expect_value(
        "missing VmFlags proof",
        smaps_match_text(altered, &executable, payload_vaddr,
                         payload_filesz, payload_foff), 0);

    memcpy(altered, exact, strlen(exact) + 1);
    {
        char *anonymous = strstr(altered, "Anonymous:");

        if (!anonymous)
            return 0;
        memcpy(anonymous, "Noonymous:", sizeof("Noonymous:") - 1);
    }
    ok &= expect_value(
        "missing Anonymous proof",
        smaps_match_text(altered, &executable, payload_vaddr,
                         payload_filesz, payload_foff), 0);

    memcpy(altered, exact, strlen(exact) + 1);
    {
        char *swap = strstr(altered, "Swap:");

        if (!swap)
            return 0;
        memcpy(swap, "Noap:", sizeof("Noap:") - 1);
    }
    ok &= expect_value(
        "missing Swap proof",
        smaps_match_text(altered, &executable, payload_vaddr,
                         payload_filesz, payload_foff), 0);

    snprintf(altered, sizeof(altered),
             "4000-6000 r--p 2000 %x:%x %llu /frozen\n"
             "Anonymous: 0 kB\nAnonymous: 0 kB\nSwap: 0 kB\n"
             "VmFlags: rd mr mw me\n",
             major(executable.st_dev), minor(executable.st_dev),
             (unsigned long long)executable.st_ino);
    ok &= expect_value(
        "duplicate Anonymous proof",
        smaps_match_text(altered, &executable, payload_vaddr,
                         payload_filesz, payload_foff), 0);

    snprintf(altered, sizeof(altered),
             "4000-6000 r--p 2000 %x:%x %llu /frozen\n"
             "Anonymous: 0 kB\nSwap: 0 kB\nSwap: 0 kB\n"
             "VmFlags: rd mr mw me\n",
             major(executable.st_dev), minor(executable.st_dev),
             (unsigned long long)executable.st_ino);
    ok &= expect_value(
        "duplicate Swap proof",
        smaps_match_text(altered, &executable, payload_vaddr,
                         payload_filesz, payload_foff), 0);

    snprintf(altered, sizeof(altered),
             "4000-5000 r--p 2000 %x:%x %llu /frozen\n"
             "Private_Dirty: 0 kB\nAnonymous: 0 kB\nSwap: 0 kB\n"
             "VmFlags: rd mr mw me\n"
             "5100-7000 r--p 3100 %x:%x %llu /frozen\n"
             "Private_Dirty: 0 kB\nAnonymous: 0 kB\nSwap: 0 kB\n"
             "VmFlags: rd mr mw me\n",
             major(executable.st_dev), minor(executable.st_dev),
             (unsigned long long)executable.st_ino,
             major(executable.st_dev), minor(executable.st_dev),
             (unsigned long long)executable.st_ino);
    ok &= expect_value(
        "smaps VMA gap",
        smaps_match_text(altered, &executable, payload_vaddr,
                         payload_filesz, payload_foff), 0);

    memcpy(altered, exact, strlen(exact) + 1);
    {
        char *value = strstr(altered, "Anonymous:             0 kB");

        if (!value)
            return 0;
        memcpy(value, "Anonymous:             x kB",
               sizeof("Anonymous:             x kB") - 1);
    }
    ok &= expect_value(
        "malformed smaps numeric field",
        smaps_match_text(altered, &executable, payload_vaddr,
                         payload_filesz, payload_foff), 0);

    {
        size_t exact_length = strlen(exact);

        memcpy(altered, exact, exact_length);
        altered[8] = '\0';
        ok &= expect_value(
            "embedded NUL in smaps stream",
            smaps_match_bytes(altered, exact_length, &executable,
                              payload_vaddr, payload_filesz,
                              payload_foff), 0);
    }
#undef EXPECT_SMAPS_REJECT
    return ok;
}

static int live_smaps_match(const void *mapping, size_t length,
                            const struct stat *status, uint64_t file_offset)
{
    FILE *stream = fopen("/proc/self/smaps", "r");
    int result;

    if (!stream)
        return 0;
    result = bs_payload_smaps_stream_matches(
        stream, status, (uint64_t)(uintptr_t)mapping, length, file_offset);
    fclose(stream);
    return result;
}

static int live_cow_smaps_gate(void)
{
    long page_value = sysconf(_SC_PAGESIZE);
    unsigned char byte = 0x5a;
    unsigned char *mapping = MAP_FAILED;
    struct stat status;
    FILE *source = NULL;
    int cow_was_visible;
    int fd = -1;
    int ok = 0;

    if (page_value <= 0)
        return 0;
    source = tmpfile();
    if (!source)
        return 0;
    fd = fileno(source);
    if (ftruncate(fd, page_value) < 0 ||
        pwrite(fd, &byte, 1, 0) != 1 ||
        fstat(fd, &status) < 0)
        goto out;
    mapping = mmap(NULL, (size_t)page_value, PROT_READ,
                   MAP_PRIVATE, fd, 0);
    if (mapping == MAP_FAILED ||
        !live_smaps_match(mapping, (size_t)page_value, &status, 0) ||
        mprotect(mapping, (size_t)page_value, PROT_READ | PROT_WRITE) < 0)
        goto out;
    mapping[0] ^= 0xff;
    if (mprotect(mapping, (size_t)page_value, PROT_READ) < 0)
        goto out;
    cow_was_visible = !live_smaps_match(
        mapping, (size_t)page_value, &status, 0);
    if (madvise(mapping, (size_t)page_value, MADV_DONTNEED) < 0 ||
        mapping[0] != byte ||
        !live_smaps_match(mapping, (size_t)page_value, &status, 0)) {
        fprintf(stderr, "discarded COW payload did not regain clean proof\n");
        goto out;
    }
    /* qemu-user and other syscall-virtualizing environments may expose a
     * synthetic smaps view that cannot observe guest COW state.  That makes
     * this live-kernel cross-check unavailable, not authoritative; the
     * synthetic cases above still require COW evidence to be rejected. */
    (void)cow_was_visible;
    ok = 1;

out:
    if (mapping != MAP_FAILED)
        munmap(mapping, (size_t)page_value);
    if (source)
        fclose(source);
    return ok;
}

static int procfs_provenance_gate(void)
{
    char fake_root[] = "/tmp/dlfreeze-fake-proc-XXXXXX";
    struct bs_proc_self_context context;
    struct stat executable_status;
    int executable_fd = -1;
    int ok = 0;

    if (bs_proc_self_context_open_at("/proc", &context) < 0)
        return 0;
    bs_proc_self_context_close(&context);

    executable_fd = bs_verified_proc_self_executable_open_at("/proc");
    if (executable_fd < 0 || fstat(executable_fd, &executable_status) < 0 ||
        !S_ISREG(executable_status.st_mode) || executable_status.st_ino == 0)
        goto out;
    close(executable_fd);
    executable_fd = -1;

    if (!mkdtemp(fake_root))
        goto out;
    if (bs_proc_self_context_open_at(fake_root, &context) == 0) {
        bs_proc_self_context_close(&context);
        goto remove_fake;
    }
    executable_fd = bs_verified_proc_self_executable_open_at(fake_root);
    if (executable_fd >= 0)
        goto remove_fake;
    ok = 1;

remove_fake:
    if (rmdir(fake_root) < 0)
        ok = 0;
out:
    if (executable_fd >= 0)
        close(executable_fd);
    return ok;
}

int main(void)
{
    if (!phdr_translation_gate())
        return 1;
    if (!auxv_gate())
        return 2;
    if (!smaps_gate())
        return 3;
    if (!live_cow_smaps_gate())
        return 4;
    if (!procfs_provenance_gate())
        return 5;
    return 0;
}
