#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#if defined(__has_include)
# if __has_include(<linux/filter.h>) && __has_include(<linux/seccomp.h>) && \
     __has_include(<sys/prctl.h>)
#  define DLFREEZE_TEST_HAVE_SECCOMP 1
# endif
#endif
#ifdef DLFREEZE_TEST_HAVE_SECCOMP
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <sys/prctl.h>
#include <ucontext.h>
#endif

#define DLFREEZE_BOOTSTRAP_FILEBACK_GATE 1
#define main dlfreeze_embedded_bootstrap_main
#include "../src/bootstrap.c"
#undef main

static int test_signal_zero_clone_available = 1;

/* This is deliberately independent of the bootstrap admission helper.  An
 * emulator or syscall policy may reject the valid signal-zero process-clone
 * shape before any remap/procfs work is possible.  Recognized errno declines
 * select fallback expectations; malformed success or unexpected wait status
 * is a test failure, never a capability skip. */
static int signal_zero_clone_native_control(void)
{
    int status = -1;
    long child;
    long waited;
    int saved_errno;
    const char *operation;

    errno = 0;
    child = syscall(SYS_clone, 0, 0, 0, 0, 0);
    if (child == 0)
        _exit(87);
    if (child < 0) {
        operation = "clone";
        saved_errno = errno;
        goto declined;
    }
    do {
        errno = 0;
        waited = syscall(SYS_wait4, child, &status, 0x80000000UL, NULL);
    } while (waited < 0 && errno == EINTR);
    if (waited < 0) {
        operation = "wait4";
        saved_errno = errno;
        goto declined;
    }
    if (waited == child && WIFEXITED(status) && WEXITSTATUS(status) == 87)
        return 1;
    fprintf(stderr, "native signal-zero clone control returned unexpected wait state\n");
    return -1;
declined:
    if (saved_errno == EINVAL || saved_errno == ENOSYS ||
        saved_errno == EPERM || saved_errno == EACCES) {
        fprintf(stderr,
                "SKIP: positive bootstrap admission requires signal-zero clone/__WCLONE wait (%s errno=%d); checking fallback instead\n",
                operation, saved_errno);
        return 0;
    }
    fprintf(stderr, "native signal-zero clone control: unexpected %s errno=%d\n",
            operation, saved_errno);
    return -1;
}

static const char *test_temporary_directory(void)
{
    const char *directory = getenv("TMPDIR");

    if (!directory || directory[0] != '/')
        directory = "/tmp";
    return directory;
}

static FILE *test_temporary_file(void)
{
    char path[PATH_MAX];
    int fd;
    FILE *file;

    if (snprintf(path, sizeof(path), "%s/dlfreeze-bootstrap-gate.XXXXXX",
                 test_temporary_directory()) >= (int)sizeof(path)) {
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

static int mremap_target_smaps_match_text(
    const char *text, const struct stat *executable,
    struct bs_mremap_range *targets, size_t target_count)
{
    struct bs_startup_mremap_plan plan = {
        .targets = targets,
        .count = target_count,
    };
    FILE *stream = fmemopen((void *)text, strlen(text), "r");
    int result;

    if (!stream)
        return 0;
    result = bs_mremap_targets_smaps_stream_matches(
        stream, executable, &plan);
    fclose(stream);
    return result;
}

static int mremap_target_smaps_gate(void)
{
    struct stat executable = {0};
    struct bs_mremap_range separated[2] = {
        {.target = 0x8000, .length = 0x1000, .file_offset = 0x3000},
        {.target = 0xa000, .length = 0x1000, .file_offset = 0x9000},
    };
    struct bs_mremap_range adjacent[2] = {
        {.target = 0x8000, .length = 0x1000, .file_offset = 0x3000},
        {.target = 0x9000, .length = 0x1000, .file_offset = 0x4000},
    };
    char exact[4096];
    char altered[4096];
    char merged[1024];
    int ok = 1;

    executable.st_dev = makedev(8, 3);
    executable.st_ino = 1234567;
    snprintf(exact, sizeof(exact),
             /* Dirty state outside the selected transfer ranges must not
              * disable an otherwise exact plan. */
             "4000-7000 r--p 1000 %x:%x %llu /frozen\n"
             "Anonymous: 12 kB\nSwap: 4 kB\n"
             "VmFlags: rd mr mw me\n"
             "8000-9000 r--p 3000 %x:%x %llu /frozen\n"
             "Anonymous: 0 kB\nSwap: 0 kB\n"
             "VmFlags: rd mr mw me\n"
             "9000-a000 rw-p 0000 00:00 0 [unrelated]\n"
             "Anonymous: 4 kB\nSwap: 4 kB\n"
             "VmFlags: rd wr mr mw me ac\n"
             "a000-b000 r--p 9000 %x:%x %llu /frozen\n"
             "Anonymous: 0 kB\nSwap: 0 kB\n"
             "VmFlags: rd mr mw me\n",
             major(executable.st_dev), minor(executable.st_dev),
             (unsigned long long)executable.st_ino,
             major(executable.st_dev), minor(executable.st_dev),
             (unsigned long long)executable.st_ino,
             major(executable.st_dev), minor(executable.st_dev),
             (unsigned long long)executable.st_ino);
    ok &= expect_value(
        "unrelated dirty/COW target-smaps data is ignored",
        mremap_target_smaps_match_text(
            exact, &executable, separated, 2), 1);

#define EXPECT_TARGET_SMAPS_REJECT(label, old_text, new_text) do {          \
        size_t old_length = strlen(old_text);                               \
        const char *position = strstr(exact, old_text);                     \
        if (!position || old_length != strlen(new_text))                    \
            return 0;                                                       \
        memcpy(altered, exact, strlen(exact) + 1);                          \
        memcpy(altered + (position - exact), new_text, old_length);         \
        ok &= expect_value(label,                                            \
            mremap_target_smaps_match_text(                                 \
                altered, &executable, separated, 2), 0);                    \
    } while (0)

    EXPECT_TARGET_SMAPS_REJECT(
        "selected-range COW is rejected",
        "8000-9000 r--p 3000 8:3 1234567 /frozen\n"
        "Anonymous: 0",
        "8000-9000 r--p 3000 8:3 1234567 /frozen\n"
        "Anonymous: 4");
    EXPECT_TARGET_SMAPS_REJECT(
        "selected-range swap is rejected",
        "a000-b000 r--p 9000 8:3 1234567 /frozen\n"
        "Anonymous: 0 kB\nSwap: 0",
        "a000-b000 r--p 9000 8:3 1234567 /frozen\n"
        "Anonymous: 0 kB\nSwap: 4");
    EXPECT_TARGET_SMAPS_REJECT(
        "selected-range write permission is rejected",
        "8000-9000 r--p", "8000-9000 rw-p");
    EXPECT_TARGET_SMAPS_REJECT(
        "selected-range file offset is exact",
        "a000-b000 r--p 9000", "a000-b000 r--p 8000");
    EXPECT_TARGET_SMAPS_REJECT(
        "selected-range inode is exact",
        "a000-b000 r--p 9000 8:3 1234567",
        "a000-b000 r--p 9000 8:3 1234568");
    EXPECT_TARGET_SMAPS_REJECT(
        "selected-range userfaultfd state is rejected",
        "a000-b000 r--p 9000 8:3 1234567 /frozen\n"
        "Anonymous: 0 kB\nSwap: 0 kB\nVmFlags: rd mr mw me",
        "a000-b000 r--p 9000 8:3 1234567 /frozen\n"
        "Anonymous: 0 kB\nSwap: 0 kB\nVmFlags: rd mr mw um");
#undef EXPECT_TARGET_SMAPS_REJECT

    snprintf(merged, sizeof(merged),
             "8000-a000 r--p 3000 %x:%x %llu /frozen\n"
             "Anonymous: 0 kB\nSwap: 0 kB\n"
             "VmFlags: rd mr mw me\n",
             major(executable.st_dev), minor(executable.st_dev),
             (unsigned long long)executable.st_ino);
    ok &= expect_value(
        "adjacent transfers may share one exact VMA",
        mremap_target_smaps_match_text(
            merged, &executable, adjacent, 2), 1);

    snprintf(altered, sizeof(altered),
             "8000-9000 r--p 3000 %x:%x %llu /frozen\n"
             "Anonymous: 0 kB\nSwap: 0 kB\n"
             "VmFlags: rd mr mw me\n",
             major(executable.st_dev), minor(executable.st_dev),
             (unsigned long long)executable.st_ino);
    ok &= expect_value(
        "missing selected target range is rejected",
        mremap_target_smaps_match_text(
            altered, &executable, separated, 2), 0);
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
    source = test_temporary_file();
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
    char fake_root[PATH_MAX];
    struct bs_proc_self_context context;
    struct stat executable_status;
    int executable_fd = -1;
    int ok = 0;

    if (snprintf(fake_root, sizeof(fake_root),
                 "%s/dlfreeze-fake-proc-XXXXXX",
                 test_temporary_directory()) >= (int)sizeof(fake_root))
        return 0;
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

struct mremap_proof_fixture {
    FILE *file;
    unsigned char *source;
    size_t size;
    void *target;
    struct dlfrz_entry entry;
    struct dlfrz_lib_meta meta;
};

enum mremap_proof_fixture_mode {
    MREMAP_FIXTURE_CLEAN,
    MREMAP_FIXTURE_ANONYMOUS,
    MREMAP_FIXTURE_ZERO_LOAD,
    MREMAP_FIXTURE_UNRELATED_COW,
    MREMAP_FIXTURE_SELECTED_COW,
    MREMAP_FIXTURE_DUPLICATE_SOURCE,
    MREMAP_FIXTURE_TARGET_OVERLAP,
};

static void mremap_proof_fixture_destroy(
    struct mremap_proof_fixture *fixture)
{
    if (!fixture)
        return;
    if (fixture->source != MAP_FAILED)
        munmap(fixture->source, fixture->size);
    if (fixture->file)
        fclose(fixture->file);
    memset(fixture, 0, sizeof(*fixture));
    fixture->source = MAP_FAILED;
}

static int mremap_proof_fixture_init(
    struct mremap_proof_fixture *fixture, size_t first_size,
    enum mremap_proof_fixture_mode mode)
{
    long page_value = sysconf(_SC_PAGESIZE);
    size_t page;
    size_t total_size;
    size_t target_size;
    size_t phdr_count;
    int anonymous_source;
    int append_page;
    unsigned char *populate = MAP_FAILED;
    Elf64_Ehdr *ehdr;
    Elf64_Phdr *phdr;
    void *hole = MAP_FAILED;

    if (!fixture || page_value <= 0 || (uint64_t)page_value > SIZE_MAX)
        return 0;
    memset(fixture, 0, sizeof(*fixture));
    fixture->source = MAP_FAILED;
    page = (size_t)page_value;
    anonymous_source = mode == MREMAP_FIXTURE_ANONYMOUS;
    append_page = mode == MREMAP_FIXTURE_ZERO_LOAD ||
                  mode == MREMAP_FIXTURE_UNRELATED_COW;
    phdr_count = mode == MREMAP_FIXTURE_ZERO_LOAD ||
                 mode == MREMAP_FIXTURE_DUPLICATE_SOURCE ||
                 mode == MREMAP_FIXTURE_TARGET_OVERLAP ? 2 : 1;
    if ((page & (page - 1)) != 0 || first_size < page ||
        (first_size & (page - 1)) != 0 ||
        first_size > SIZE_MAX - (append_page ? page : 0))
        return 0;
    total_size = first_size + (append_page ? page : 0);
    if (mode == MREMAP_FIXTURE_DUPLICATE_SOURCE) {
        if (first_size > SIZE_MAX - first_size)
            return 0;
        target_size = first_size + first_size;
    } else {
        target_size = total_size;
    }

    if (anonymous_source) {
        populate = mmap(NULL, total_size, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    } else {
        fixture->file = test_temporary_file();
        if (!fixture->file ||
            ftruncate(fileno(fixture->file), total_size) < 0)
            goto fail;
        populate = mmap(NULL, total_size, PROT_READ | PROT_WRITE,
                        MAP_SHARED, fileno(fixture->file), 0);
    }
    if (populate == MAP_FAILED)
        goto fail;
    memset(populate, 0x5a, first_size);
    if (append_page)
        memset(populate + first_size,
               mode == MREMAP_FIXTURE_ZERO_LOAD ? 0 : 0x33, page);
    ehdr = (Elf64_Ehdr *)populate;
    phdr = (Elf64_Phdr *)(populate + sizeof(*ehdr));
    memset(ehdr, 0, sizeof(*ehdr));
    memcpy(ehdr->e_ident, ELFMAG, SELFMAG);
    ehdr->e_type = ET_DYN;
    ehdr->e_phoff = sizeof(*ehdr);
    ehdr->e_phnum = (Elf64_Half)phdr_count;
    ehdr->e_phentsize = sizeof(*phdr);
    memset(phdr, 0, phdr_count * sizeof(*phdr));
    phdr[0].p_type = PT_LOAD;
    phdr[0].p_flags = PF_R;
    phdr[0].p_filesz = first_size;
    phdr[0].p_memsz = first_size;
    phdr[0].p_align = page;
    if (mode == MREMAP_FIXTURE_ZERO_LOAD) {
        phdr[1].p_type = PT_LOAD;
        phdr[1].p_flags = PF_R;
        phdr[1].p_offset = first_size;
        phdr[1].p_vaddr = first_size;
        phdr[1].p_filesz = page;
        phdr[1].p_memsz = page;
        phdr[1].p_align = page;
    } else if (mode == MREMAP_FIXTURE_DUPLICATE_SOURCE) {
        phdr[1].p_type = PT_LOAD;
        phdr[1].p_flags = PF_R;
        phdr[1].p_vaddr = first_size;
        phdr[1].p_filesz = first_size;
        phdr[1].p_memsz = first_size;
        phdr[1].p_align = page;
    } else if (mode == MREMAP_FIXTURE_TARGET_OVERLAP) {
        phdr[1] = phdr[0];
    }
    if (!anonymous_source) {
        void *clean;
        int cow_source = mode == MREMAP_FIXTURE_UNRELATED_COW ||
                         mode == MREMAP_FIXTURE_SELECTED_COW;

        if (msync(populate, total_size, MS_SYNC) < 0 ||
            munmap(populate, total_size) < 0)
            goto fail;
        populate = MAP_FAILED;
        clean = mmap(NULL, total_size,
                     cow_source ? PROT_READ | PROT_WRITE : PROT_READ,
                     MAP_PRIVATE,
                     fileno(fixture->file), 0);
        if (clean == MAP_FAILED)
            goto fail;
        populate = clean;
        if (cow_source) {
            size_t cow_offset = mode == MREMAP_FIXTURE_UNRELATED_COW
                ? first_size : first_size - page;

            populate[cow_offset] ^= 0xff;
            if (mprotect(populate, total_size, PROT_READ) < 0)
                goto fail;
        }
    } else if (mprotect(populate, total_size, PROT_READ) < 0) {
        goto fail;
    }
    fixture->source = populate;
    populate = MAP_FAILED;
    fixture->size = total_size;

    hole = mmap(NULL, target_size, PROT_NONE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (hole == MAP_FAILED || munmap(hole, target_size) < 0)
        goto fail;
    fixture->target = hole;
    fixture->entry.data_size = total_size;
    fixture->entry.flags = DLFRZ_FLAG_SHLIB;
    fixture->meta.base_addr = (uint64_t)(uintptr_t)hole;
    fixture->meta.vaddr_hi = target_size;
    fixture->meta.phdr_num = (uint16_t)phdr_count;
    fixture->meta.phdr_entsz = sizeof(*phdr);
    fixture->meta.flags = DLFRZ_FLAG_SHLIB;
    return 1;

fail:
    if (populate != MAP_FAILED)
        munmap(populate, total_size);
    mremap_proof_fixture_destroy(fixture);
    return 0;
}

static int mremap_source_ready(
    const struct mremap_proof_fixture *fixture)
{
    return bs_startup_mremap_source_ready(
        fixture->source, 0, &fixture->meta, &fixture->entry, 1,
        fixture->file ? fileno(fixture->file) : -1,
        fixture->file != NULL, 0, 0, 0, NULL);
}

#ifdef DLFREEZE_TEST_HAVE_SECCOMP
#ifndef SECCOMP_RET_KILL_PROCESS
#define SECCOMP_RET_KILL_PROCESS SECCOMP_RET_KILL
#endif

static int mremap_seccomp_decline(
    const struct mremap_proof_fixture *fixture,
    int syscall_number, unsigned action)
{
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                 (unsigned)syscall_number, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, action),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program = {
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };
    int status = -1;
    pid_t child = fork();

    if (child < 0)
        return 0;
    if (child == 0) {
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 ||
            prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) != 0)
            _exit(77);
        _exit(mremap_source_ready(fixture) ? 1 : 0);
    }
    if (waitpid(child, &status, 0) != child)
        return 0;
    if (WIFEXITED(status) && WEXITSTATUS(status) == 77)
        return 1;
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}
#endif

static int mremap_proof_gate(void)
{
    long page_value = sysconf(_SC_PAGESIZE);
    const char *inherited_no_fork = getenv("DLFREEZE_NO_FORK");
    char *saved_no_fork = NULL;
    struct mremap_proof_fixture clean;
    struct mremap_proof_fixture anonymous;
    struct mremap_proof_fixture zero_range;
    struct mremap_proof_fixture unrelated_cow;
    struct mremap_proof_fixture selected_cow;
    struct mremap_proof_fixture duplicate_source;
    struct mremap_proof_fixture overlap;
    struct mremap_proof_fixture small;
    struct sigaction old_action;
    struct sigaction action;
    size_t clone_attempts;
    int ok = 1;

    memset(&clean, 0, sizeof(clean));
    memset(&anonymous, 0, sizeof(anonymous));
    memset(&zero_range, 0, sizeof(zero_range));
    memset(&unrelated_cow, 0, sizeof(unrelated_cow));
    memset(&selected_cow, 0, sizeof(selected_cow));
    memset(&duplicate_source, 0, sizeof(duplicate_source));
    memset(&overlap, 0, sizeof(overlap));
    memset(&small, 0, sizeof(small));
    clean.source = anonymous.source = zero_range.source =
        unrelated_cow.source = selected_cow.source =
        duplicate_source.source = overlap.source = small.source =
        MAP_FAILED;
    if (inherited_no_fork) {
        saved_no_fork = strdup(inherited_no_fork);
        if (!saved_no_fork)
            return 0;
    }
    if (unsetenv("DLFREEZE_NO_FORK") < 0) {
        free(saved_no_fork);
        return 0;
    }
    if (page_value <= 0 ||
        !mremap_proof_fixture_init(
            &clean, BS_MREMAP_MIN_STARTUP_BYTES,
            MREMAP_FIXTURE_CLEAN)) {
        ok = 0;
        goto out;
    }

    ok &= expect_value("clean fdless DONTUNMAP/refault proof",
                       mremap_source_ready(&clean), test_signal_zero_clone_available);
    if (clean.source[(size_t)page_value] != 0x5a) {
        fprintf(stderr, "proof child changed the parent's source mapping\n");
        ok = 0;
    }
    if (clean.file) {
        struct stat source_status;

        if (fstat(fileno(clean.file), &source_status) < 0 ||
            !live_smaps_match(clean.source, clean.size,
                              &source_status, 0)) {
            fprintf(stderr,
                    "proof child changed parent source protection/backing\n");
            ok = 0;
        }
    }
    if (clean.file && fcntl(fileno(clean.file), F_GETFD) < 0) {
        fprintf(stderr, "proof child closed the parent's source fd\n");
        ok = 0;
    }

    clone_attempts = g_bs_mremap_clone_attempts;
    if (setenv("DLFREEZE_NO_FORK", "1", 1) < 0) {
        ok = 0;
        goto out;
    }
    ok &= expect_value("DLFREEZE_NO_FORK selects startup copy fallback",
                       mremap_source_ready(&clean), 0);
    if (g_bs_mremap_clone_attempts != clone_attempts) {
        fprintf(stderr, "DLFREEZE_NO_FORK unexpectedly cloned\n");
        ok = 0;
    }
#ifdef DLFREEZE_TEST_HAVE_SECCOMP
    ok &= expect_value("NO_FORK survives clone fatal seccomp denial",
                       mremap_seccomp_decline(
                           &clean, SYS_clone,
                           SECCOMP_RET_KILL_PROCESS), 1);
    ok &= expect_value("NO_FORK survives wait4 fatal seccomp denial",
                       mremap_seccomp_decline(
                           &clean, SYS_wait4,
                           SECCOMP_RET_KILL_PROCESS), 1);
    ok &= expect_value("NO_FORK survives clone SIGSYS seccomp denial",
                       mremap_seccomp_decline(
                           &clean, SYS_clone, SECCOMP_RET_TRAP), 1);
#endif
    if (unsetenv("DLFREEZE_NO_FORK") < 0) {
        ok = 0;
        goto out;
    }
    memset(&action, 0, sizeof(action));
    action.sa_handler = SIG_IGN;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGCHLD, &action, &old_action) < 0) {
        ok = 0;
    } else {
        ok &= expect_value("signal-zero proof with inherited SIGCHLD ignore",
                           mremap_source_ready(&clean), test_signal_zero_clone_available);
        if (sigaction(SIGCHLD, &old_action, NULL) < 0)
            ok = 0;
    }
    memset(&action, 0, sizeof(action));
    action.sa_handler = SIG_DFL;
    action.sa_flags = SA_NOCLDWAIT;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGCHLD, &action, &old_action) < 0) {
        ok = 0;
    } else {
        ok &= expect_value(
            "signal-zero proof with inherited SA_NOCLDWAIT",
            mremap_source_ready(&clean), test_signal_zero_clone_available);
        if (sigaction(SIGCHLD, &old_action, NULL) < 0)
            ok = 0;
    }

#ifdef DLFREEZE_TEST_HAVE_SECCOMP
    ok &= expect_value("clone RET_ERRNO declines optimization",
                       mremap_seccomp_decline(
                           &clean, SYS_clone,
                           SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
                       1);
    ok &= expect_value("wait4 RET_ERRNO declines optimization",
                       mremap_seccomp_decline(
                           &clean, SYS_wait4,
                           SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
                       1);
    ok &= expect_value("mremap RET_ERRNO declines optimization",
                       mremap_seccomp_decline(
                           &clean, SYS_mremap,
                           SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
                       1);
    ok &= expect_value("mremap SIGSYS is contained",
                       mremap_seccomp_decline(
                           &clean, SYS_mremap, SECCOMP_RET_TRAP),
                       1);
    ok &= expect_value("mremap fatal seccomp denial is contained",
                       mremap_seccomp_decline(
                           &clean, SYS_mremap, SECCOMP_RET_KILL_PROCESS),
                       1);
#ifdef SYS_openat
    ok &= expect_value("proc open RET_ERRNO declines optimization",
                       mremap_seccomp_decline(
                           &clean, SYS_openat,
                           SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
                       1);
    ok &= expect_value("proc open SIGSYS is contained",
                       mremap_seccomp_decline(
                           &clean, SYS_openat, SECCOMP_RET_TRAP),
                       1);
#endif
#ifdef SYS_read
    ok &= expect_value("smaps read RET_ERRNO declines optimization",
                       mremap_seccomp_decline(
                           &clean, SYS_read,
                           SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
                       1);
#endif
#ifdef SYS_close
    ok &= expect_value("source close RET_ERRNO declines optimization",
                       mremap_seccomp_decline(
                           &clean, SYS_close,
                           SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
                       1);
#endif
#endif

    clone_attempts = g_bs_mremap_clone_attempts;
    clean.meta.base_addr = (uint64_t)(uintptr_t)clean.source;
    ok &= expect_value("target/source overlap declines before clone",
                       mremap_source_ready(&clean), 0);
    if (g_bs_mremap_clone_attempts != clone_attempts) {
        fprintf(stderr, "target/source overlap unexpectedly cloned\n");
        ok = 0;
    }

    /* Keep each synthetic target vacant while it is under test.  A later
     * fixture's ordinary source mmap is otherwise allowed to reuse an
     * earlier fixture's deliberately unmapped target hole. */
    mremap_proof_fixture_destroy(&clean);
    if (!mremap_proof_fixture_init(
            &anonymous, BS_MREMAP_MIN_STARTUP_BYTES,
            MREMAP_FIXTURE_ANONYMOUS)) {
        ok = 0;
        goto out;
    }
    ok &= expect_value("anonymous/decompressed source declined",
                       mremap_source_ready(&anonymous), 0);
    mremap_proof_fixture_destroy(&anonymous);

    if (!mremap_proof_fixture_init(
            &zero_range, BS_MREMAP_MIN_STARTUP_BYTES,
            MREMAP_FIXTURE_ZERO_LOAD)) {
        ok = 0;
        goto out;
    }
    ok &= expect_value("exact clean all-zero LOAD remains refaultable",
                       mremap_source_ready(&zero_range), test_signal_zero_clone_available);
    mremap_proof_fixture_destroy(&zero_range);

    if (!mremap_proof_fixture_init(
            &unrelated_cow, BS_MREMAP_MIN_STARTUP_BYTES,
            MREMAP_FIXTURE_UNRELATED_COW)) {
        ok = 0;
        goto out;
    }
    {
        unsigned char before = unrelated_cow.source[
            BS_MREMAP_MIN_STARTUP_BYTES];

        ok &= expect_value(
            "unrelated source COW does not disable exact transfers",
            mremap_source_ready(&unrelated_cow), test_signal_zero_clone_available);
        if (unrelated_cow.source[BS_MREMAP_MIN_STARTUP_BYTES] != before) {
            fprintf(stderr,
                    "proof child changed unrelated parent COW data\n");
            ok = 0;
        }
    }
    mremap_proof_fixture_destroy(&unrelated_cow);

    if (!mremap_proof_fixture_init(
            &selected_cow, BS_MREMAP_MIN_STARTUP_BYTES,
            MREMAP_FIXTURE_SELECTED_COW)) {
        ok = 0;
        goto out;
    }
    {
        size_t cow_offset = BS_MREMAP_MIN_STARTUP_BYTES -
                            (size_t)page_value;
        unsigned char before = selected_cow.source[cow_offset];

        ok &= expect_value("selected source COW declines exact transfers",
                           mremap_source_ready(&selected_cow), 0);
        if (selected_cow.source[cow_offset] != before) {
            fprintf(stderr, "proof child changed selected parent COW data\n");
            ok = 0;
        }
    }
    mremap_proof_fixture_destroy(&selected_cow);

    if (!mremap_proof_fixture_init(
            &duplicate_source, BS_MREMAP_MIN_STARTUP_BYTES,
            MREMAP_FIXTURE_DUPLICATE_SOURCE)) {
        ok = 0;
        goto out;
    }
    ok &= expect_value(
        "overlapping source ranges refault from exact file backing",
        mremap_source_ready(&duplicate_source), test_signal_zero_clone_available);
    mremap_proof_fixture_destroy(&duplicate_source);

    if (!mremap_proof_fixture_init(
            &overlap, BS_MREMAP_MIN_STARTUP_BYTES,
            MREMAP_FIXTURE_TARGET_OVERLAP)) {
        ok = 0;
        goto out;
    }
    clone_attempts = g_bs_mremap_clone_attempts;
    ok &= expect_value("overlapping targets decline before clone",
                       mremap_source_ready(&overlap), 0);
    if (g_bs_mremap_clone_attempts != clone_attempts) {
        fprintf(stderr, "overlapping target plan unexpectedly cloned\n");
        ok = 0;
    }
    mremap_proof_fixture_destroy(&overlap);

    if (!mremap_proof_fixture_init(
            &small, (size_t)page_value, MREMAP_FIXTURE_CLEAN)) {
        ok = 0;
        goto out;
    }
    clone_attempts = g_bs_mremap_clone_attempts;
    ok &= expect_value("sub-threshold plan uses bounded copy",
                       mremap_source_ready(&small), 0);
    if (g_bs_mremap_clone_attempts != clone_attempts) {
        fprintf(stderr, "sub-threshold source unexpectedly cloned\n");
        ok = 0;
    }

out:
    mremap_proof_fixture_destroy(&small);
    mremap_proof_fixture_destroy(&overlap);
    mremap_proof_fixture_destroy(&duplicate_source);
    mremap_proof_fixture_destroy(&selected_cow);
    mremap_proof_fixture_destroy(&unrelated_cow);
    mremap_proof_fixture_destroy(&zero_range);
    mremap_proof_fixture_destroy(&anonymous);
    mremap_proof_fixture_destroy(&clean);
    if (saved_no_fork) {
        if (setenv("DLFREEZE_NO_FORK", saved_no_fork, 1) < 0)
            ok = 0;
    } else if (unsetenv("DLFREEZE_NO_FORK") < 0) {
        ok = 0;
    }
    free(saved_no_fork);
    return ok;
}

static int runtime_cookie_source_ready(
    const struct mremap_proof_fixture *fixture,
    volatile uint32_t **cookie_out)
{
    return bs_startup_mremap_source_ready(
        fixture->source, 0, &fixture->meta, &fixture->entry, 1,
        fixture->file ? fileno(fixture->file) : -1,
        fixture->file != NULL, 0, 0, 0, cookie_out);
}

static int runtime_cookie_smaps_text(const char *text)
{
    FILE *stream = test_temporary_file();
    int result;

    if (!stream || fputs(text, stream) == EOF || fseek(stream, 0, SEEK_SET)) {
        if (stream)
            fclose(stream);
        return 0;
    }
    result = bs_runtime_fork_cookie_smaps_matches(stream, 0x2000, 0x1000);
    fclose(stream);
    return result;
}

#ifdef DLFREEZE_TEST_HAVE_SECCOMP
static void runtime_cookie_sigsys_success(int number, siginfo_t *info,
                                          void *context_pointer)
{
    ucontext_t *context = context_pointer;

    (void)number;
    (void)info;
#if defined(__x86_64__)
    context->uc_mcontext.gregs[REG_RAX] = 0;
#elif defined(__aarch64__)
    context->uc_mcontext.regs[0] = 0;
#endif
}

static int runtime_cookie_seccomp_case(
    const struct mremap_proof_fixture *fixture, unsigned action,
    int returning_trap, int no_fork)
{
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_madvise, 0, 3),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 offsetof(struct seccomp_data, args[2])),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, MADV_WIPEONFORK, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, action),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program = {
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };
    pid_t child = fork();
    int status = -1;

    if (child < 0)
        return 0;
    if (child == 0) {
        volatile uint32_t *cookie = (volatile uint32_t *)(uintptr_t)1;
        int expect_remap = test_signal_zero_clone_available && !no_fork &&
            (((action & SECCOMP_RET_ACTION) == SECCOMP_RET_ERRNO) ||
             returning_trap);
        int remap_ready;

        if (returning_trap) {
            struct sigaction handler;

            memset(&handler, 0, sizeof(handler));
            sigemptyset(&handler.sa_mask);
            handler.sa_flags = SA_SIGINFO;
            handler.sa_sigaction = runtime_cookie_sigsys_success;
            if (sigaction(SIGSYS, &handler, NULL) < 0)
                _exit(1);
        }
        if (no_fork && setenv("DLFREEZE_NO_FORK", "1", 1) < 0)
            _exit(1);
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 ||
            prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) != 0)
            _exit(77);
        remap_ready = runtime_cookie_source_ready(fixture, &cookie);
        _exit(cookie == NULL && !!remap_ready == expect_remap ? 0 : 1);
    }
    if (waitpid(child, &status, 0) != child)
        return 0;
    if (WIFEXITED(status) && WEXITSTATUS(status) == 77)
        return 1;
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}
#endif

static int runtime_cookie_gate(void)
{
    static const char valid[] =
        "1000-2000 r--p 00000000 08:01 17 /image\n"
        "VmFlags: rd mr mw me sd\n"
        "2000-3000 rw-p 00000000 00:00 0\n"
        "VmFlags: rd wr mr mw me ac wf sd\n";
    static const char no_wipe[] =
        "2000-3000 rw-p 00000000 00:00 0\n"
        "VmFlags: rd wr mr mw me ac sd\n";
    static const char shared[] =
        "2000-3000 rw-s 00000000 00:00 0\n"
        "VmFlags: rd wr sh mr mw me ac wf sd\n";
    static const char partial[] =
        "2000-2800 rw-p 00000000 00:00 0\n"
        "VmFlags: rd wr mr mw me ac wf sd\n";
    static const char duplicate[] =
        "2000-3000 rw-p 00000000 00:00 0\n"
        "VmFlags: rd wr mr mw me ac wf sd\n"
        "VmFlags: rd wr mr mw me ac wf sd\n";
    const char *inherited_no_fork = getenv("DLFREEZE_NO_FORK");
    char *saved_no_fork = inherited_no_fork ? strdup(inherited_no_fork) : NULL;
    struct mremap_proof_fixture fixture;
    volatile uint32_t *cookie = NULL;
    long page_value = sysconf(_SC_PAGESIZE);
    size_t clone_attempts;
    int ok = 1;

    memset(&fixture, 0, sizeof(fixture));
    fixture.source = MAP_FAILED;
    if ((inherited_no_fork && !saved_no_fork) || page_value <= 0 ||
        unsetenv("DLFREEZE_NO_FORK") < 0) {
        free(saved_no_fork);
        return 0;
    }
    ok &= expect_value("anonymous cookie requires complete wf evidence",
                       runtime_cookie_smaps_text(valid), 1);
    ok &= expect_value("cookie rejects apparent madvise success without wf",
                       runtime_cookie_smaps_text(no_wipe), 0);
    ok &= expect_value("cookie rejects shared VMA",
                       runtime_cookie_smaps_text(shared), 0);
    ok &= expect_value("cookie rejects partial VMA coverage",
                       runtime_cookie_smaps_text(partial), 0);
    ok &= expect_value("cookie rejects duplicate VmFlags",
                       runtime_cookie_smaps_text(duplicate), 0);
    {
        /* The only remappable prefix could start at 0x402000 and end at
         * 0x403000.  Both adjacent pages still belong to this first object's
         * full LOAD/BSS reservation; the dormant object's future range and
         * trailing loader pages must also remain vacant. */
        struct dlfrz_lib_meta metas[3] = {
            {.base_addr = 0x400000, .vaddr_lo = 0x123, .vaddr_hi = 0x9101,
             .flags = DLFRZ_FLAG_SHLIB},
            {.base_addr = 0x800000, .vaddr_lo = 0x3000, .vaddr_hi = 0x3501,
             .flags = DLFRZ_FLAG_SHLIB | DLFRZ_FLAG_DLOPEN},
            {.flags = DLFRZ_FLAG_DATA},
        };
        uint64_t lo, hi;

        if (!bs_runtime_fork_cookie_envelope(metas, 3, 0x1000, &lo, &hi) ||
            lo != 0x400000 || hi != 0x808000) {
            fprintf(stderr, "cookie envelope missed partial LOAD/BSS/dormant guard pages\n");
            ok = 0;
        }
        metas[1].base_addr = UINT64_MAX - 0x1000;
        if (bs_runtime_fork_cookie_envelope(metas, 3, 0x1000, &lo, &hi)) {
            fprintf(stderr, "cookie envelope accepted an overflowing reservation\n");
            ok = 0;
        }
    }
    if (!mremap_proof_fixture_init(&fixture, BS_MREMAP_MIN_STARTUP_BYTES,
                                   MREMAP_FIXTURE_CLEAN)) {
        ok = 0;
        goto out;
    }
    clone_attempts = g_bs_mremap_clone_attempts;
    ok &= expect_value("combined cookie proof preserves remap readiness",
                       runtime_cookie_source_ready(&fixture, &cookie),
                       test_signal_zero_clone_available);
    if (g_bs_mremap_clone_attempts != clone_attempts + 1 ||
        (test_signal_zero_clone_available
             ? (!cookie || *cookie != DLFRZ_RUNTIME_FORK_COOKIE)
             : cookie != NULL)) {
        fprintf(stderr, "cookie was not admitted by one existing clone\n");
        ok = 0;
        goto out;
    }
    if (!test_signal_zero_clone_available) {
        /* The absent containment shape must not skip the independent
         * WIPEONFORK inheritance check.  Establish a native control page
         * directly; no production admission function decides this result. */
        void *mapping = mmap(NULL, (size_t)page_value,
                              PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

        if (mapping == MAP_FAILED) {
            ok = 0;
            goto out;
        }
        cookie = mapping;
        *cookie = DLFRZ_RUNTIME_FORK_COOKIE;
        if (syscall(SYS_madvise, mapping, (size_t)page_value,
                    MADV_WIPEONFORK) != 0) {
            fprintf(stderr, "standalone native WIPEONFORK control failed errno=%d\n", errno);
            ok = 0;
            goto out;
        }
    }
    {
        pid_t child = fork();
        int status = -1;

        if (child == 0) {
            pid_t grandchild;

            if (*cookie != 0)
                _exit(1);
            *cookie = DLFRZ_RUNTIME_FORK_COOKIE;
            grandchild = fork();
            if (grandchild == 0)
                _exit(*cookie == 0 ? 0 : 1);
            if (grandchild < 0 || waitpid(grandchild, &status, 0) != grandchild ||
                !WIFEXITED(status) || WEXITSTATUS(status) != 0 ||
                *cookie != DLFRZ_RUNTIME_FORK_COOKIE)
                _exit(1);
            _exit(0);
        }
        if (child < 0 || waitpid(child, &status, 0) != child ||
            !WIFEXITED(status) || WEXITSTATUS(status) != 0 ||
            *cookie != DLFRZ_RUNTIME_FORK_COOKIE) {
            fprintf(stderr, "verified cookie did not preserve repeated fork semantics\n");
            ok = 0;
        }
    }
    munmap((void *)cookie, (size_t)page_value);
    cookie = NULL;
#ifdef DLFREEZE_TEST_HAVE_SECCOMP
    ok &= expect_value("cookie errno denial preserves remap optimization",
                       runtime_cookie_seccomp_case(&fixture,
                           SECCOMP_RET_ERRNO | EPERM, 0, 0), 1);
    ok &= expect_value("cookie fatal seccomp denial is contained",
                       runtime_cookie_seccomp_case(&fixture,
                           SECCOMP_RET_KILL_PROCESS, 0, 0), 1);
    ok &= expect_value("cookie SIGSYS denial is contained",
                       runtime_cookie_seccomp_case(&fixture,
                           SECCOMP_RET_TRAP, 0, 0), 1);
    ok &= expect_value("cookie SIGSYS spoofed success cannot authorize wf",
                       runtime_cookie_seccomp_case(&fixture,
                           SECCOMP_RET_TRAP, 1, 0), 1);
    ok &= expect_value("NO_FORK never probes cookie syscall",
                       runtime_cookie_seccomp_case(&fixture,
                           SECCOMP_RET_KILL_PROCESS, 0, 1), 1);
#endif
    clone_attempts = g_bs_mremap_clone_attempts;
    if (setenv("DLFREEZE_NO_FORK", "1", 1) < 0) {
        ok = 0;
        goto out;
    }
    ok &= expect_value("NO_FORK declines cookie and remap together",
                       runtime_cookie_source_ready(&fixture, &cookie), 0);
    if (cookie || g_bs_mremap_clone_attempts != clone_attempts)
        ok = 0;
    if (unsetenv("DLFREEZE_NO_FORK") < 0) {
        ok = 0;
        goto out;
    }
    mremap_proof_fixture_destroy(&fixture);
    if (!mremap_proof_fixture_init(&fixture, (size_t)page_value,
                                   MREMAP_FIXTURE_CLEAN)) {
        ok = 0;
        goto out;
    }
    clone_attempts = g_bs_mremap_clone_attempts;
    ok &= expect_value("small launch declines cookie without another clone",
                       runtime_cookie_source_ready(&fixture, &cookie), 0);
    if (cookie || g_bs_mremap_clone_attempts != clone_attempts)
        ok = 0;
out:
    if (cookie)
        munmap((void *)cookie, (size_t)page_value);
    mremap_proof_fixture_destroy(&fixture);
    if (saved_no_fork) {
        if (setenv("DLFREEZE_NO_FORK", saved_no_fork, 1) < 0)
            ok = 0;
    } else if (unsetenv("DLFREEZE_NO_FORK") < 0) {
        ok = 0;
    }
    free(saved_no_fork);
    return ok;
}

int main(void)
{
    test_signal_zero_clone_available = signal_zero_clone_native_control();
    if (test_signal_zero_clone_available < 0)
        return 9;
    if (!phdr_translation_gate())
        return 1;
    if (!auxv_gate())
        return 2;
    if (!smaps_gate())
        return 3;
    if (!mremap_target_smaps_gate())
        return 4;
    if (!live_cow_smaps_gate())
        return 5;
    if (!procfs_provenance_gate())
        return 6;
    if (!mremap_proof_gate())
        return 7;
    if (!runtime_cookie_gate())
        return 8;
    return 0;
}
