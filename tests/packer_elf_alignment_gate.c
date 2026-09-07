#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../src/packer.c"

#if defined(__x86_64__)
#define TEST_MACHINE EM_X86_64
#elif defined(__aarch64__)
#define TEST_MACHINE EM_AARCH64
#else
#error "unsupported packer alignment test architecture"
#endif

enum {
    TEST_IMAGE_SIZE = 512,
    TEST_PHDR_OFFSET = sizeof(Elf64_Ehdr) + 1,
    TEST_BOOTSTRAP_SIZE = 512,
    TEST_PAYLOAD_OFFSET = PAYLOAD_ALIGN,
    TEST_TOTAL_SIZE = 2 * PAYLOAD_ALIGN,
    TEST_NOTE_OFFSET = 256,
    TEST_LOADER_INFO_OFFSET = 400
};

static void initialize_ehdr(Elf64_Ehdr *ehdr, uint16_t phnum)
{
    memset(ehdr, 0, sizeof(*ehdr));
    memcpy(ehdr->e_ident, ELFMAG, SELFMAG);
    ehdr->e_ident[EI_CLASS] = ELFCLASS64;
    ehdr->e_ident[EI_DATA] = ELFDATA2LSB;
    ehdr->e_ident[EI_VERSION] = EV_CURRENT;
    ehdr->e_ident[EI_OSABI] = ELFOSABI_NONE;
    ehdr->e_type = ET_EXEC;
    ehdr->e_machine = TEST_MACHINE;
    ehdr->e_version = EV_CURRENT;
    ehdr->e_ehsize = sizeof(*ehdr);
    ehdr->e_phoff = TEST_PHDR_OFFSET;
    ehdr->e_phentsize = sizeof(Elf64_Phdr);
    ehdr->e_phnum = phnum;
    ehdr->e_shstrndx = SHN_UNDEF;
}

static int write_exact(int fd, const void *data, size_t size)
{
    const unsigned char *bytes = data;
    size_t done = 0;

    while (done < size) {
        ssize_t written = write(fd, bytes + done, size - done);

        if (written < 0 && errno == EINTR)
            continue;
        if (written <= 0)
            return 0;
        done += (size_t)written;
    }
    return 1;
}

static int read_exact_at(int fd, void *data, size_t size, off_t offset)
{
    unsigned char *bytes = data;
    size_t done = 0;

    while (done < size) {
        ssize_t got = pread(fd, bytes + done, size - done,
                            offset + (off_t)done);

        if (got < 0 && errno == EINTR)
            continue;
        if (got <= 0)
            return 0;
        done += (size_t)got;
    }
    return 1;
}

static int phdr_byte_access_gate(void)
{
    unsigned char phdr_storage[1 + sizeof(Elf64_Phdr)];
    unsigned char mapped_bytes[64];
    Elf64_Phdr expected = {0};
    Elf64_Phdr actual;
    struct prelink_obj object = {0};
    struct pl_control_range_builder control_builder = {0};
    void *pointer = NULL;
    size_t available = 0;

    expected.p_type = PT_LOAD;
    expected.p_flags = PF_R | PF_W;
    expected.p_filesz = sizeof(mapped_bytes);
    expected.p_memsz = sizeof(mapped_bytes);
    if (!packer_phdr_write(phdr_storage + 1, sizeof(expected), 0,
                           sizeof(expected), &expected) ||
        !packer_phdr_read(phdr_storage + 1, sizeof(expected), 0,
                          sizeof(expected), &actual) ||
        memcmp(&actual, &expected, sizeof(actual)) != 0)
        return 0;

    object.base = (uintptr_t)mapped_bytes;
    object.phdr_base = phdr_storage + 1;
    object.phdr_num = 1;
    object.phdr_entsz = sizeof(Elf64_Phdr);
    if (pl_parse_dynamic(&object, object.base, object.phdr_base,
                         object.phdr_num, object.phdr_entsz,
                         &control_builder) != 0 ||
        !pl_vaddr_pointer(&object, 3, 7, 1, PF_R, &pointer) ||
        pointer != mapped_bytes + 3 ||
        !pl_file_bytes_available(&object, 5, &available) ||
        available != sizeof(mapped_bytes) - 5 ||
        !pl_signed_offset_pointer(&object, 9, 4, PF_W, &pointer) ||
        pointer != mapped_bytes + 9) {
        pl_control_range_builder_release(&control_builder);
        return 0;
    }
    pl_control_range_builder_release(&control_builder);
    return 1;
}

static int compute_meta_unaligned_gate(void)
{
    unsigned char image[TEST_IMAGE_SIZE] = {0};
    char path[] = "/tmp/dlfreeze-packer-unaligned-meta.XXXXXX";
    struct packed_input_snapshot snapshot = {0};
    struct dlfrz_lib_meta meta = {0};
    Elf64_Ehdr ehdr;
    Elf64_Phdr load = {0};
    Elf64_Phdr stack = {0};
    int fd = -1;
    int result = 0;

    initialize_ehdr(&ehdr, 2);
    load.p_type = PT_LOAD;
    load.p_flags = PF_R | PF_X;
    load.p_filesz = sizeof(image);
    load.p_memsz = sizeof(image);
    load.p_align = 1;
    stack.p_type = PT_GNU_STACK;
    stack.p_flags = PF_R | PF_W;
    stack.p_align = 16;
    memcpy(image, &ehdr, sizeof(ehdr));
    if (!packer_phdr_write(image + TEST_PHDR_OFFSET,
                           sizeof(image) - TEST_PHDR_OFFSET, 0,
                           sizeof(Elf64_Phdr), &load) ||
        !packer_phdr_write(image + TEST_PHDR_OFFSET,
                           sizeof(image) - TEST_PHDR_OFFSET, 1,
                           sizeof(Elf64_Phdr), &stack))
        goto out;

    fd = mkstemp(path);
    if (fd < 0 || !write_exact(fd, image, sizeof(image)) ||
        fstat(fd, &snapshot.st) < 0)
        goto out;
    snapshot.valid = 1;
    if (close(fd) < 0)
        goto out;
    fd = -1;

    if (compute_lib_meta(path, &snapshot, DIRECT_LOAD_BASE,
                         DLFRZ_FLAG_MAIN_EXE, &meta) != 0 ||
        meta.phdr_off != DLFRZ_PHDR_EXTERNAL ||
        meta.phdr_file_off != TEST_PHDR_OFFSET || meta.phdr_num != 2 ||
        meta.phdr_entsz != sizeof(Elf64_Phdr) ||
        meta.vaddr_lo != 0 || meta.vaddr_hi != sizeof(image))
        goto out;
    result = 1;

out:
    if (fd >= 0)
        close(fd);
    unlink(path);
    return result;
}

static int initialize_bootstrap(unsigned char image[TEST_TOTAL_SIZE],
                                int include_sentinel)
{
    static const unsigned char owner[] = "DLFREEZE";
    static const unsigned char descriptor[] = "DLFRZPLD";
    Elf64_Ehdr ehdr;
    Elf64_Phdr note = {0};
    Elf64_Phdr load = {0};
    Elf64_Nhdr note_header = {0};
    size_t position = TEST_NOTE_OFFSET;

    memset(image, 0, TEST_TOTAL_SIZE);
    initialize_ehdr(&ehdr, 2);
    ehdr.e_entry = UINT64_C(0x40000040);
    ehdr.e_shoff = 0;
    ehdr.e_shentsize = sizeof(Elf64_Shdr);
    ehdr.e_shnum = 1;
    ehdr.e_shstrndx = 1;
    memcpy(image, &ehdr, sizeof(ehdr));

    note.p_type = PT_NOTE;
    note.p_offset = TEST_NOTE_OFFSET;
    note.p_filesz = sizeof(note_header) + sizeof(owner) - 1 +
                    sizeof(descriptor) - 1;
    note.p_memsz = note.p_filesz;
    note.p_align = 4;
    load.p_type = PT_LOAD;
    load.p_flags = PF_R | PF_W;
    load.p_offset = 0;
    load.p_vaddr = UINT64_C(0x40000000);
    load.p_paddr = load.p_vaddr;
    load.p_filesz = TEST_BOOTSTRAP_SIZE;
    load.p_memsz = TEST_BOOTSTRAP_SIZE;
    load.p_align = 1;
    if (!packer_phdr_write(image + TEST_PHDR_OFFSET,
                           TEST_BOOTSTRAP_SIZE - TEST_PHDR_OFFSET, 0,
                           sizeof(Elf64_Phdr), &note) ||
        !packer_phdr_write(image + TEST_PHDR_OFFSET,
                           TEST_BOOTSTRAP_SIZE - TEST_PHDR_OFFSET, 1,
                           sizeof(Elf64_Phdr), &load))
        return 0;

    note_header.n_namesz = sizeof(owner) - 1;
    note_header.n_descsz = sizeof(descriptor) - 1;
    note_header.n_type = UINT32_C(0x44504c44);
    memcpy(image + position, &note_header, sizeof(note_header));
    position += sizeof(note_header);
    memcpy(image + position, owner, sizeof(owner) - 1);
    position += sizeof(owner) - 1;
    memcpy(image + position, descriptor, sizeof(descriptor) - 1);
    if (include_sentinel)
        memcpy(image + TEST_LOADER_INFO_OFFSET, "DLFRZLDR", 8);
    for (size_t i = TEST_PAYLOAD_OFFSET; i < TEST_TOTAL_SIZE; i++)
        image[i] = (unsigned char)(i * 29U + 7U);
    return 1;
}

static int patched_bootstrap_valid(const unsigned char *image)
{
    Elf64_Ehdr ehdr;
    Elf64_Phdr load;
    Elf64_Phdr payload;
    uint64_t payload_address;
    uint64_t payload_size;
    uint64_t payload_offset;

    memcpy(&ehdr, image, sizeof(ehdr));
    if (!packer_phdr_read(image + TEST_PHDR_OFFSET,
                          TEST_BOOTSTRAP_SIZE - TEST_PHDR_OFFSET, 0,
                          sizeof(Elf64_Phdr), &load) ||
        !packer_phdr_read(image + TEST_PHDR_OFFSET,
                          TEST_BOOTSTRAP_SIZE - TEST_PHDR_OFFSET, 1,
                          sizeof(Elf64_Phdr), &payload))
        return 0;
    memcpy(&payload_address, image + TEST_LOADER_INFO_OFFSET + 8, 8);
    memcpy(&payload_size, image + TEST_LOADER_INFO_OFFSET + 16, 8);
    memcpy(&payload_offset, image + TEST_LOADER_INFO_OFFSET + 24, 8);
    return ehdr.e_shentsize == 0 && ehdr.e_shnum == 0 &&
           ehdr.e_shstrndx == 0 && load.p_type == PT_LOAD &&
           (load.p_flags & PF_W) != 0 && payload.p_type == PT_LOAD &&
           payload.p_flags == PF_R &&
           payload.p_offset == TEST_PAYLOAD_OFFSET &&
           payload.p_vaddr ==
               ((UINT64_C(0x40000000) + TEST_BOOTSTRAP_SIZE +
                 PAYLOAD_ALIGN - 1) & ~(uint64_t)(PAYLOAD_ALIGN - 1)) &&
           payload.p_filesz == TEST_TOTAL_SIZE - TEST_PAYLOAD_OFFSET &&
           payload.p_memsz == payload.p_filesz &&
           payload.p_align == PAYLOAD_ALIGN &&
           payload_address == payload.p_vaddr &&
           payload_size == payload.p_filesz &&
           payload_offset == payload.p_offset;
}

static int patch_unaligned_bootstrap_gate(void)
{
    unsigned char *image = calloc(1, TEST_TOTAL_SIZE);
    unsigned char *result_image = calloc(1, TEST_TOTAL_SIZE);
    char path[] = "/tmp/dlfreeze-packer-unaligned-bootstrap.XXXXXX";
    int fd = -1;
    int result = 0;

    if (!image || !result_image || !initialize_bootstrap(image, 1))
        goto out;
    fd = mkstemp(path);
    if (fd < 0 || !write_exact(fd, image, TEST_TOTAL_SIZE) || close(fd) < 0)
        goto out;
    fd = -1;
    if (patch_elf_for_upx_inplace(path, TEST_BOOTSTRAP_SIZE,
                                  TEST_PAYLOAD_OFFSET,
                                  TEST_TOTAL_SIZE) < 0)
        goto out;
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0 || !read_exact_at(fd, result_image, TEST_TOTAL_SIZE, 0) ||
        !patched_bootstrap_valid(result_image))
        goto out;
    result = 1;

out:
    if (fd >= 0)
        close(fd);
    unlink(path);
    free(result_image);
    free(image);
    return result;
}

static int failed_patch_is_transactional_gate(void)
{
    unsigned char *image = calloc(1, TEST_TOTAL_SIZE);
    unsigned char *after = calloc(1, TEST_TOTAL_SIZE);
    char path[] = "/tmp/dlfreeze-packer-transaction.XXXXXX";
    int fd = -1;
    int result = 0;

    if (!image || !after || !initialize_bootstrap(image, 0))
        goto out;
    fd = mkstemp(path);
    if (fd < 0 || !write_exact(fd, image, TEST_TOTAL_SIZE) || close(fd) < 0)
        goto out;
    fd = -1;
    errno = 0;
    if (patch_elf_for_upx(path, TEST_BOOTSTRAP_SIZE,
                          TEST_PAYLOAD_OFFSET, TEST_TOTAL_SIZE) == 0)
        goto out;
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0 || !read_exact_at(fd, after, TEST_TOTAL_SIZE, 0) ||
        memcmp(after, image, TEST_TOTAL_SIZE) != 0)
        goto out;
    result = 1;

out:
    if (fd >= 0)
        close(fd);
    unlink(path);
    free(after);
    free(image);
    return result;
}

static int prelink_manifest_bounds_gate(void)
{
    Elf64_Ehdr ehdr;
    Elf64_Phdr load = {0};
    struct dlfrz_entry entry = {0};
    struct dlfrz_lib_meta meta = {0};
    size_t phdr_size = 0;
    size_t span = 0;
    void *requested = NULL;

    initialize_ehdr(&ehdr, 1);
    entry.data_offset = 17;
    entry.data_size = TEST_IMAGE_SIZE;
    meta.base_addr = DIRECT_LOAD_BASE;
    meta.vaddr_lo = 0;
    meta.vaddr_hi = TEST_IMAGE_SIZE;
    meta.phdr_num = 1;
    meta.phdr_entsz = sizeof(Elf64_Phdr);
    if (!prelink_embedded_header_valid(&ehdr, &entry, &meta,
                                       TEST_IMAGE_SIZE + 17, &phdr_size) ||
        phdr_size != sizeof(Elf64_Phdr))
        return 0;
    ehdr.e_phoff = entry.data_size - sizeof(Elf64_Phdr) + 1;
    if (prelink_embedded_header_valid(&ehdr, &entry, &meta,
                                      TEST_IMAGE_SIZE + 17, &phdr_size))
        return 0;
    ehdr.e_phoff = TEST_PHDR_OFFSET;
    ehdr.e_phentsize--;
    if (prelink_embedded_header_valid(&ehdr, &entry, &meta,
                                      TEST_IMAGE_SIZE + 17, &phdr_size))
        return 0;

    load.p_type = PT_LOAD;
    load.p_flags = PF_R;
    load.p_offset = entry.data_size;
    load.p_filesz = 1;
    load.p_memsz = 1;
    if (prelink_program_header_valid(&load, &entry))
        return 0;
    load.p_offset = 0;
    load.p_vaddr = UINT64_MAX;
    if (prelink_program_header_valid(&load, &entry))
        return 0;
    if (!prelink_mapping_span(&meta, &span, &requested) ||
        span < TEST_IMAGE_SIZE || !requested)
        return 0;
    meta.vaddr_hi = UINT64_MAX;
    return !prelink_mapping_span(&meta, &span, &requested);
}

int main(void)
{
    if (!phdr_byte_access_gate()) {
        fprintf(stderr, "unaligned program-header byte access failed\n");
        return 1;
    }
    if (!compute_meta_unaligned_gate()) {
        fprintf(stderr, "unaligned application e_phoff admission failed\n");
        return 1;
    }
    if (!patch_unaligned_bootstrap_gate()) {
        fprintf(stderr, "unaligned bootstrap mutation failed\n");
        return 1;
    }
    if (!failed_patch_is_transactional_gate()) {
        fprintf(stderr, "failed bootstrap mutation changed the artifact\n");
        return 1;
    }
    if (!prelink_manifest_bounds_gate()) {
        fprintf(stderr, "prelink manifest bounds admission failed\n");
        return 1;
    }
    return 0;
}
