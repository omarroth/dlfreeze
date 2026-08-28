#include <elf.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

struct mapped_elf {
    int fd;
    size_t size;
    uint8_t *data;
    Elf64_Ehdr *ehdr;
    Elf64_Phdr *phdr;
};

static int map_elf(const char *path, int writable, struct mapped_elf *image)
{
    struct stat st;

    memset(image, 0, sizeof(*image));
    image->fd = -1;
    image->data = MAP_FAILED;
    image->fd = open(path, (writable ? O_RDWR : O_RDONLY) | O_CLOEXEC);
    if (image->fd < 0 || fstat(image->fd, &st) < 0 || st.st_size <= 0 ||
        (uint64_t)st.st_size > SIZE_MAX)
        return -1;
    image->size = (size_t)st.st_size;
    image->data = mmap(NULL, image->size,
                       PROT_READ | (writable ? PROT_WRITE : 0),
                       writable ? MAP_SHARED : MAP_PRIVATE, image->fd, 0);
    if (image->data == MAP_FAILED || image->size < sizeof(Elf64_Ehdr))
        return -1;
    image->ehdr = (Elf64_Ehdr *)image->data;
    if (memcmp(image->ehdr->e_ident, ELFMAG, SELFMAG) != 0 ||
        image->ehdr->e_ident[EI_CLASS] != ELFCLASS64 ||
        image->ehdr->e_ident[EI_DATA] != ELFDATA2LSB ||
        image->ehdr->e_phentsize != sizeof(Elf64_Phdr) ||
        image->ehdr->e_phnum == 0 ||
        image->ehdr->e_phoff > image->size ||
        image->ehdr->e_phnum >
            (image->size - (size_t)image->ehdr->e_phoff) /
                sizeof(Elf64_Phdr))
        return -1;
    image->phdr = (Elf64_Phdr *)(image->data + image->ehdr->e_phoff);
    return 0;
}

static void unmap_elf(struct mapped_elf *image)
{
    if (image->data != MAP_FAILED)
        munmap(image->data, image->size);
    if (image->fd >= 0)
        close(image->fd);
}

static int note_has_payload_marker(const struct mapped_elf *image,
                                   const Elf64_Phdr *phdr)
{
    static const unsigned char owner[] = "DLFREEZE";
    static const unsigned char descriptor[] = "DLFRZPLD";
    const uint32_t payload_note_type = 0x44504c44;
    size_t position;
    size_t end;

    if (phdr->p_type != PT_NOTE || phdr->p_offset > image->size ||
        phdr->p_filesz > image->size - (size_t)phdr->p_offset)
        return 0;
    position = (size_t)phdr->p_offset;
    end = position + (size_t)phdr->p_filesz;
    while (position <= end && end - position >= sizeof(Elf64_Nhdr)) {
        Elf64_Nhdr note;
        size_t name_offset;
        size_t descriptor_offset;

        memcpy(&note, image->data + position, sizeof(note));
        position += sizeof(note);
        name_offset = position;
        if (note.n_namesz > end - position)
            return 0;
        position += note.n_namesz;
        if (position > SIZE_MAX - 3)
            return 0;
        position = (position + 3) & ~(size_t)3;
        if (position > end)
            return 0;
        descriptor_offset = position;
        if (note.n_descsz > end - position)
            return 0;
        position += note.n_descsz;
        if (position > SIZE_MAX - 3)
            return 0;
        position = (position + 3) & ~(size_t)3;
        if (position > end)
            return 0;
        if (note.n_type == payload_note_type &&
            note.n_namesz == sizeof(owner) - 1 &&
            note.n_descsz == sizeof(descriptor) - 1 &&
            memcmp(image->data + name_offset, owner,
                   sizeof(owner) - 1) == 0 &&
            memcmp(image->data + descriptor_offset, descriptor,
                   sizeof(descriptor) - 1) == 0)
            return 1;
    }
    return 0;
}

static int move_payload_note_before_load(const char *path)
{
    struct mapped_elf image;
    int first_load = -1;
    int payload_note = -1;
    int result = 1;

    if (map_elf(path, 1, &image) < 0)
        goto out;
    for (uint16_t i = 0; i < image.ehdr->e_phnum; i++) {
        if (first_load < 0 && image.phdr[i].p_type == PT_LOAD)
            first_load = i;
        if (payload_note < 0 &&
            note_has_payload_marker(&image, &image.phdr[i]))
            payload_note = i;
    }
    if (first_load < 0 || payload_note < 0)
        goto out;
    if (payload_note > first_load) {
        Elf64_Phdr payload = image.phdr[payload_note];

        memmove(&image.phdr[first_load + 1], &image.phdr[first_load],
                (size_t)(payload_note - first_load) * sizeof(Elf64_Phdr));
        image.phdr[first_load] = payload;
    }
    if (msync(image.data, image.size, MS_SYNC) < 0)
        goto out;
    result = 0;

out:
    unmap_elf(&image);
    return result;
}

static int verify_load_order(const char *path)
{
    struct mapped_elf image;
    uint64_t previous_vaddr = 0;
    int found_load = 0;
    int result = 1;

    if (map_elf(path, 0, &image) < 0)
        goto out;
    for (uint16_t i = 0; i < image.ehdr->e_phnum; i++) {
        const Elf64_Phdr *phdr = &image.phdr[i];

        if (phdr->p_type != PT_LOAD)
            continue;
        if ((!found_load && phdr->p_offset != 0) ||
            (found_load && phdr->p_vaddr < previous_vaddr))
            goto out;
        found_load = 1;
        previous_vaddr = phdr->p_vaddr;
    }
    if (found_load)
        result = 0;

out:
    unmap_elf(&image);
    return result;
}

static int insert_readonly_loader_decoy(const char *path)
{
    static const unsigned char marker[] = "DLFRZLDR";
    static const unsigned char zero_values[24];
    static const unsigned char target[] =
        "dlfreeze-bootstrap: no embedded payload";
    struct mapped_elf image;
    size_t live_offset = SIZE_MAX;
    size_t target_offset = SIZE_MAX;
    int result = 1;

    _Static_assert(sizeof(target) - 1 >= 32,
                   "decoy target must hold a loader descriptor");
    if (map_elf(path, 1, &image) < 0)
        goto out;
    for (uint16_t p = 0; p < image.ehdr->e_phnum; p++) {
        const Elf64_Phdr *phdr = &image.phdr[p];
        size_t begin;
        size_t end;

        if (phdr->p_type != PT_LOAD || phdr->p_offset > image.size ||
            phdr->p_filesz > image.size - (size_t)phdr->p_offset)
            continue;
        begin = (size_t)phdr->p_offset;
        end = begin + (size_t)phdr->p_filesz;
        if (phdr->p_flags & PF_W) {
            for (size_t offset = begin;
                 offset <= end && end - offset >= 32; offset++) {
                if (memcmp(image.data + offset, marker,
                           sizeof(marker) - 1) != 0 ||
                    memcmp(image.data + offset + sizeof(marker) - 1,
                           zero_values, sizeof(zero_values)) != 0)
                    continue;
                if (live_offset != SIZE_MAX)
                    goto out;
                live_offset = offset;
            }
            continue;
        }
        for (size_t offset = begin;
             offset <= end && end - offset >= sizeof(target) - 1;
             offset++) {
            if (memcmp(image.data + offset, target,
                       sizeof(target) - 1) != 0)
                continue;
            if (target_offset != SIZE_MAX)
                goto out;
            target_offset = offset;
        }
    }
    if (target_offset == SIZE_MAX || live_offset == SIZE_MAX ||
        target_offset >= live_offset)
        goto out;
    memcpy(image.data + target_offset, marker, sizeof(marker) - 1);
    memset(image.data + target_offset + sizeof(marker) - 1, 0,
           (sizeof(target) - 1) - (sizeof(marker) - 1));
    if (msync(image.data, image.size, MS_SYNC) < 0)
        goto out;
    result = 0;

out:
    unmap_elf(&image);
    return result;
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr,
                "usage: %s --note-before-load|--verify-load-order|"
                "--insert-readonly-decoy FILE\n",
                argv[0]);
        return 2;
    }
    if (strcmp(argv[1], "--note-before-load") == 0)
        return move_payload_note_before_load(argv[2]);
    if (strcmp(argv[1], "--verify-load-order") == 0)
        return verify_load_order(argv[2]);
    if (strcmp(argv[1], "--insert-readonly-decoy") == 0)
        return insert_readonly_loader_decoy(argv[2]);
    return 2;
}
