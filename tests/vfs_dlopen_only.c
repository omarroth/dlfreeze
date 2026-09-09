#define _GNU_SOURCE
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

static int same_node(const struct stat *left, const struct stat *right)
{
    return left->st_dev == right->st_dev &&
           left->st_ino == right->st_ino &&
           left->st_mode == right->st_mode &&
           left->st_size == right->st_size;
}

static int check_file_identity(const char *path, struct stat *path_status)
{
    struct stat descriptor_status;
    struct stat empty_path_status;
    struct stat duplicate_status;
    int descriptor = -1;
    int duplicate = -1;
    int target = -1;
    int ok = 0;

    if (stat(path, path_status) < 0 ||
        (descriptor = open(path, O_RDONLY | O_CLOEXEC)) < 0 ||
        fstat(descriptor, &descriptor_status) < 0 ||
        fstatat(descriptor, "", &empty_path_status, AT_EMPTY_PATH) < 0 ||
        !same_node(path_status, &descriptor_status) ||
        !same_node(path_status, &empty_path_status))
        goto out;
    duplicate = dup(descriptor);
    if (duplicate < 0 || fstat(duplicate, &duplicate_status) < 0 ||
        !same_node(path_status, &duplicate_status) || close(duplicate) < 0)
        goto out;
    duplicate = -1;
#ifdef F_DUPFD_CLOEXEC
    duplicate = fcntl(descriptor, F_DUPFD_CLOEXEC, 3);
#else
    duplicate = fcntl(descriptor, F_DUPFD, 3);
#endif
    if (duplicate < 0 || fstat(duplicate, &duplicate_status) < 0 ||
        !same_node(path_status, &duplicate_status))
        goto out;
    target = duplicate;
    if (close(duplicate) < 0)
        goto out;
    duplicate = -1;
    if (dup3(descriptor, target, O_CLOEXEC) != target ||
        fstat(target, &duplicate_status) < 0 ||
        !same_node(path_status, &duplicate_status) || close(target) < 0)
        goto out;
    target = -1;
    ok = 1;

out:
    if (duplicate >= 0)
        close(duplicate);
    if (target >= 0)
        close(target);
    if (descriptor >= 0 && close(descriptor) < 0)
        ok = 0;
    return ok;
}

static int check_raw_fd_reuse(const char *captured_path,
                              const char *host_path)
{
    struct stat expected;
    struct stat actual;
    int host_fd = -1;
    int captured_fd = -1;
    int ok = 0;

    host_fd = open(host_path, O_RDONLY | O_CLOEXEC);
    captured_fd = open(captured_path, O_RDONLY | O_CLOEXEC);
    if (host_fd < 0 || captured_fd < 0 || host_fd == captured_fd ||
        fstat(host_fd, &expected) < 0 ||
        syscall(SYS_close, captured_fd) != 0)
        goto out;
    if (syscall(SYS_dup3, host_fd, captured_fd, O_CLOEXEC) != captured_fd)
        goto out;
    if (fstat(captured_fd, &actual) < 0 || !same_node(&expected, &actual))
        goto out;
    ok = 1;

out:
    if (captured_fd >= 0)
        close(captured_fd);
    if (host_fd >= 0)
        close(host_fd);
    return ok;
}

static int read_magic_fd(int fd)
{
    unsigned char magic[4];

    if (fd < 0)
        return 0;
    if (read(fd, magic, sizeof(magic)) != (ssize_t)sizeof(magic) ||
        close(fd) < 0)
        return 0;
    return memcmp(magic, "\177ELF", sizeof(magic)) == 0;
}

static int read_text(const char *path, char *buffer, size_t size)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    ssize_t length;

    if (fd < 0 || size < 2)
        return 0;
    length = read(fd, buffer, size - 1);
    if (length < 0 || close(fd) < 0)
        return 0;
    buffer[length] = '\0';
    buffer[strcspn(buffer, "\r\n")] = '\0';
    return 1;
}

struct saved_directory_position {
    long location;
    char name[256];
};

/* Exercise opaque directory cookies in both directions.  In the frozen
 * case the host sibling is emitted while getdents64 is active and the
 * captured DSO is emitted later by the virtual phase, so replaying every
 * saved position in reverse crosses the real/virtual boundary repeatedly. */
static int check_positioned_directory(const char *path,
                                      const char *plugin_name,
                                      const char *sibling_name,
                                      int *plugin_count_out,
                                      int *sibling_count_out,
                                      unsigned char *plugin_type_out,
                                      ino_t *plugin_inode_out)
{
    enum { MAX_POSITIONS = 128 };
    struct saved_directory_position saved[MAX_POSITIONS];
    struct dirent *entry;
    DIR *directory = NULL;
    long initial_alias;
    long next_location;
    long end_location;
    size_t count = 0;
    int plugin_count = 0;
    int sibling_count = 0;
    unsigned char plugin_type = DT_UNKNOWN;
    ino_t plugin_inode = 0;
    int ok = 0;

    directory = opendir(path);
    if (!directory)
        goto out;
    next_location = telldir(directory);
    initial_alias = telldir(directory);
    if (next_location < 0 || initial_alias < 0)
        goto out;

    for (;;) {
        size_t length;

        errno = 0;
        entry = readdir(directory);
        if (!entry)
            break;
        if (count == MAX_POSITIONS)
            goto out;
        length = strlen(entry->d_name);
        if (length >= sizeof(saved[count].name))
            goto out;
        saved[count].location = next_location;
        memcpy(saved[count].name, entry->d_name, length + 1);
        count++;
        if (strcmp(entry->d_name, plugin_name) == 0) {
            plugin_count++;
            plugin_type = entry->d_type;
            plugin_inode = entry->d_ino;
        }
        if (strcmp(entry->d_name, sibling_name) == 0)
            sibling_count++;
        next_location = telldir(directory);
        if (next_location < 0)
            goto out;
    }
    if (errno != 0 || count == 0)
        goto out;
    end_location = next_location;

    /* Start in the virtual tail and work backwards into kernel positions.
     * Every saved cookie must remain valid despite intervening seeks. */
    for (size_t index = count; index-- > 0;) {
        seekdir(directory, saved[index].location);
        errno = 0;
        entry = readdir(directory);
        if (!entry || errno != 0 ||
            strcmp(entry->d_name, saved[index].name) != 0)
            goto out;
    }
    seekdir(directory, initial_alias);
    errno = 0;
    entry = readdir(directory);
    if (!entry || errno != 0 || strcmp(entry->d_name, saved[0].name) != 0)
        goto out;
    seekdir(directory, end_location);
    errno = 0;
    if (readdir(directory) != NULL || errno != 0)
        goto out;

    *plugin_count_out = plugin_count;
    *sibling_count_out = sibling_count;
    *plugin_type_out = plugin_type;
    *plugin_inode_out = plugin_inode;
    ok = 1;

out:
    if (directory && closedir(directory) != 0)
        ok = 0;
    return ok;
}

int main(int argc, char **argv)
{
    const char *plugin_name;
    const char *sibling_name;
    struct stat status;
    struct stat canonical_status;
    struct stat directory_status;
    struct stat directory_fd_status;
    struct stat directory_empty_status;
    struct stat link_status;
    char resolved[PATH_MAX];
    char sibling[64];
    char link_target[PATH_MAX];
    unsigned char magic[4];
    FILE *stream;
    void *handle;
    int (*value)(void);
    int plugin_count = 0;
    int sibling_count = 0;
    unsigned char plugin_type = DT_UNKNOWN;
    ino_t plugin_inode = 0;
    int dirfd_value;
    int frozen;

    if (argc != 6)
        return 2;
    plugin_name = strrchr(argv[1], '/');
    sibling_name = strrchr(argv[3], '/');
    if (!plugin_name || !sibling_name)
        return 3;
    plugin_name++;
    sibling_name++;
    frozen = strcmp(argv[4], "runtime-host") == 0;

    handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    value = handle ? (int (*)(void))dlsym(handle, "dlfrz_vfs_plugin_value")
                   : NULL;
    if (!value || value() != 83)
        return 4;
    if (!check_file_identity(argv[1], &status) ||
        !check_file_identity(argv[5], &canonical_status) ||
        !same_node(&status, &canonical_status) ||
        !S_ISREG(status.st_mode) ||
        status.st_size <= 4 || access(argv[1], R_OK | X_OK) < 0)
        return 5;
    if (!read_magic_fd(open(argv[1], O_RDONLY | O_CLOEXEC)) ||
        !read_magic_fd(open(argv[5], O_RDONLY | O_CLOEXEC)))
        return 6;

    dirfd_value = open(argv[2], O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (stat(argv[2], &directory_status) < 0 || dirfd_value < 0 ||
        fstat(dirfd_value, &directory_fd_status) < 0 ||
        fstatat(dirfd_value, "", &directory_empty_status,
                AT_EMPTY_PATH) < 0 ||
        !same_node(&directory_status, &directory_fd_status) ||
        !same_node(&directory_status, &directory_empty_status) ||
        (status.st_dev == directory_status.st_dev &&
         status.st_ino == directory_status.st_ino) ||
        !read_magic_fd(openat(dirfd_value, plugin_name,
                              O_RDONLY | O_CLOEXEC))) {
        if (dirfd_value >= 0)
            close(dirfd_value);
        return 7;
    }
    if (frozen) {
        errno = 0;
        if (readlinkat(dirfd_value, plugin_name, link_target,
                       sizeof(link_target)) != -1 || errno != EINVAL) {
            close(dirfd_value);
            return 7;
        }
    }
    if (close(dirfd_value) < 0)
        return 7;

    errno = 0;
    if (readlink(argv[5], link_target, sizeof(link_target)) != -1 ||
        errno != EINVAL)
        return 8;
    errno = 0;
    if (readlink(argv[2], link_target, sizeof(link_target)) != -1 ||
        errno != EINVAL)
        return 8;
    if (frozen) {
        errno = 0;
        if (readlink(argv[1], link_target, sizeof(link_target)) != -1 ||
            errno != EINVAL || lstat(argv[1], &link_status) < 0 ||
            !same_node(&status, &link_status))
            return 8;
    }

    if (!check_raw_fd_reuse(argv[1], argv[3]))
        return 9;

    stream = fopen(argv[1], "rb");
    if (!stream || fread(magic, 1, sizeof(magic), stream) != sizeof(magic) ||
        fclose(stream) != 0 ||
        memcmp(magic, "\177ELF", sizeof(magic)) != 0)
        return 10;
    if (!realpath(argv[1], resolved) ||
        strcmp(resolved, frozen ? argv[1] : argv[5]) != 0)
        return 11;

    if (!check_positioned_directory(
            argv[2], plugin_name, sibling_name,
            &plugin_count, &sibling_count, &plugin_type, &plugin_inode))
        return 12;
    if (plugin_count != 1 ||
        sibling_count != 1 ||
        (frozen &&
         (plugin_type != DT_REG || plugin_inode != status.st_ino))) {
        fprintf(stderr,
                "directory counts: plugin=%d type=%u inode=%llu "
                "expected=%llu sibling=%d\n",
                plugin_count, (unsigned int)plugin_type,
                (unsigned long long)plugin_inode,
                (unsigned long long)status.st_ino, sibling_count);
        return 13;
    }

    if (!read_text(argv[3], sibling, sizeof(sibling)) ||
        strcmp(sibling, argv[4]) != 0)
        return 14;
    if (frozen) {
        ssize_t length = readlink(
            argv[3], link_target, sizeof(link_target) - 1);

        if (length < 0 || (size_t)length >= sizeof(link_target))
            return 15;
        link_target[length] = '\0';
        if (strcmp(link_target, "host-sibling-target.txt") != 0)
            return 15;
    }
    puts("dlopen-only-vfs-ok");
    return 0;
}
