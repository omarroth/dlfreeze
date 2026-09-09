#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define DLFREEZE_PACKER_PUBLISH_GATE 1
#include "../src/packer.c"

static int g_hook_result;
static const char *g_hook_source_leaf;
static char g_hook_backup_leaf[NAME_MAX + 1];
static enum packer_publish_test_stage g_hook_stage;

static int write_all(int fd, const void *data, size_t size)
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

static int write_file_at(int directory_fd, const char *leaf,
                         const char *contents, mode_t mode)
{
    size_t size = strlen(contents);
    int fd = openat(directory_fd, leaf,
                    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, mode);
    int result = 0;

    if (fd < 0)
        return 0;
    if (fchmod(fd, mode) == 0 && write_all(fd, contents, size) &&
        fsync(fd) == 0 && close(fd) == 0) {
        fd = -1;
        result = 1;
    }
    if (fd >= 0)
        close(fd);
    return result;
}

static int file_matches_at(int directory_fd, const char *leaf,
                           const char *contents, mode_t mode)
{
    char buffer[256];
    struct stat before;
    struct stat opened;
    size_t expected = strlen(contents);
    ssize_t got;
    int fd;
    int result = 0;

    if (expected >= sizeof(buffer) ||
        fstatat(directory_fd, leaf, &before, AT_SYMLINK_NOFOLLOW) < 0 ||
        !S_ISREG(before.st_mode) || (before.st_mode & 07777) != mode)
        return 0;
    fd = openat(directory_fd, leaf, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return 0;
    if (fstat(fd, &opened) < 0 ||
        !output_identity_equal(&before, &opened))
        goto out;
    do {
        got = read(fd, buffer, sizeof(buffer));
    } while (got < 0 && errno == EINTR);
    if (got != (ssize_t)expected ||
        memcmp(buffer, contents, expected) != 0)
        goto out;
    do {
        got = read(fd, buffer, sizeof(buffer));
    } while (got < 0 && errno == EINTR);
    result = got == 0;

out:
    close(fd);
    return result;
}

static int no_publication_debris(int directory_fd)
{
    DIR *directory;
    struct dirent *entry;
    int duplicate = dup(directory_fd);
    int result = 1;

    if (duplicate < 0)
        return 0;
    directory = fdopendir(duplicate);
    if (!directory) {
        close(duplicate);
        return 0;
    }
    errno = 0;
    while ((entry = readdir(directory)) != NULL) {
        if (strncmp(entry->d_name, ".dlfreeze-pack.", 16) == 0 ||
            strncmp(entry->d_name, ".dlfreeze-backup.", 19) == 0) {
            result = 0;
            break;
        }
    }
    if (!entry && errno != 0)
        result = 0;
    closedir(directory);
    return result;
}

static int make_transaction(const char *output_path, const char *contents,
                            char transaction_path[PATH_MAX],
                            struct stat *identity)
{
    FILE *stream = NULL;

    if (create_output_transaction(output_path, transaction_path, &stream,
                                  identity) < 0)
        return 0;
    if (fwrite(contents, 1, strlen(contents), stream) != strlen(contents) ||
        finish_output_stream(&stream) < 0 ||
        sync_output_transaction(transaction_path, identity) < 0) {
        if (stream)
            fclose(stream);
        unlink(transaction_path);
        return 0;
    }
    return 1;
}

static void reset_injection(int rename_error)
{
    g_packer_publish_test_renameat2_errno = rename_error;
    g_packer_publish_test_backup_stat_errno = 0;
    g_packer_publish_test_fsync_calls = 0;
    g_packer_publish_test_fail_fsync_call = 0;
    g_packer_publish_test_stage_hook = NULL;
    g_hook_result = 1;
    g_hook_source_leaf = NULL;
    g_hook_backup_leaf[0] = '\0';
    g_hook_stage = 0;
}

static void publication_race_hook(enum packer_publish_test_stage stage,
                                  int directory_fd,
                                  const char *transaction_leaf,
                                  const char *output_leaf)
{
    if (stage != g_hook_stage)
        return;
    if (stage == PACKER_PUBLISH_TEST_AFTER_DESTINATION_PROBE) {
        if (!write_file_at(directory_fd, output_leaf,
                           "competing-create", 0644))
            g_hook_result = 0;
    } else if (stage == PACKER_PUBLISH_TEST_BEFORE_FALLBACK_RENAME) {
        if (!g_hook_source_leaf ||
            renameat(directory_fd, g_hook_source_leaf,
                     directory_fd, output_leaf) < 0)
            g_hook_result = 0;
    } else if (stage == PACKER_PUBLISH_TEST_AFTER_FAST_RENAME) {
        if (!g_hook_source_leaf ||
            renameat(directory_fd, g_hook_source_leaf,
                     directory_fd, transaction_leaf) < 0)
            g_hook_result = 0;
    } else if (stage == PACKER_PUBLISH_TEST_AFTER_BACKUP_LINK) {
        if (strlen(transaction_leaf) > NAME_MAX) {
            g_hook_result = 0;
            return;
        }
        memcpy(g_hook_backup_leaf, transaction_leaf,
               strlen(transaction_leaf) + 1);
        if (!g_hook_source_leaf ||
            renameat(directory_fd, g_hook_source_leaf,
                     directory_fd, transaction_leaf) < 0)
            g_hook_result = 0;
    }
}

static int create_fallback_case(const char *root, int directory_fd,
                                int rename_error, const char *leaf)
{
    char output_path[PATH_MAX];
    char transaction_path[PATH_MAX];
    struct stat transaction_identity;

    if (snprintf(output_path, sizeof(output_path), "%s/%s", root, leaf) >=
        (int)sizeof(output_path) ||
        !make_transaction(output_path, "new-create", transaction_path,
                          &transaction_identity))
        return 0;
    reset_injection(rename_error);
    {
        int transaction_name_owned = 1;

        if (commit_output_transaction(transaction_path, output_path,
                                      &transaction_identity,
                                      &transaction_name_owned) < 0 ||
            transaction_name_owned) {
            unlink(transaction_path);
            return 0;
        }
    }
    if (
        !file_matches_at(directory_fd, leaf, "new-create", 0755) ||
        access(transaction_path, F_OK) == 0 || errno != ENOENT ||
        !no_publication_debris(directory_fd)) {
        unlink(transaction_path);
        unlinkat(directory_fd, leaf, 0);
        return 0;
    }
    return 1;
}

static int replace_fallback_case(const char *root, int directory_fd)
{
    static const char leaf[] = "replace-output";
    char output_path[PATH_MAX];
    char transaction_path[PATH_MAX];
    struct stat transaction_identity;

    if (!write_file_at(directory_fd, leaf, "old-replace", 0640) ||
        snprintf(output_path, sizeof(output_path), "%s/%s", root, leaf) >=
            (int)sizeof(output_path) ||
        !make_transaction(output_path, "new-replace", transaction_path,
                          &transaction_identity))
        return 0;
    reset_injection(ENOSYS);
    {
        int transaction_name_owned = 1;

        if (commit_output_transaction(transaction_path, output_path,
                                      &transaction_identity,
                                      &transaction_name_owned) < 0 ||
            transaction_name_owned) {
            unlink(transaction_path);
            return 0;
        }
    }
    if (
        !file_matches_at(directory_fd, leaf, "new-replace", 0755) ||
        g_packer_publish_test_fsync_calls != 4 ||
        access(transaction_path, F_OK) == 0 || errno != ENOENT ||
        !no_publication_debris(directory_fd)) {
        unlink(transaction_path);
        unlinkat(directory_fd, leaf, 0);
        return 0;
    }
    return 1;
}

static int competing_create_case(const char *root, int directory_fd)
{
    static const char leaf[] = "competing-output";
    char output_path[PATH_MAX];
    char transaction_path[PATH_MAX];
    struct stat transaction_identity;
    int transaction_name_owned = 1;
    int commit_result;

    if (snprintf(output_path, sizeof(output_path), "%s/%s", root, leaf) >=
            (int)sizeof(output_path) ||
        !make_transaction(output_path, "must-not-win", transaction_path,
                          &transaction_identity))
        return 0;
    reset_injection(ENOSYS);
    g_hook_stage = PACKER_PUBLISH_TEST_AFTER_DESTINATION_PROBE;
    g_packer_publish_test_stage_hook = publication_race_hook;
    errno = 0;
    commit_result = commit_output_transaction(transaction_path, output_path,
                                              &transaction_identity,
                                              &transaction_name_owned);
    g_packer_publish_test_stage_hook = NULL;
    if (commit_result == 0 || errno != EEXIST || !g_hook_result ||
        !file_matches_at(directory_fd, leaf, "competing-create", 0644) ||
        access(transaction_path, F_OK) != 0 || !transaction_name_owned) {
        unlink(transaction_path);
        unlinkat(directory_fd, leaf, 0);
        return 0;
    }
    if (unlink(transaction_path) < 0 ||
        !no_publication_debris(directory_fd)) {
        unlinkat(directory_fd, leaf, 0);
        return 0;
    }
    return 1;
}

static int replacement_race_case(const char *root, int directory_fd)
{
    static const char leaf[] = "raced-replace-output";
    static const char source_leaf[] = "raced-replace-source";
    char output_path[PATH_MAX];
    char transaction_path[PATH_MAX];
    struct stat transaction_identity;
    int transaction_name_owned = 1;
    int commit_result;

    if (!write_file_at(directory_fd, leaf, "old-before-race", 0640) ||
        !write_file_at(directory_fd, source_leaf, "external-winner", 0600) ||
        snprintf(output_path, sizeof(output_path), "%s/%s", root, leaf) >=
            (int)sizeof(output_path) ||
        !make_transaction(output_path, "must-not-overwrite-race",
                          transaction_path, &transaction_identity))
        return 0;
    reset_injection(ENOSYS);
    g_hook_source_leaf = source_leaf;
    g_hook_stage = PACKER_PUBLISH_TEST_BEFORE_FALLBACK_RENAME;
    g_packer_publish_test_stage_hook = publication_race_hook;
    errno = 0;
    commit_result = commit_output_transaction(transaction_path, output_path,
                                              &transaction_identity,
                                              &transaction_name_owned);
    g_packer_publish_test_stage_hook = NULL;
    if (commit_result == 0 || errno != ESTALE || !g_hook_result ||
        !file_matches_at(directory_fd, leaf, "external-winner", 0600) ||
        access(transaction_path, F_OK) != 0 || !transaction_name_owned) {
        unlink(transaction_path);
        unlinkat(directory_fd, leaf, 0);
        unlinkat(directory_fd, source_leaf, 0);
        return 0;
    }
    if (unlink(transaction_path) < 0 ||
        !no_publication_debris(directory_fd)) {
        unlinkat(directory_fd, leaf, 0);
        return 0;
    }
    return 1;
}

static int failed_replace_rollback_case(const char *root, int directory_fd)
{
    static const char leaf[] = "rollback-output";
    char output_path[PATH_MAX];
    char transaction_path[PATH_MAX];
    struct stat old_identity;
    struct stat current_identity;
    struct stat transaction_identity;
    int transaction_name_owned = 1;
    int commit_result;

    if (!write_file_at(directory_fd, leaf, "preserve-exactly", 0644) ||
        fstatat(directory_fd, leaf, &old_identity,
                AT_SYMLINK_NOFOLLOW) < 0 ||
        snprintf(output_path, sizeof(output_path), "%s/%s", root, leaf) >=
            (int)sizeof(output_path) ||
        !make_transaction(output_path, "failed-new-value", transaction_path,
                          &transaction_identity))
        return 0;
    reset_injection(ENOSYS);
    /* Initial sync is call 1 and backup sync is call 2.  Fail the
     * post-rename durability sync, then require exact-inode rollback. */
    g_packer_publish_test_fail_fsync_call = 3;
    errno = 0;
    commit_result = commit_output_transaction(transaction_path, output_path,
                                              &transaction_identity,
                                              &transaction_name_owned);
    g_packer_publish_test_fail_fsync_call = 0;
    if (commit_result == 0 || errno != EIO ||
        fstatat(directory_fd, leaf, &current_identity,
                AT_SYMLINK_NOFOLLOW) < 0 ||
        !output_identity_equal(&old_identity, &current_identity) ||
        !file_matches_at(directory_fd, leaf, "preserve-exactly", 0644) ||
        access(transaction_path, F_OK) == 0 || errno != ENOENT ||
        transaction_name_owned ||
        !no_publication_debris(directory_fd)) {
        unlink(transaction_path);
        unlinkat(directory_fd, leaf, 0);
        return 0;
    }
    return 1;
}

static int failed_backup_sync_case(const char *root, int directory_fd)
{
    static const char leaf[] = "backup-sync-output";
    char output_path[PATH_MAX];
    char transaction_path[PATH_MAX];
    struct stat old_identity;
    struct stat current_identity;
    struct stat transaction_identity;
    int transaction_name_owned = 1;
    int commit_result;

    if (!write_file_at(directory_fd, leaf, "old-before-backup", 0640) ||
        fstatat(directory_fd, leaf, &old_identity,
                AT_SYMLINK_NOFOLLOW) < 0 ||
        snprintf(output_path, sizeof(output_path), "%s/%s", root, leaf) >=
            (int)sizeof(output_path) ||
        !make_transaction(output_path, "must-not-publish", transaction_path,
                          &transaction_identity))
        return 0;
    reset_injection(ENOSYS);
    /* Call 1 syncs the pre-transaction directory state.  Call 2 must sync
     * the backup before rename; force it to fail and require no rename. */
    g_packer_publish_test_fail_fsync_call = 2;
    errno = 0;
    commit_result = commit_output_transaction(transaction_path, output_path,
                                              &transaction_identity,
                                              &transaction_name_owned);
    g_packer_publish_test_fail_fsync_call = 0;
    if (commit_result == 0 || errno != EIO ||
        g_packer_publish_test_fsync_calls != 3 ||
        !transaction_name_owned ||
        fstatat(directory_fd, leaf, &current_identity,
                AT_SYMLINK_NOFOLLOW) < 0 ||
        !output_identity_equal(&old_identity, &current_identity) ||
        !file_matches_at(directory_fd, leaf, "old-before-backup", 0640) ||
        access(transaction_path, F_OK) != 0) {
        unlink(transaction_path);
        unlinkat(directory_fd, leaf, 0);
        return 0;
    }
    if (cleanup_output_transaction(transaction_path,
                                   &transaction_identity) < 0 ||
        !no_publication_debris(directory_fd)) {
        unlinkat(directory_fd, leaf, 0);
        return 0;
    }
    return 1;
}

static int failed_backup_identity_probe_race_case(const char *root,
                                                  int directory_fd)
{
    static const char leaf[] = "backup-probe-output";
    static const char source_leaf[] = "backup-probe-competitor";
    char output_path[PATH_MAX];
    char transaction_path[PATH_MAX];
    struct stat old_identity;
    struct stat current_identity;
    struct stat transaction_identity;
    int transaction_name_owned = 1;
    int commit_result;

    if (!write_file_at(directory_fd, leaf, "old-before-probe", 0640) ||
        !write_file_at(directory_fd, source_leaf, "backup-name-winner", 0600) ||
        fstatat(directory_fd, leaf, &old_identity,
                AT_SYMLINK_NOFOLLOW) < 0 ||
        snprintf(output_path, sizeof(output_path), "%s/%s", root, leaf) >=
            (int)sizeof(output_path) ||
        !make_transaction(output_path, "must-not-publish", transaction_path,
                          &transaction_identity))
        return 0;
    reset_injection(ENOSYS);
    g_hook_source_leaf = source_leaf;
    g_hook_stage = PACKER_PUBLISH_TEST_AFTER_BACKUP_LINK;
    g_packer_publish_test_stage_hook = publication_race_hook;
    g_packer_publish_test_backup_stat_errno = EIO;
    errno = 0;
    commit_result = commit_output_transaction(transaction_path, output_path,
                                              &transaction_identity,
                                              &transaction_name_owned);
    g_packer_publish_test_stage_hook = NULL;
    if (commit_result == 0 || errno != EIO || !g_hook_result ||
        !transaction_name_owned || g_hook_backup_leaf[0] == '\0' ||
        fstatat(directory_fd, leaf, &current_identity,
                AT_SYMLINK_NOFOLLOW) < 0 ||
        !output_identity_equal(&old_identity, &current_identity) ||
        !file_matches_at(directory_fd, leaf, "old-before-probe", 0640) ||
        !file_matches_at(directory_fd, g_hook_backup_leaf,
                         "backup-name-winner", 0600) ||
        fstatat(directory_fd, source_leaf, &current_identity,
                AT_SYMLINK_NOFOLLOW) == 0 || errno != ENOENT ||
        access(transaction_path, F_OK) != 0) {
        unlink(transaction_path);
        unlinkat(directory_fd, leaf, 0);
        unlinkat(directory_fd, source_leaf, 0);
        if (g_hook_backup_leaf[0] != '\0')
            unlinkat(directory_fd, g_hook_backup_leaf, 0);
        return 0;
    }
    if (cleanup_output_transaction(transaction_path,
                                   &transaction_identity) < 0 ||
        unlinkat(directory_fd, g_hook_backup_leaf, 0) < 0 ||
        !no_publication_debris(directory_fd)) {
        unlinkat(directory_fd, leaf, 0);
        return 0;
    }
    return 1;
}

static int fast_exchange_ownership_race_case(const char *root,
                                             int directory_fd)
{
    static const char leaf[] = "fast-raced-output";
    static const char source_leaf[] = "fast-raced-source";
    char output_path[PATH_MAX];
    char transaction_path[PATH_MAX];
    struct stat transaction_identity;
    int transaction_name_owned = 1;
    int commit_result;
    int cleanup_result;

    if (!write_file_at(directory_fd, leaf, "old-fast-value", 0644) ||
        !write_file_at(directory_fd, source_leaf, "fast-race-winner", 0600) ||
        snprintf(output_path, sizeof(output_path), "%s/%s", root, leaf) >=
            (int)sizeof(output_path) ||
        !make_transaction(output_path, "new-fast-value", transaction_path,
                          &transaction_identity))
        return 0;
    reset_injection(0);
    g_hook_source_leaf = source_leaf;
    g_hook_stage = PACKER_PUBLISH_TEST_AFTER_FAST_RENAME;
    g_packer_publish_test_stage_hook = publication_race_hook;
    errno = 0;
    commit_result = commit_output_transaction(transaction_path, output_path,
                                              &transaction_identity,
                                              &transaction_name_owned);
    g_packer_publish_test_stage_hook = NULL;
    errno = 0;
    cleanup_result = cleanup_output_transaction(transaction_path,
                                                &transaction_identity);
    if (commit_result == 0 || transaction_name_owned || !g_hook_result ||
        cleanup_result == 0 || errno != ESTALE ||
        !file_matches_at(directory_fd,
                         output_path_leaf(transaction_path),
                         "fast-race-winner", 0600) ||
        !file_matches_at(directory_fd, leaf, "new-fast-value", 0755)) {
        unlink(transaction_path);
        unlinkat(directory_fd, leaf, 0);
        unlinkat(directory_fd, source_leaf, 0);
        return 0;
    }
    /* The transaction name is now owned by the simulated competitor.  The
     * gate removes its own fixture only after proving production cleanup did
     * not do so. */
    if (unlink(transaction_path) < 0 ||
        !no_publication_debris(directory_fd)) {
        unlinkat(directory_fd, leaf, 0);
        return 0;
    }
    return 1;
}

static int nonregular_refusal_case(const char *root, int directory_fd)
{
    static const char leaf[] = "symlink-output";
    static const char target_leaf[] = "symlink-target";
    char output_path[PATH_MAX];
    char transaction_path[PATH_MAX];
    char link_target[64];
    struct stat transaction_identity;
    int transaction_name_owned = 1;
    struct stat link_identity;
    ssize_t length;
    int commit_result;

    if (!write_file_at(directory_fd, target_leaf, "symlink-target", 0644) ||
        symlinkat(target_leaf, directory_fd, leaf) < 0 ||
        snprintf(output_path, sizeof(output_path), "%s/%s", root, leaf) >=
            (int)sizeof(output_path) ||
        !make_transaction(output_path, "must-not-follow", transaction_path,
                          &transaction_identity))
        return 0;
    reset_injection(ENOSYS);
    errno = 0;
    commit_result = commit_output_transaction(transaction_path, output_path,
                                              &transaction_identity,
                                              &transaction_name_owned);
    length = readlinkat(directory_fd, leaf, link_target,
                        sizeof(link_target) - 1);
    if (length >= 0)
        link_target[length] = '\0';
    if (commit_result == 0 || errno != EINVAL || length < 0 ||
        strcmp(link_target, target_leaf) != 0 ||
        fstatat(directory_fd, leaf, &link_identity,
                AT_SYMLINK_NOFOLLOW) < 0 ||
        !S_ISLNK(link_identity.st_mode) ||
        access(transaction_path, F_OK) != 0 || !transaction_name_owned) {
        unlink(transaction_path);
        unlinkat(directory_fd, leaf, 0);
        unlinkat(directory_fd, target_leaf, 0);
        return 0;
    }
    if (unlink(transaction_path) < 0 ||
        !no_publication_debris(directory_fd))
        return 0;
    return 1;
}

static int transaction_sync_swap_refusal_case(const char *root,
                                               int directory_fd)
{
    static const char victim_leaf[] = "sync-swap-victim";
    char output_path[PATH_MAX];
    char transaction_path[PATH_MAX];
    struct stat transaction_identity;
    struct stat victim_identity;
    FILE *stream = NULL;
    int result;

    if (snprintf(output_path, sizeof(output_path), "%s/sync-swap-output",
                 root) >= (int)sizeof(output_path) ||
        !write_file_at(directory_fd, victim_leaf, "victim", 0600) ||
        create_output_transaction(output_path, transaction_path, &stream,
                                  &transaction_identity) < 0 ||
        fwrite("owned", 1, 5, stream) != 5 ||
        finish_output_stream(&stream) < 0 ||
        unlink(transaction_path) < 0 ||
        symlinkat(victim_leaf, directory_fd,
                  output_path_leaf(transaction_path)) < 0)
        return 0;

    errno = 0;
    result = sync_output_transaction(transaction_path,
                                     &transaction_identity);
    if (result == 0 ||
        fstatat(directory_fd, victim_leaf, &victim_identity,
                AT_SYMLINK_NOFOLLOW) < 0 ||
        !S_ISREG(victim_identity.st_mode) ||
        (victim_identity.st_mode & 07777) != 0600) {
        unlink(transaction_path);
        unlinkat(directory_fd, victim_leaf, 0);
        return 0;
    }
    if (unlink(transaction_path) < 0 ||
        unlinkat(directory_fd, victim_leaf, 0) < 0 ||
        !no_publication_debris(directory_fd))
        return 0;
    return 1;
}

int main(void)
{
    const char *temporary = getenv("TMPDIR");
    char root[PATH_MAX];
    int directory_fd = -1;
    int result = 1;

    if (!temporary || temporary[0] == '\0')
        temporary = "/dev/shm";
    if (snprintf(root, sizeof(root), "%s/dlfreeze-publish-gate.XXXXXX",
                 temporary) >= (int)sizeof(root) || !mkdtemp(root))
        return 90;
    directory_fd = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory_fd < 0) {
        rmdir(root);
        return 91;
    }

    if (!create_fallback_case(root, directory_fd, ENOSYS,
                              "create-enosys") ||
        !create_fallback_case(root, directory_fd, EINVAL,
                              "create-einval") ||
        !replace_fallback_case(root, directory_fd) ||
        !competing_create_case(root, directory_fd) ||
        !replacement_race_case(root, directory_fd) ||
        !failed_backup_identity_probe_race_case(root, directory_fd) ||
        !failed_backup_sync_case(root, directory_fd) ||
        !failed_replace_rollback_case(root, directory_fd) ||
        !fast_exchange_ownership_race_case(root, directory_fd) ||
        !nonregular_refusal_case(root, directory_fd) ||
        !transaction_sync_swap_refusal_case(root, directory_fd))
        goto out;
    result = 0;

out:
    reset_injection(0);
    if (directory_fd >= 0) {
        DIR *directory;
        struct dirent *entry;
        int duplicate = dup(directory_fd);

        if (duplicate >= 0 && (directory = fdopendir(duplicate)) != NULL) {
            while ((entry = readdir(directory)) != NULL) {
                if (strcmp(entry->d_name, ".") != 0 &&
                    strcmp(entry->d_name, "..") != 0)
                    unlinkat(directory_fd, entry->d_name, 0);
            }
            closedir(directory);
        } else if (duplicate >= 0) {
            close(duplicate);
        }
        close(directory_fd);
    }
    rmdir(root);
    return result;
}
