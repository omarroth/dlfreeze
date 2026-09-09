#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "dep_resolver.h"
#include "packer.h"

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

enum {
    TEST_AFTER_PRELINK = 1,
    TEST_AFTER_SYMTAB = 2,
    TEST_AFTER_PAYLOAD = 3,
    TEST_STAGE_COUNT = 3,
    TEST_AFTER_PRIVATE_RENAME = 4,
};

static int fail_stage;
static unsigned int seen_mask;
static struct stat seen_identity[TEST_STAGE_COUNT + 1];
static unsigned int private_rename_calls;

int dlfreeze_packer_transaction_gate_after_private_rename(
    const struct stat *replacement_identity)
{
    if (!replacement_identity)
        return 1;
    private_rename_calls++;
    return fail_stage == TEST_AFTER_PRIVATE_RENAME &&
           private_rename_calls == 1;
}

int dlfreeze_packer_transaction_gate_after_replacement(
    int stage, const struct stat *replacement_identity)
{
    if (stage < TEST_AFTER_PRELINK || stage > TEST_AFTER_PAYLOAD ||
        !replacement_identity)
        return 1;
    seen_mask |= 1U << (unsigned int)(stage - 1);
    seen_identity[stage] = *replacement_identity;
    return fail_stage == stage;
}

static int same_identity(const struct stat *left, const struct stat *right)
{
    return left->st_dev == right->st_dev && left->st_ino == right->st_ino &&
           (left->st_mode & S_IFMT) == (right->st_mode & S_IFMT);
}

static int no_transaction_debris(const char *output_path)
{
    const char *slash = strrchr(output_path, '/');
    char directory_path[PATH_MAX];
    DIR *directory;
    struct dirent *entry;
    size_t length;
    int result = 1;

    if (!slash)
        return 0;
    length = (size_t)(slash - output_path);
    if (length == 0) {
        directory_path[0] = '/';
        directory_path[1] = '\0';
    } else {
        if (length >= sizeof(directory_path))
            return 0;
        memcpy(directory_path, output_path, length);
        directory_path[length] = '\0';
    }
    directory = opendir(directory_path);
    if (!directory)
        return 0;
    errno = 0;
    while ((entry = readdir(directory)) != NULL) {
        if (strncmp(entry->d_name, ".dlfreeze-pack.", 16) == 0) {
            fprintf(stderr, "transaction debris remains: %s\n",
                    entry->d_name);
            result = 0;
            break;
        }
    }
    if (!entry && errno != 0)
        result = 0;
    closedir(directory);
    return result;
}

int main(int argc, char **argv)
{
    const unsigned int all_stages = (1U << TEST_STAGE_COUNT) - 1U;
    struct pack_options options = {0};
    struct dep_list dependencies;
    struct stat published;
    char *end = NULL;
    long requested_stage;
    int pack_result;
    int result = 1;

    if (argc != 5)
        return 90;
    errno = 0;
    requested_stage = strtol(argv[4], &end, 10);
    if (errno != 0 || !end || *end != '\0' || requested_stage < 0 ||
        requested_stage > TEST_AFTER_PRIVATE_RENAME)
        return 91;
    fail_stage = (int)requested_stage;
    if (lstat(argv[3], &published) == 0 || errno != ENOENT)
        return 92;
    if (dep_resolve(argv[1], &dependencies) < 0)
        return 93;

    options.exe_path = argv[1];
    options.exe_name = argv[1];
    options.output_path = argv[3];
    options.bootstrap_path = argv[2];
    options.deps = &dependencies;
    options.direct_load = 1;
    pack_result = pack_frozen(&options);
    dep_list_free(&dependencies);

    if (!no_transaction_debris(argv[3]))
        goto out;
    if (fail_stage == TEST_AFTER_PRIVATE_RENAME) {
        if (pack_result >= 0 || seen_mask != 0 ||
            private_rename_calls != 1 ||
            (lstat(argv[3], &published) == 0 || errno != ENOENT))
            goto out;
    } else if (fail_stage != 0) {
        unsigned int expected_mask =
            (1U << (unsigned int)fail_stage) - 1U;

        if (pack_result >= 0 || seen_mask != expected_mask ||
            private_rename_calls != (unsigned int)fail_stage ||
            (lstat(argv[3], &published) == 0 || errno != ENOENT))
            goto out;
    } else {
        if (pack_result < 0 || seen_mask != all_stages ||
            private_rename_calls != TEST_STAGE_COUNT ||
            lstat(argv[3], &published) < 0 ||
            !S_ISREG(published.st_mode) ||
            (published.st_mode & 07777) != 0755 ||
            !same_identity(&published,
                           &seen_identity[TEST_AFTER_PAYLOAD]))
            goto out;
    }
    if (fail_stage != TEST_AFTER_PRIVATE_RENAME) {
        for (int stage = TEST_AFTER_PRELINK + 1;
             stage <= (fail_stage ? fail_stage : TEST_AFTER_PAYLOAD);
             stage++)
            if (same_identity(&seen_identity[stage - 1],
                              &seen_identity[stage]))
                goto out;
    }
    result = 0;

out:
    if (result != 0)
        fprintf(stderr,
                "identity gate failed: fail_stage=%d pack=%d seen=0x%x "
                "private-renames=%u errno=%d\n",
                fail_stage, pack_result, seen_mask,
                private_rename_calls, errno);
    return result;
}
