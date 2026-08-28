/* Focused pack-resolver search grammar and process-lifetime snapshot gate. */
#include "../src/dep_resolver.c"

static int write_all(int fd, const char *value)
{
    size_t size = strlen(value);

    while (size != 0) {
        ssize_t written = write(fd, value, size);

        if (written < 0 && errno == EINTR)
            continue;
        if (written <= 0)
            return -1;
        value += written;
        size -= (size_t)written;
    }
    return 0;
}

static int replace_path(const char *path, const char *value)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    int result;

    if (fd < 0)
        return -1;
    result = write_all(fd, value);
    if (close(fd) < 0)
        result = -1;
    return result;
}

static int origin_grammar_gate(void)
{
    struct dep_list aarch64_gnu = {
        .runtime_family = DEP_RUNTIME_GNU,
        .target_e_machine = EM_AARCH64,
        .gnu_platform = (char *)"aarch64",
    };
    struct dep_list x86_gnu = {
        .runtime_family = DEP_RUNTIME_GNU,
        .target_e_machine = EM_X86_64,
        .gnu_platform = (char *)"haswell",
    };
    enum origin_expansion_result result;
    char origin[DEP_MUSL_SEARCH_BUFFER_SIZE];
    char *expanded;

    expanded = expand_origin("$ORIGINsuffix", "/prefix",
                             SEARCH_MUSL_RPATH,
                             NULL,
                             DEP_MUSL_SEARCH_BUFFER_SIZE, &result);
    if (!expanded || strcmp(expanded, "/prefixsuffix") != 0)
        return -1;
    free(expanded);
    expanded = expand_origin("$ORIGIN$ORIGIN", "/prefix",
                             SEARCH_MUSL_RPATH,
                             NULL,
                             DEP_MUSL_SEARCH_BUFFER_SIZE, &result);
    if (!expanded || strcmp(expanded, "/prefix/prefix") != 0)
        return -1;
    free(expanded);

    expanded = expand_origin("$ORIGINsuffix", "/prefix", SEARCH_GNU_ELF,
                             NULL, PATH_MAX, &result);
    if (expanded || result != ORIGIN_EXPANSION_UNSUPPORTED)
        return -1;
    expanded = expand_origin("$ORIGIN$ORIGIN", "/prefix", SEARCH_GNU_ELF,
                             NULL, PATH_MAX, &result);
    if (expanded || result != ORIGIN_EXPANSION_UNSUPPORTED)
        return -1;

    expanded = expand_origin("$PLATFORM/subdir", "/prefix",
                             SEARCH_GNU_ELF, &aarch64_gnu,
                             PATH_MAX, &result);
    if (!expanded || strcmp(expanded, "aarch64/subdir") != 0)
        return -1;
    free(expanded);
    expanded = expand_origin("${PLATFORM}.suffix", "/prefix",
                             SEARCH_GNU_ELF, &aarch64_gnu,
                             PATH_MAX, &result);
    if (!expanded || strcmp(expanded, "aarch64.suffix") != 0)
        return -1;
    free(expanded);
    /* Official 2.27 treats punctuation after an unbraced token literally;
     * 2.28+ uses the wider gABI boundary.  The resolver admits only their
     * safe intersection instead of guessing from a downstream version. */
    expanded = expand_origin("$PLATFORM.suffix", "/prefix",
                             SEARCH_GNU_ELF, &aarch64_gnu,
                             PATH_MAX, &result);
    if (expanded || result != ORIGIN_EXPANSION_UNSUPPORTED)
        return -1;
    /* x86-64 platform selection is CPU/tunable dependent, and $LIB is a
     * target-glibc build constant.  A host-derived spelling is forbidden. */
    expanded = expand_origin("$PLATFORM", "/prefix", SEARCH_GNU_ELF,
                             &x86_gnu, PATH_MAX, &result);
    if (expanded || result != ORIGIN_EXPANSION_UNSUPPORTED)
        return -1;
    expanded = expand_origin("${LIB}", "/prefix", SEARCH_GNU_ELF,
                             &aarch64_gnu, PATH_MAX, &result);
    if (expanded || result != ORIGIN_EXPANSION_UNSUPPORTED)
        return -1;
    /* Native glibc leaves an unknown DST literal.  Freezing that spelling
     * could silently select a literal `$FOO` directory, so this intentional
     * conservative divergence remains an admission error. */
    expanded = expand_origin("$UNKNOWN", "/prefix", SEARCH_GNU_ELF,
                             &aarch64_gnu, PATH_MAX, &result);
    if (expanded || result != ORIGIN_EXPANSION_UNSUPPORTED)
        return -1;
    if (gnu_path_tokens_admitted(
            "/already-valid:$LIB", SEARCH_GNU_ELF,
            &aarch64_gnu) != 0 ||
        gnu_path_tokens_admitted(
            "${PLATFORM}.suffix:/plain", SEARCH_GNU_ELF,
            &aarch64_gnu) != 1)
        return -1;

    memset(origin, 'x', sizeof(origin));
    origin[sizeof(origin) - 1] = '\0';
    expanded = expand_origin("$ORIGIN", origin, SEARCH_MUSL_RPATH,
                             NULL, sizeof(origin), &result);
    if (!expanded || strlen(expanded) != sizeof(origin) - 1)
        return -1;
    free(expanded);
    expanded = expand_origin("$ORIGINx", origin, SEARCH_MUSL_RPATH,
                             NULL, sizeof(origin), &result);
    if (expanded || result != ORIGIN_EXPANSION_TOO_LONG)
        return -1;
    return 0;
}

static int musl_path_snapshot_gate(void)
{
    struct dep_list deps = {0};
    char root[] = "/tmp/dlfreeze-musl-path-snapshot-XXXXXX";
    char etc[PATH_MAX];
    char lib[PATH_MAX];
    char interp[PATH_MAX];
    char config[PATH_MAX];
    const char *arch;
    int result = -1;

#if defined(__x86_64__)
    deps.target_e_machine = EM_X86_64;
    arch = "x86_64";
#elif defined(__aarch64__)
    deps.target_e_machine = EM_AARCH64;
    arch = "aarch64";
#else
    return 0;
#endif
    deps.runtime_family = DEP_RUNTIME_MUSL;
    if (!mkdtemp(root) ||
        snprintf(etc, sizeof(etc), "%s/etc", root) >= (int)sizeof(etc) ||
        snprintf(lib, sizeof(lib), "%s/lib", root) >= (int)sizeof(lib) ||
        snprintf(interp, sizeof(interp), "%s/lib/renamed-loader", root) >=
            (int)sizeof(interp) ||
        snprintf(config, sizeof(config), "%s/etc/ld-musl-%s.path", root,
                 arch) >= (int)sizeof(config) ||
        mkdir(etc, 0700) < 0 || mkdir(lib, 0700) < 0)
        goto out;
    deps.interp_path = strdup(interp);
    if (!deps.interp_path || replace_path(config, "/first/search") < 0 ||
        initialize_musl_system_path(&deps) != LIBRARY_LOOKUP_FOUND ||
        !deps.musl_system_path ||
        strcmp(deps.musl_system_path, "/first/search") != 0)
        goto out;
    if (replace_path(config, "/second/search") < 0 ||
        initialize_musl_system_path(&deps) != LIBRARY_LOOKUP_FOUND ||
        strcmp(deps.musl_system_path, "/first/search") != 0)
        goto out;
    result = 0;

out:
    dep_list_free(&deps);
    unlink(config);
    rmdir(etc);
    rmdir(lib);
    rmdir(root);
    return result;
}

static int gnu_platform_snapshot_gate(void)
{
#if defined(__aarch64__)
    const char *kernel_platform = (const char *)getauxval(AT_PLATFORM);
    struct dep_list deps = {
        .runtime_family = DEP_RUNTIME_GNU,
        .target_e_machine = EM_AARCH64,
    };
    int result = -1;

    if (!kernel_platform || !kernel_platform[0])
        return 0;
    if (initialize_gnu_platform(&deps) == 0 && deps.gnu_platform &&
        strcmp(deps.gnu_platform, kernel_platform) == 0)
        result = 0;
    dep_list_free(&deps);
    return result;
#else
    return 0;
#endif
}

static int public_input_gate(void)
{
    struct dep_list deps = {0};

    errno = 0;
    if (dep_resolve(NULL, &deps) == 0 || errno != EINVAL)
        return -1;
    errno = 0;
    if (dep_resolve("", &deps) == 0 || errno != EINVAL)
        return -1;
    errno = 0;
    if (dep_resolve("/unused", NULL) == 0 || errno != EINVAL)
        return -1;
    errno = 0;
    if (dep_add_dlopen_libs(NULL, "/unused") == 0 || errno != EINVAL)
        return -1;
    errno = 0;
    if (dep_add_dlopen_libs(&deps, NULL) == 0 || errno != EINVAL)
        return -1;
    dep_list_free(NULL);
    return 0;
}

int main(void)
{
    if (origin_grammar_gate() < 0)
        return 1;
    if (musl_path_snapshot_gate() < 0)
        return 2;
    if (gnu_platform_snapshot_gate() < 0)
        return 3;
    if (public_input_gate() < 0)
        return 4;
    return 0;
}
