/* Focused direct-loader GNU dynamic-token grammar gate. */
#include "../src/loader.c"

static int expect_expansion(const char *input, const char *expected,
                            int expected_result)
{
    struct loaded_obj owner;
    char output[PATH_MAX];
    int absolute = -1;
    int result;

    memset(&owner, 0, sizeof(owner));
    owner.name = "/fixture/bin/main";
    result = dl_expand_search_component(
        input, strlen(input), DL_SEARCH_GNU_ELF, &owner,
        output, sizeof(output), &absolute);
    if (result != expected_result)
        return 0;
    if (result != DL_SEARCH_EXPANSION_OK)
        return 1;
    return strcmp(output, expected) == 0;
}

int main(void)
{
    static const char full_list[] = "/first:/second/$LIB";
    static const char origin_list[] = "$ORIGIN/lib:/plain";
    static const char ambiguous_origin[] = "$ORIGIN.suffix:/plain";
    static const char unknown_list[] = "/first:$UNKNOWN";
    static const char ambiguous_platform[] = "$PLATFORM.suffix:/plain";

    if (dl_gnu_path_tokens_admitted(
            full_list, sizeof(full_list) - 1, DL_SEARCH_GNU_ELF) ||
        dl_gnu_path_tokens_admitted(
            unknown_list, sizeof(unknown_list) - 1,
            DL_SEARCH_GNU_ELF) ||
        dl_gnu_path_tokens_admitted(
            ambiguous_origin, sizeof(ambiguous_origin) - 1,
            DL_SEARCH_GNU_ELF) ||
        dl_gnu_path_tokens_admitted(
            ambiguous_platform, sizeof(ambiguous_platform) - 1,
            DL_SEARCH_GNU_ELF) ||
        !dl_gnu_path_tokens_admitted(
            origin_list, sizeof(origin_list) - 1,
            DL_SEARCH_GNU_ELF) ||
        !expect_expansion("$ORIGIN/lib", "/fixture/bin/lib",
                          DL_SEARCH_EXPANSION_OK) ||
        !expect_expansion("${ORIGIN}.suffix", "/fixture/bin.suffix",
                          DL_SEARCH_EXPANSION_OK) ||
        !expect_expansion("$LIB", NULL, DL_SEARCH_EXPANSION_ERROR))
        return 1;

#if defined(__aarch64__)
    {
        static const char platform_list[] = "$PLATFORM/lib:/plain";

        if (!dl_gnu_path_tokens_admitted(
                platform_list, sizeof(platform_list) - 1,
                DL_SEARCH_GNU_ELF))
            return 2;
        memcpy(g_kernel_platform, "aarch64", sizeof("aarch64"));
        g_kernel_platform_present = 1;
        if (!expect_expansion("$PLATFORM/lib", "aarch64/lib",
                              DL_SEARCH_EXPANSION_OK))
            return 3;
        g_kernel_platform_present = 0;
        if (!expect_expansion("${PLATFORM}/lib", NULL,
                              DL_SEARCH_EXPANSION_UNAVAILABLE))
            return 4;
    }
#elif defined(__x86_64__)
    {
        static const char platform_list[] = "/first:$PLATFORM/lib";

        if (dl_gnu_path_tokens_admitted(
                platform_list, sizeof(platform_list) - 1,
                DL_SEARCH_GNU_ENV) ||
            !expect_expansion("$PLATFORM/lib", NULL,
                              DL_SEARCH_EXPANSION_ERROR))
            return 5;
    }
#endif
    return 0;
}
