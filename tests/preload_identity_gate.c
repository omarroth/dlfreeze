/* Exercise helper identity selection without requiring a distro-specific
 * libc SONAME. Unused CLI sections are discarded by --gc-sections. */
#define main dlfreeze_cli_main
#include "../src/main.c"
#undef main

int main(void)
{
    struct dep_list deps = {0};
    struct resolved_lib collision = {0};
    const char *provider = NULL;

    deps.runtime_family = DEP_RUNTIME_MUSL;
    deps.interp_path = "/nonexistent/renamed-runtime";
    deps.interp_soname = "explicit-runtime-identity.so.1";
    if (target_musl_shortname_provider(&deps, deps.interp_soname,
                                      &provider) != 1 ||
        provider != deps.interp_path)
        return 1;
    if (target_musl_shortname_provider(&deps, "renamed-runtime",
                                      &provider) != 0)
        return 2; /* a pathname basename is not an ELF identity */
    if (target_musl_shortname_provider(&deps, "libc.so",
                                      &provider) != 1 ||
        provider != deps.interp_path)
        return 3;

    collision.name = deps.interp_soname;
    collision.path = "/nonexistent/different-object";
    deps.libs = &collision;
    deps.count = 1;
    if (target_musl_shortname_provider(&deps, deps.interp_soname,
                                      &provider) != -1)
        return 4; /* conflicting startup providers remain ambiguous */
    collision.path = deps.interp_path;
    if (target_musl_shortname_provider(&deps, deps.interp_soname,
                                      &provider) != 1)
        return 5;
    deps.count = 0;
    deps.interp_soname = NULL;
    if (target_musl_shortname_provider(&deps, "explicit-runtime-identity.so.1",
                                      &provider) != 0)
        return 6;
    return 0;
}
