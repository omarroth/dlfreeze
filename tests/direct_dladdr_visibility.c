#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef void *(*address_fn)(void);

static int fail(int code)
{
    fprintf(stderr, "dladdr-visibility failure %d\n", code);
    return code;
}

static int load_address(void *handle, const char *name, void **address_out)
{
    void *symbol = dlsym(handle, name);
    address_fn call;

    if (!symbol)
        return 0;
    memcpy(&call, &symbol, sizeof(call));
    *address_out = call();
    return *address_out != NULL;
}

int main(int argc, char **argv)
{
    static const char local_name[] = "loader_dladdr_candidate_a";
    static const char hidden_name[] = "loader_dladdr_candidate_b";
    void *handle;
    void *local_address;
    void *hidden_address;
    int target_has_glibc_api;
    Dl_info info;

    if (argc != 2)
        return fail(2);
    target_has_glibc_api =
        dlsym(RTLD_DEFAULT, "gnu_get_libc_version") != NULL;
    handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle)
        return fail(3);
    if (!load_address(handle, "loader_dladdr_candidate_a_address",
                      &local_address) ||
        !load_address(handle, "loader_dladdr_candidate_b_address",
                      &hidden_address))
        return fail(4);

    memset(&info, 0, sizeof(info));
    if (dladdr(local_address, &info) != 1 || !info.dli_fname ||
        (info.dli_sname && strcmp(info.dli_sname, local_name) == 0))
        return fail(5);
    memset(&info, 0, sizeof(info));
    if (dladdr(hidden_address, &info) != 1 || !info.dli_fname ||
        (target_has_glibc_api
             ? (info.dli_sname && strcmp(info.dli_sname, hidden_name) == 0)
             : (!info.dli_sname || strcmp(info.dli_sname, hidden_name) != 0 ||
                info.dli_saddr != hidden_address)))
        return fail(6);

    puts("dladdr-visibility-ok");
    return 0;
}
