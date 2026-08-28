#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <iconv.h>
#include <netdb.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>

extern int __nss_configure_lookup(const char *, const char *);

static int test_iconv(void)
{
    static const char input_bytes[] = { (char)0xc1, (char)0xc2, (char)0xc3 };
    char input[sizeof(input_bytes)];
    char output[32];
    char *in = input;
    char *out = output;
    size_t in_left = sizeof(input);
    size_t out_left = sizeof(output);
    iconv_t cd;

    memcpy(input, input_bytes, sizeof(input));
    cd = iconv_open("UTF-8", "IBM1047");
    if (cd == (iconv_t)-1) {
        if (errno == EINVAL) {
            puts("iconv=unavailable");
            return 77;
        }
        fprintf(stderr, "iconv_open: %s\n", strerror(errno));
        return 1;
    }
    if (iconv(cd, &in, &in_left, &out, &out_left) == (size_t)-1) {
        fprintf(stderr, "iconv: %s\n", strerror(errno));
        iconv_close(cd);
        return 1;
    }
    if (iconv_close(cd) != 0) {
        fprintf(stderr, "iconv_close: %s\n", strerror(errno));
        return 1;
    }

    printf("iconv=%.*s\n", (int)(sizeof(output) - out_left), output);
    return 0;
}

static int test_nss(const char *services, int unavailable_is_expected)
{
    struct passwd *pw;
    struct addrinfo hints = {0};
    struct addrinfo *result = NULL;
    int error;

    if (services && __nss_configure_lookup("passwd", services) != 0) {
        fprintf(stderr, "__nss_configure_lookup failed\n");
        return 1;
    }
    errno = 0;
    pw = getpwnam("root");
    if (!pw) {
        if (unavailable_is_expected) {
            puts("nss=unavailable");
            return 77;
        }
        fprintf(stderr, "getpwnam: %s\n", errno ? strerror(errno) : "not found");
        return 1;
    }

    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    error = getaddrinfo("localhost", NULL, &hints, &result);
    if (error != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(error));
        return 1;
    }
    freeaddrinfo(result);
    printf("nss=%s:%lu\n", pw->pw_name, (unsigned long)pw->pw_uid);
    return 0;
}

static int test_internal_error_isolation(void)
{
    static const char missing[] =
        "/dlfreeze-test/this-module-must-not-exist.so";
    iconv_t cd;
    const char *error;

    (void)dlerror();
    if (dlopen(missing, RTLD_NOW) != NULL) {
        fputs("unexpected dlopen success\n", stderr);
        return 1;
    }
    cd = iconv_open("UTF-8", "IBM1047");
    if (cd != (iconv_t)-1 && iconv_close(cd) != 0) {
        fprintf(stderr, "iconv_close: %s\n", strerror(errno));
        return 1;
    }
    error = dlerror();
    if (!error || !strstr(error, "this-module-must-not-exist.so") ||
        dlerror() != NULL) {
        fputs("internal module probe changed public dlerror state\n", stderr);
        return 1;
    }
    puts("dlerror=preserved");
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "iconv") == 0)
        return test_iconv();
    if (argc == 2 && strcmp(argv[1], "nss-module") == 0)
        return test_nss("compat", 1);
    if (argc == 2 && strcmp(argv[1], "nss-fallback") == 0)
        return test_nss("compat files", 0);
    if (argc == 2 && strcmp(argv[1], "error-isolation") == 0)
        return test_internal_error_isolation();
    if (argc != 1) {
        fprintf(stderr, "unexpected arguments\n");
        return 2;
    }
    {
        int result = test_nss(NULL, 0);

        return result ? result : test_iconv();
    }
}
