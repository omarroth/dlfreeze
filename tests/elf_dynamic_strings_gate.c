#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "elf_parser.h"

#include <stddef.h>
#include <string.h>

static int field_has_minimum(const char *path, const char *field,
                             size_t minimum)
{
    struct elf_info info;
    const char *value = NULL;
    int result = -1;

    if (elf_parse(path, &info) < 0)
        return -1;
    if (strcmp(field, "rpath") == 0)
        value = info.rpath;
    else if (strcmp(field, "runpath") == 0)
        value = info.runpath;
    else if (strcmp(field, "soname") == 0)
        value = info.soname;
    else if (strcmp(field, "interp") == 0)
        value = info.interp;
    if (value && strlen(value) >= minimum)
        result = 0;
    elf_info_free(&info);
    return result;
}

int main(int argc, char **argv)
{
    if (argc != 5)
        return 64;
    if (field_has_minimum(argv[1], "runpath", 1025) < 0)
        return 1;
    if (field_has_minimum(argv[2], "rpath", 1025) < 0)
        return 2;
    if (field_has_minimum(argv[3], "soname", 257) < 0)
        return 3;
    if (field_has_minimum(argv[4], "interp", 257) < 0)
        return 4;
    return 0;
}
