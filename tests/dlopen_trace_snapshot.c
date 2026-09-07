#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

static int write_encoded_path(char fill)
{
    if (fputs("2f", stdout) == EOF)
        return -1;
    for (size_t i = 1; i < PATH_MAX - 1U; i++) {
        if (printf("%02x", (unsigned int)(unsigned char)fill) < 0)
            return -1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    struct stat st;

    if (argc == 3 && strcmp(argv[1], "--max-record") == 0) {
        if (strlen(argv[2]) != 16 ||
            printf("B %s 0000000000000002\n"
                   "P %s 0000000000000002 0000000000000000 "
                   "00000002 ", argv[2], argv[2]) < 0 ||
            write_encoded_path('r') < 0 || putchar(' ') == EOF ||
            write_encoded_path('l') < 0 || putchar(' ') == EOF ||
            write_encoded_path('s') < 0 ||
            fputs(" 0000000000000001 0000000000000001"
                  " 0000000000008000 0000000000000001"
                  " 0000000000000001 0000000000000000"
                  " 0000000000000001 0000000000000000\n", stdout) == EOF)
            return 1;
        return ferror(stdout) ? 1 : 0;
    }
    if (argc != 2 || stat(argv[1], &st) < 0 || !S_ISREG(st.st_mode) ||
        st.st_size < 0)
        return 1;
    printf("%016" PRIx64 " %016" PRIx64 " %016" PRIx64
           " %016" PRIx64 " %016" PRIx64 " %016" PRIx64
           " %016" PRIx64 " %016" PRIx64 "\n",
           (uint64_t)st.st_dev, (uint64_t)st.st_ino,
           (uint64_t)(st.st_mode & S_IFMT), (uint64_t)st.st_size,
           (uint64_t)st.st_mtim.tv_sec, (uint64_t)st.st_mtim.tv_nsec,
           (uint64_t)st.st_ctim.tv_sec, (uint64_t)st.st_ctim.tv_nsec);
    return 0;
}
