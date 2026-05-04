#ifndef DLFREEZE_PACKER_H
#define DLFREEZE_PACKER_H

#include "dep_resolver.h"

/* List of data files to embed alongside ELF objects */
struct data_file_list {
    char **paths;      /* absolute paths of files to embed */
    int   *is_virtual; /* 0=real, 1=virtual placeholder, 2=negative (not found) */
    int    count;
    int    capacity;
};

void data_file_list_init(struct data_file_list *dl);
void data_file_list_add(struct data_file_list *dl, const char *path);
void data_file_list_add_virtual(struct data_file_list *dl, const char *path);
void data_file_list_add_negative(struct data_file_list *dl, const char *path);
void data_file_list_free(struct data_file_list *dl);

struct pack_options {
    const char      *exe_path;        /* resolved executable to embed  */
    const char      *exe_name;        /* runtime name/path for argv[0] */
    const char      *output_path;     /* frozen output file            */
    const char      *bootstrap_path;  /* statically-linked bootstrap   */
    struct dep_list *deps;            /* resolved dependencies         */
    int              direct_load;     /* 1 = embed loader metadata     */
    struct data_file_list *data_files; /* non-ELF files to embed       */
};

/* Create a frozen (self-extracting) ELF binary. */
int pack_frozen(const struct pack_options *opts);

#endif /* DLFREEZE_PACKER_H */
