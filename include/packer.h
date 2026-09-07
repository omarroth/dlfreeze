#ifndef DLFREEZE_PACKER_H
#define DLFREEZE_PACKER_H

#include "dep_resolver.h"

/* List of data files to embed alongside ELF objects */
enum data_file_kind {
    DATA_FILE_KIND_REGULAR = 0,
    DATA_FILE_KIND_VIRTUAL,
    DATA_FILE_KIND_NEGATIVE,
    DATA_FILE_KIND_DIRECTORY
};

struct data_file_list {
    char **paths;      /* exact absolute request identities */
    char **source_paths; /* canonical sources for real entries, else NULL */
    enum data_file_kind *kinds;
    struct dep_file_snapshot *snapshots; /* traced regular-file revisions */
    int    count;
    int    capacity;
    int    failed;     /* allocation/size failure while collecting paths */
};

void data_file_list_init(struct data_file_list *dl);
void data_file_list_add(struct data_file_list *dl, const char *path,
                        const char *source_path,
                        const struct dep_file_snapshot *snapshot);
void data_file_list_add_virtual(struct data_file_list *dl, const char *path);
void data_file_list_add_negative(struct data_file_list *dl, const char *path);
void data_file_list_add_directory(struct data_file_list *dl, const char *path);
void data_file_list_free(struct data_file_list *dl);

struct pack_options {
    const char      *exe_path;        /* resolved executable to embed  */
    const char      *exe_name;        /* loader-visible executable spelling */
    const char      *output_path;     /* frozen output file            */
    const char      *bootstrap_path;  /* statically-linked bootstrap   */
    struct dep_list *deps;            /* resolved dependencies         */
    int              direct_load;     /* 1 = embed loader metadata     */
    struct data_file_list *data_files; /* non-ELF files to embed       */
};

/* Create a frozen (self-extracting) ELF binary. */
int pack_frozen(const struct pack_options *opts);

#endif /* DLFREEZE_PACKER_H */
