#ifndef DLFREEZE_DEP_RESOLVER_H
#define DLFREEZE_DEP_RESOLVER_H

struct resolved_lib {
    char *name;          /* soname (e.g. "libc.so.6") */
    char *path;          /* resolved absolute path     */
    int   from_dlopen;   /* found via dlopen tracing   */
};

struct dep_list {
    struct resolved_lib *libs;
    int    count;
    int    capacity;
    char  *interp_path;  /* dynamic linker (PT_INTERP) */
};

/* Resolve all shared-library dependencies of an ELF binary (BFS). */
int dep_resolve(const char *exe_path, struct dep_list *deps);

/* Merge dlopen-traced libraries (one path per line in trace_file). */
int dep_add_dlopen_libs(struct dep_list *deps, const char *trace_file);

/* Free all resources in a dep_list. */
void dep_list_free(struct dep_list *deps);

#endif /* DLFREEZE_DEP_RESOLVER_H */
