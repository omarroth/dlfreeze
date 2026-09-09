#ifndef DLFREEZE_DEP_RESOLVER_H
#define DLFREEZE_DEP_RESOLVER_H

#include <stdint.h>
#include <sys/types.h>
#include <time.h>

/* Identity of the exact file revision admitted by the resolver.  Consumers
 * recheck it on the descriptor they actually parse/copy, so replacing a
 * pathname between resolution, closure traversal, and packing fails closed
 * instead of mixing metadata and bytes from different objects. */
struct dep_file_snapshot {
    dev_t device;
    ino_t inode;
    off_t size;
    time_t mtime_sec;
    long mtime_nsec;
    time_t ctime_sec;
    long ctime_nsec;
    int valid;
};

struct resolved_lib {
    char *name;          /* soname (e.g. "libc.so.6") */
    char *path;          /* canonical snapshot source path */
    char *logical_path;  /* first loader-visible path; owns $ORIGIN */
    dev_t device;        /* snapshot identity used for native-style dedup */
    ino_t inode;
    struct dep_file_snapshot snapshot;
    int   from_dlopen;   /* found via dlopen tracing   */
    int   dlopen_direct; /* path appeared in trace file */
    int   dlopen_pathful;/* direct dlopen argument contained '/' */
    int   needed_pathful;/* name is an exact slash-containing DT_NEEDED */
    int   dlopen_early;  /* closure must be mapped before static TLS setup */
    char *dlopen_request;/* exact direct dlopen argument, or NULL */
};

enum dep_runtime_family {
    DEP_RUNTIME_UNKNOWN = 0,
    DEP_RUNTIME_GNU,
    DEP_RUNTIME_MUSL,
};

struct dep_list {
    struct resolved_lib *libs;
    int    count;
    int    capacity;
    char  *interp_path;  /* dynamic linker (PT_INTERP) */
    struct dep_file_snapshot main_snapshot;
    struct dep_file_snapshot interp_snapshot;
    char  *interp_soname;/* exact DT_SONAME exported by the interpreter */
    char  *gnu_platform; /* exact target $PLATFORM, when structurally known */
    char  *gnu_cache_path; /* target glibc's compiled cache pathname */
    uint8_t *gnu_cache_image; /* immutable first-lookup cache snapshot */
    size_t gnu_cache_image_size;
    int gnu_cache_snapshot_state;
    void *gnu_cache_index; /* private validated lookup index */
    char *musl_system_path; /* immutable first-lookup path-file snapshot */
    size_t musl_system_path_size;
    int musl_system_path_initialized;
    int musl_system_path_status;
    char  *main_origin;  /* directory containing the target executable */
    char  *main_rpath;   /* GNU main-object DT_RPATH inherited by preloads */
    int       target_ei_class;  /* required ELF class for dependencies */
    uint16_t  target_e_machine; /* required ELF machine for dependencies */
    enum dep_runtime_family runtime_family; /* target loader search ABI */
    int gnu_release_minor; /* stable target glibc 2.x minor, or -1 for unknown cache policy */
    /* At least one successful pure-RTLD_LAZY request names an identity outside
     * the immutable startup dependency graph.  V8 tags fork-descendant
     * records and tracks first observations per process; loader namespaces
     * and unload/reload cycles still mean only startup ownership proves that
     * an object is already visible before a traced call. */
    int traced_requires_native_lazy_semantics;
    /* A failed dlopen/dlmopen has no link-map identity to replay and its
     * loader-owned error state is observable through dlerror().  Direct mode
     * cannot infer that native result from a successful-object manifest, so
     * a complete trace must retain the call and select native-loader
     * semantics regardless of the target libc family. */
    int traced_requires_native_loader_semantics;
};

/* Resolve all shared-library dependencies of an ELF binary (BFS). */
int dep_resolve(const char *exe_path, struct dep_list *deps);

/* Merge versioned dlopen trace records from trace_file. */
int dep_add_dlopen_libs(struct dep_list *deps, const char *trace_file);

/* Descriptor-bound variant; consumes trace_fd on every return path. */
int dep_add_dlopen_libs_fd(struct dep_list *deps, int trace_fd);

/* Mark traced dlopen closures that require startup static-TLS placement.
 * Returns 1 when two such direct roots share a dormant closure member and
 * therefore require native-loader scope semantics, 0 when representable,
 * and -1 on an inspection/allocation failure. */
int dep_mark_dlopen_early_closures(struct dep_list *deps);

/* Resolve one dependency of an auxiliary ELF object (for example the trace
 * preload helper) with the target interpreter's search ABI.  The result is
 * allocated and does not mutate the packaged dependency closure.  Returns 1
 * when found, 0 when no compatible provider exists, and -1 for invalid input
 * or a resolver/configuration/allocation failure. */
int dep_resolve_aux_dependency(struct dep_list *deps,
                               const char *requester_path,
                               const char *name, char **path_out);

/* Free all resources in a dep_list. */
void dep_list_free(struct dep_list *deps);

#endif /* DLFREEZE_DEP_RESOLVER_H */
