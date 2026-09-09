/*
 * dlfreeze in-process loader — maps embedded ELF objects directly from the
 * frozen binary's memory and resolves relocations without ld.so.
 */
#ifndef DLFREEZE_LOADER_H
#define DLFREEZE_LOADER_H

#include <stdint.h>
#include <stddef.h>
#include "premap.h"

/* Forward declarations — full definitions in common.h */
struct dlfrz_lib_meta;
struct dlfrz_entry;

#define DLFRZ_HANDOFF_APPLICATION_STARTED '1'
#define DLFRZ_HANDOFF_TERMINAL_REFUSAL     'R'

/* loader_run() uses a distinct return only when it also requested a terminal
 * handoff refusal.  The supervised bootstrap child converts that internal
 * result to a reserved process status, providing a fail-closed backup when a
 * sandbox denies the primary marker write. */
#define DLFRZ_LOADER_RUN_TERMINAL_REFUSAL   (-2)
#define DLFRZ_LOADER_CHILD_TERMINAL_REFUSAL 126

/* The bootstrap sets this only when the retained read-only memory authority
 * and srcfd are exact, clean MAP_PRIVATE views of the same regular file.
 * It does not claim that the backing file is globally immutable.  This is a
 * proof token, not a request: without it the loader must continue treating
 * mem as the sole byte authority. */
#define DLFRZ_SOURCE_EXACT_CLEAN_FILE (1U << 0)

/* The bootstrap sets this only after a disposable, signal-zero clone has
 * successfully exercised the complete eligible startup PT_LOAD transfer
 * batch with MREMAP_DONTUNMAP, then positively authenticated exactly the
 * resulting target VMAs as clean mappings of the expected file ranges.  The
 * loader may consume this token only before application handoff; it is
 * cleared before target code can replace the inherited seccomp policy.
 * Unlike DLFRZ_SOURCE_EXACT_CLEAN_FILE, this proof intentionally requires no
 * retained source descriptor and makes no claim about unselected payload
 * pages. */
#define DLFRZ_SOURCE_MREMAP_DONTUNMAP (1U << 1)

/* Same contained startup proof, but move separately owned kernel staging
 * aliases with ordinary MREMAP_FIXED. Canonical payload pages never move. */
#define DLFRZ_SOURCE_KERNEL_PREMAP (1U << 2)

/* Bootstrap transfers only validated, trimmed, independently owned ranges.
 * Unconsumed ranges are released before any target callback. */
int loader_install_kernel_premap(const struct dlfrz_premap_range *ranges,
                                 size_t count);

/* A bootstrap-owned anonymous page whose MADV_WIPEONFORK state was positively
 * verified before any target callback.  The loader consumes the armed word;
 * a zero inherited word then proves a later fork without a getpid syscall. */
#define DLFRZ_RUNTIME_FORK_COOKIE UINT32_C(0x444c4652)

/*
 * Load all libraries from the frozen binary's in-memory payload,
 * resolve relocations, set up TLS, and jump to the executable's _start.
 *
 *   mem:          pointer to start of frozen file / payload in memory
 *   mem_foff:     file offset corresponding to mem[0]
 *                 (mapped canonical payload: payload file offset;
 *                  compatibility whole-file mapping: 0)
 *   source_flags: bootstrap-proven properties of mem/srcfd
 *   runtime_fork_cookie: optional verified, armed WIPEONFORK page; ownership
 *                       transfers to the loader, NULL keeps syscall identity
 *   metas:        per-library metadata array (num_entries elements)
 *   entries:      manifest entry array (num_entries elements)
 *   strtab:       string table
 *   num_entries:  number of entries
 *   handoff_fd:    optional pipe written immediately before target code, or
 *                  with a terminal-refusal marker for an incompatible direct
 *                  artifact; -1 disables the parent notification
 *   argc, argv, envp: passed to the loaded program's entry point
 *
 * On success this function does NOT return — it transfers control to the
 * loaded executable.  On failure it returns -1.
 */
int loader_run(const uint8_t *mem, uint64_t mem_foff, int srcfd,
               uint32_t source_flags,
               volatile uint32_t *runtime_fork_cookie,
               const struct dlfrz_lib_meta *metas,
               const struct dlfrz_entry *entries,
               const char *strtab,
               uint32_t num_entries,
               const uint32_t *runtime_fixups,
               uint32_t runtime_fixup_count,
               int handoff_fd,
               int argc, char **argv, char **envp);

#endif /* DLFREEZE_LOADER_H */
