/*
 * dlfreeze in-process loader — maps embedded ELF objects directly from the
 * frozen binary's memory and resolves relocations without ld.so.
 */
#ifndef DLFREEZE_LOADER_H
#define DLFREEZE_LOADER_H

#include <stdint.h>
#include <stddef.h>

/* Forward declarations — full definitions in common.h */
struct dlfrz_lib_meta;
struct dlfrz_entry;

/*
 * Load all libraries from the frozen binary's in-memory payload,
 * resolve relocations, set up TLS, and jump to the executable's _start.
 *
 *   mem:          pointer to start of frozen file / payload in memory
 *   mem_foff:     file offset corresponding to mem[0]
 *                 (normal path: 0, UPX path: g_loader_info.payload_foff)
 *   metas:        per-library metadata array (num_entries elements)
 *   entries:      manifest entry array (num_entries elements)
 *   strtab:       string table
 *   num_entries:  number of entries
 *   argc, argv, envp: passed to the loaded program's entry point
 *
 * On success this function does NOT return — it transfers control to the
 * loaded executable.  On failure it returns -1.
 */
int loader_run(const uint8_t *mem, uint64_t mem_foff, int srcfd,
               const struct dlfrz_lib_meta *metas,
               const struct dlfrz_entry *entries,
               const char *strtab,
               uint32_t num_entries,
               int argc, char **argv, char **envp);

#endif /* DLFREEZE_LOADER_H */
