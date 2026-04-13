CC       ?= gcc
CFLAGS   = -Wall -Wextra -O2 -g -D_GNU_SOURCE -Iinclude
LDFLAGS  =

BUILD    = build
SRC      = src

# ── sources for the main dlfreeze tool ──────────────────────────────
TOOL_SRCS = $(SRC)/main.c $(SRC)/elf_parser.c $(SRC)/dep_resolver.c $(SRC)/packer.c
TOOL_OBJS = $(patsubst $(SRC)/%.c,$(BUILD)/%.o,$(TOOL_SRCS))

# ── final artefacts ─────────────────────────────────────────────────
DLFREEZE  = $(BUILD)/dlfreeze
BOOTSTRAP = $(BUILD)/dlfreeze-bootstrap
PRELOAD   = $(BUILD)/dlfreeze-preload.so

# Use musl-gcc for static tools when available; fall back to system gcc.
TOOL_CC := $(shell command -v musl-gcc 2>/dev/null || echo $(CC))

.PHONY: all clean test bench

all: $(DLFREEZE) $(BOOTSTRAP) $(PRELOAD)

$(BUILD):
	mkdir -p $(BUILD)

# ── main tool ───────────────────────────────────────────────────────
$(BUILD)/%.o: $(SRC)/%.c | $(BUILD)
	$(TOOL_CC) $(CFLAGS) -c -o $@ $<

# Link at 0x40000000 so the default 0x400000 range is free for non-PIE
# executables in the prelinker child process.
$(DLFREEZE): $(TOOL_OBJS)
	$(TOOL_CC) $(CFLAGS) -static -Wl,-Ttext-segment=0x40000000 -o $@ $^ $(LDFLAGS)

# ── bootstrap (statically linked, includes in-process loader) ──────
# Use musl-gcc for much smaller static binary (fewer page faults).
# Fall back to system gcc if musl-gcc isn't available.
# -fno-stack-protector: the loader changes FS register (TLS) which
# invalidates the stack canary, so SSP must be disabled.
BOOTSTRAP_CC := $(shell command -v musl-gcc 2>/dev/null || echo $(CC))
INC      = include

$(BOOTSTRAP): $(SRC)/bootstrap.c $(SRC)/loader.c $(INC)/common.h $(INC)/loader.h | $(BUILD)
	$(BOOTSTRAP_CC) -Wall -Wextra -O2 -D_GNU_SOURCE -Iinclude -fno-stack-protector \
	    -ffunction-sections -fdata-sections \
	    -static -Wl,--gc-sections -Wl,-Ttext-segment=0x40000000 \
	    -o $@ $(SRC)/bootstrap.c $(SRC)/loader.c

# ── LD_PRELOAD library for tracing dlopen ──────────────────────────
# -U_FORTIFY_SOURCE: glibc fortification (__fprintf_chk etc.) is not
# available on musl, so disable it for cross-platform portability.
$(PRELOAD): $(SRC)/dlopen_preload.c | $(BUILD)
	$(CC) $(CFLAGS) -U_FORTIFY_SOURCE -shared -fPIC -o $@ $< -ldl -lpthread

# ── test suite ─────────────────────────────────────────────────────
test: all
	@bash tests/run_tests.sh "$(BUILD)"

bench: all
	@bash tests/run_benchmarks.sh "$(BUILD)"

clean:
	rm -rf $(BUILD)

# ── header deps (manual, good enough) ─────────────────────────────
$(BUILD)/main.o:         $(SRC)/main.c $(INC)/elf_parser.h $(INC)/dep_resolver.h $(INC)/packer.h
$(BUILD)/elf_parser.o:   $(SRC)/elf_parser.c $(INC)/elf_parser.h
$(BUILD)/dep_resolver.o: $(SRC)/dep_resolver.c $(INC)/dep_resolver.h $(INC)/elf_parser.h
$(BUILD)/packer.o:       $(SRC)/packer.c $(INC)/packer.h $(INC)/common.h $(INC)/dep_resolver.h
