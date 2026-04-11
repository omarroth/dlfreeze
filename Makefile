CC       ?= gcc
CFLAGS   = -Wall -Wextra -O2 -g -D_GNU_SOURCE
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

$(DLFREEZE): $(TOOL_OBJS)
	$(TOOL_CC) $(CFLAGS) -static -o $@ $^ $(LDFLAGS)

# ── bootstrap (statically linked, includes in-process loader) ──────
# Use musl-gcc for much smaller static binary (fewer page faults).
# Fall back to system gcc if musl-gcc isn't available.
# -fno-stack-protector: the loader changes FS register (TLS) which
# invalidates the stack canary, so SSP must be disabled.
BOOTSTRAP_CC := $(shell command -v musl-gcc 2>/dev/null || echo $(CC))
$(BOOTSTRAP): $(SRC)/bootstrap.c $(SRC)/loader.c $(SRC)/common.h $(SRC)/loader.h | $(BUILD)
	$(BOOTSTRAP_CC) -Wall -Wextra -O2 -D_GNU_SOURCE -fno-stack-protector \
	    -ffunction-sections -fdata-sections \
	    -static -Wl,--gc-sections -o $@ $(SRC)/bootstrap.c $(SRC)/loader.c

# ── LD_PRELOAD library for tracing dlopen ──────────────────────────
$(PRELOAD): $(SRC)/dlopen_preload.c | $(BUILD)
	$(CC) $(CFLAGS) -shared -fPIC -o $@ $< -ldl -lpthread

# ── test suite ─────────────────────────────────────────────────────
test: all
	@bash tests/run_tests.sh "$(BUILD)"

bench: all
	@bash tests/run_benchmarks.sh "$(BUILD)"

clean:
	rm -rf $(BUILD)

# ── header deps (manual, good enough) ─────────────────────────────
$(BUILD)/main.o:         $(SRC)/main.c $(SRC)/elf_parser.h $(SRC)/dep_resolver.h $(SRC)/packer.h
$(BUILD)/elf_parser.o:   $(SRC)/elf_parser.c $(SRC)/elf_parser.h
$(BUILD)/dep_resolver.o: $(SRC)/dep_resolver.c $(SRC)/dep_resolver.h $(SRC)/elf_parser.h
$(BUILD)/packer.o:       $(SRC)/packer.c $(SRC)/packer.h $(SRC)/common.h $(SRC)/dep_resolver.h
