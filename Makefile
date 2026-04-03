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

.PHONY: all clean test

all: $(DLFREEZE) $(BOOTSTRAP) $(PRELOAD)

$(BUILD):
	mkdir -p $(BUILD)

# ── main tool ───────────────────────────────────────────────────────
$(BUILD)/%.o: $(SRC)/%.c | $(BUILD)
	$(CC) $(CFLAGS) -c -o $@ $<

$(DLFREEZE): $(TOOL_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# ── bootstrap (statically linked) ──────────────────────────────────
$(BOOTSTRAP): $(SRC)/bootstrap.c | $(BUILD)
	$(CC) $(CFLAGS) -static -o $@ $<

# ── LD_PRELOAD library for tracing dlopen ──────────────────────────
$(PRELOAD): $(SRC)/dlopen_preload.c | $(BUILD)
	$(CC) $(CFLAGS) -shared -fPIC -o $@ $< -ldl -lpthread

# ── test suite ─────────────────────────────────────────────────────
test: all
	@bash tests/run_tests.sh "$(BUILD)"

clean:
	rm -rf $(BUILD)

# ── header deps (manual, good enough) ─────────────────────────────
$(BUILD)/main.o:         $(SRC)/main.c $(SRC)/elf_parser.h $(SRC)/dep_resolver.h $(SRC)/packer.h
$(BUILD)/elf_parser.o:   $(SRC)/elf_parser.c $(SRC)/elf_parser.h
$(BUILD)/dep_resolver.o: $(SRC)/dep_resolver.c $(SRC)/dep_resolver.h $(SRC)/elf_parser.h
$(BUILD)/packer.o:       $(SRC)/packer.c $(SRC)/packer.h $(SRC)/common.h $(SRC)/dep_resolver.h
