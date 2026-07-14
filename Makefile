CC       ?= gcc
CFLAGS   = -Wall -Wextra -O2 -g -D_GNU_SOURCE -Iinclude
LDFLAGS  =

BUILD    = build
SRC      = src
BUILD_ARCH := $(shell uname -m)
BUILD_TRIPLE := $(shell $(CC) -dumpmachine 2>/dev/null || uname -m)
BUILD_OS := $(shell if [ -r /etc/os-release ]; then . /etc/os-release; fi; printf '%s:%s' "$${ID:-unknown}" "$${VERSION_ID:-unknown}")
BUILD_LIBC := $(shell ldd --version 2>&1 | head -n 1 || true)
BUILD_CC_VERSION := $(shell $(CC) --version 2>/dev/null | head -n 1 || true)
BUILD_SOURCE_HASH := $(shell find src include -type f \( -name '*.c' -o -name '*.h' \) -print 2>/dev/null | sort | xargs sha256sum 2>/dev/null | sha256sum 2>/dev/null | awk '{print $$1}')
BUILD_RECIPE_HASH := $(shell sha256sum Makefile 2>/dev/null | awk '{print $$1}')
STATIC_CC := $(shell command -v musl-gcc 2>/dev/null || echo $(CC))
STATIC_CC_STAMP := $(shell printf '%s:%s:%s' '$(STATIC_CC)' "$$('$(STATIC_CC)' -dumpmachine 2>/dev/null || true)" "$$('$(STATIC_CC)' --version 2>/dev/null | head -n 1 || true)")
BUILD_STAMP := $(BUILD_ARCH)|$(BUILD_TRIPLE)|$(BUILD_OS)|$(BUILD_LIBC)|cc:$(CC):$(BUILD_CC_VERSION)|static-cc:$(STATIC_CC_STAMP)|cflags:$(CFLAGS)|ldflags:$(LDFLAGS)|recipe:$(BUILD_RECIPE_HASH)|src:$(BUILD_SOURCE_HASH)
# Quote arbitrary flag text as one shell word.  In particular, CFLAGS may
# legitimately contain quotes, dollar signs, or command-looking text; none of
# it should be reinterpreted while deriving or recording the build identity.
sh_quote = '$(subst ','"'"',$(1))'
BUILD_STAMP_KEY := $(shell printf '%s' $(call sh_quote,$(BUILD_STAMP)) | sha256sum | awk '{print $$1}')
BUILD_STAMP_FILE := $(BUILD)/.build-stamp-$(BUILD_STAMP_KEY)

# ── sources for the main dlfreeze tool ──────────────────────────────
TOOL_SRCS = $(SRC)/main.c $(SRC)/elf_parser.c $(SRC)/dep_resolver.c $(SRC)/packer.c
TOOL_OBJS = $(patsubst $(SRC)/%.c,$(BUILD)/%.o,$(TOOL_SRCS))

# ── final artefacts ─────────────────────────────────────────────────
DLFREEZE  = $(BUILD)/dlfreeze
BOOTSTRAP = $(BUILD)/dlfreeze-bootstrap
PRELOAD   = $(BUILD)/dlfreeze-preload.so

# Use musl-gcc for static tools when available; fall back to system gcc.
TOOL_CC := $(STATIC_CC)

# Some toolchains (gcc >= 16) inject -latomic_asneeded into the link line,
# but musl-gcc.specs only adds -L/usr/lib/musl/lib so the system copy
# isn't found.  Add /usr/lib via LIBRARY_PATH (searched AFTER gcc's own
# -L paths, so musl's -lc still wins) when the host file exists.
ifneq (,$(wildcard /usr/lib/libatomic_asneeded.a))
MUSL_LIB_PATH := LIBRARY_PATH=/usr/lib
endif

.DEFAULT_GOAL := all

.PHONY: all clean test bench local-verify local-cross prepare-build

prepare-build: $(BUILD_STAMP_FILE)

$(BUILD_STAMP_FILE):
	@if [ -d "$(BUILD)" ]; then \
		new_stamp=$(call sh_quote,$(BUILD_STAMP)); \
		old_stamp=; \
		if [ -f "$(BUILD)/.build-stamp" ]; then old_stamp=`cat "$(BUILD)/.build-stamp"`; \
		elif [ -f "$(BUILD)/.arch" ]; then old_stamp=`cat "$(BUILD)/.arch"`; fi; \
		if [ -n "$$old_stamp" ] && [ "$$old_stamp" != "$$new_stamp" ]; then \
			echo "build environment changed ($$old_stamp -> $$new_stamp); cleaning $(BUILD)"; \
			rm -rf "$(BUILD)"; \
		fi; \
	fi
	@mkdir -p "$(BUILD)"
	@printf '%s\n' $(call sh_quote,$(BUILD_STAMP)) > "$(BUILD)/.build-stamp"
	@rm -f "$(BUILD)/.arch"
	@touch "$@"

all: $(DLFREEZE) $(BOOTSTRAP) $(PRELOAD)

$(BUILD):
	mkdir -p $(BUILD)

# ── main tool ───────────────────────────────────────────────────────
$(BUILD)/%.o: $(SRC)/%.c $(BUILD_STAMP_FILE)
	$(TOOL_CC) $(CFLAGS) -c -o $@ $<

# Link at 0x40000000 so the default 0x400000 range is free for non-PIE
# executables in the prelinker child process.
$(DLFREEZE): $(TOOL_OBJS)
	$(MUSL_LIB_PATH) $(TOOL_CC) $(CFLAGS) -static -Wl,-Ttext-segment=0x40000000 -o $@ $^ $(LDFLAGS)

# ── bootstrap (statically linked, includes in-process loader) ──────
# Use musl-gcc for much smaller static binary (fewer page faults).
# Fall back to system gcc if musl-gcc isn't available.
# -fno-stack-protector: the loader changes FS register (TLS) which
# invalidates the stack canary, so SSP must be disabled.
BOOTSTRAP_CC := $(STATIC_CC)
INC      = include

$(BOOTSTRAP): $(SRC)/bootstrap.c $(SRC)/loader.c $(INC)/common.h $(INC)/glibc_layout.h $(INC)/musl_layout.h $(INC)/loader.h $(BUILD_STAMP_FILE)
	$(MUSL_LIB_PATH) $(BOOTSTRAP_CC) -Wall -Wextra -O2 -D_GNU_SOURCE -Iinclude -fno-stack-protector \
	    -ffunction-sections -fdata-sections \
	    -static -Wl,--gc-sections -Wl,-Ttext-segment=0x40000000 \
	    -o $@ $(SRC)/bootstrap.c $(SRC)/loader.c

# ── LD_PRELOAD library for tracing dlopen ──────────────────────────
# -U_FORTIFY_SOURCE: glibc fortification (__fprintf_chk etc.) is not
# available on musl, so disable it for cross-platform portability.
$(PRELOAD): $(SRC)/dlopen_preload.c $(BUILD_STAMP_FILE)
	$(CC) $(CFLAGS) -U_FORTIFY_SOURCE -shared -fPIC -o $@ $< -ldl -lpthread

# ── test suite ─────────────────────────────────────────────────────
test: all
	@bash tests/run_tests.sh "$(BUILD)"

bench: all
	@bash tests/run_benchmarks.sh "$(BUILD)"

local-verify: all
	@bash tests/local-verify.sh --build-dir "$(BUILD)"

local-cross:
	@bash tests/local-cross-matrix.sh

clean:
	rm -rf $(BUILD)

# ── header deps (manual, good enough) ─────────────────────────────
$(BUILD)/main.o:         $(SRC)/main.c $(INC)/elf_parser.h $(INC)/dep_resolver.h $(INC)/packer.h
$(BUILD)/elf_parser.o:   $(SRC)/elf_parser.c $(INC)/elf_parser.h
$(BUILD)/dep_resolver.o: $(SRC)/dep_resolver.c $(INC)/dep_resolver.h $(INC)/elf_parser.h
$(BUILD)/packer.o:       $(SRC)/packer.c $(INC)/packer.h $(INC)/common.h $(INC)/glibc_layout.h $(INC)/musl_layout.h $(INC)/dep_resolver.h
