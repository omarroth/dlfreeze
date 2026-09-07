CC       ?= gcc
CFLAGS   = -Wall -Wextra -O2 -g -D_GNU_SOURCE -Iinclude
LDFLAGS  =
WERROR   ?= 0
ERROR_CFLAGS := $(if $(filter 1,$(WERROR)),-Werror,)

BUILD    = build
SRC      = src
BUILD_TRIPLE := $(shell $(CC) -dumpmachine 2>/dev/null || uname -m)
# Compare compiler targets by admitted ELF architecture, not by vendor/libc
# components of the triple (x86_64-linux-musl and x86_64-linux-gnu are
# intentionally compatible here).
triple_arch = $(strip $(if $(filter x86_64 amd64,$(firstword $(subst -, ,$(1)))),x86_64,$(if $(filter aarch64 arm64,$(firstword $(subst -, ,$(1)))),aarch64,$(firstword $(subst -, ,$(1))))))
BUILD_ARCH := $(call triple_arch,$(BUILD_TRIPLE))
BUILD_OS := $(shell if [ -r /etc/os-release ]; then . /etc/os-release; fi; printf '%s:%s' "$${ID:-unknown}" "$${VERSION_ID:-unknown}")
BUILD_LIBC := $(shell ldd --version 2>&1 | head -n 1 || true)
BUILD_CC_VERSION := $(shell $(CC) --version 2>/dev/null | head -n 1 || true)
BUILD_SOURCE_HASH := $(shell find src include -type f \( -name '*.c' -o -name '*.h' \) -print 2>/dev/null | sort | xargs sha256sum 2>/dev/null | sha256sum 2>/dev/null | awk '{print $$1}')
BUILD_RECIPE_HASH := $(shell sha256sum Makefile 2>/dev/null | awk '{print $$1}')
MUSL_CC := $(shell command -v musl-gcc 2>/dev/null || true)
MUSL_CC_TRIPLE := $(shell if [ -n '$(MUSL_CC)' ]; then '$(MUSL_CC)' -dumpmachine 2>/dev/null; fi)
MUSL_CC_ARCH := $(call triple_arch,$(MUSL_CC_TRIPLE))
AUTO_STATIC_CC := $(if $(and $(MUSL_CC),$(filter $(BUILD_ARCH),$(MUSL_CC_ARCH))),$(MUSL_CC),$(CC))
# An explicit STATIC_CC always wins.  Automatic musl selection is permitted
# only when it targets the same ELF architecture as CC; silently mixing a host
# musl-gcc into a cross build would produce an unusable tool/bootstrap pair.
STATIC_CC ?= $(AUTO_STATIC_CC)
STATIC_CC_TRIPLE := $(shell $(STATIC_CC) -dumpmachine 2>/dev/null || true)
STATIC_CC_ARCH := $(call triple_arch,$(STATIC_CC_TRIPLE))
STATIC_CC_STAMP := $(shell printf '%s:%s:%s' '$(STATIC_CC)' "$$($(STATIC_CC) -dumpmachine 2>/dev/null || true)" "$$($(STATIC_CC) --version 2>/dev/null | head -n 1 || true)")
BUILD_STAMP := $(BUILD_ARCH)|$(BUILD_TRIPLE)|$(BUILD_OS)|$(BUILD_LIBC)|cc:$(CC):$(BUILD_CC_VERSION)|static-cc:$(STATIC_CC_STAMP)|cflags:$(CFLAGS)|werror:$(WERROR)|ldflags:$(LDFLAGS)|recipe:$(BUILD_RECIPE_HASH)|src:$(BUILD_SOURCE_HASH)
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
PRELOAD_STATIC = $(BUILD)/dlfreeze-preload-static.so
PRELOAD_VARIANTS := $(PRELOAD) $(PRELOAD_STATIC)

# Prefer musl-gcc for the small static tool and bootstrap when available.
# Direct handoff is bootstrap-libc-neutral; a static system compiler is also
# supported and covered by the bootstrap-independence regression.
TOOL_CC := $(STATIC_CC)

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

all: $(DLFREEZE) $(BOOTSTRAP) $(PRELOAD_VARIANTS)

$(BUILD):
	mkdir -p $(BUILD)

# ── main tool ───────────────────────────────────────────────────────
$(BUILD)/%.o: $(SRC)/%.c $(BUILD_STAMP_FILE)
	$(TOOL_CC) $(CFLAGS) $(ERROR_CFLAGS) -c -o $@ $<

# Link at 0x40000000 so the default 0x400000 range is free for non-PIE
# executables in the prelinker child process.
$(DLFREEZE): $(TOOL_OBJS)
	$(TOOL_CC) $(CFLAGS) $(ERROR_CFLAGS) -static -Wl,-Ttext-segment=0x40000000 -o $@ $^ $(LDFLAGS)

# ── bootstrap (statically linked, includes in-process loader) ──────
# After replacing the thread pointer the loader calls only its raw syscall
# layer, target-libc entry points, and loader-owned memory/string helpers.
# -fno-stack-protector keeps loader frames independent of either libc's TCB
# while the handoff changes the thread pointer.
BOOTSTRAP_CC := $(STATIC_CC)
INC      = include

$(BOOTSTRAP): $(SRC)/bootstrap.c $(SRC)/loader.c $(INC)/common.h $(INC)/dynamic_semantics.h $(INC)/gnu_properties.h $(INC)/glibc_layout.h $(INC)/libc_semantics.h $(INC)/load_segments.h $(INC)/musl_layout.h $(INC)/loader.h $(BUILD_STAMP_FILE)
	$(BOOTSTRAP_CC) -Wall -Wextra $(ERROR_CFLAGS) -O2 -D_GNU_SOURCE -Iinclude -fno-stack-protector \
	    -ffunction-sections -fdata-sections \
	    -static -Wl,--gc-sections -Wl,-Ttext-segment=0x40000000 \
	    -o $@ $(SRC)/bootstrap.c $(SRC)/loader.c

# ── LD_PRELOAD library for tracing dlopen ──────────────────────────
# -U_FORTIFY_SOURCE: glibc fortification (__fprintf_chk etc.) is not
# available on musl, so disable it for cross-platform portability.
# AArch64 GCC otherwise lowers compare-exchange through an outlined libgcc
# helper.  Some musl-gcc installations reuse a glibc-target libgcc whose LSE
# initializer imports glibc-private __getauxval, making the resulting helper
# unloadable by musl.  Inline LL/SC atomics have no runtime-libc dependency;
# -z defs also makes any future required runtime import fail at build time.
supported_cc_option = $(shell printf '' | $(1) -Werror $(2) -x c -c -o /dev/null - >/dev/null 2>&1 && printf '%s' '$(2)')
PRELOAD_ARCH_CFLAGS := $(if $(filter aarch64,$(BUILD_ARCH)),$(call supported_cc_option,$(CC),-mno-outline-atomics),)
PRELOAD_STATIC_ARCH_CFLAGS := $(if $(filter aarch64,$(STATIC_CC_ARCH)),$(call supported_cc_option,$(STATIC_CC),-mno-outline-atomics),)

$(PRELOAD): $(SRC)/dlopen_preload.c $(INC)/dynamic_semantics.h $(BUILD_STAMP_FILE)
	$(CC) $(CFLAGS) $(ERROR_CFLAGS) $(PRELOAD_ARCH_CFLAGS) -U_FORTIFY_SOURCE -shared -fPIC -Wl,-z,defs -o $@ $< -ldl

$(PRELOAD_STATIC): $(SRC)/dlopen_preload.c $(INC)/dynamic_semantics.h $(BUILD_STAMP_FILE)
	$(STATIC_CC) $(CFLAGS) $(ERROR_CFLAGS) $(PRELOAD_STATIC_ARCH_CFLAGS) -U_FORTIFY_SOURCE -shared -fPIC -Wl,-z,defs -o $@ $< -ldl

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
$(BUILD)/elf_parser.o:   $(SRC)/elf_parser.c $(INC)/elf_parser.h $(INC)/load_segments.h
$(BUILD)/dep_resolver.o: $(SRC)/dep_resolver.c $(INC)/dep_resolver.h $(INC)/elf_parser.h $(INC)/glibc_layout.h $(INC)/libc_semantics.h
$(BUILD)/packer.o:       $(SRC)/packer.c $(INC)/packer.h $(INC)/common.h $(INC)/dynamic_semantics.h $(INC)/elf_sections.h $(INC)/gnu_properties.h $(INC)/glibc_layout.h $(INC)/load_segments.h $(INC)/musl_layout.h $(INC)/dep_resolver.h
