#!/usr/bin/env bash
set -euo pipefail

root=$(mktemp -d "${1:-build}/build-stamp.XXXXXX")
trap 'rm -rf "$root"' EXIT
root=$(cd "$root" && pwd -P)
cp Makefile "$root/Makefile"
cp -R src include "$root/"
cc=$(command -v "${TEST_REAL_GCC:-gcc}")
export TEST_STAMP_REAL_CC="$cc"
printf '%s\n' \
    '#!/bin/sh' \
    'if [ "${1:-}" = --version ]; then' \
    '    printf "test compiler locale=%s\n" "${LC_ALL:-unset}"' \
    '    exit 0' \
    'fi' \
    'exec "$TEST_STAMP_REAL_CC" "$@"' >"$root/cc"
chmod +x "$root/cc"

alternate=C.UTF-8
if command -v locale >/dev/null 2>&1 &&
   locale -a 2>/dev/null | grep -Ei '^en_US[.](utf-?8)$' >/dev/null; then
    alternate=en_US.UTF-8
fi

make_at() {
    local language=$1
    shift
    LC_ALL="$language" make --no-print-directory -s -C "$root" \
        BUILD="$root/out" CC="$root/cc" STATIC_CC="$root/cc" "$@"
}

fingerprint() {
    make_at "$1" -f Makefile -f - inspect-stamp <<'MAKE'
.PHONY: inspect-stamp
inspect-stamp:
	@printf '%s\n' $(call sh_quote,$(BUILD_SOURCE_HASH)) $(call sh_quote,$(BUILD_STAMP_KEY))
MAKE
}

initial=$(fingerprint C)
[ "$initial" = "$(fingerprint C)" ]
[ "$initial" = "$(fingerprint "$alternate")" ]

# An unchanged prepare-build must not clean or rewrite the build, including
# when a caller such as a test runner changes the process locale.
make_at C prepare-build
printf 'preserve\n' >"$root/out/sentinel"
cp "$root/out/.build-stamp" "$root/stamp.saved"
make_at "$alternate" prepare-build
make_at C prepare-build
[ -f "$root/out/sentinel" ]
cmp "$root/stamp.saved" "$root/out/.build-stamp"

# Metadata-only changes leave the content fingerprint alone. A real source
# change must still invalidate the build once, then become a stable no-op.
touch "$root/include/common.h"
[ "$initial" = "$(fingerprint "$alternate")" ]
printf '\n/* fingerprint regression */\n' >>"$root/include/common.h"
changed=$(fingerprint C)
[ "$changed" != "$initial" ]
make_at C prepare-build >"$root/changed.log"
[ ! -e "$root/out/sentinel" ]
grep -F 'cleaning ' "$root/changed.log" >/dev/null
printf 'preserve\n' >"$root/out/sentinel"
make_at "$alternate" prepare-build
[ -f "$root/out/sentinel" ]
[ "$changed" = "$(fingerprint "$alternate")" ]

# The source list must not silently drop files whose names xargs would split.
for name in 'space name.h' $'line\nbreak.h'; do
    printf '/* first */\n' >"$root/include/$name"
    before=$(fingerprint C)
    printf '/* second */\n' >>"$root/include/$name"
    after=$(fingerprint "$alternate")
    [ "$before" != "$after" ]
    [ "$after" = "$(fingerprint C)" ]
done

echo 'build stamps preserve unchanged builds across locales and track exact source bytes'
