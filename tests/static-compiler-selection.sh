#!/usr/bin/env bash
set -euo pipefail

cc=${TEST_REAL_GCC:-gcc}
root=$(mktemp -d "${1:-build}/static-selection.XXXXXX")
trap 'rm -rf "$root"' EXIT
root=$(cd "$root" && pwd -P)
cat >"$root/musl-gcc" <<'SH'
#!/bin/sh
for argument do
    if [ "$argument" = -static ] && [ "${TEST_STATIC_BROKEN:-1}" = 1 ]; then
        echo 'test compiler: missing implicit static runtime library' >&2
        exit 1
    fi
done
exec "$TEST_STATIC_REAL_CC" "$@"
SH
chmod +x "$root/musl-gcc"
cat >"$root/print.mk" <<'MAKE'
.PHONY: print-static-selection
print-static-selection:
	@printf '%s\n' '$(STATIC_CC)'
MAKE
export TEST_STATIC_REAL_CC="$cc"
selection() {
    make --no-print-directory -s -f Makefile -f "$root/print.mk" \
        CC="$cc" MUSL_CC="$root/musl-gcc" "$@" print-static-selection
}
selected=$(selection)
[ "$selected" = "$cc" ]
selected=$(selection STATIC_CC="$root/musl-gcc")
[ "$selected" = "$root/musl-gcc" ]
if printf 'int main(void){return 0;}' | "$cc" -static -x c - -o "$root/probe"; then
    selected=$(TEST_STATIC_BROKEN=0 selection)
    [ "$selected" = "$root/musl-gcc" ]
fi
