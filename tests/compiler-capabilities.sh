#!/bin/sh
# Shared by local tests and cross-build orchestration. A compiler installed
# on PATH is optional coverage only if its driver can actually link.
test_compiler_available() {
    dlfrz_cc_path=$(command -v "$1" 2>/dev/null) || return 1
    case "
${DLFRZ_TEST_CC_GOOD:-}
" in
        *"
$dlfrz_cc_path
"*) printf '%s\n' "$dlfrz_cc_path"; return 0 ;;
    esac
    case "
${DLFRZ_TEST_CC_BAD:-}
" in
        *"
$dlfrz_cc_path
"*) return 1 ;;
    esac
    dlfrz_cc_dir=$(mktemp -d) || return 1
    if printf 'int main(void){return 0;}\n' |
       "$1" -x c - -x none -o "$dlfrz_cc_dir/probe" \
           >"$dlfrz_cc_dir/log" 2>&1; then
        DLFRZ_TEST_CC_GOOD="${DLFRZ_TEST_CC_GOOD:-}
$dlfrz_cc_path"
        rm -rf "$dlfrz_cc_dir"
        printf '%s\n' "$dlfrz_cc_path"
        return 0
    fi
    printf 'optional test compiler cannot link: %s\n' "$dlfrz_cc_path" >&2
    cat "$dlfrz_cc_dir/log" >&2
    DLFRZ_TEST_CC_BAD="${DLFRZ_TEST_CC_BAD:-}
$dlfrz_cc_path"
    rm -rf "$dlfrz_cc_dir"
    return 1
}
