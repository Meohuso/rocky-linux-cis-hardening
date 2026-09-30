#!/usr/bin/env bash
# CIS 5.4.2.4 - Read-only root password observation; never emit shadow data.
# SPDX-License-Identifier: MIT
RLCH_CIS_5_4_2_4_SHADOW="${RLCH_CIS_5_4_2_4_SHADOW:-/etc/shadow}"

rlch_5_4_2_4_observe() {
    local file="$RLCH_CIS_5_4_2_4_SHADOW" canonical before after mode fd result=0
    [[ -f "$file" && -r "$file" && ! -L "$file" ]] || return 2
    canonical="$(realpath -e -- "$file" 2>/dev/null)" || return 2
    # Reject symlinks in parent components as well as the file itself.
    [[ "$canonical" == "$file" ]] || return 2
    before="$(stat -Lc '%d:%i:%s:%y:%z:%a' -- "$file" 2>/dev/null)" || return 2
    mode="${before##*:}"
    [[ "$mode" =~ ^[0-7]{3,4}$ ]] || return 2
    (( (8#$mode & 0444) != 0 )) || return 2
    { exec {fd}<"$file"; } 2>/dev/null || return 2
    after="$(stat -Lc '%d:%i:%s:%y:%z:%a' -- "/proc/self/fd/$fd" 2>/dev/null)" || result=2
    if [[ "$result" -eq 0 && "$before" == "$after" ]]; then
        # Match the actual CAS full-line expression, not a guessed hash allowlist.
        LC_ALL=C awk -F: '
            NF != 9 || $1 !~ /^[a-zA-Z_][a-zA-Z0-9_.-]*$/ || $0 ~ /[[:cntrl:]]/ {bad=1; next}
            {if (seen[$1]++) bad=1}
            $1 == "root" {count++; if ($0 ~ /^root:\$(y|[0-9].+)\$.*$/) compliant=1}
            END {if (bad || count!=1) exit 2; if (!compliant) exit 1}
        ' <&"$fd" 2>/dev/null || result=$?
    else
        result=2
    fi
    exec {fd}<&-
    after="$(stat -Lc '%d:%i:%s:%y:%z:%a' -- "$file" 2>/dev/null)" || return 2
    [[ "$before" == "$after" && ! -L "$file" ]] || return 2
    return "$result"
}

check() {
    local result=0
    rlch_5_4_2_4_observe || result=$?
    case "$result" in
        0) return "$RLCH_MODULE_RESULT_SUCCESS" ;;
        1) printf 'CIS 5.4.2.4: root password does not satisfy the CAS access-control pattern\n' >&2
           return "$RLCH_MODULE_RESULT_NON_COMPLIANT" ;;
        *) printf 'CIS 5.4.2.4: cannot safely analyze the shadow file\n' >&2
           return "$RLCH_MODULE_RESULT_ERROR" ;;
    esac
}
apply() {
    local result=0
    check || result=$?
    if [[ "$result" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]]; then
        printf 'CIS 5.4.2.4: manual remediation required; review recovery access and configure root password with passwd root\n' >&2
        return "$RLCH_MODULE_RESULT_ERROR"
    fi
    return "$result"
}
validate() { check; }
rollback() { return "$RLCH_MODULE_RESULT_SUCCESS"; }
