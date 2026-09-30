#!/usr/bin/env bash
# CIS 5.4.2.2 - Primary GID 0 in /etc/passwd, without mutation.
# SPDX-License-Identifier: MIT

RLCH_CIS_5_4_2_2_PASSWD="${RLCH_CIS_5_4_2_2_PASSWD:-/etc/passwd}"

rlch_5_4_2_2_rows() {
    [[ -f "$RLCH_CIS_5_4_2_2_PASSWD" && -r "$RLCH_CIS_5_4_2_2_PASSWD" && ! -L "$RLCH_CIS_5_4_2_2_PASSWD" ]] || return 2
    awk -F: '
        NF!=7 || $1 !~ /^[a-zA-Z_][a-zA-Z0-9_.-]*$/ || $3 !~ /^[0-9]+$/ || $4 !~ /^[0-9]+$/ || length($3)>10 || length($4)>10 {bad=1; next}
        {if (seen[$1]++) bad=1; print $1 "|" ($4 ~ /^0+$/ ? "0" : $4)}
        END {if (bad) exit 2}
    ' "$RLCH_CIS_5_4_2_2_PASSWD"
}

check() {
    local rows account gid root_count=0 finding=0
    rows="$(rlch_5_4_2_2_rows)" || return "$RLCH_MODULE_RESULT_ERROR"
    while IFS='|' read -r account gid; do
        [[ -n "$account" ]] || continue
        if [[ "$account" == root ]]; then
            root_count=$((root_count + 1))
            if [[ "$gid" != 0 ]]; then
                printf 'CIS 5.4.2.2: root primary GID is not 0\n' >&2
                finding=1
            fi
            continue
        fi
        case "$account" in sync|shutdown|halt|operator) continue;; esac
        if [[ "$gid" == 0 ]]; then
            printf 'CIS 5.4.2.2: %s has primary GID 0\n' "$account" >&2
            finding=1
        fi
    done <<< "$rows"
    [[ "$root_count" -eq 1 ]] || return "$RLCH_MODULE_RESULT_ERROR"
    [[ "$finding" -eq 0 ]] || return "$RLCH_MODULE_RESULT_NON_COMPLIANT"
    return "$RLCH_MODULE_RESULT_SUCCESS"
}

apply() {
    local result=0
    check || result=$?
    if [[ "$result" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]]; then
        printf 'CIS 5.4.2.2: review account ownership and services before changing primary GIDs manually\n' >&2
        return "$RLCH_MODULE_RESULT_ERROR"
    fi
    [[ "$result" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]] || return "$RLCH_MODULE_RESULT_ERROR"
    return "$RLCH_MODULE_RESULT_SUCCESS"
}

validate() { check; }
rollback() { return "$RLCH_MODULE_RESULT_SUCCESS"; }
