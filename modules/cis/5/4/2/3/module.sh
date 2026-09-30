#!/usr/bin/env bash
# CIS 5.4.2.3 - Observation-only group GID zero.
# SPDX-License-Identifier: MIT

RLCH_CIS_5_4_2_3_GROUP="${RLCH_CIS_5_4_2_3_GROUP:-/etc/group}"

rlch_5_4_2_3_rows() {
    [[ -f "$RLCH_CIS_5_4_2_3_GROUP" && -r "$RLCH_CIS_5_4_2_3_GROUP" && ! -L "$RLCH_CIS_5_4_2_3_GROUP" ]] || return 2
    awk -F: '
        NF!=4 || $1 !~ /^[a-zA-Z_][a-zA-Z0-9_.-]*$/ || $3 !~ /^[0-9]+$/ || length($3)>10 {bad=1; next}
        {if (seen[$1]++) bad=1; print $1 "|" ($3 ~ /^0+$/ ? "0" : $3)}
        END {if (bad) exit 2}
    ' "$RLCH_CIS_5_4_2_3_GROUP"
}

check() {
    local rows group gid root_count=0 finding=0
    rows="$(rlch_5_4_2_3_rows)" || return "$RLCH_MODULE_RESULT_ERROR"
    while IFS='|' read -r group gid; do
        [[ -n "$group" ]] || continue
        if [[ "$group" == root ]]; then
            root_count=$((root_count + 1))
            if [[ "$gid" != 0 ]]; then
                printf 'CIS 5.4.2.3: root group does not have GID 0\n' >&2
                finding=1
            fi
        elif [[ "$gid" == 0 ]]; then
            printf 'CIS 5.4.2.3: %s group has GID 0\n' "$group" >&2
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
        printf 'CIS 5.4.2.3: review memberships, ownership and services before changing group GIDs manually\n' >&2
        return "$RLCH_MODULE_RESULT_ERROR"
    fi
    [[ "$result" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]] || return "$RLCH_MODULE_RESULT_ERROR"
    return "$RLCH_MODULE_RESULT_SUCCESS"
}

validate() { check; }
rollback() { return "$RLCH_MODULE_RESULT_SUCCESS"; }
