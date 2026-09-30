#!/usr/bin/env bash
# CIS 5.4.2.1 - No unlocked non-root UID-zero accounts.
# SPDX-License-Identifier: MIT

RLCH_CIS_5_4_2_1_PASSWD="${RLCH_CIS_5_4_2_1_PASSWD:-/etc/passwd}"
RLCH_CIS_5_4_2_1_SHADOW="${RLCH_CIS_5_4_2_1_SHADOW:-/etc/shadow}"

# Only identifiers and UID leave the parser; never emit password fields.
rlch_5_4_2_1_passwd_rows() {
    [[ -f "$RLCH_CIS_5_4_2_1_PASSWD" && -r "$RLCH_CIS_5_4_2_1_PASSWD" && ! -L "$RLCH_CIS_5_4_2_1_PASSWD" ]] || return 2
    awk -F: '
        NF!=7 || $1 !~ /^[a-zA-Z_][a-zA-Z0-9_.-]*$/ || $3 !~ /^[0-9]+$/ || $4 !~ /^[0-9]+$/ || length($3)>10 || length($4)>10 {bad=1; next}
        {if (seen[$1]++) bad=1; print $1 "|" ($3 ~ /^0+$/ ? "0" : $3)}
        END {if (bad) exit 2}
    ' "$RLCH_CIS_5_4_2_1_PASSWD"
}

# CAC recognizes any leading ! or * as a lock. Keep the rest of shadow private.
rlch_5_4_2_1_shadow_rows() {
    [[ -f "$RLCH_CIS_5_4_2_1_SHADOW" && -r "$RLCH_CIS_5_4_2_1_SHADOW" && ! -L "$RLCH_CIS_5_4_2_1_SHADOW" ]] || return 2
    awk -F: '
        NF!=9 || $1 !~ /^[a-zA-Z_][a-zA-Z0-9_.-]*$/ {bad=1; next}
        {if (seen[$1]++) bad=1; print $1 "|" ($2 ~ /^[!*]/ ? "locked" : "unlocked")}
        END {if (bad) exit 2}
    ' "$RLCH_CIS_5_4_2_1_SHADOW"
}

check() {
    local accounts locks account uid state root_count=0 finding=0
    accounts="$(rlch_5_4_2_1_passwd_rows)" || return "$RLCH_MODULE_RESULT_ERROR"
    locks="$(rlch_5_4_2_1_shadow_rows)" || return "$RLCH_MODULE_RESULT_ERROR"
    while IFS='|' read -r account uid; do
        [[ -n "$account" ]] || continue
        if [[ "$account" == root ]]; then
            root_count=$((root_count + 1))
            if [[ "$uid" != 0 ]]; then
                printf 'CIS 5.4.2.1: root does not have UID 0\n' >&2
                finding=1
            fi
        fi
        if [[ "$account" == root || "$uid" == 0 ]]; then
            state="$(awk -F '|' -v name="$account" '$1==name {print $2; found++} END {if (found!=1) exit 2}' <<< "$locks")" || return "$RLCH_MODULE_RESULT_ERROR"
            if [[ "$account" != root && "$state" != locked ]]; then
                printf 'CIS 5.4.2.1: %s has UID 0 and is not locked\n' "$account" >&2
                finding=1
            fi
        fi
    done <<< "$accounts"
    [[ "$root_count" -eq 1 ]] || return "$RLCH_MODULE_RESULT_ERROR"
    [[ "$finding" -eq 0 ]] || return "$RLCH_MODULE_RESULT_NON_COMPLIANT"
    return "$RLCH_MODULE_RESULT_SUCCESS"
}

apply() {
    local result=0
    check || result=$?
    if [[ "$result" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]]; then
        printf 'CIS 5.4.2.1: review UID-zero account ownership, services and access before manual remediation\n' >&2
        return "$RLCH_MODULE_RESULT_ERROR"
    fi
    [[ "$result" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]] || return "$RLCH_MODULE_RESULT_ERROR"
    return "$RLCH_MODULE_RESULT_SUCCESS"
}

validate() { check; }
rollback() { return "$RLCH_MODULE_RESULT_SUCCESS"; }
