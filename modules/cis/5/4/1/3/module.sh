#!/usr/bin/env bash
# CIS 5.4.1.3 - PASS_WARN_AGE and existing shadow warning age.
# SPDX-License-Identifier: MIT

RLCH_CIS_5_4_1_3_LOGIN_DEFS="${RLCH_CIS_5_4_1_3_LOGIN_DEFS:-/etc/login.defs}"
RLCH_CIS_5_4_1_3_SHADOW="${RLCH_CIS_5_4_1_3_SHADOW:-/etc/shadow}"
RLCH_CIS_5_4_1_3_CHAGE="${RLCH_CIS_5_4_1_3_CHAGE:-chage}"
RLCH_CIS_5_4_1_3_STATE="${RLCH_CIS_5_4_1_3_STATE:-/var/lib/rlch/cis/5.4.1.3}"
RLCH_CIS_5_4_1_3_MARKER='PASS_WARN_AGE 7 # rlch-cis-5.4.1.3'

# 0: missing, 1: one valid value printed, 2: malformed/ambiguous/unsafe.
rlch_5_4_1_3_setting() {
    [[ -f "$RLCH_CIS_5_4_1_3_LOGIN_DEFS" && -r "$RLCH_CIS_5_4_1_3_LOGIN_DEFS" && ! -L "$RLCH_CIS_5_4_1_3_LOGIN_DEFS" ]] || return 2
    awk '
        /^[[:space:]]*#/ {next}
        /^[[:space:]]*PASS_WARN_AGE([[:space:]]|$)/ {
            sub(/#.*/, "", $0)
            if ($0 !~ /^[[:space:]]*PASS_WARN_AGE[[:space:]]+[0-9]+[[:space:]]*$/) bad=1
            value=$2; count++
        }
        END {if (bad || count>1 || length(value)>10) exit 2; if (count) {print value; exit 1}}
    ' "$RLCH_CIS_5_4_1_3_LOGIN_DEFS"
}

# Emit only selected account name and existing warning; never expose hashes.
# The upstream Bash fix selects only modular hashes beginning with $, while
# its OVAL also matches traditional hashes and apparently empty passwords.
# As for 5.4.1.1, select nonempty, nonlocked password fields consistently.
rlch_5_4_1_3_accounts() {
    [[ -f "$RLCH_CIS_5_4_1_3_SHADOW" && -r "$RLCH_CIS_5_4_1_3_SHADOW" && ! -L "$RLCH_CIS_5_4_1_3_SHADOW" ]] || return 2
    awk -F: '
        NF!=9 || $1 !~ /^[a-zA-Z_][a-zA-Z0-9_.-]*$/ {bad=1; next}
        {if (seen[$1]++) bad=1}
        $2!="" && $2 !~ /^[!*]/ {
            if ($6!="" && ($6 !~ /^[0-9]+$/ || length($6)>10)) {bad=1; next}
            print $1 "|" $6
        }
        END {if (bad) exit 2}
    ' "$RLCH_CIS_5_4_1_3_SHADOW"
}

rlch_5_4_1_3_age() {
    local account="$1" rows
    rows="$(rlch_5_4_1_3_accounts)" || return 2
    awk -F '|' -v account="$account" '$1==account {print $2; found++} END {if (found!=1) exit 2}' <<< "$rows"
}

check() {
    local value code=0 rows account age finding=0
    value="$(rlch_5_4_1_3_setting)" || code=$?
    [[ "$code" -ne 2 ]] || return "$RLCH_MODULE_RESULT_ERROR"
    if [[ "$code" -eq 0 ]]; then finding=1
    elif ((10#$value < 7)); then finding=1; fi
    rows="$(rlch_5_4_1_3_accounts)" || return "$RLCH_MODULE_RESULT_ERROR"
    while IFS='|' read -r account age; do
        [[ -n "$account" ]] || continue
        if [[ -z "$age" ]]; then finding=1
        elif ((10#$age < 7)); then finding=1; fi
    done <<< "$rows"
    [[ "$finding" -eq 0 ]] || return "$RLCH_MODULE_RESULT_NON_COMPLIANT"
    return "$RLCH_MODULE_RESULT_SUCCESS"
}

rlch_5_4_1_3_write() {
    local original="$1" replacement="$2" temp
    temp="$(mktemp "${RLCH_CIS_5_4_1_3_LOGIN_DEFS}.XXXXXX")" || return 1
    cp -p --attributes-only "$RLCH_CIS_5_4_1_3_LOGIN_DEFS" "$temp" || { rm -f "$temp"; return 1; }
    awk -v old="$original" -v replacement="$replacement" '
        $0==old && old!="" {if (replacement!="") print replacement; next}
        {print}
        END {if (old=="" && replacement!="") print replacement}
    ' "$RLCH_CIS_5_4_1_3_LOGIN_DEFS" > "$temp" || { rm -f "$temp"; return 1; }
    mv -f "$temp" "$RLCH_CIS_5_4_1_3_LOGIN_DEFS"
}

apply() {
    local result=0 setting_code=0 value original='' rows account age
    check || result=$?
    [[ "$result" -ne "$RLCH_MODULE_RESULT_SUCCESS" ]] || return "$RLCH_MODULE_RESULT_SUCCESS"
    [[ "$result" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]] || return "$RLCH_MODULE_RESULT_ERROR"
    [[ "$(id -u)" -eq 0 && ! -e "$RLCH_CIS_5_4_1_3_STATE" && ! -L "$RLCH_CIS_5_4_1_3_STATE" ]] || return "$RLCH_MODULE_RESULT_ERROR"
    [[ -s "$RLCH_CIS_5_4_1_3_LOGIN_DEFS" && "$(tail -c 1 "$RLCH_CIS_5_4_1_3_LOGIN_DEFS" | wc -l)" -eq 1 ]] || return "$RLCH_MODULE_RESULT_ERROR"
    value="$(rlch_5_4_1_3_setting)" || setting_code=$?
    rows="$(rlch_5_4_1_3_accounts)" || return "$RLCH_MODULE_RESULT_ERROR"
    if [[ "$setting_code" -eq 1 ]] && ((10#$value < 7)); then
        original="$(awk '/^[[:space:]]*#/ {next} /^[[:space:]]*PASS_WARN_AGE([[:space:]]|$)/ {print; exit}' "$RLCH_CIS_5_4_1_3_LOGIN_DEFS")"
    fi
    mkdir -p "$RLCH_CIS_5_4_1_3_STATE" || return "$RLCH_MODULE_RESULT_ERROR"
    chmod 0700 "$RLCH_CIS_5_4_1_3_STATE" || return "$RLCH_MODULE_RESULT_ERROR"
    printf '%s\n' "$original" > "$RLCH_CIS_5_4_1_3_STATE/original" || return "$RLCH_MODULE_RESULT_ERROR"
    : > "$RLCH_CIS_5_4_1_3_STATE/accounts" || return "$RLCH_MODULE_RESULT_ERROR"
    while IFS='|' read -r account age; do
        [[ -n "$account" ]] || continue
        if [[ -z "$age" ]]; then
            printf '%s|%s\n' "$account" "$age" >> "$RLCH_CIS_5_4_1_3_STATE/accounts" || return "$RLCH_MODULE_RESULT_ERROR"
        elif ((10#$age < 7)); then
            printf '%s|%s\n' "$account" "$age" >> "$RLCH_CIS_5_4_1_3_STATE/accounts" || return "$RLCH_MODULE_RESULT_ERROR"
        fi
    done <<< "$rows"
    if [[ "$setting_code" -eq 0 ]] || ((10#$value < 7)); then
        printf 'yes\n' > "$RLCH_CIS_5_4_1_3_STATE/setting"
        if ! rlch_5_4_1_3_write "$original" "$RLCH_CIS_5_4_1_3_MARKER"; then
            rollback >/dev/null 2>&1 || true
            return "$RLCH_MODULE_RESULT_ERROR"
        fi
    else
        printf 'no\n' > "$RLCH_CIS_5_4_1_3_STATE/setting"
    fi
    while IFS='|' read -r account age; do
        [[ -n "$account" ]] || continue
        if ! "$RLCH_CIS_5_4_1_3_CHAGE" --warndays 7 "$account"; then
            rollback >/dev/null 2>&1 || true
            return "$RLCH_MODULE_RESULT_ERROR"
        fi
    done < "$RLCH_CIS_5_4_1_3_STATE/accounts"
    if ! check; then
        rollback >/dev/null 2>&1 || true
        return "$RLCH_MODULE_RESULT_ERROR"
    fi
    return "$RLCH_MODULE_RESULT_CHANGED"
}

validate() { check; }

rollback() {
    local setting original account old age rows file_rows failed=0
    [[ -e "$RLCH_CIS_5_4_1_3_STATE" ]] || return "$RLCH_MODULE_RESULT_SUCCESS"
    [[ -d "$RLCH_CIS_5_4_1_3_STATE" && ! -L "$RLCH_CIS_5_4_1_3_STATE" && -f "$RLCH_CIS_5_4_1_3_STATE/accounts" && -f "$RLCH_CIS_5_4_1_3_STATE/setting" && -f "$RLCH_CIS_5_4_1_3_STATE/original" ]] || return "$RLCH_MODULE_RESULT_ERROR"
    [[ -f "$RLCH_CIS_5_4_1_3_LOGIN_DEFS" && ! -L "$RLCH_CIS_5_4_1_3_LOGIN_DEFS" ]] || return "$RLCH_MODULE_RESULT_ERROR"
    setting="$(cat "$RLCH_CIS_5_4_1_3_STATE/setting")"
    original="$(cat "$RLCH_CIS_5_4_1_3_STATE/original")"
    if [[ "$setting" == yes ]]; then
        file_rows="$(awk '/^[[:space:]]*#/ {next} /^[[:space:]]*PASS_WARN_AGE([[:space:]]|$)/ {print}' "$RLCH_CIS_5_4_1_3_LOGIN_DEFS")"
        [[ "$file_rows" == "$RLCH_CIS_5_4_1_3_MARKER" || "$file_rows" == "$original" ]] || return "$RLCH_MODULE_RESULT_ERROR"
    elif [[ "$setting" != no ]]; then return "$RLCH_MODULE_RESULT_ERROR"; fi
    rows="$(rlch_5_4_1_3_accounts)" || return "$RLCH_MODULE_RESULT_ERROR"
    while IFS='|' read -r account old; do
        [[ -n "$account" ]] || continue
        age="$(awk -F '|' -v account="$account" '$1==account {print $2; found++} END {if (found!=1) exit 2}' <<< "$rows")" || return "$RLCH_MODULE_RESULT_ERROR"
        [[ "$age" == 7 || "$age" == "$old" ]] || return "$RLCH_MODULE_RESULT_ERROR"
    done < "$RLCH_CIS_5_4_1_3_STATE/accounts"
    while IFS='|' read -r account old; do
        [[ -n "$account" ]] || continue
        age="$(rlch_5_4_1_3_age "$account")" || return "$RLCH_MODULE_RESULT_ERROR"
        if [[ "$age" == 7 && "$old" != 7 ]]; then
            "$RLCH_CIS_5_4_1_3_CHAGE" --warndays "${old:--1}" "$account" || failed=1
        fi
    done < "$RLCH_CIS_5_4_1_3_STATE/accounts"
    [[ "$failed" -eq 0 ]] || return "$RLCH_MODULE_RESULT_ERROR"
    if [[ "$setting" == yes && "$file_rows" != "$original" ]]; then
        rlch_5_4_1_3_write "$RLCH_CIS_5_4_1_3_MARKER" "$original" || return "$RLCH_MODULE_RESULT_ERROR"
    fi
    rm -rf "$RLCH_CIS_5_4_1_3_STATE" || return "$RLCH_MODULE_RESULT_ERROR"
    return "$RLCH_MODULE_RESULT_CHANGED"
}
