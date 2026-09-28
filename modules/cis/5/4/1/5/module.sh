#!/usr/bin/env bash
# CIS 5.4.1.5 - Default and existing account inactivity.
# SPDX-License-Identifier: MIT

RLCH_CIS_5_4_1_5_USERADD="${RLCH_CIS_5_4_1_5_USERADD:-/etc/default/useradd}"
RLCH_CIS_5_4_1_5_SHADOW="${RLCH_CIS_5_4_1_5_SHADOW:-/etc/shadow}"
RLCH_CIS_5_4_1_5_CHAGE="${RLCH_CIS_5_4_1_5_CHAGE:-chage}"
RLCH_CIS_5_4_1_5_STATE="${RLCH_CIS_5_4_1_5_STATE:-/var/lib/rlch/cis/5.4.1.5}"
RLCH_CIS_5_4_1_5_MARKER='INACTIVE=45'

# 0: absent, 1: single valid value printed, 2: malformed/unsafe.
rlch_5_4_1_5_setting() {
    [[ -f "$RLCH_CIS_5_4_1_5_USERADD" && -r "$RLCH_CIS_5_4_1_5_USERADD" && ! -L "$RLCH_CIS_5_4_1_5_USERADD" ]] || return 2
    awk '
        /^[[:space:]]*#/ {next}
        /^[[:space:]]*INACTIVE([[:space:]]|=|$)/ {
            sub(/#.*/, "", $0)
            if ($0 !~ /^[[:space:]]*INACTIVE[[:space:]]*=[[:space:]]*(-1|[0-9]+)[[:space:]]*$/) bad=1
            split($0, parts, "="); value=parts[2]; gsub(/[[:space:]]/, "", value); count++
        }
        END {if (bad || count>1 || length(value)>10) exit 2; if (count) {print value; exit 1}}
    ' "$RLCH_CIS_5_4_1_5_USERADD"
}

# CAC's default-value regex is end-anchored and does not accept inline comments.
rlch_5_4_1_5_comment() {
    awk '/^[[:space:]]*#/ {next} /^[[:space:]]*INACTIVE([[:space:]]|=|$)/ && /#/ {found=1} END {exit !found}' "$RLCH_CIS_5_4_1_5_USERADD"
}

# Active nonempty, nonlocked password fields, including traditional hashes and
# system accounts. Upstream OVAL/Bash/OCIL disagree on their exact population.
# Never emit the password field; malformed shadow rows are errors.
rlch_5_4_1_5_accounts() {
    [[ -f "$RLCH_CIS_5_4_1_5_SHADOW" && -r "$RLCH_CIS_5_4_1_5_SHADOW" && ! -L "$RLCH_CIS_5_4_1_5_SHADOW" ]] || return 2
    awk -F: '
        NF!=9 || $1 !~ /^[a-zA-Z_][a-zA-Z0-9_.-]*$/ {bad=1; next}
        {if (seen[$1]++) bad=1}
        $2!="" && $2 !~ /^[!*]/ {
            if ($7!="" && $7!="-1" && ($7 !~ /^[0-9]+$/ || length($7)>10)) {bad=1; next}
            print $1 "|" $7
        }
        END {if (bad) exit 2}
    ' "$RLCH_CIS_5_4_1_5_SHADOW"
}

rlch_5_4_1_5_age() {
    local account="$1" rows
    rows="$(rlch_5_4_1_5_accounts)" || return 2
    awk -F '|' -v account="$account" '$1==account {print $2; found++} END {if (found!=1) exit 2}' <<< "$rows"
}

rlch_5_4_1_5_deficient() {
    local age="$1"
    [[ -z "$age" || "$age" == -1 ]] || ((10#$age > 45))
}

check() {
    local value code=0 rows account age finding=0
    value="$(rlch_5_4_1_5_setting)" || code=$?
    [[ "$code" -ne 2 ]] || return "$RLCH_MODULE_RESULT_ERROR"
    if [[ "$code" -eq 0 ]] || rlch_5_4_1_5_deficient "$value" || rlch_5_4_1_5_comment; then finding=1; fi
    rows="$(rlch_5_4_1_5_accounts)" || return "$RLCH_MODULE_RESULT_ERROR"
    while IFS='|' read -r account age; do
        [[ -n "$account" ]] || continue
        if rlch_5_4_1_5_deficient "$age"; then finding=1; fi
    done <<< "$rows"
    [[ "$finding" -eq 0 ]] || return "$RLCH_MODULE_RESULT_NON_COMPLIANT"
    return "$RLCH_MODULE_RESULT_SUCCESS"
}

# Rewrite only the selected line, retaining unrelated defaults and metadata.
rlch_5_4_1_5_write() {
    local original="$1" replacement="$2" temp
    temp="$(mktemp "${RLCH_CIS_5_4_1_5_USERADD}.XXXXXX")" || return 1
    cp -p --attributes-only "$RLCH_CIS_5_4_1_5_USERADD" "$temp" || { rm -f "$temp"; return 1; }
    awk -v old="$original" -v replacement="$replacement" '
        $0==old && old!="" {if (replacement!="") print replacement; next}
        {print}
        END {if (old=="" && replacement!="") print replacement}
    ' "$RLCH_CIS_5_4_1_5_USERADD" > "$temp" || { rm -f "$temp"; return 1; }
    mv -f "$temp" "$RLCH_CIS_5_4_1_5_USERADD"
}

apply() {
    local result=0 setting_code=0 value original='' rows account age
    check || result=$?
    [[ "$result" -ne "$RLCH_MODULE_RESULT_SUCCESS" ]] || return "$RLCH_MODULE_RESULT_SUCCESS"
    [[ "$result" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]] || return "$RLCH_MODULE_RESULT_ERROR"
    [[ "$(id -u)" -eq 0 && ! -e "$RLCH_CIS_5_4_1_5_STATE" && ! -L "$RLCH_CIS_5_4_1_5_STATE" ]] || return "$RLCH_MODULE_RESULT_ERROR"
    [[ -s "$RLCH_CIS_5_4_1_5_USERADD" && "$(tail -c 1 "$RLCH_CIS_5_4_1_5_USERADD" | wc -l)" -eq 1 ]] || return "$RLCH_MODULE_RESULT_ERROR"
    value="$(rlch_5_4_1_5_setting)" || setting_code=$?
    rows="$(rlch_5_4_1_5_accounts)" || return "$RLCH_MODULE_RESULT_ERROR"
    if [[ "$setting_code" -eq 1 ]] && { rlch_5_4_1_5_deficient "$value" || rlch_5_4_1_5_comment; }; then
        original="$(awk '/^[[:space:]]*#/ {next} /^[[:space:]]*INACTIVE([[:space:]]|=|$)/ {print; exit}' "$RLCH_CIS_5_4_1_5_USERADD")"
    fi
    mkdir -p "$RLCH_CIS_5_4_1_5_STATE" || return "$RLCH_MODULE_RESULT_ERROR"
    chmod 0700 "$RLCH_CIS_5_4_1_5_STATE" || return "$RLCH_MODULE_RESULT_ERROR"
    printf '%s\n' "$original" > "$RLCH_CIS_5_4_1_5_STATE/original" || return "$RLCH_MODULE_RESULT_ERROR"
    : > "$RLCH_CIS_5_4_1_5_STATE/accounts" || return "$RLCH_MODULE_RESULT_ERROR"
    while IFS='|' read -r account age; do
        [[ -n "$account" ]] || continue
        if rlch_5_4_1_5_deficient "$age"; then
            printf '%s|%s\n' "$account" "$age" >> "$RLCH_CIS_5_4_1_5_STATE/accounts" || return "$RLCH_MODULE_RESULT_ERROR"
        fi
    done <<< "$rows"
    if [[ "$setting_code" -eq 0 ]] || rlch_5_4_1_5_deficient "$value" || rlch_5_4_1_5_comment; then
        printf 'yes\n' > "$RLCH_CIS_5_4_1_5_STATE/setting"
        if ! rlch_5_4_1_5_write "$original" "$RLCH_CIS_5_4_1_5_MARKER"; then
            rollback >/dev/null 2>&1 || true
            return "$RLCH_MODULE_RESULT_ERROR"
        fi
    else
        printf 'no\n' > "$RLCH_CIS_5_4_1_5_STATE/setting"
    fi
    while IFS='|' read -r account age; do
        [[ -n "$account" ]] || continue
        if ! "$RLCH_CIS_5_4_1_5_CHAGE" --inactive 45 "$account"; then
            rollback >/dev/null 2>&1 || true
            return "$RLCH_MODULE_RESULT_ERROR"
        fi
    done < "$RLCH_CIS_5_4_1_5_STATE/accounts"
    if ! check; then
        rollback >/dev/null 2>&1 || true
        return "$RLCH_MODULE_RESULT_ERROR"
    fi
    return "$RLCH_MODULE_RESULT_CHANGED"
}

validate() { check; }

rollback() {
    local setting original account old age rows file_rows failed=0
    [[ -e "$RLCH_CIS_5_4_1_5_STATE" ]] || return "$RLCH_MODULE_RESULT_SUCCESS"
    [[ -d "$RLCH_CIS_5_4_1_5_STATE" && ! -L "$RLCH_CIS_5_4_1_5_STATE" && -f "$RLCH_CIS_5_4_1_5_STATE/accounts" && -f "$RLCH_CIS_5_4_1_5_STATE/setting" && -f "$RLCH_CIS_5_4_1_5_STATE/original" ]] || return "$RLCH_MODULE_RESULT_ERROR"
    [[ -f "$RLCH_CIS_5_4_1_5_USERADD" && ! -L "$RLCH_CIS_5_4_1_5_USERADD" ]] || return "$RLCH_MODULE_RESULT_ERROR"
    setting="$(cat "$RLCH_CIS_5_4_1_5_STATE/setting")"
    original="$(cat "$RLCH_CIS_5_4_1_5_STATE/original")"
    if [[ "$setting" == yes ]]; then
        file_rows="$(awk '/^[[:space:]]*#/ {next} /^[[:space:]]*INACTIVE([[:space:]]|=|$)/ {print}' "$RLCH_CIS_5_4_1_5_USERADD")"
        [[ "$file_rows" == "$RLCH_CIS_5_4_1_5_MARKER" || "$file_rows" == "$original" ]] || return "$RLCH_MODULE_RESULT_ERROR"
    elif [[ "$setting" != no ]]; then return "$RLCH_MODULE_RESULT_ERROR"; fi
    rows="$(rlch_5_4_1_5_accounts)" || return "$RLCH_MODULE_RESULT_ERROR"
    while IFS='|' read -r account old; do
        [[ -n "$account" ]] || continue
        age="$(awk -F '|' -v account="$account" '$1==account {print $2; found++} END {if (found!=1) exit 2}' <<< "$rows")" || return "$RLCH_MODULE_RESULT_ERROR"
        [[ "$age" == 45 || "$age" == "$old" ]] || return "$RLCH_MODULE_RESULT_ERROR"
    done < "$RLCH_CIS_5_4_1_5_STATE/accounts"
    while IFS='|' read -r account old; do
        [[ -n "$account" ]] || continue
        age="$(rlch_5_4_1_5_age "$account")" || return "$RLCH_MODULE_RESULT_ERROR"
        if [[ "$age" == 45 && "$old" != 45 ]]; then
            "$RLCH_CIS_5_4_1_5_CHAGE" --inactive "${old:--1}" "$account" || failed=1
        fi
    done < "$RLCH_CIS_5_4_1_5_STATE/accounts"
    [[ "$failed" -eq 0 ]] || return "$RLCH_MODULE_RESULT_ERROR"
    if [[ "$setting" == yes && "$file_rows" != "$original" ]]; then
        rlch_5_4_1_5_write "$RLCH_CIS_5_4_1_5_MARKER" "$original" || return "$RLCH_MODULE_RESULT_ERROR"
    fi
    rm -rf "$RLCH_CIS_5_4_1_5_STATE" || return "$RLCH_MODULE_RESULT_ERROR"
    return "$RLCH_MODULE_RESULT_CHANGED"
}
