#!/usr/bin/env bash
# CIS 5.4.1.6 - Observation only: CAC explicitly declines auto-remediation.
# SPDX-License-Identifier: MIT

RLCH_CIS_5_4_1_6_SHADOW="${RLCH_CIS_5_4_1_6_SHADOW:-/etc/shadow}"
RLCH_CIS_5_4_1_6_DATE="${RLCH_CIS_5_4_1_6_DATE:-date}"

# OVAL excludes exactly five password values, rather than every locked prefix.
# Emit only account names and change days, never hashes. An empty/invalid day
# cannot be converted to seconds and must not produce a false SUCCESS.
rlch_5_4_1_6_accounts() {
    [[ -f "$RLCH_CIS_5_4_1_6_SHADOW" && -r "$RLCH_CIS_5_4_1_6_SHADOW" && ! -L "$RLCH_CIS_5_4_1_6_SHADOW" ]] || return 2
    awk -F: '
        NF!=9 || $1 !~ /^[a-zA-Z_][a-zA-Z0-9_.-]*$/ {bad=1; next}
        {if (seen[$1]++) bad=1}
        $2 !~ /^(!|!!|!\*|\*|!locked)$/ {
            if ($3 !~ /^[0-9]+$/ || length($3)>10) {bad=1; next}
            print $1 "|" $3
        }
        END {if (bad) exit 2}
    ' "$RLCH_CIS_5_4_1_6_SHADOW"
}

check() {
    local now rows account day finding=0
    now="$("$RLCH_CIS_5_4_1_6_DATE" +%s)" || return "$RLCH_MODULE_RESULT_ERROR"
    [[ "$now" =~ ^[0-9]{1,12}$ ]] || return "$RLCH_MODULE_RESULT_ERROR"
    rows="$(rlch_5_4_1_6_accounts)" || return "$RLCH_MODULE_RESULT_ERROR"
    while IFS='|' read -r account day; do
        [[ -n "$account" ]] || continue
        if ((10#$day * 86400 > 10#$now)); then
            printf 'CIS 5.4.1.6: %s: last password change date is in the future\n' "$account" >&2
            finding=1
        fi
    done <<< "$rows"
    [[ "$finding" -eq 0 ]] || return "$RLCH_MODULE_RESULT_NON_COMPLIANT"
    return "$RLCH_MODULE_RESULT_SUCCESS"
}

apply() {
    local result=0
    check || result=$?
    [[ "$result" -ne "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]] || {
        printf 'CIS 5.4.1.6: manual remediation required; automatic password expiration could disrupt accounts\n' >&2
        return "$RLCH_MODULE_RESULT_ERROR"
    }
    [[ "$result" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]] || return "$RLCH_MODULE_RESULT_ERROR"
    return "$RLCH_MODULE_RESULT_SUCCESS"
}

validate() { check; }

# Neither check nor apply mutates shadow or creates state.
rollback() { return "$RLCH_MODULE_RESULT_SUCCESS"; }
