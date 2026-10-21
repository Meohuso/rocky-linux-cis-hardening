#!/usr/bin/env bash
# CIS 7.2.7 - Pinned local greedy textfilecontent54 captures, not NSS.
# SPDX-License-Identifier: MIT
# shellcheck source=lib/identity_observation.sh
source "${BASH_SOURCE[0]%/*}/../../../../../lib/identity_observation.sh"
# shellcheck source=lib/rpm_observation.sh
source "${BASH_SOURCE[0]%/*}/../../../../../lib/rpm_observation.sh"
RLCH_CIS_7_2_7_GROUP="${RLCH_CIS_7_2_7_GROUP:-/etc/group}"
RLCH_CIS_7_2_7_RPM="${RLCH_CIS_7_2_7_RPM:-/usr/bin/rpm}"

# All name-bearing variables/pipelines stay inside an untraced subshell. The
# caller retains its tracing state; only fixed guidance/counts leave this scope.
rlch_7_2_7_observe() (
    set +x
    local applicable=0 after_applicable=0 before after first second selected distinct
    rlch_rpm_package_status "$RLCH_CIS_7_2_7_RPM" kernel-core 2>/dev/null || applicable=$?
    case "$applicable" in
        0) : ;;
        1) return "$RLCH_MODULE_RESULT_NOT_APPLICABLE" ;;
        *) return "$RLCH_MODULE_RESULT_ERROR" ;;
    esac
    before="$(rlch_identity_stamp "$RLCH_CIS_7_2_7_GROUP" 2>/dev/null)" || return "$RLCH_MODULE_RESULT_ERROR"
    first="$(rlch_identity_group_name_counts "$RLCH_CIS_7_2_7_GROUP" 2>/dev/null)" || return "$RLCH_MODULE_RESULT_ERROR"
    second="$(rlch_identity_group_name_counts "$RLCH_CIS_7_2_7_GROUP" 2>/dev/null)" || return "$RLCH_MODULE_RESULT_ERROR"
    after="$(rlch_identity_stamp "$RLCH_CIS_7_2_7_GROUP" 2>/dev/null)" || return "$RLCH_MODULE_RESULT_ERROR"
    rlch_rpm_package_status "$RLCH_CIS_7_2_7_RPM" kernel-core 2>/dev/null || after_applicable=$?
    [[ "$after_applicable" -eq 0 && -n "$first" && "$first" == "$second" && "$before" == "$after" ]] || return "$RLCH_MODULE_RESULT_ERROR"
    # Only validated counts leave the reader; no captures enter the shell.
    [[ "$first" =~ ^COUNTS\|([0-9]{1,5})\|([0-9]{1,5})$ ]] || return "$RLCH_MODULE_RESULT_ERROR"
    selected="${BASH_REMATCH[1]}"; distinct="${BASH_REMATCH[2]}"
    # Canonical decimal strings only; reject octal-like defensive API stubs.
    [[ "$selected" =~ ^(0|[1-9][0-9]*)$ && "$distinct" =~ ^(0|[1-9][0-9]*)$ ]] || return "$RLCH_MODULE_RESULT_ERROR"
    # Empty capture semantics/collection flags require real OpenSCAP testing.
    (( selected > 0 && selected <= 65536 && distinct > 0 && distinct <= selected )) || return "$RLCH_MODULE_RESULT_ERROR"
    if (( selected != distinct )); then
        printf 'CIS 7.2.7: %s selected local group entries have %s distinct OVAL captures; identities and captures withheld\n' "$selected" "$distinct" >&2
        return "$RLCH_MODULE_RESULT_NON_COMPLIANT"
    fi
    return "$RLCH_MODULE_RESULT_SUCCESS"
)
check() {
    local result=0
    rlch_7_2_7_observe || result=$?
    case "$result" in
        0|1|3) return "$result" ;;
        *) printf 'CIS 7.2.7: cannot reliably evaluate local name uniqueness; applicability or complete stable supported captures unproven\n' >&2
           return "$RLCH_MODULE_RESULT_ERROR" ;;
    esac
}
validate() { check; }
apply() {
    local result=0
    check || result=$?
    case "$result" in
        0|3) return "$result" ;;
        *) printf 'CIS 7.2.7: manual remediation required; review group access and ownership before changing group names\n' >&2
           return "$RLCH_MODULE_RESULT_ERROR" ;;
    esac
}
rollback() { return "$RLCH_MODULE_RESULT_SUCCESS"; }
