#!/usr/bin/env bash
# CIS 7.2.1 - Literal pinned CAS password-state pattern, local passwd scope.
# SPDX-License-Identifier: MIT
# shellcheck source=lib/identity_observation.sh
source "${BASH_SOURCE[0]%/*}/../../../../../lib/identity_observation.sh"
RLCH_CIS_7_2_1_PASSWD="${RLCH_CIS_7_2_1_PASSWD:-/etc/passwd}"

rlch_7_2_1_observe() {
    local before after first second marker total=0 rejected=0
    before="$(rlch_identity_stamp "$RLCH_CIS_7_2_1_PASSWD" 2>/dev/null)" || return 2
    first="$(rlch_identity_password_markers "$RLCH_CIS_7_2_1_PASSWD" 2>/dev/null)" || return 2
    second="$(rlch_identity_password_markers "$RLCH_CIS_7_2_1_PASSWD" 2>/dev/null)" || return 2
    after="$(rlch_identity_stamp "$RLCH_CIS_7_2_1_PASSWD" 2>/dev/null)" || return 2
    [[ -n "$first" && "$first" == "$second" && "$before" == "$after" ]] || return 2
    while IFS= read -r marker; do
        total=$((total + 1)); (( total <= 65536 )) || return 2
        case "$marker" in
            X|STAR) : ;;
            OTHER) rejected=$((rejected + 1)) ;;
            *) return 2 ;;
        esac
    done <<< "$first"
    if (( rejected > 0 )); then
        printf 'CIS 7.2.1: %s of %s local account entries do not match the required password-field markers; values withheld\n' "$rejected" "$total" >&2
        return 1
    fi
    return 0
}
check() {
    local result=0
    rlch_7_2_1_observe || result=$?
    case "$result" in
        0|1) return "$result" ;;
        *) printf 'CIS 7.2.1: cannot reliably evaluate the local account database; evidence unavailable, invalid or unstable\n' >&2
           return "$RLCH_MODULE_RESULT_ERROR" ;;
    esac
}
validate() { check; }
apply() {
    local result=0
    check || result=$?
    if [[ "$result" -ne "$RLCH_MODULE_RESULT_SUCCESS" ]]; then
        printf 'CIS 7.2.1: manual remediation required; review account access and protected password storage in an isolated environment\n' >&2
        return "$RLCH_MODULE_RESULT_ERROR"
    fi
    return "$RLCH_MODULE_RESULT_SUCCESS"
}
rollback() { return "$RLCH_MODULE_RESULT_SUCCESS"; }
