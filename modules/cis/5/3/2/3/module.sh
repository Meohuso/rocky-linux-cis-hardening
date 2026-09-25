#!/usr/bin/env bash
# CIS 5.3.2.3 - Verify pam_pwquality in authselect-managed password stacks.
# SPDX-License-Identifier: MIT

RLCH_CIS_5_3_2_3_AUTHSELECT="${RLCH_CIS_5_3_2_3_AUTHSELECT:-authselect}"
RLCH_CIS_5_3_2_3_PAM_DIR="${RLCH_CIS_5_3_2_3_PAM_DIR:-/etc/pam.d}"

rlch_5_3_2_3_stack_enabled() {
    [[ -f "${1:-}" ]] || return 1
    awk '
        /^[[:space:]]*#/ { next }
        /^[[:space:]]*password[[:space:]]+(\[[^]]+\]|[^[:space:]]+)[[:space:]]+pam_pwquality\.so([[:space:]]|$)/ { count++ }
        END { exit !(count == 1) }
    ' "$1"
}

check() {
    local file
    "${RLCH_CIS_5_3_2_3_AUTHSELECT}" check >/dev/null 2>&1 || return "${RLCH_MODULE_RESULT_ERROR}"
    for file in system-auth password-auth; do
        rlch_5_3_2_3_stack_enabled "${RLCH_CIS_5_3_2_3_PAM_DIR}/${file}" ||
            return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    done
    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

apply() {
    local result=0
    check || result=$?
    [[ "${result}" -ne "${RLCH_MODULE_RESULT_SUCCESS}" ]] || return "${RLCH_MODULE_RESULT_SUCCESS}"
    [[ "${result}" -ne "${RLCH_MODULE_RESULT_ERROR}" ]] || return "${RLCH_MODULE_RESULT_ERROR}"
    error_message "CIS 5.3.2.3 requires a reviewed authselect profile change; generated PAM files cannot be edited directly."
    return "${RLCH_MODULE_RESULT_ERROR}"
}

validate() { check; }
rollback() { return "${RLCH_MODULE_RESULT_SUCCESS}"; }
