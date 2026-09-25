#!/usr/bin/env bash
# CIS 5.3.2.2 - Verify pam_faillock in authselect-managed PAM stacks.
# SPDX-License-Identifier: MIT

RLCH_CIS_5_3_2_2_AUTHSELECT="${RLCH_CIS_5_3_2_2_AUTHSELECT:-authselect}"
RLCH_CIS_5_3_2_2_PAM_DIR="${RLCH_CIS_5_3_2_2_PAM_DIR:-/etc/pam.d}"

rlch_5_3_2_2_stack_complete() {
    [[ -f "${1:-}" ]] || return 1
    awk '
        function normalized(line, control) {
            sub(/^[[:space:]]+/, "", line)
            if (line !~ /^(auth|account)[[:space:]]+\[/) return line
            control = line
            sub(/^[^[]*\[/, "", control); sub(/\].*$/, "", control)
            gsub(/[[:space:]]+/, " ", control)
            control = " " control " "
            if (index(control, " success=ok ") && index(control, " new_authtok_reqd=ok ") &&
                index(control, " ignore=ignore ") && index(control, " default=bad ")) {
                sub(/\[[^]]+\]/, "required", line)
            } else if (index(control, " success=done ") &&
                       index(control, " new_authtok_reqd=done ") &&
                       index(control, " default=ignore ")) {
                sub(/\[[^]]+\]/, "sufficient", line)
            }
            return line
        }
        /^[[:space:]]*#/ { next }
        {
            count = split(normalized($0), field, /[[:space:]]+/)
            if (field[1] == "auth" && field[3] == "pam_unix.so") unix_any++
            if (field[1] == "auth" && field[3] == "pam_unix.so" && field[2] == "sufficient") {
                unix++; unix_line = NR
            }
            if (field[1] == "auth" && field[2] == "required" && field[3] == "pam_faillock.so") {
                for (i = 4; i <= count; i++) {
                    if (field[i] == "preauth") { preauth++; preauth_line = NR }
                    if (field[i] == "authfail") { authfail++; authfail_line = NR }
                }
            }
            if (field[1] == "account" && field[2] == "required" && field[3] == "pam_unix.so") {
                account_unix++; account_unix_line = NR
            }
            if (field[1] == "account" && field[2] == "required" && field[3] == "pam_faillock.so") {
                account_lock++; account_lock_line = NR
            }
        }
        END {
            exit !(unix == 1 && unix_any == 1 && preauth == 1 && authfail == 1 &&
                   preauth_line < unix_line && unix_line < authfail_line &&
                   account_lock == 1 && account_unix == 1 && account_lock_line < account_unix_line)
        }
    ' "$1"
}

check() {
    local file
    "${RLCH_CIS_5_3_2_2_AUTHSELECT}" check >/dev/null 2>&1 || return "${RLCH_MODULE_RESULT_ERROR}"
    for file in system-auth password-auth; do
        rlch_5_3_2_2_stack_complete "${RLCH_CIS_5_3_2_2_PAM_DIR}/${file}" ||
            return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    done
    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

apply() {
    local result=0
    check || result=$?
    [[ "${result}" -ne "${RLCH_MODULE_RESULT_SUCCESS}" ]] || return "${RLCH_MODULE_RESULT_SUCCESS}"
    [[ "${result}" -ne "${RLCH_MODULE_RESULT_ERROR}" ]] || return "${RLCH_MODULE_RESULT_ERROR}"
    error_message "CIS 5.3.2.2 requires a reviewed change to the active authselect profile; generated PAM files cannot be edited directly."
    return "${RLCH_MODULE_RESULT_ERROR}"
}

validate() { check; }
rollback() { return "${RLCH_MODULE_RESULT_SUCCESS}"; }
