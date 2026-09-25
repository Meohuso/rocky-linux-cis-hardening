#!/usr/bin/env bash
# CIS 5.3.2.1 - Inspect sources of the active authselect profile.
# SPDX-License-Identifier: MIT

RLCH_CIS_5_3_2_1_AUTHSELECT="${RLCH_CIS_5_3_2_1_AUTHSELECT:-authselect}"
RLCH_CIS_5_3_2_1_CONFIG="${RLCH_CIS_5_3_2_1_CONFIG:-/etc/authselect/authselect.conf}"
RLCH_CIS_5_3_2_1_CUSTOM_DIR="${RLCH_CIS_5_3_2_1_CUSTOM_DIR:-/etc/authselect/custom}"
RLCH_CIS_5_3_2_1_DEFAULT_DIR="${RLCH_CIS_5_3_2_1_DEFAULT_DIR:-/usr/share/authselect/default}"

rlch_5_3_2_1_profile_dir() {
    local profile
    IFS= read -r profile < "${RLCH_CIS_5_3_2_1_CONFIG}" || return 1
    case "${profile}" in
        custom/*)
            profile="${profile#custom/}"
            [[ "${profile}" =~ ^[a-zA-Z0-9_-]+$ ]] || return 1
            printf '%s/%s\n' "${RLCH_CIS_5_3_2_1_CUSTOM_DIR}" "${profile}"
            ;;
        *)
            [[ "${profile}" =~ ^[a-zA-Z0-9_-]+$ ]] || return 1
            printf '%s/%s\n' "${RLCH_CIS_5_3_2_1_DEFAULT_DIR}" "${profile}"
            ;;
    esac
}

rlch_5_3_2_1_source_complete() {
    local file="${1:-}"
    [[ -f "${file}" ]] || return 1
    awk '
        /^[[:space:]]*#/ { next }
        {
            for (i = 1; i <= NF; i++) {
                if (i != 3) continue
                if ($1 !~ /^(auth|account|password|session)$/) continue
                if ($i == "pam_pwquality.so") quality = 1
                if ($i == "pam_pwhistory.so") history = 1
                if ($i == "pam_faillock.so") lockout = 1
                if ($i == "pam_unix.so") unix = 1
            }
        }
        END { exit !(quality && history && lockout && unix) }
    ' "${file}"
}

check() {
    local directory file
    [[ -f "${RLCH_CIS_5_3_2_1_CONFIG}" ]] || return "${RLCH_MODULE_RESULT_ERROR}"
    "${RLCH_CIS_5_3_2_1_AUTHSELECT}" check >/dev/null 2>&1 ||
        return "${RLCH_MODULE_RESULT_ERROR}"
    directory="$(rlch_5_3_2_1_profile_dir)" || return "${RLCH_MODULE_RESULT_ERROR}"
    [[ -d "${directory}" ]] || return "${RLCH_MODULE_RESULT_ERROR}"
    for file in system-auth password-auth; do
        rlch_5_3_2_1_source_complete "${directory}/${file}" ||
            return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    done
    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

apply() {
    local result=0
    check || result=$?
    [[ "${result}" -ne "${RLCH_MODULE_RESULT_SUCCESS}" ]] || return "${RLCH_MODULE_RESULT_SUCCESS}"
    [[ "${result}" -ne "${RLCH_MODULE_RESULT_ERROR}" ]] || return "${RLCH_MODULE_RESULT_ERROR}"
    error_message "CIS 5.3.2.1 requires a reviewed authselect profile change; PAM stack order cannot be inferred safely."
    return "${RLCH_MODULE_RESULT_ERROR}"
}

validate() { check; }

rollback() { return "${RLCH_MODULE_RESULT_SUCCESS}"; }
