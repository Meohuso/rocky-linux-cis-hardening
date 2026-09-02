#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
#
# CIS 1.7.3 - Ensure remote login warning banner is configured properly.
#
# SPDX-License-Identifier: MIT
#

RLCH_CIS_1_7_3_ISSUE_NET_FILE="${RLCH_CIS_1_7_3_ISSUE_NET_FILE:-/etc/issue.net}"
RLCH_CIS_1_7_3_OS_RELEASE_FILE="${RLCH_CIS_1_7_3_OS_RELEASE_FILE:-/etc/os-release}"
RLCH_CIS_1_7_3_BANNER="${RLCH_CIS_1_7_3_BANNER:-Authorized users only. All activity may be monitored and reported.}"

cis_1_7_3_os_id() {
    local os_id

    if [[ ! -f "${RLCH_CIS_1_7_3_OS_RELEASE_FILE}" ]]; then
        printf '%s\n' ""
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    os_id="$(awk -F= '
        /^[[:space:]]*ID[[:space:]]*=/ {
            value = $2
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
            gsub(/^"|"$/, "", value)
            print value
            exit
        }
    ' "${RLCH_CIS_1_7_3_OS_RELEASE_FILE}")"

    printf '%s\n' "${os_id}"
}

check() {
    local result
    local os_id

    if [[ ! -f "${RLCH_CIS_1_7_3_ISSUE_NET_FILE}" ]]; then
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi

    if ! os_id="$(cis_1_7_3_os_id)"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    banner_contains_system_information "${RLCH_CIS_1_7_3_ISSUE_NET_FILE}" "${os_id}"
    result=$?

    if [[ "${result}" -ne "${RLCH_MODULE_RESULT_SUCCESS}" ]]; then
        return "${result}"
    fi

    banner_file_matches "${RLCH_CIS_1_7_3_ISSUE_NET_FILE}" "${RLCH_CIS_1_7_3_BANNER}"
}

apply() {
    local result

    check
    result=$?

    if [[ "${result}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    if [[ "${result}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    banner_write_file "${RLCH_CIS_1_7_3_ISSUE_NET_FILE}" "${RLCH_CIS_1_7_3_BANNER}"
}

validate() {
    check
}

rollback() {
    banner_rollback_file "${RLCH_CIS_1_7_3_ISSUE_NET_FILE}"
}
