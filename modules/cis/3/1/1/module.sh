#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
# CIS 3.1.1 - Ensure IPv6 status is identified.
# SPDX-License-Identifier: MIT
#

RLCH_CIS_3_1_1_IPV6_DISABLE_FILE="${RLCH_CIS_3_1_1_IPV6_DISABLE_FILE:-/sys/module/ipv6/parameters/disable}"

cis_3_1_1_ipv6_status() {
    local disable_value

    if [[ ! -e "${RLCH_CIS_3_1_1_IPV6_DISABLE_FILE}" ]]; then
        printf '%s\n' "disabled (IPv6 kernel support is unavailable)"
        return 0
    fi
    if [[ ! -f "${RLCH_CIS_3_1_1_IPV6_DISABLE_FILE}" ]] ||
       ! IFS= read -r disable_value < "${RLCH_CIS_3_1_1_IPV6_DISABLE_FILE}"; then
        return 1
    fi

    case "${disable_value}" in
        0|N|n)
            printf '%s\n' enabled
            ;;
        1|Y|y)
            printf '%s\n' disabled
            ;;
        *)
            return 1
            ;;
    esac
}

check() {
    local ipv6_status

    if ! ipv6_status="$(cis_3_1_1_ipv6_status)"; then
        error_message "Unable to identify the IPv6 status for CIS 3.1.1."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    printf 'CIS 3.1.1 IPv6 status: %s\n' "${ipv6_status}"
    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

apply() {
    error_message "CIS 3.1.1 is an observation-only manual control; changing IPv6 policy is intentionally unsupported."
    return "${RLCH_MODULE_RESULT_ERROR}"
}

validate() {
    check
}

rollback() {
    log_info "CIS 3.1.1 does not modify the system; no rollback action is required."
    return "${RLCH_MODULE_RESULT_SUCCESS}"
}
