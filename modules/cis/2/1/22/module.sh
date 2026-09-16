#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
# CIS 2.1.22 - Ensure only approved services are listening on a network interface.
# SPDX-License-Identifier: MIT
#

RLCH_CIS_2_1_22_SS_COMMAND="${RLCH_CIS_2_1_22_SS_COMMAND:-ss}"

cis_2_1_22_list_listeners() {
    "${RLCH_CIS_2_1_22_SS_COMMAND}" -plntuH
}

check() {
    local listener_inventory

    if ! listener_inventory="$(cis_2_1_22_list_listeners 2>/dev/null)"; then
        error_message "Unable to inventory listening network services for CIS 2.1.22."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if [[ -z "${listener_inventory//[[:space:]]/}" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    printf '%s\n' "CIS 2.1.22 listening network service inventory:"
    printf '%s\n' "${listener_inventory}"
    error_message "CIS 2.1.22 requires manual comparison with the organization's approved service baseline."

    return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
}

apply() {
    error_message "CIS 2.1.22 is a manual control; automatic service shutdown or removal is intentionally unsupported."
    return "${RLCH_MODULE_RESULT_ERROR}"
}

validate() {
    check
}

rollback() {
    log_info "CIS 2.1.22 does not modify the system; no rollback action is required."
    return "${RLCH_MODULE_RESULT_SUCCESS}"
}
