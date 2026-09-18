#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
# CIS 4.2.1 - Ensure firewalld drops unnecessary services and ports.
# SPDX-License-Identifier: MIT
#

RLCH_CIS_4_2_1_FIREWALL_CMD="${RLCH_CIS_4_2_1_FIREWALL_CMD:-firewall-cmd}"

cis_4_2_1_firewalld_inventory() {
    "${RLCH_CIS_4_2_1_FIREWALL_CMD}" --list-all
}

check() {
    local firewall_inventory

    if ! firewall_inventory="$(cis_4_2_1_firewalld_inventory 2>/dev/null)"; then
        error_message "Unable to inventory firewalld services and ports for CIS 4.2.1."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    printf '%s\n' "CIS 4.2.1 firewalld service and port inventory:"
    printf '%s\n' "${firewall_inventory}"
    error_message "CIS 4.2.1 requires manual comparison with the approved services and ports for this server role."
    return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
}

apply() {
    error_message "CIS 4.2.1 is a manual control; automatic service or port changes are intentionally unsupported."
    return "${RLCH_MODULE_RESULT_ERROR}"
}

validate() {
    check
}

rollback() {
    log_info "CIS 4.2.1 does not modify firewalld; no rollback action is required."
    return "${RLCH_MODULE_RESULT_SUCCESS}"
}
