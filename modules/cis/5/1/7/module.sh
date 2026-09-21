#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
# CIS 5.1.7 - Ensure sshd access is configured.
# SPDX-License-Identifier: MIT
#

RLCH_CIS_5_1_7_CONFIG_ROOT="${RLCH_CIS_5_1_7_CONFIG_ROOT:-/etc/ssh}"

cis_5_1_7_access_inventory() {
    [[ -d "${RLCH_CIS_5_1_7_CONFIG_ROOT}" ]] || return 2
    grep -rEih \
        '^[[:space:]]*(allow|deny)(users|groups)[[:space:]]+[^#[:space:]]+([[:space:]]+[^#[:space:]]+)*([[:space:]]*#.*)?$' \
        "${RLCH_CIS_5_1_7_CONFIG_ROOT}"
}

check() {
    local inventory result=0

    inventory="$(cis_5_1_7_access_inventory 2>/dev/null)" || result=$?
    if [[ "${result}" -eq 2 ]]; then
        error_message "Unable to inspect SSH access directives for CIS 5.1.7."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    if [[ "${result}" -eq 1 || -z "${inventory//[[:space:]]/}" ]]; then
        error_message "CIS 5.1.7 requires an organization-approved AllowUsers, AllowGroups, DenyUsers, or DenyGroups policy."
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi
    printf '%s\n' "CIS 5.1.7 configured SSH access directives:"
    printf '%s\n' "${inventory}"
    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

apply() {
    error_message "CIS 5.1.7 has no generic remediation because SSH account and group policy is organization-specific."
    return "${RLCH_MODULE_RESULT_ERROR}"
}

validate() { check; }

rollback() {
    log_info "CIS 5.1.7 is observation-only; no rollback action is required."
    return "${RLCH_MODULE_RESULT_SUCCESS}"
}
