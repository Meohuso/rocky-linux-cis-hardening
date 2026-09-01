#!/usr/bin/env bash
#
# CIS 1.3.3 - Ensure cryptographic mechanisms are used to protect the integrity of audit tools.
# SPDX-License-Identifier: MIT
#

RLCH_CIS_1_3_3_AIDE_CONFIG="${RLCH_CIS_1_3_3_AIDE_CONFIG:-${RLCH_AIDE_CONFIG:-/etc/aide.conf}}"
readonly RLCH_CIS_1_3_3_ATTRIBUTES="p+i+n+u+g+s+b+acl+xattrs+sha512"
readonly RLCH_CIS_1_3_3_AUDIT_TOOLS=(
    "/usr/sbin/auditctl"
    "/usr/sbin/auditd"
    "/usr/sbin/ausearch"
    "/usr/sbin/aureport"
    "/usr/sbin/autrace"
    "/usr/sbin/augenrules"
)

check() {
    local audit_tool

    if ! rpm_package_is_installed "aide"; then
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi

    for audit_tool in "${RLCH_CIS_1_3_3_AUDIT_TOOLS[@]}"; do
        if ! aide_rule_is_configured "${audit_tool}" "${RLCH_CIS_1_3_3_ATTRIBUTES}" "${RLCH_CIS_1_3_3_AIDE_CONFIG}"; then
            return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
        fi
    done

    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

apply() {
    local audit_tool
    local result
    local changed="false"

    if ! rpm_package_is_installed "aide"; then
        error_message "AIDE must be installed before protecting audit tools."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    for audit_tool in "${RLCH_CIS_1_3_3_AUDIT_TOOLS[@]}"; do
        aide_set_rule "${audit_tool}" "${RLCH_CIS_1_3_3_ATTRIBUTES}" "${RLCH_CIS_1_3_3_AIDE_CONFIG}"
        result=$?

        if [[ "${result}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]]; then
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
        if [[ "${result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]]; then
            changed="true"
        fi
    done

    if [[ "${changed}" == "true" ]]; then
        return "${RLCH_MODULE_RESULT_CHANGED}"
    fi
    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

validate() { check; }

rollback() {
    aide_rollback_config "${RLCH_CIS_1_3_3_AIDE_CONFIG}"
}
