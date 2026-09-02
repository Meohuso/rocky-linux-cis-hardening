#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
#
# CIS 1.6.1 - Ensure system wide crypto policy is not set to legacy.
#
# SPDX-License-Identifier: MIT
#

RLCH_CIS_1_6_1_TARGET_POLICY="${RLCH_CIS_1_6_1_TARGET_POLICY:-DEFAULT}"

check() {
    crypto_policy_is_legacy
}

apply() {
    local result

    crypto_policy_is_legacy
    result=$?

    if [[ "${result}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    if [[ "${result}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    crypto_policy_set "${RLCH_CIS_1_6_1_TARGET_POLICY}"
}

validate() { check; }

rollback() {
    crypto_policy_rollback
}
