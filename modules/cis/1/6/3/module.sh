#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
#
# CIS 1.6.3 - Ensure system wide crypto policy disables sha1 hash and signature support.
#
# SPDX-License-Identifier: MIT
#

RLCH_CIS_1_6_3_SUBPOLICY="${RLCH_CIS_1_6_3_SUBPOLICY:-NO-SHA1}"
RLCH_CIS_1_6_3_MODULE_FILE="${RLCH_CIS_1_6_3_MODULE_FILE:-${RLCH_CRYPTO_POLICY_MODULE_DIR:-/etc/crypto-policies/policies/modules}/NO-SHA1.pmod}"
RLCH_CIS_1_6_3_CURRENT_FILE="${RLCH_CIS_1_6_3_CURRENT_FILE:-${RLCH_CRYPTO_POLICY_CURRENT_FILE:-/etc/crypto-policies/state/CURRENT.pol}}"

check() {
    crypto_policy_sha1_is_disabled "${RLCH_CIS_1_6_3_CURRENT_FILE}"
}

apply() {
    local result
    local changed="false"

    check
    result=$?

    if [[ "${result}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    if [[ "${result}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    crypto_policy_write_module \
        "${RLCH_CIS_1_6_3_MODULE_FILE}" \
        "# Disable SHA-1 hash and signature support." \
        "hash = -SHA1" \
        "sign = -*-SHA1" \
        "sha1_in_certs = 0"
    result=$?

    if [[ "${result}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    [[ "${result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]] && changed="true"

    crypto_policy_add_subpolicy "${RLCH_CIS_1_6_3_SUBPOLICY}"
    result=$?

    if [[ "${result}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    [[ "${result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]] && changed="true"

    if [[ "${changed}" == "true" ]]; then
        return "${RLCH_MODULE_RESULT_CHANGED}"
    fi

    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

validate() {
    check
}

rollback() {
    local result
    local changed="false"

    crypto_policy_rollback
    result=$?

    if [[ "${result}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    [[ "${result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]] && changed="true"

    crypto_policy_rollback_module "${RLCH_CIS_1_6_3_MODULE_FILE}"
    result=$?

    if [[ "${result}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    [[ "${result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]] && changed="true"

    if [[ "${changed}" == "true" ]]; then
        return "${RLCH_MODULE_RESULT_CHANGED}"
    fi

    return "${RLCH_MODULE_RESULT_SUCCESS}"
}
