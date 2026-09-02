#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
#
# CIS 1.6.6 - Ensure system wide crypto policy disables chacha20-poly1305 for ssh.
#
# SPDX-License-Identifier: MIT
#

RLCH_CIS_1_6_6_SUBPOLICY="${RLCH_CIS_1_6_6_SUBPOLICY:-NO-SSHCHACHA20}"
RLCH_CIS_1_6_6_MODULE_FILE="${RLCH_CIS_1_6_6_MODULE_FILE:-${RLCH_CRYPTO_POLICY_MODULE_DIR:-/etc/crypto-policies/policies/modules}/NO-SSHCHACHA20.pmod}"
RLCH_CIS_1_6_6_CURRENT_FILE="${RLCH_CIS_1_6_6_CURRENT_FILE:-${RLCH_CRYPTO_POLICY_CURRENT_FILE:-/etc/crypto-policies/state/CURRENT.pol}}"

check() {
    crypto_policy_ssh_chacha20_poly1305_is_disabled "${RLCH_CIS_1_6_6_CURRENT_FILE}"
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

    crypto_policy_write_module         "${RLCH_CIS_1_6_6_MODULE_FILE}"         "# Disable the ChaCha20-Poly1305 cipher for SSH."         "cipher@SSH = -CHACHA20-POLY1305"
    result=$?

    if [[ "${result}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    if [[ "${result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]]; then
        changed="true"
    fi

    crypto_policy_add_subpolicy "${RLCH_CIS_1_6_6_SUBPOLICY}"
    result=$?

    if [[ "${result}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    if [[ "${result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]]; then
        changed="true"
    fi

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
    if [[ "${result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]]; then
        changed="true"
    fi

    crypto_policy_rollback_module "${RLCH_CIS_1_6_6_MODULE_FILE}"
    result=$?

    if [[ "${result}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    if [[ "${result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]]; then
        changed="true"
    fi

    if [[ "${changed}" == "true" ]]; then
        return "${RLCH_MODULE_RESULT_CHANGED}"
    fi

    return "${RLCH_MODULE_RESULT_SUCCESS}"
}
