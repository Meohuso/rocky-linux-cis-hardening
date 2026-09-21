#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
# CIS 5.1.5 - Ensure sshd KexAlgorithms is configured.
# SPDX-License-Identifier: MIT
#

RLCH_CIS_5_1_5_SUBPOLICY="${RLCH_CIS_5_1_5_SUBPOLICY:-NO-SHA1}"
RLCH_CIS_5_1_5_CURRENT_FILE="${RLCH_CIS_5_1_5_CURRENT_FILE:-${RLCH_CRYPTO_POLICY_CURRENT_FILE:-/etc/crypto-policies/state/CURRENT.pol}}"
RLCH_CIS_5_1_5_STATE_DIR="${RLCH_CIS_5_1_5_STATE_DIR:-/var/lib/rlch/cis/5.1.5}"
RLCH_CIS_5_1_5_POLICY_STATE="${RLCH_CIS_5_1_5_POLICY_STATE:-${RLCH_CIS_5_1_5_STATE_DIR}/crypto-policy.backup}"

cis_5_1_5_sha1_hash_is_disabled() {
    local current_file="${1:-}" hash_value

    [[ -f "${current_file}" ]] || return "${RLCH_MODULE_RESULT_ERROR}"
    hash_value="$(awk -F= '
        /^[[:space:]]*hash(@SSH)?[[:space:]]*=/ {
            value = $2
            sub(/[[:space:]]*#.*/, "", value)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
            result = value
        }
        END { if (result != "") print result }
    ' "${current_file}")"
    [[ -n "${hash_value}" ]] || return "${RLCH_MODULE_RESULT_ERROR}"
    if [[ " ${hash_value^^} " == *" SHA1 "* ]]; then
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi
    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

check() { cis_5_1_5_sha1_hash_is_disabled "${RLCH_CIS_5_1_5_CURRENT_FILE}"; }

apply() {
    local result=0

    check || result=$?
    [[ "${result}" -ne "${RLCH_MODULE_RESULT_SUCCESS}" ]] || return "${RLCH_MODULE_RESULT_SUCCESS}"
    [[ "${result}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]] || return "${RLCH_MODULE_RESULT_ERROR}"

    # These globals select control-specific state for the shared helper.
    # shellcheck disable=SC2034
    RLCH_CRYPTO_POLICY_STATE_DIR="${RLCH_CIS_5_1_5_STATE_DIR}"
    # shellcheck disable=SC2034
    RLCH_CRYPTO_POLICY_BACKUP_FILE="${RLCH_CIS_5_1_5_POLICY_STATE}"
    crypto_policy_add_subpolicy "${RLCH_CIS_5_1_5_SUBPOLICY}" || result=$?
    [[ "${result}" -ne "${RLCH_MODULE_RESULT_ERROR}" ]] || return "${RLCH_MODULE_RESULT_ERROR}"
    check || return "${RLCH_MODULE_RESULT_ERROR}"
    return "${RLCH_MODULE_RESULT_CHANGED}"
}

validate() { check; }

rollback() {
    # These globals select control-specific state for the shared helper.
    # shellcheck disable=SC2034
    RLCH_CRYPTO_POLICY_STATE_DIR="${RLCH_CIS_5_1_5_STATE_DIR}"
    # shellcheck disable=SC2034
    RLCH_CRYPTO_POLICY_BACKUP_FILE="${RLCH_CIS_5_1_5_POLICY_STATE}"
    crypto_policy_rollback
}
