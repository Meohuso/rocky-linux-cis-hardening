#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
# CIS 5.1.6 - Ensure sshd MACs are configured.
# SPDX-License-Identifier: MIT
#

RLCH_CIS_5_1_6_SUBPOLICY="${RLCH_CIS_5_1_6_SUBPOLICY:-NO-SSHWEAKMACS}"
RLCH_CIS_5_1_6_MODULE_FILE="${RLCH_CIS_5_1_6_MODULE_FILE:-${RLCH_CRYPTO_POLICY_MODULE_DIR:-/etc/crypto-policies/policies/modules}/NO-SSHWEAKMACS.pmod}"
RLCH_CIS_5_1_6_CURRENT_FILE="${RLCH_CIS_5_1_6_CURRENT_FILE:-${RLCH_CRYPTO_POLICY_CURRENT_FILE:-/etc/crypto-policies/state/CURRENT.pol}}"
RLCH_CIS_5_1_6_STATE_DIR="${RLCH_CIS_5_1_6_STATE_DIR:-/var/lib/rlch/cis/5.1.6}"
RLCH_CIS_5_1_6_POLICY_STATE="${RLCH_CIS_5_1_6_POLICY_STATE:-${RLCH_CIS_5_1_6_STATE_DIR}/crypto-policy.backup}"

cis_5_1_6_weak_macs_are_disabled() {
    local current_file="${1:-}"

    [[ -f "${current_file}" ]] || return "${RLCH_MODULE_RESULT_ERROR}"
    if awk -F= '
        /^[[:space:]]*mac@SSH[[:space:]]*=/ {
            value = toupper($2)
            sub(/[[:space:]]*#.*/, "", value)
            if (value ~ /(^|[[:space:]])(HMAC-MD5[^[:space:]]*|UMAC-(64|128)[^[:space:]]*)([[:space:]]|$)/) found = 1
        }
        END { exit(found ? 0 : 1) }
    ' "${current_file}"; then
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi
    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

check() { cis_5_1_6_weak_macs_are_disabled "${RLCH_CIS_5_1_6_CURRENT_FILE}"; }

apply() {
    local result=0

    check || result=$?
    [[ "${result}" -ne "${RLCH_MODULE_RESULT_SUCCESS}" ]] || return "${RLCH_MODULE_RESULT_SUCCESS}"
    [[ "${result}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]] || return "${RLCH_MODULE_RESULT_ERROR}"
    # shellcheck disable=SC2034 # Select control-specific shared-helper state.
    RLCH_CRYPTO_POLICY_STATE_DIR="${RLCH_CIS_5_1_6_STATE_DIR}"
    # shellcheck disable=SC2034
    RLCH_CRYPTO_POLICY_BACKUP_FILE="${RLCH_CIS_5_1_6_POLICY_STATE}"
    crypto_policy_write_module \
        "${RLCH_CIS_5_1_6_MODULE_FILE}" \
        "# Disable weak MACs for SSH." \
        "mac@SSH = -HMAC-MD5* -UMAC-64* -UMAC-128*" || result=$?
    [[ "${result}" -ne "${RLCH_MODULE_RESULT_ERROR}" ]] || return "${RLCH_MODULE_RESULT_ERROR}"
    result=0
    crypto_policy_add_subpolicy "${RLCH_CIS_5_1_6_SUBPOLICY}" || result=$?
    [[ "${result}" -ne "${RLCH_MODULE_RESULT_ERROR}" ]] || return "${RLCH_MODULE_RESULT_ERROR}"
    check || return "${RLCH_MODULE_RESULT_ERROR}"
    return "${RLCH_MODULE_RESULT_CHANGED}"
}

validate() { check; }

rollback() {
    local changed=false result=0

    # shellcheck disable=SC2034 # Select control-specific shared-helper state.
    RLCH_CRYPTO_POLICY_STATE_DIR="${RLCH_CIS_5_1_6_STATE_DIR}"
    # shellcheck disable=SC2034
    RLCH_CRYPTO_POLICY_BACKUP_FILE="${RLCH_CIS_5_1_6_POLICY_STATE}"
    crypto_policy_rollback || result=$?
    [[ "${result}" -ne "${RLCH_MODULE_RESULT_ERROR}" ]] || return "${RLCH_MODULE_RESULT_ERROR}"
    [[ "${result}" -ne "${RLCH_MODULE_RESULT_CHANGED}" ]] || changed=true
    result=0
    crypto_policy_rollback_module "${RLCH_CIS_5_1_6_MODULE_FILE}" || result=$?
    [[ "${result}" -ne "${RLCH_MODULE_RESULT_ERROR}" ]] || return "${RLCH_MODULE_RESULT_ERROR}"
    [[ "${result}" -ne "${RLCH_MODULE_RESULT_CHANGED}" ]] || changed=true
    [[ "${changed}" == true ]] && return "${RLCH_MODULE_RESULT_CHANGED}"
    return "${RLCH_MODULE_RESULT_SUCCESS}"
}
