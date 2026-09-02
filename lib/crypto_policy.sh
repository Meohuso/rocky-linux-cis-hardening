#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
#
# Reusable system-wide cryptographic policy helpers.
#
# SPDX-License-Identifier: MIT
#

if [[ -n "${RLCH_CRYPTO_POLICY_LOADED:-}" ]]; then
    return 0
fi
readonly RLCH_CRYPTO_POLICY_LOADED=1

RLCH_CRYPTO_POLICY_STATE_DIR="${RLCH_CRYPTO_POLICY_STATE_DIR:-/var/lib/rlch}"
RLCH_CRYPTO_POLICY_BACKUP_FILE="${RLCH_CRYPTO_POLICY_BACKUP_FILE:-${RLCH_CRYPTO_POLICY_STATE_DIR}/crypto-policy.backup}"

crypto_policy_current() {
    local policy

    if ! command -v update-crypto-policies >/dev/null 2>&1; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! policy="$(update-crypto-policies --show 2>/dev/null)"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    policy="${policy#"${policy%%[![:space:]]*}"}"
    policy="${policy%"${policy##*[![:space:]]}"}"

    if [[ -z "${policy}" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    printf '%s\n' "${policy}"
}

crypto_policy_is_legacy() {
    local policy
    local base_policy

    if ! policy="$(crypto_policy_current)"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    base_policy="${policy%%:*}"

    if [[ "${base_policy}" == "LEGACY" ]]; then
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi

    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

crypto_policy_set() {
    local target_policy="${1:-}"
    local current_policy

    if [[ -z "${target_policy}" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if [[ "$(id -u)" -ne 0 ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! current_policy="$(crypto_policy_current)"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if [[ "${current_policy}" == "${target_policy}" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    if ! mkdir -p -- "${RLCH_CRYPTO_POLICY_STATE_DIR}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if [[ ! -e "${RLCH_CRYPTO_POLICY_BACKUP_FILE}" ]]; then
        if ! printf '%s\n' "${current_policy}" > "${RLCH_CRYPTO_POLICY_BACKUP_FILE}"; then
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
        if ! chmod 0600 -- "${RLCH_CRYPTO_POLICY_BACKUP_FILE}"; then
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
    fi

    if ! update-crypto-policies --set "${target_policy}" >/dev/null 2>&1; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_CHANGED}"
}

crypto_policy_rollback() {
    local previous_policy
    local current_policy

    if [[ "$(id -u)" -ne 0 ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if [[ ! -f "${RLCH_CRYPTO_POLICY_BACKUP_FILE}" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    if ! IFS= read -r previous_policy < "${RLCH_CRYPTO_POLICY_BACKUP_FILE}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if [[ -z "${previous_policy}" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! current_policy="$(crypto_policy_current)"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if [[ "${current_policy}" != "${previous_policy}" ]]; then
        if ! update-crypto-policies --set "${previous_policy}" >/dev/null 2>&1; then
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
    fi

    if ! rm -f -- "${RLCH_CRYPTO_POLICY_BACKUP_FILE}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_CHANGED}"
}
