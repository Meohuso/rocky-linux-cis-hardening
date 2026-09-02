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
RLCH_CRYPTO_POLICY_MODULE_DIR="${RLCH_CRYPTO_POLICY_MODULE_DIR:-/etc/crypto-policies/policies/modules}"
RLCH_CRYPTO_POLICY_CURRENT_FILE="${RLCH_CRYPTO_POLICY_CURRENT_FILE:-/etc/crypto-policies/state/CURRENT.pol}"
RLCH_CRYPTO_POLICY_BACKUP_SUFFIX="${RLCH_CRYPTO_POLICY_BACKUP_SUFFIX:-.rlch.bak}"

crypto_policy_current() {
    local policy
    command -v update-crypto-policies >/dev/null 2>&1 || return "${RLCH_MODULE_RESULT_ERROR}"
    policy="$(update-crypto-policies --show 2>/dev/null)" || return "${RLCH_MODULE_RESULT_ERROR}"
    policy="${policy#"${policy%%[![:space:]]*}"}"
    policy="${policy%"${policy##*[![:space:]]}"}"
    [[ -n "${policy}" ]] || return "${RLCH_MODULE_RESULT_ERROR}"
    printf '%s\n' "${policy}"
}

crypto_policy_is_legacy() {
    local policy
    policy="$(crypto_policy_current)" || return "${RLCH_MODULE_RESULT_ERROR}"
    [[ "${policy%%:*}" != "LEGACY" ]] || return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

crypto_policy_set() {
    local target_policy="${1:-}"
    local current_policy
    [[ -n "${target_policy}" ]] || return "${RLCH_MODULE_RESULT_ERROR}"
    [[ "$(id -u)" -eq 0 ]] || return "${RLCH_MODULE_RESULT_ERROR}"
    current_policy="$(crypto_policy_current)" || return "${RLCH_MODULE_RESULT_ERROR}"
    [[ "${current_policy}" != "${target_policy}" ]] || return "${RLCH_MODULE_RESULT_SUCCESS}"
    mkdir -p -- "${RLCH_CRYPTO_POLICY_STATE_DIR}" || return "${RLCH_MODULE_RESULT_ERROR}"
    if [[ ! -e "${RLCH_CRYPTO_POLICY_BACKUP_FILE}" ]]; then
        printf '%s\n' "${current_policy}" > "${RLCH_CRYPTO_POLICY_BACKUP_FILE}" || return "${RLCH_MODULE_RESULT_ERROR}"
        chmod 0600 -- "${RLCH_CRYPTO_POLICY_BACKUP_FILE}" || return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    update-crypto-policies --set "${target_policy}" >/dev/null 2>&1 || return "${RLCH_MODULE_RESULT_ERROR}"
    return "${RLCH_MODULE_RESULT_CHANGED}"
}

crypto_policy_rollback() {
    local previous_policy
    local current_policy
    [[ "$(id -u)" -eq 0 ]] || return "${RLCH_MODULE_RESULT_ERROR}"
    [[ -f "${RLCH_CRYPTO_POLICY_BACKUP_FILE}" ]] || return "${RLCH_MODULE_RESULT_SUCCESS}"
    IFS= read -r previous_policy < "${RLCH_CRYPTO_POLICY_BACKUP_FILE}" || return "${RLCH_MODULE_RESULT_ERROR}"
    [[ -n "${previous_policy}" ]] || return "${RLCH_MODULE_RESULT_ERROR}"
    current_policy="$(crypto_policy_current)" || return "${RLCH_MODULE_RESULT_ERROR}"
    if [[ "${current_policy}" != "${previous_policy}" ]]; then
        update-crypto-policies --set "${previous_policy}" >/dev/null 2>&1 || return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    rm -f -- "${RLCH_CRYPTO_POLICY_BACKUP_FILE}" || return "${RLCH_MODULE_RESULT_ERROR}"
    return "${RLCH_MODULE_RESULT_CHANGED}"
}

crypto_policy_has_subpolicy() {
    local subpolicy="${1:-}"
    local policy
    [[ -n "${subpolicy}" ]] || return "${RLCH_MODULE_RESULT_ERROR}"
    policy="$(crypto_policy_current)" || return "${RLCH_MODULE_RESULT_ERROR}"
    case ":${policy}:" in
        *":${subpolicy}:"*) return "${RLCH_MODULE_RESULT_SUCCESS}" ;;
    esac
    return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
}

crypto_policy_add_subpolicy() {
    local subpolicy="${1:-}"
    local current_policy
    [[ -n "${subpolicy}" ]] || return "${RLCH_MODULE_RESULT_ERROR}"
    if crypto_policy_has_subpolicy "${subpolicy}"; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi
    current_policy="$(crypto_policy_current)" || return "${RLCH_MODULE_RESULT_ERROR}"
    crypto_policy_set "${current_policy}:${subpolicy}"
}

crypto_policy_sha1_is_disabled() {
    local current_file="${1:-${RLCH_CRYPTO_POLICY_CURRENT_FILE}}"
    local sha1_in_certs
    [[ -f "${current_file}" ]] || return "${RLCH_MODULE_RESULT_ERROR}"
    if grep -Eiq '^[[:space:]]*(hash|sign)[[:space:]]*=[^#]*-SHA1([[:space:]]|$)' "${current_file}"; then
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi
    sha1_in_certs="$(awk -F= '/^[[:space:]]*sha1_in_certs[[:space:]]*=/ { value=$2; sub(/[[:space:]]*#.*/, "", value); gsub(/^[[:space:]]+|[[:space:]]+$/, "", value); result=value } END { if (result != "") print result }' "${current_file}")"
    [[ "${sha1_in_certs}" == "0" ]] || return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

crypto_policy_write_module() {
    local file="${1:-}"
    shift || true
    local directory backup_file temporary_file line
    [[ -n "${file}" && "$#" -gt 0 ]] || return "${RLCH_MODULE_RESULT_ERROR}"
    [[ "$(id -u)" -eq 0 ]] || return "${RLCH_MODULE_RESULT_ERROR}"
    directory="$(dirname -- "${file}")"
    backup_file="${file}${RLCH_CRYPTO_POLICY_BACKUP_SUFFIX}"
    mkdir -p -- "${directory}" || return "${RLCH_MODULE_RESULT_ERROR}"
    temporary_file="$(mktemp "${directory}/.rlch-crypto-module.XXXXXX")" || return "${RLCH_MODULE_RESULT_ERROR}"
    for line in "$@"; do
        printf '%s\n' "${line}" >> "${temporary_file}" || { rm -f -- "${temporary_file}"; return "${RLCH_MODULE_RESULT_ERROR}"; }
    done
    if [[ -f "${file}" ]] && cmp -s -- "${temporary_file}" "${file}"; then
        rm -f -- "${temporary_file}"
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi
    if [[ -f "${file}" && ! -e "${backup_file}" ]]; then
        cp -a -- "${file}" "${backup_file}" || { rm -f -- "${temporary_file}"; return "${RLCH_MODULE_RESULT_ERROR}"; }
    fi
    chmod 0644 -- "${temporary_file}" && chown 0:0 -- "${temporary_file}" && mv -f -- "${temporary_file}" "${file}" || { rm -f -- "${temporary_file}"; return "${RLCH_MODULE_RESULT_ERROR}"; }
    return "${RLCH_MODULE_RESULT_CHANGED}"
}

crypto_policy_rollback_module() {
    local file="${1:-}"
    local backup_file
    [[ -n "${file}" ]] || return "${RLCH_MODULE_RESULT_ERROR}"
    [[ "$(id -u)" -eq 0 ]] || return "${RLCH_MODULE_RESULT_ERROR}"
    backup_file="${file}${RLCH_CRYPTO_POLICY_BACKUP_SUFFIX}"
    if [[ -f "${backup_file}" ]]; then
        cp -a -- "${backup_file}" "${file}" && rm -f -- "${backup_file}" || return "${RLCH_MODULE_RESULT_ERROR}"
        return "${RLCH_MODULE_RESULT_CHANGED}"
    fi
    if [[ -f "${file}" ]]; then
        rm -f -- "${file}" || return "${RLCH_MODULE_RESULT_ERROR}"
        return "${RLCH_MODULE_RESULT_CHANGED}"
    fi
    return "${RLCH_MODULE_RESULT_SUCCESS}"
}
