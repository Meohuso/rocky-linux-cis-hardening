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

crypto_policy_has_subpolicy() {
    local subpolicy="${1:-}"
    local policy

    if [[ -z "${subpolicy}" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! policy="$(crypto_policy_current)"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    case ":${policy}:" in
        *":${subpolicy}:"*)
            return "${RLCH_MODULE_RESULT_SUCCESS}"
            ;;
    esac

    return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
}

crypto_policy_add_subpolicy() {
    local subpolicy="${1:-}"
    local current_policy

    if [[ -z "${subpolicy}" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if crypto_policy_has_subpolicy "${subpolicy}"; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    if ! current_policy="$(crypto_policy_current)"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    crypto_policy_set "${current_policy}:${subpolicy}"
}

crypto_policy_sha1_is_disabled() {
    local current_file="${1:-${RLCH_CRYPTO_POLICY_CURRENT_FILE}}"
    local sha1_in_certs

    if [[ ! -f "${current_file}" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if grep -Eiq '^[[:space:]]*(hash|sign)[[:space:]]*=[^#]*-SHA1([[:space:]]|$)' "${current_file}"; then
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi

    sha1_in_certs="$(awk -F= '
        /^[[:space:]]*sha1_in_certs[[:space:]]*=/ {
            value = $2
            sub(/[[:space:]]*#.*/, "", value)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
            result = value
        }
        END {
            if (result != "") {
                print result
            }
        }
    ' "${current_file}")"

    if [[ "${sha1_in_certs}" != "0" ]]; then
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi

    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

crypto_policy_weak_macs_are_disabled() {
    local current_file="${1:-${RLCH_CRYPTO_POLICY_CURRENT_FILE}}"

    if [[ ! -f "${current_file}" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if awk -F= '
        /^[[:space:]]*mac[[:space:]]*=/ {
            value = $2
            sub(/[[:space:]]*#.*/, "", value)
            if (value ~ /(^|[[:space:]])[^[:space:]]*-64([^[:space:]]*)?([[:space:]]|$)/) {
                found = 1
            }
        }
        END {
            exit(found ? 0 : 1)
        }
    ' "${current_file}"; then
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi

    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

crypto_policy_ssh_cbc_is_disabled() {
    local current_file="${1:-${RLCH_CRYPTO_POLICY_CURRENT_FILE}}"

    if [[ ! -f "${current_file}" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if awk -F= '
        /^[[:space:]]*cipher@SSH[[:space:]]*=/ {
            value = $2
            sub(/[[:space:]]*#.*/, "", value)
            if (toupper(value) ~ /(^|[[:space:]])[^[:space:]]*CBC([^[:space:]]*)?([[:space:]]|$)/) {
                found = 1
            }
        }
        END {
            exit(found ? 0 : 1)
        }
    ' "${current_file}"; then
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi

    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

crypto_policy_ssh_chacha20_poly1305_is_disabled() {
    local current_file="${1:-${RLCH_CRYPTO_POLICY_CURRENT_FILE}}"

    if [[ ! -f "${current_file}" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if awk -F= '
        /^[[:space:]]*cipher@SSH[[:space:]]*=/ {
            value = toupper($2)
            sub(/[[:space:]]*#.*/, "", value)
            if (value ~ /(^|[[:space:]])CHACHA20-POLY1305([[:space:]]|$)/) {
                found = 1
            }
        }
        END {
            exit(found ? 0 : 1)
        }
    ' "${current_file}"; then
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi

    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

crypto_policy_ssh_etm_is_disabled() {
    local current_file="${1:-${RLCH_CRYPTO_POLICY_CURRENT_FILE}}"
    local etm_value

    if [[ ! -f "${current_file}" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    etm_value="$(awk -F= '
        /^[[:space:]]*etm@SSH[[:space:]]*=/ {
            value = $2
            sub(/[[:space:]]*#.*/, "", value)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
            result = value
        }
        END {
            if (result != "") {
                print result
            }
        }
    ' "${current_file}")"

    if [[ "${etm_value}" != "DISABLE_ETM" ]]; then
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi

    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

crypto_policy_write_module() {
    local file="${1:-}"
    shift || true
    local directory
    local backup_file
    local temporary_file
    local line

    if [[ -z "${file}" || "$#" -eq 0 ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if [[ "$(id -u)" -ne 0 ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    directory="$(dirname -- "${file}")"
    backup_file="${file}${RLCH_CRYPTO_POLICY_BACKUP_SUFFIX}"

    if ! mkdir -p -- "${directory}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    temporary_file="$(mktemp "${directory}/.rlch-crypto-module.XXXXXX")" ||
        return "${RLCH_MODULE_RESULT_ERROR}"

    for line in "$@"; do
        if ! printf '%s\n' "${line}" >> "${temporary_file}"; then
            rm -f -- "${temporary_file}"
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
    done

    if [[ -f "${file}" ]] && cmp -s -- "${temporary_file}" "${file}"; then
        rm -f -- "${temporary_file}"
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    if [[ -f "${file}" && ! -e "${backup_file}" ]]; then
        if ! cp -a -- "${file}" "${backup_file}"; then
            rm -f -- "${temporary_file}"
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
    fi

    if ! chmod 0644 -- "${temporary_file}" ||
       ! chown 0:0 -- "${temporary_file}" ||
       ! mv -f -- "${temporary_file}" "${file}"; then
        rm -f -- "${temporary_file}"
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_CHANGED}"
}

crypto_policy_rollback_module() {
    local file="${1:-}"
    local backup_file

    if [[ -z "${file}" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if [[ "$(id -u)" -ne 0 ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    backup_file="${file}${RLCH_CRYPTO_POLICY_BACKUP_SUFFIX}"

    if [[ -f "${backup_file}" ]]; then
        if ! cp -a -- "${backup_file}" "${file}" ||
           ! rm -f -- "${backup_file}"; then
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi

        return "${RLCH_MODULE_RESULT_CHANGED}"
    fi

    if [[ -f "${file}" ]]; then
        if ! rm -f -- "${file}"; then
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi

        return "${RLCH_MODULE_RESULT_CHANGED}"
    fi

    return "${RLCH_MODULE_RESULT_SUCCESS}"
}
