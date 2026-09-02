#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
#
# Reusable warning banner helpers.
#
# SPDX-License-Identifier: MIT
#

if [[ -n "${RLCH_BANNER_LOADED:-}" ]]; then
    return 0
fi
readonly RLCH_BANNER_LOADED=1

RLCH_BANNER_BACKUP_SUFFIX="${RLCH_BANNER_BACKUP_SUFFIX:-.rlch.bak}"

banner_contains_system_information() {
    local file="${1:-}"
    local os_id="${2:-}"

    if [[ -z "${file}" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if [[ ! -f "${file}" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    if grep -Eiq '\\[mrsv]' "${file}"; then
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi

    if [[ -n "${os_id}" ]] && grep -Fqi -- "${os_id}" "${file}"; then
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi

    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

banner_file_matches() {
    local file="${1:-}"
    local expected_content="${2:-}"
    local actual_content

    if [[ -z "${file}" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if [[ ! -f "${file}" ]]; then
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi

    if ! actual_content="$(cat -- "${file}")"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if [[ "${actual_content}" == "${expected_content}" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
}

banner_write_file() {
    local file="${1:-}"
    local content="${2:-}"
    local directory
    local backup_file
    local temporary_file

    if [[ -z "${file}" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if [[ "$(id -u)" -ne 0 ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if banner_file_matches "${file}" "${content}"; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    directory="$(dirname -- "${file}")"
    backup_file="${file}${RLCH_BANNER_BACKUP_SUFFIX}"

    if ! mkdir -p -- "${directory}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if [[ -e "${file}" && ! -e "${backup_file}" ]]; then
        if ! cp -a -- "${file}" "${backup_file}"; then
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
    fi

    temporary_file="$(mktemp "${directory}/.rlch-banner.XXXXXX")" ||
        return "${RLCH_MODULE_RESULT_ERROR}"

    if ! printf '%s\n' "${content}" > "${temporary_file}"; then
        rm -f -- "${temporary_file}"
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! chmod 0644 -- "${temporary_file}" ||
       ! chown 0:0 -- "${temporary_file}" ||
       ! mv -f -- "${temporary_file}" "${file}"; then
        rm -f -- "${temporary_file}"
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_CHANGED}"
}

banner_rollback_file() {
    local file="${1:-}"
    local backup_file

    if [[ -z "${file}" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if [[ "$(id -u)" -ne 0 ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    backup_file="${file}${RLCH_BANNER_BACKUP_SUFFIX}"

    if [[ -e "${backup_file}" ]]; then
        if ! cp -a -- "${backup_file}" "${file}" ||
           ! rm -f -- "${backup_file}"; then
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi

        return "${RLCH_MODULE_RESULT_CHANGED}"
    fi

    return "${RLCH_MODULE_RESULT_SUCCESS}"
}
