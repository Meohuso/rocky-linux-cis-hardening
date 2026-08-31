#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
#
# Reusable cron configuration helpers.
#
# SPDX-License-Identifier: MIT
#

# Prevent multiple sourcing.
if [[ -n "${RLCH_CRON_LOADED:-}" ]]; then
    return 0
fi
readonly RLCH_CRON_LOADED=1

RLCH_CRON_BACKUP_SUFFIX="${RLCH_CRON_BACKUP_SUFFIX:-.rlch.bak}"

cron_file_has_entry() {
    local cron_file="${1:-}"
    local entry="${2:-}"

    if [[ -z "${cron_file}" || -z "${entry}" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if [[ ! -f "${cron_file}" ]]; then
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi

    if grep -Fqx -- "${entry}" "${cron_file}"; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
}

cron_ensure_entry() {
    local cron_file="${1:-}"
    local entry="${2:-}"
    local matching_pattern="${3:-}"
    local backup_file

    if [[ -z "${cron_file}" || -z "${entry}" || -z "${matching_pattern}" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if [[ "$(id -u)" -ne 0 ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if [[ ! -f "${cron_file}" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if cron_file_has_entry "${cron_file}" "${entry}"; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    backup_file="${cron_file}${RLCH_CRON_BACKUP_SUFFIX}"

    if [[ ! -e "${backup_file}" ]]; then
        if ! cp -p -- "${cron_file}" "${backup_file}"; then
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
    fi

    if ! filesystem_replace_line \
        "${cron_file}" \
        "${matching_pattern}" \
        "${entry}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_CHANGED}"
}

cron_rollback_file() {
    local cron_file="${1:-}"
    local backup_file

    if [[ -z "${cron_file}" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if [[ "$(id -u)" -ne 0 ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    backup_file="${cron_file}${RLCH_CRON_BACKUP_SUFFIX}"

    if [[ ! -e "${backup_file}" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    if ! cp -p -- "${backup_file}" "${cron_file}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_CHANGED}"
}
