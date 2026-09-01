#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
# Reusable AIDE configuration helpers.
# SPDX-License-Identifier: MIT
#

if [[ -n "${RLCH_AIDE_LOADED:-}" ]]; then
    return 0
fi
readonly RLCH_AIDE_LOADED=1

RLCH_AIDE_CONFIG="${RLCH_AIDE_CONFIG:-/etc/aide.conf}"
RLCH_AIDE_CONFIG_BACKUP_SUFFIX="${RLCH_AIDE_CONFIG_BACKUP_SUFFIX:-.rlch.bak}"

aide_rule_is_configured() {
    local path="${1:-}"
    local attributes="${2:-}"
    local config_file="${3:-${RLCH_AIDE_CONFIG}}"

    if [[ -z "${path}" || -z "${attributes}" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if [[ ! -f "${config_file}" ]]; then
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi

    if awk -v path="${path}" -v attributes="${attributes}" '
        $0 !~ /^[[:space:]]*#/ && NF >= 2 && $1 == path && $2 == attributes {
            found = 1
        }
        END { exit(found ? 0 : 1) }
    ' "${config_file}"; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
}

aide_set_rule() {
    local path="${1:-}"
    local attributes="${2:-}"
    local config_file="${3:-${RLCH_AIDE_CONFIG}}"
    local backup_file
    local temporary_file

    if [[ -z "${path}" || -z "${attributes}" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if [[ "$(id -u)" -ne 0 || ! -f "${config_file}" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if aide_rule_is_configured "${path}" "${attributes}" "${config_file}"; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    backup_file="${config_file}${RLCH_AIDE_CONFIG_BACKUP_SUFFIX}"
    if [[ ! -e "${backup_file}" ]] && ! cp -p -- "${config_file}" "${backup_file}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    temporary_file="$(mktemp "${config_file}.XXXXXX")" ||
        return "${RLCH_MODULE_RESULT_ERROR}"

    if ! awk -v path="${path}" -v attributes="${attributes}" '
        BEGIN { written = 0 }
        $0 !~ /^[[:space:]]*#/ && NF >= 1 && $1 == path {
            if (!written) {
                print path " " attributes
                written = 1
            }
            next
        }
        { print }
        END {
            if (!written) {
                print path " " attributes
            }
        }
    ' "${config_file}" > "${temporary_file}"; then
        rm -f -- "${temporary_file}"
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! chmod --reference="${config_file}" "${temporary_file}" ||
       ! chown --reference="${config_file}" "${temporary_file}" ||
       ! mv -f -- "${temporary_file}" "${config_file}"; then
        rm -f -- "${temporary_file}"
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_CHANGED}"
}

aide_rollback_config() {
    local config_file="${1:-${RLCH_AIDE_CONFIG}}"
    local backup_file="${config_file}${RLCH_AIDE_CONFIG_BACKUP_SUFFIX}"

    if [[ "$(id -u)" -ne 0 ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if [[ ! -e "${backup_file}" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    if ! cp -p -- "${backup_file}" "${config_file}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_CHANGED}"
}
