#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
#
# Reusable GRUB2 helpers.
#
# SPDX-License-Identifier: MIT
#

if [[ -n "${RLCH_GRUB_LOADED:-}" ]]; then
    return 0
fi
readonly RLCH_GRUB_LOADED=1

RLCH_GRUB_CONFIG="${RLCH_GRUB_CONFIG:-/boot/grub2/grub.cfg}"
RLCH_GRUB_USER_CONFIG="${RLCH_GRUB_USER_CONFIG:-/boot/grub2/user.cfg}"
RLCH_GRUB_BACKUP_SUFFIX="${RLCH_GRUB_BACKUP_SUFFIX:-.rlch.bak}"

grub_password_is_configured() {
    local user_config="${1:-${RLCH_GRUB_USER_CONFIG}}"

    if [[ ! -s "${user_config}" ]]; then
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi

    if awk '
        /^[[:space:]]*GRUB2_PASSWORD=grub\.pbkdf2\.sha512\.[^[:space:]]+[[:space:]]*$/ {
            found = 1
        }

        END {
            exit(found ? 0 : 1)
        }
    ' "${user_config}"; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
}

grub_file_access_is_configured() {
    local file="${1:-}"
    local owner
    local group
    local mode

    if [[ -z "${file}" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if [[ ! -e "${file}" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    if ! owner="$(stat -Lc '%U' -- "${file}")" ||
       ! group="$(stat -Lc '%G' -- "${file}")" ||
       ! mode="$(stat -Lc '%a' -- "${file}")"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if [[ "${owner}" == "root" &&
          "${group}" == "root" &&
          "${mode}" == "600" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
}

grub_set_file_access() {
    local file="${1:-}"
    local backup_file

    if [[ -z "${file}" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if [[ ! -e "${file}" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    if [[ "$(id -u)" -ne 0 ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if grub_file_access_is_configured "${file}"; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    backup_file="${file}${RLCH_GRUB_BACKUP_SUFFIX}"

    if [[ ! -e "${backup_file}" ]] &&
       ! cp -a -- "${file}" "${backup_file}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! chown root:root -- "${file}" ||
       ! chmod 0600 -- "${file}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_CHANGED}"
}

grub_rollback_file_access() {
    local file="${1:-}"
    local backup_file

    if [[ -z "${file}" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if [[ "$(id -u)" -ne 0 ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    backup_file="${file}${RLCH_GRUB_BACKUP_SUFFIX}"

    if [[ ! -e "${backup_file}" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    if ! cp -a -- "${backup_file}" "${file}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_CHANGED}"
}
