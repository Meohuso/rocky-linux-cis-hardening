#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
#
# CIS 1.8.5 - Ensure GDM screen locks cannot be overridden.
#
# SPDX-License-Identifier: MIT
#

RLCH_CIS_1_8_5_GDM_PACKAGE="${RLCH_CIS_1_8_5_GDM_PACKAGE:-gdm}"
RLCH_CIS_1_8_5_LOCK_DIR="${RLCH_CIS_1_8_5_LOCK_DIR:-/etc/dconf/db/local.d/locks}"
RLCH_CIS_1_8_5_LOCK_FILE="${RLCH_CIS_1_8_5_LOCK_FILE:-${RLCH_CIS_1_8_5_LOCK_DIR}/00-screensaver}"
RLCH_CIS_1_8_5_STATE_DIR="${RLCH_CIS_1_8_5_STATE_DIR:-/var/lib/rlch/cis/1.8.5}"

cis_1_8_5_gdm_installed() {
    rpm -q "${RLCH_CIS_1_8_5_GDM_PACKAGE}" >/dev/null 2>&1
}

cis_1_8_5_expected_lock() {
    printf '%s\n' \
        '/org/gnome/desktop/session/idle-delay' \
        '/org/gnome/desktop/screensaver/lock-delay'
}

cis_1_8_5_lock_matches() {
    local actual

    if [[ ! -f "${RLCH_CIS_1_8_5_LOCK_FILE}" ]]; then
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi

    if ! actual="$(cat -- "${RLCH_CIS_1_8_5_LOCK_FILE}")"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if [[ "${actual}" == "$(cis_1_8_5_expected_lock)" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
}

cis_1_8_5_backup_state() {
    if [[ -e "${RLCH_CIS_1_8_5_STATE_DIR}/state" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    if ! mkdir -p -- "${RLCH_CIS_1_8_5_STATE_DIR}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if [[ -e "${RLCH_CIS_1_8_5_LOCK_FILE}" ]]; then
        if ! cp -a -- \
            "${RLCH_CIS_1_8_5_LOCK_FILE}" \
            "${RLCH_CIS_1_8_5_STATE_DIR}/lock.backup"; then
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
    else
        if ! : > "${RLCH_CIS_1_8_5_STATE_DIR}/lock.created"; then
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
    fi

    if ! : > "${RLCH_CIS_1_8_5_STATE_DIR}/state"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_CHANGED}"
}

cis_1_8_5_write_lock() {
    local temporary_file

    if ! mkdir -p -- "${RLCH_CIS_1_8_5_LOCK_DIR}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    temporary_file="$(mktemp "${RLCH_CIS_1_8_5_LOCK_DIR}/.rlch-gdm-lock.XXXXXX")" ||
        return "${RLCH_MODULE_RESULT_ERROR}"

    if ! cis_1_8_5_expected_lock > "${temporary_file}"; then
        rm -f -- "${temporary_file}"
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! chmod 0644 -- "${temporary_file}"; then
        rm -f -- "${temporary_file}"
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! chown 0:0 -- "${temporary_file}"; then
        rm -f -- "${temporary_file}"
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! mv -f -- "${temporary_file}" "${RLCH_CIS_1_8_5_LOCK_FILE}"; then
        rm -f -- "${temporary_file}"
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

check() {
    if ! cis_1_8_5_gdm_installed; then
        return "${RLCH_MODULE_RESULT_NOT_APPLICABLE}"
    fi

    cis_1_8_5_lock_matches
}

apply() {
    local result

    check
    result=$?

    if [[ "${result}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ||
          "${result}" -eq "${RLCH_MODULE_RESULT_NOT_APPLICABLE}" ]]; then
        return "${result}"
    fi

    if [[ "${result}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    cis_1_8_5_backup_state
    result=$?

    if [[ "${result}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! cis_1_8_5_write_lock; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! dconf update; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_CHANGED}"
}

validate() {
    check
}

rollback() {
    if [[ ! -e "${RLCH_CIS_1_8_5_STATE_DIR}/state" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    if [[ -e "${RLCH_CIS_1_8_5_STATE_DIR}/lock.backup" ]]; then
        if ! mkdir -p -- "${RLCH_CIS_1_8_5_LOCK_DIR}"; then
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi

        if ! cp -a -- \
            "${RLCH_CIS_1_8_5_STATE_DIR}/lock.backup" \
            "${RLCH_CIS_1_8_5_LOCK_FILE}"; then
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
    elif [[ -e "${RLCH_CIS_1_8_5_STATE_DIR}/lock.created" ]]; then
        if ! rm -f -- "${RLCH_CIS_1_8_5_LOCK_FILE}"; then
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
    fi

    if cis_1_8_5_gdm_installed; then
        if ! dconf update; then
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
    fi

    if ! rm -rf -- "${RLCH_CIS_1_8_5_STATE_DIR}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_CHANGED}"
}
