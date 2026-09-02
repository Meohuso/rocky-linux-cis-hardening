#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
#
# CIS 1.8.3 - Ensure GDM disable-user-list option is enabled.
#
# SPDX-License-Identifier: MIT
#

RLCH_CIS_1_8_3_GDM_PACKAGE="${RLCH_CIS_1_8_3_GDM_PACKAGE:-gdm}"
RLCH_CIS_1_8_3_PROFILE_FILE="${RLCH_CIS_1_8_3_PROFILE_FILE:-/etc/dconf/profile/gdm}"
RLCH_CIS_1_8_3_CONFIG_FILE="${RLCH_CIS_1_8_3_CONFIG_FILE:-/etc/dconf/db/gdm.d/00-login-screen}"
RLCH_CIS_1_8_3_LOCK_DIR="${RLCH_CIS_1_8_3_LOCK_DIR:-/etc/dconf/db/gdm.d/locks}"
RLCH_CIS_1_8_3_LOCK_FILE="${RLCH_CIS_1_8_3_LOCK_FILE:-${RLCH_CIS_1_8_3_LOCK_DIR}/00-login-screen}"
RLCH_CIS_1_8_3_STATE_DIR="${RLCH_CIS_1_8_3_STATE_DIR:-/var/lib/rlch/cis/1.8.3}"

cis_1_8_3_gdm_installed() {
    rpm -q "${RLCH_CIS_1_8_3_GDM_PACKAGE}" >/dev/null 2>&1
}

cis_1_8_3_expected_profile() {
    printf '%s\n' \
        'user-db:user' \
        'system-db:gdm' \
        'file-db:/usr/share/gdm/greeter-dconf-defaults'
}

cis_1_8_3_expected_config() {
    printf '%s\n' \
        '[org/gnome/login-screen]' \
        'disable-user-list=true'
}

cis_1_8_3_expected_lock() {
    printf '%s\n' '/org/gnome/login-screen/disable-user-list'
}

cis_1_8_3_file_matches() {
    local file="${1:-}"
    local expected="${2:-}"
    local actual

    if [[ -z "${file}" || ! -f "${file}" ]]; then
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi

    if ! actual="$(cat -- "${file}")"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if [[ "${actual}" == "${expected}" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
}

cis_1_8_3_save_file() {
    local label="${1:-}"
    local file="${2:-}"

    if [[ -z "${label}" || -z "${file}" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if [[ -e "${RLCH_CIS_1_8_3_STATE_DIR}/${label}.backup" ||
          -e "${RLCH_CIS_1_8_3_STATE_DIR}/${label}.created" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    if [[ -e "${file}" ]]; then
        if ! cp -a -- "${file}" "${RLCH_CIS_1_8_3_STATE_DIR}/${label}.backup"; then
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
    else
        if ! : > "${RLCH_CIS_1_8_3_STATE_DIR}/${label}.created"; then
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
    fi

    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

cis_1_8_3_backup_state() {
    if [[ -e "${RLCH_CIS_1_8_3_STATE_DIR}/state" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    if ! mkdir -p -- "${RLCH_CIS_1_8_3_STATE_DIR}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! cis_1_8_3_save_file profile "${RLCH_CIS_1_8_3_PROFILE_FILE}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! cis_1_8_3_save_file config "${RLCH_CIS_1_8_3_CONFIG_FILE}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! cis_1_8_3_save_file lock "${RLCH_CIS_1_8_3_LOCK_FILE}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! : > "${RLCH_CIS_1_8_3_STATE_DIR}/state"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_CHANGED}"
}

cis_1_8_3_write_file() {
    local file="${1:-}"
    local content="${2:-}"
    local directory
    local temporary_file

    if [[ -z "${file}" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    directory="$(dirname -- "${file}")"

    if ! mkdir -p -- "${directory}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    temporary_file="$(mktemp "${directory}/.rlch-gdm.XXXXXX")" ||
        return "${RLCH_MODULE_RESULT_ERROR}"

    if ! printf '%s\n' "${content}" > "${temporary_file}"; then
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

    if ! mv -f -- "${temporary_file}" "${file}"; then
        rm -f -- "${temporary_file}"
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

check() {
    local result

    if ! cis_1_8_3_gdm_installed; then
        return "${RLCH_MODULE_RESULT_NOT_APPLICABLE}"
    fi

    cis_1_8_3_file_matches \
        "${RLCH_CIS_1_8_3_PROFILE_FILE}" \
        "$(cis_1_8_3_expected_profile)"
    result=$?

    if [[ "${result}" -ne "${RLCH_MODULE_RESULT_SUCCESS}" ]]; then
        return "${result}"
    fi

    cis_1_8_3_file_matches \
        "${RLCH_CIS_1_8_3_CONFIG_FILE}" \
        "$(cis_1_8_3_expected_config)"
    result=$?

    if [[ "${result}" -ne "${RLCH_MODULE_RESULT_SUCCESS}" ]]; then
        return "${result}"
    fi

    cis_1_8_3_file_matches \
        "${RLCH_CIS_1_8_3_LOCK_FILE}" \
        "$(cis_1_8_3_expected_lock)"
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

    cis_1_8_3_backup_state
    result=$?

    if [[ "${result}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! cis_1_8_3_write_file \
        "${RLCH_CIS_1_8_3_PROFILE_FILE}" \
        "$(cis_1_8_3_expected_profile)"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! cis_1_8_3_write_file \
        "${RLCH_CIS_1_8_3_CONFIG_FILE}" \
        "$(cis_1_8_3_expected_config)"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! cis_1_8_3_write_file \
        "${RLCH_CIS_1_8_3_LOCK_FILE}" \
        "$(cis_1_8_3_expected_lock)"; then
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

cis_1_8_3_restore_file() {
    local label="${1:-}"
    local file="${2:-}"
    local backup_file="${RLCH_CIS_1_8_3_STATE_DIR}/${label}.backup"
    local created_file="${RLCH_CIS_1_8_3_STATE_DIR}/${label}.created"

    if [[ -e "${backup_file}" ]]; then
        if ! mkdir -p -- "$(dirname -- "${file}")"; then
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi

        if ! cp -a -- "${backup_file}" "${file}"; then
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
    elif [[ -e "${created_file}" ]]; then
        if ! rm -f -- "${file}"; then
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
    fi

    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

rollback() {
    if [[ ! -e "${RLCH_CIS_1_8_3_STATE_DIR}/state" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    if ! cis_1_8_3_restore_file profile "${RLCH_CIS_1_8_3_PROFILE_FILE}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! cis_1_8_3_restore_file config "${RLCH_CIS_1_8_3_CONFIG_FILE}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! cis_1_8_3_restore_file lock "${RLCH_CIS_1_8_3_LOCK_FILE}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if cis_1_8_3_gdm_installed; then
        if ! dconf update; then
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
    fi

    if ! rm -rf -- "${RLCH_CIS_1_8_3_STATE_DIR}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_CHANGED}"
}
