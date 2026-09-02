#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
# CIS 1.8.6 - Ensure GDM automatic mounting of removable media is disabled.
# SPDX-License-Identifier: MIT
#

RLCH_CIS_1_8_6_GDM_PACKAGE="${RLCH_CIS_1_8_6_GDM_PACKAGE:-gdm}"
RLCH_CIS_1_8_6_PROFILE_FILE="${RLCH_CIS_1_8_6_PROFILE_FILE:-/etc/dconf/profile/user}"
RLCH_CIS_1_8_6_CONFIG_FILE="${RLCH_CIS_1_8_6_CONFIG_FILE:-/etc/dconf/db/local.d/00-media-automount}"
RLCH_CIS_1_8_6_STATE_DIR="${RLCH_CIS_1_8_6_STATE_DIR:-/var/lib/rlch/cis/1.8.6}"

cis_1_8_6_gdm_installed() {
    rpm -q "${RLCH_CIS_1_8_6_GDM_PACKAGE}" >/dev/null 2>&1
}

cis_1_8_6_expected_profile() {
    printf '%s\n' 'user-db:user' 'system-db:local'
}

cis_1_8_6_expected_config() {
    printf '%s\n' \
        '[org/gnome/desktop/media-handling]' \
        'automount=false' \
        'automount-open=false'
}

cis_1_8_6_file_matches() {
    local file="${1:-}" expected="${2:-}" actual
    [[ -f "${file}" ]] || return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    actual="$(cat -- "${file}")" || return "${RLCH_MODULE_RESULT_ERROR}"
    if [[ "${actual}" == "${expected}" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi
    return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
}

cis_1_8_6_save_file() {
    local label="${1:-}" file="${2:-}"
    if [[ -z "${label}" || -z "${file}" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    if [[ -e "${RLCH_CIS_1_8_6_STATE_DIR}/${label}.backup" ||
          -e "${RLCH_CIS_1_8_6_STATE_DIR}/${label}.created" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi
    if [[ -e "${file}" ]]; then
        cp -a -- "${file}" "${RLCH_CIS_1_8_6_STATE_DIR}/${label}.backup" ||
            return "${RLCH_MODULE_RESULT_ERROR}"
    else
        : > "${RLCH_CIS_1_8_6_STATE_DIR}/${label}.created" ||
            return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

cis_1_8_6_backup_state() {
    [[ ! -e "${RLCH_CIS_1_8_6_STATE_DIR}/state" ]] ||
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    mkdir -p -- "${RLCH_CIS_1_8_6_STATE_DIR}" ||
        return "${RLCH_MODULE_RESULT_ERROR}"
    cis_1_8_6_save_file profile "${RLCH_CIS_1_8_6_PROFILE_FILE}" ||
        return "${RLCH_MODULE_RESULT_ERROR}"
    cis_1_8_6_save_file config "${RLCH_CIS_1_8_6_CONFIG_FILE}" ||
        return "${RLCH_MODULE_RESULT_ERROR}"
    : > "${RLCH_CIS_1_8_6_STATE_DIR}/state" ||
        return "${RLCH_MODULE_RESULT_ERROR}"
    return "${RLCH_MODULE_RESULT_CHANGED}"
}

cis_1_8_6_write_file() {
    local file="${1:-}" content="${2:-}" directory temporary_file
    [[ -n "${file}" ]] || return "${RLCH_MODULE_RESULT_ERROR}"
    directory="$(dirname -- "${file}")"
    mkdir -p -- "${directory}" || return "${RLCH_MODULE_RESULT_ERROR}"
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
    cis_1_8_6_gdm_installed || return "${RLCH_MODULE_RESULT_NOT_APPLICABLE}"
    cis_1_8_6_file_matches "${RLCH_CIS_1_8_6_PROFILE_FILE}" "$(cis_1_8_6_expected_profile)"
    result=$?
    [[ "${result}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]] || return "${result}"
    cis_1_8_6_file_matches "${RLCH_CIS_1_8_6_CONFIG_FILE}" "$(cis_1_8_6_expected_config)"
}

apply() {
    local result
    check
    result=$?
    if [[ "${result}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ||
          "${result}" -eq "${RLCH_MODULE_RESULT_NOT_APPLICABLE}" ]]; then
        return "${result}"
    fi
    [[ "${result}" -ne "${RLCH_MODULE_RESULT_ERROR}" ]] ||
        return "${RLCH_MODULE_RESULT_ERROR}"
    cis_1_8_6_backup_state
    result=$?
    [[ "${result}" -ne "${RLCH_MODULE_RESULT_ERROR}" ]] ||
        return "${RLCH_MODULE_RESULT_ERROR}"
    cis_1_8_6_write_file "${RLCH_CIS_1_8_6_PROFILE_FILE}" "$(cis_1_8_6_expected_profile)" ||
        return "${RLCH_MODULE_RESULT_ERROR}"
    cis_1_8_6_write_file "${RLCH_CIS_1_8_6_CONFIG_FILE}" "$(cis_1_8_6_expected_config)" ||
        return "${RLCH_MODULE_RESULT_ERROR}"
    dconf update || return "${RLCH_MODULE_RESULT_ERROR}"
    return "${RLCH_MODULE_RESULT_CHANGED}"
}

validate() { check; }

cis_1_8_6_restore_file() {
    local label="${1:-}" file="${2:-}"
    if [[ -e "${RLCH_CIS_1_8_6_STATE_DIR}/${label}.backup" ]]; then
        mkdir -p -- "$(dirname -- "${file}")" || return "${RLCH_MODULE_RESULT_ERROR}"
        cp -a -- "${RLCH_CIS_1_8_6_STATE_DIR}/${label}.backup" "${file}" ||
            return "${RLCH_MODULE_RESULT_ERROR}"
    elif [[ -e "${RLCH_CIS_1_8_6_STATE_DIR}/${label}.created" ]]; then
        rm -f -- "${file}" || return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

rollback() {
    [[ -e "${RLCH_CIS_1_8_6_STATE_DIR}/state" ]] ||
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    cis_1_8_6_restore_file profile "${RLCH_CIS_1_8_6_PROFILE_FILE}" ||
        return "${RLCH_MODULE_RESULT_ERROR}"
    cis_1_8_6_restore_file config "${RLCH_CIS_1_8_6_CONFIG_FILE}" ||
        return "${RLCH_MODULE_RESULT_ERROR}"
    if cis_1_8_6_gdm_installed; then
        dconf update || return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    rm -rf -- "${RLCH_CIS_1_8_6_STATE_DIR}" ||
        return "${RLCH_MODULE_RESULT_ERROR}"
    return "${RLCH_MODULE_RESULT_CHANGED}"
}
