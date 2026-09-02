#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
#
# CIS 1.8.4 - Ensure GDM screen locks when the user is idle.
#
# SPDX-License-Identifier: MIT
#

RLCH_CIS_1_8_4_GDM_PACKAGE="${RLCH_CIS_1_8_4_GDM_PACKAGE:-gdm}"
RLCH_CIS_1_8_4_PROFILE_FILE="${RLCH_CIS_1_8_4_PROFILE_FILE:-/etc/dconf/profile/user}"
RLCH_CIS_1_8_4_CONFIG_FILE="${RLCH_CIS_1_8_4_CONFIG_FILE:-/etc/dconf/db/local.d/00-screensaver}"
RLCH_CIS_1_8_4_STATE_DIR="${RLCH_CIS_1_8_4_STATE_DIR:-/var/lib/rlch/cis/1.8.4}"
RLCH_CIS_1_8_4_IDLE_DELAY_SECONDS="${RLCH_CIS_1_8_4_IDLE_DELAY_SECONDS:-900}"
RLCH_CIS_1_8_4_LOCK_DELAY_SECONDS="${RLCH_CIS_1_8_4_LOCK_DELAY_SECONDS:-5}"

cis_1_8_4_gdm_installed() {
    rpm -q "${RLCH_CIS_1_8_4_GDM_PACKAGE}" >/dev/null 2>&1
}

cis_1_8_4_expected_profile() {
    printf '%s\n' \
        'user-db:user' \
        'system-db:local'
}

cis_1_8_4_expected_config() {
    printf '%s\n' \
        '[org/gnome/desktop/session]' \
        "idle-delay=uint32 ${RLCH_CIS_1_8_4_IDLE_DELAY_SECONDS}" \
        '' \
        '[org/gnome/desktop/screensaver]' \
        "lock-delay=uint32 ${RLCH_CIS_1_8_4_LOCK_DELAY_SECONDS}"
}

cis_1_8_4_file_matches() {
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

cis_1_8_4_save_file() {
    local label="${1:-}"
    local file="${2:-}"

    if [[ -z "${label}" || -z "${file}" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if [[ -e "${RLCH_CIS_1_8_4_STATE_DIR}/${label}.backup" ||
          -e "${RLCH_CIS_1_8_4_STATE_DIR}/${label}.created" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    if [[ -e "${file}" ]]; then
        if ! cp -a -- "${file}" "${RLCH_CIS_1_8_4_STATE_DIR}/${label}.backup"; then
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
    else
        if ! : > "${RLCH_CIS_1_8_4_STATE_DIR}/${label}.created"; then
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
    fi

    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

cis_1_8_4_backup_state() {
    if [[ -e "${RLCH_CIS_1_8_4_STATE_DIR}/state" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    if ! mkdir -p -- "${RLCH_CIS_1_8_4_STATE_DIR}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! cis_1_8_4_save_file profile "${RLCH_CIS_1_8_4_PROFILE_FILE}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! cis_1_8_4_save_file config "${RLCH_CIS_1_8_4_CONFIG_FILE}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! : > "${RLCH_CIS_1_8_4_STATE_DIR}/state"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_CHANGED}"
}

cis_1_8_4_write_file() {
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

    if ! cis_1_8_4_gdm_installed; then
        return "${RLCH_MODULE_RESULT_NOT_APPLICABLE}"
    fi

    cis_1_8_4_file_matches \
        "${RLCH_CIS_1_8_4_PROFILE_FILE}" \
        "$(cis_1_8_4_expected_profile)"
    result=$?

    if [[ "${result}" -ne "${RLCH_MODULE_RESULT_SUCCESS}" ]]; then
        return "${result}"
    fi

    cis_1_8_4_file_matches \
        "${RLCH_CIS_1_8_4_CONFIG_FILE}" \
        "$(cis_1_8_4_expected_config)"
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

    cis_1_8_4_backup_state
    result=$?

    if [[ "${result}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! cis_1_8_4_write_file \
        "${RLCH_CIS_1_8_4_PROFILE_FILE}" \
        "$(cis_1_8_4_expected_profile)"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! cis_1_8_4_write_file \
        "${RLCH_CIS_1_8_4_CONFIG_FILE}" \
        "$(cis_1_8_4_expected_config)"; then
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

cis_1_8_4_restore_file() {
    local label="${1:-}"
    local file="${2:-}"
    local backup_file="${RLCH_CIS_1_8_4_STATE_DIR}/${label}.backup"
    local created_file="${RLCH_CIS_1_8_4_STATE_DIR}/${label}.created"

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
    if [[ ! -e "${RLCH_CIS_1_8_4_STATE_DIR}/state" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    if ! cis_1_8_4_restore_file profile "${RLCH_CIS_1_8_4_PROFILE_FILE}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! cis_1_8_4_restore_file config "${RLCH_CIS_1_8_4_CONFIG_FILE}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if cis_1_8_4_gdm_installed; then
        if ! dconf update; then
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
    fi

    if ! rm -rf -- "${RLCH_CIS_1_8_4_STATE_DIR}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_CHANGED}"
}
