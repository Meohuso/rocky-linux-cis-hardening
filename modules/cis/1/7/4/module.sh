#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
#
# CIS 1.7.4 - Ensure access to /etc/motd is configured.
#
# SPDX-License-Identifier: MIT
#

RLCH_CIS_1_7_4_MOTD_FILE="${RLCH_CIS_1_7_4_MOTD_FILE:-/etc/motd}"
RLCH_CIS_1_7_4_OWNER="${RLCH_CIS_1_7_4_OWNER:-root}"
RLCH_CIS_1_7_4_GROUP="${RLCH_CIS_1_7_4_GROUP:-root}"
RLCH_CIS_1_7_4_MODE="${RLCH_CIS_1_7_4_MODE:-0644}"
RLCH_CIS_1_7_4_STATE_DIR="${RLCH_CIS_1_7_4_STATE_DIR:-/var/lib/rlch/cis/1.7.4}"
RLCH_CIS_1_7_4_STATE_FILE="${RLCH_CIS_1_7_4_STATE_FILE:-${RLCH_CIS_1_7_4_STATE_DIR}/motd.access}"

cis_1_7_4_get_access() {
    local file="${1:-}"
    local owner
    local group
    local mode

    if [[ -z "${file}" || ! -e "${file}" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! owner="$(stat -c '%U' -- "${file}")"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! group="$(stat -c '%G' -- "${file}")"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! mode="$(stat -c '%a' -- "${file}")"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    printf '%s:%s:%s\n' "${owner}" "${group}" "${mode}"
}

cis_1_7_4_backup_access() {
    local access

    if [[ -e "${RLCH_CIS_1_7_4_STATE_FILE}" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    if ! access="$(cis_1_7_4_get_access "${RLCH_CIS_1_7_4_MOTD_FILE}")"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! mkdir -p -- "${RLCH_CIS_1_7_4_STATE_DIR}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! printf '%s\n' "${access}" > "${RLCH_CIS_1_7_4_STATE_FILE}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! chmod 0600 -- "${RLCH_CIS_1_7_4_STATE_FILE}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_CHANGED}"
}

check() {
    local owner
    local group
    local mode
    local mode_value

    if [[ ! -e "${RLCH_CIS_1_7_4_MOTD_FILE}" ]]; then
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi

    if ! owner="$(stat -c '%U' -- "${RLCH_CIS_1_7_4_MOTD_FILE}")"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! group="$(stat -c '%G' -- "${RLCH_CIS_1_7_4_MOTD_FILE}")"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! mode="$(stat -c '%a' -- "${RLCH_CIS_1_7_4_MOTD_FILE}")"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if [[ "${owner}" != "${RLCH_CIS_1_7_4_OWNER}" ||
          "${group}" != "${RLCH_CIS_1_7_4_GROUP}" ]]; then
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi

    mode_value=$((8#${mode}))

    if (( (mode_value & 0022) != 0 || (mode_value & 0111) != 0 )); then
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi

    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

apply() {
    local result

    check
    result=$?

    if [[ "${result}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    if [[ "${result}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if [[ ! -e "${RLCH_CIS_1_7_4_MOTD_FILE}" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    cis_1_7_4_backup_access
    result=$?

    if [[ "${result}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! chown "${RLCH_CIS_1_7_4_OWNER}:${RLCH_CIS_1_7_4_GROUP}" -- "${RLCH_CIS_1_7_4_MOTD_FILE}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! chmod "${RLCH_CIS_1_7_4_MODE}" -- "${RLCH_CIS_1_7_4_MOTD_FILE}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_CHANGED}"
}

validate() {
    check
}

rollback() {
    local state
    local owner
    local group
    local mode

    if [[ ! -f "${RLCH_CIS_1_7_4_STATE_FILE}" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    if ! IFS= read -r state < "${RLCH_CIS_1_7_4_STATE_FILE}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    IFS=: read -r owner group mode <<< "${state}"

    if [[ -z "${owner}" || -z "${group}" || -z "${mode}" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if [[ ! -e "${RLCH_CIS_1_7_4_MOTD_FILE}" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! chown "${owner}:${group}" -- "${RLCH_CIS_1_7_4_MOTD_FILE}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! chmod "${mode}" -- "${RLCH_CIS_1_7_4_MOTD_FILE}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! rm -f -- "${RLCH_CIS_1_7_4_STATE_FILE}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_CHANGED}"
}
