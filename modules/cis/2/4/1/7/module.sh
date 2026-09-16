#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
# CIS 2.4.1.7 - Ensure permissions on /etc/cron.d are configured.
# SPDX-License-Identifier: MIT
#

RLCH_CIS_2_4_1_7_PATH="${RLCH_CIS_2_4_1_7_PATH:-/etc/cron.d}"
RLCH_CIS_2_4_1_7_OWNER="${RLCH_CIS_2_4_1_7_OWNER:-0}"
RLCH_CIS_2_4_1_7_GROUP="${RLCH_CIS_2_4_1_7_GROUP:-0}"
RLCH_CIS_2_4_1_7_MODE="${RLCH_CIS_2_4_1_7_MODE:-0700}"
RLCH_CIS_2_4_1_7_STATE_DIR="${RLCH_CIS_2_4_1_7_STATE_DIR:-/var/lib/rlch/cis/2.4.1.7}"
RLCH_CIS_2_4_1_7_STATE_FILE="${RLCH_CIS_2_4_1_7_STATE_FILE:-${RLCH_CIS_2_4_1_7_STATE_DIR}/access}"

cis_2_4_1_7_read_access() {
    local owner
    local group
    local mode

    if [[ ! -e "${RLCH_CIS_2_4_1_7_PATH}" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! owner="$(stat -c '%u' -- "${RLCH_CIS_2_4_1_7_PATH}")" ||
       ! group="$(stat -c '%g' -- "${RLCH_CIS_2_4_1_7_PATH}")" ||
       ! mode="$(stat -c '%a' -- "${RLCH_CIS_2_4_1_7_PATH}")"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    printf '%s:%s:%s\n' "${owner}" "${group}" "${mode}"
}

cis_2_4_1_7_capture_state() {
    local access

    if [[ -e "${RLCH_CIS_2_4_1_7_STATE_FILE}" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    if ! access="$(cis_2_4_1_7_read_access)" ||
       ! mkdir -p -- "${RLCH_CIS_2_4_1_7_STATE_DIR}" ||
       ! printf '%s\n' "${access}" > "${RLCH_CIS_2_4_1_7_STATE_FILE}" ||
       ! chmod 0700 -- "${RLCH_CIS_2_4_1_7_STATE_FILE}"; then
        error_message "Unable to record CIS 2.4.1.7 rollback state."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

check() {
    local access
    local owner
    local group
    local mode
    local mode_value

    if [[ ! -e "${RLCH_CIS_2_4_1_7_PATH}" ]]; then
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi

    if ! access="$(cis_2_4_1_7_read_access)"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    IFS=: read -r owner group mode <<< "${access}"
    if [[ "${owner}" != "${RLCH_CIS_2_4_1_7_OWNER}" ||
          "${group}" != "${RLCH_CIS_2_4_1_7_GROUP}" ]]; then
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi

    mode_value=$((8#${mode}))
    if (( (mode_value & 0077) != 0 )); then
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi

    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

apply() {
    local result=0

    check || result=$?
    if [[ "${result}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi
    if [[ "${result}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    if [[ ! -e "${RLCH_CIS_2_4_1_7_PATH}" ]]; then
        error_message "Cannot remediate missing file: ${RLCH_CIS_2_4_1_7_PATH}"
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    cis_2_4_1_7_capture_state || return "${RLCH_MODULE_RESULT_ERROR}"

    if ! chown "${RLCH_CIS_2_4_1_7_OWNER}:${RLCH_CIS_2_4_1_7_GROUP}" -- "${RLCH_CIS_2_4_1_7_PATH}" ||
       ! chmod "${RLCH_CIS_2_4_1_7_MODE}" -- "${RLCH_CIS_2_4_1_7_PATH}"; then
        error_message "Unable to configure access on ${RLCH_CIS_2_4_1_7_PATH}."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! check; then
        error_message "${RLCH_CIS_2_4_1_7_PATH} is not compliant after remediation."
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

    if [[ ! -e "${RLCH_CIS_2_4_1_7_STATE_FILE}" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    if ! IFS= read -r state < "${RLCH_CIS_2_4_1_7_STATE_FILE}"; then
        error_message "Unable to read CIS 2.4.1.7 rollback state."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    IFS=: read -r owner group mode <<< "${state}"
    if [[ ! "${owner}" =~ ^[0-9]+$ || ! "${group}" =~ ^[0-9]+$ ||
          ! "${mode}" =~ ^[0-7]{3,4}$ || ! -e "${RLCH_CIS_2_4_1_7_PATH}" ]]; then
        error_message "Invalid CIS 2.4.1.7 rollback state."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! chown "${owner}:${group}" -- "${RLCH_CIS_2_4_1_7_PATH}" ||
       ! chmod "${mode}" -- "${RLCH_CIS_2_4_1_7_PATH}" ||
       ! rm -f -- "${RLCH_CIS_2_4_1_7_STATE_FILE}"; then
        error_message "Unable to restore access on ${RLCH_CIS_2_4_1_7_PATH}."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_CHANGED}"
}
