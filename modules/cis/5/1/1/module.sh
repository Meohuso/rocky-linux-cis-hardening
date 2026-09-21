#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
# CIS 5.1.1 - Ensure permissions on /etc/ssh/sshd_config are configured.
# SPDX-License-Identifier: MIT
#

RLCH_CIS_5_1_1_PATH="${RLCH_CIS_5_1_1_PATH:-/etc/ssh/sshd_config}"
RLCH_CIS_5_1_1_OWNER="${RLCH_CIS_5_1_1_OWNER:-0}"
RLCH_CIS_5_1_1_GROUP="${RLCH_CIS_5_1_1_GROUP:-0}"
RLCH_CIS_5_1_1_MODE="${RLCH_CIS_5_1_1_MODE:-0600}"
RLCH_CIS_5_1_1_STATE_DIR="${RLCH_CIS_5_1_1_STATE_DIR:-/var/lib/rlch/cis/5.1.1}"
RLCH_CIS_5_1_1_STATE_FILE="${RLCH_CIS_5_1_1_STATE_FILE:-${RLCH_CIS_5_1_1_STATE_DIR}/access}"
RLCH_CIS_5_1_1_ID_COMMAND="${RLCH_CIS_5_1_1_ID_COMMAND:-id}"

cis_5_1_1_require_root() {
    local effective_uid

    if ! effective_uid="$("${RLCH_CIS_5_1_1_ID_COMMAND}" -u 2>/dev/null)"; then
        error_message "Unable to determine effective user ID for CIS 5.1.1."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    if [[ "${effective_uid}" != "0" ]]; then
        error_message "CIS 5.1.1 remediation requires root privileges."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

cis_5_1_1_read_access() {
    local group mode owner

    [[ -f "${RLCH_CIS_5_1_1_PATH}" ]] || return 1
    if ! owner="$(stat -c '%u' -- "${RLCH_CIS_5_1_1_PATH}")" ||
       ! group="$(stat -c '%g' -- "${RLCH_CIS_5_1_1_PATH}")" ||
       ! mode="$(stat -c '%a' -- "${RLCH_CIS_5_1_1_PATH}")"; then
        return 1
    fi

    printf '%s:%s:%s\n' "${owner}" "${group}" "${mode}"
}

cis_5_1_1_capture_state() {
    local access temporary_state

    [[ ! -e "${RLCH_CIS_5_1_1_STATE_FILE}" ]] || return "${RLCH_MODULE_RESULT_SUCCESS}"
    temporary_state="${RLCH_CIS_5_1_1_STATE_FILE}.tmp.$$"

    if ! access="$(cis_5_1_1_read_access)" ||
       ! mkdir -p -- "${RLCH_CIS_5_1_1_STATE_DIR}" ||
       ! printf '%s\n' "${access}" > "${temporary_state}" ||
       ! chmod 0600 -- "${temporary_state}" ||
       ! mv -- "${temporary_state}" "${RLCH_CIS_5_1_1_STATE_FILE}"; then
        rm -f -- "${temporary_state}"
        error_message "Unable to record CIS 5.1.1 rollback state."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

check() {
    local access group mode mode_value owner

    if [[ ! -f "${RLCH_CIS_5_1_1_PATH}" ]]; then
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi
    if ! access="$(cis_5_1_1_read_access)"; then
        error_message "Unable to inspect ${RLCH_CIS_5_1_1_PATH} for CIS 5.1.1."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    IFS=: read -r owner group mode <<< "${access}"
    if [[ "${owner}" != "${RLCH_CIS_5_1_1_OWNER}" ||
          "${group}" != "${RLCH_CIS_5_1_1_GROUP}" ||
          ! "${mode}" =~ ^[0-7]{3,4}$ ]]; then
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi
    mode_value=$((8#${mode}))
    if (( (mode_value & 0177) != 0 )); then
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi

    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

apply() {
    local result=0

    check || result=$?
    case "${result}" in
        "${RLCH_MODULE_RESULT_SUCCESS}")
            return "${RLCH_MODULE_RESULT_SUCCESS}"
            ;;
        "${RLCH_MODULE_RESULT_NON_COMPLIANT}")
            ;;
        *)
            return "${RLCH_MODULE_RESULT_ERROR}"
            ;;
    esac
    if [[ ! -f "${RLCH_CIS_5_1_1_PATH}" ]]; then
        error_message "Cannot remediate missing file: ${RLCH_CIS_5_1_1_PATH}"
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    cis_5_1_1_require_root || return "${RLCH_MODULE_RESULT_ERROR}"
    cis_5_1_1_capture_state || return "${RLCH_MODULE_RESULT_ERROR}"

    if ! chown "${RLCH_CIS_5_1_1_OWNER}:${RLCH_CIS_5_1_1_GROUP}" -- "${RLCH_CIS_5_1_1_PATH}" ||
       ! chmod "${RLCH_CIS_5_1_1_MODE}" -- "${RLCH_CIS_5_1_1_PATH}"; then
        error_message "Unable to configure access on ${RLCH_CIS_5_1_1_PATH}."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    if ! check; then
        error_message "${RLCH_CIS_5_1_1_PATH} is not compliant after remediation."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_CHANGED}"
}

validate() {
    check
}

rollback() {
    local group mode owner state

    [[ -e "${RLCH_CIS_5_1_1_STATE_FILE}" ]] || return "${RLCH_MODULE_RESULT_SUCCESS}"
    cis_5_1_1_require_root || return "${RLCH_MODULE_RESULT_ERROR}"
    if ! IFS= read -r state < "${RLCH_CIS_5_1_1_STATE_FILE}"; then
        error_message "Unable to read CIS 5.1.1 rollback state."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    IFS=: read -r owner group mode <<< "${state}"
    if [[ ! "${owner}" =~ ^[0-9]+$ || ! "${group}" =~ ^[0-9]+$ ||
          ! "${mode}" =~ ^[0-7]{3,4}$ || ! -f "${RLCH_CIS_5_1_1_PATH}" ]]; then
        error_message "Invalid CIS 5.1.1 rollback state."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    if ! chown "${owner}:${group}" -- "${RLCH_CIS_5_1_1_PATH}" ||
       ! chmod "${mode}" -- "${RLCH_CIS_5_1_1_PATH}" ||
       ! rm -f -- "${RLCH_CIS_5_1_1_STATE_FILE}"; then
        error_message "Unable to restore access on ${RLCH_CIS_5_1_1_PATH}."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_CHANGED}"
}
