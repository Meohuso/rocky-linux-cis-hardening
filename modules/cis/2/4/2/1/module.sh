#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
# CIS 2.4.2.1 - Ensure at is restricted to authorized users.
# SPDX-License-Identifier: MIT
#

RLCH_CIS_2_4_2_1_ALLOW_FILE="${RLCH_CIS_2_4_2_1_ALLOW_FILE:-/etc/at.allow}"
RLCH_CIS_2_4_2_1_DENY_FILE="${RLCH_CIS_2_4_2_1_DENY_FILE:-/etc/at.deny}"
RLCH_CIS_2_4_2_1_OWNER="${RLCH_CIS_2_4_2_1_OWNER:-0}"
RLCH_CIS_2_4_2_1_GROUP="${RLCH_CIS_2_4_2_1_GROUP:-0}"
RLCH_CIS_2_4_2_1_MODE="${RLCH_CIS_2_4_2_1_MODE:-0640}"
RLCH_CIS_2_4_2_1_STATE_DIR="${RLCH_CIS_2_4_2_1_STATE_DIR:-/var/lib/rlch/cis/2.4.2.1}"
RLCH_CIS_2_4_2_1_STATE_FILE="${RLCH_CIS_2_4_2_1_STATE_FILE:-${RLCH_CIS_2_4_2_1_STATE_DIR}/state}"

cis_2_4_2_1_path_exists() {
    [[ -e "${1:-}" || -L "${1:-}" ]]
}

cis_2_4_2_1_record_file() {
    local path="${1:?Path is required}"
    local label="${2:?Label is required}"
    local target_dir="${3:?Target directory is required}"
    local owner
    local group
    local mode

    if ! cis_2_4_2_1_path_exists "${path}"; then
        printf '%s\n' absent > "${target_dir}/${label}.state"
        return $?
    fi

    if [[ ! -f "${path}" ]] ||
       ! owner="$(stat -c '%u' -- "${path}")" ||
       ! group="$(stat -c '%g' -- "${path}")" ||
       ! mode="$(stat -c '%a' -- "${path}")" ||
       ! cp --dereference -- "${path}" "${target_dir}/${label}.content" ||
       ! printf '%s:%s:%s\n' "${owner}" "${group}" "${mode}" > "${target_dir}/${label}.access" ||
       ! printf '%s\n' present > "${target_dir}/${label}.state"; then
        return 1
    fi

    chmod 0600 -- "${target_dir}/${label}.content" "${target_dir}/${label}.access" "${target_dir}/${label}.state"
}

cis_2_4_2_1_capture_state() {
    local state_parent
    local temporary_dir

    if [[ -e "${RLCH_CIS_2_4_2_1_STATE_FILE}" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi
    if [[ -e "${RLCH_CIS_2_4_2_1_STATE_DIR}" ]]; then
        error_message "Incomplete CIS 2.4.2.1 rollback state already exists."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    state_parent="$(dirname -- "${RLCH_CIS_2_4_2_1_STATE_DIR}")"
    if ! mkdir -p -- "${state_parent}" ||
       ! temporary_dir="$(mktemp -d "${RLCH_CIS_2_4_2_1_STATE_DIR}.tmp.XXXXXX")"; then
        error_message "Unable to create CIS 2.4.2.1 rollback state."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! cis_2_4_2_1_record_file "${RLCH_CIS_2_4_2_1_ALLOW_FILE}" allow "${temporary_dir}" ||
       ! cis_2_4_2_1_record_file "${RLCH_CIS_2_4_2_1_DENY_FILE}" deny "${temporary_dir}" ||
       ! : > "${temporary_dir}/state" ||
       ! chmod 0600 -- "${temporary_dir}/state" ||
       ! mv -- "${temporary_dir}" "${RLCH_CIS_2_4_2_1_STATE_DIR}"; then
        rm -rf -- "${temporary_dir}"
        error_message "Unable to record CIS 2.4.2.1 rollback state."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

cis_2_4_2_1_allow_access_compliant() {
    local owner
    local group
    local mode
    local mode_value

    if [[ ! -f "${RLCH_CIS_2_4_2_1_ALLOW_FILE}" ]] ||
       ! owner="$(stat -c '%u' -- "${RLCH_CIS_2_4_2_1_ALLOW_FILE}")" ||
       ! group="$(stat -c '%g' -- "${RLCH_CIS_2_4_2_1_ALLOW_FILE}")" ||
       ! mode="$(stat -c '%a' -- "${RLCH_CIS_2_4_2_1_ALLOW_FILE}")"; then
        return 1
    fi

    mode_value=$((8#${mode}))
    [[ "${owner}" == "${RLCH_CIS_2_4_2_1_OWNER}" &&
       "${group}" == "${RLCH_CIS_2_4_2_1_GROUP}" ]] &&
        (( (mode_value & 0137) == 0 ))
}

check() {
    if cis_2_4_2_1_path_exists "${RLCH_CIS_2_4_2_1_DENY_FILE}"; then
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi
    if ! cis_2_4_2_1_allow_access_compliant; then
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

    if cis_2_4_2_1_path_exists "${RLCH_CIS_2_4_2_1_DENY_FILE}" &&
       [[ ! -f "${RLCH_CIS_2_4_2_1_DENY_FILE}" ]]; then
        error_message "Cannot safely remove non-file path: ${RLCH_CIS_2_4_2_1_DENY_FILE}"
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    if cis_2_4_2_1_path_exists "${RLCH_CIS_2_4_2_1_ALLOW_FILE}" &&
       [[ ! -f "${RLCH_CIS_2_4_2_1_ALLOW_FILE}" ]]; then
        error_message "Cannot safely configure non-file path: ${RLCH_CIS_2_4_2_1_ALLOW_FILE}"
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    cis_2_4_2_1_capture_state || return "${RLCH_MODULE_RESULT_ERROR}"

    if ! rm -f -- "${RLCH_CIS_2_4_2_1_DENY_FILE}" ||
       ! touch -- "${RLCH_CIS_2_4_2_1_ALLOW_FILE}" ||
       ! chown "${RLCH_CIS_2_4_2_1_OWNER}:${RLCH_CIS_2_4_2_1_GROUP}" -- "${RLCH_CIS_2_4_2_1_ALLOW_FILE}" ||
       ! chmod "${RLCH_CIS_2_4_2_1_MODE}" -- "${RLCH_CIS_2_4_2_1_ALLOW_FILE}"; then
        error_message "Unable to restrict at to authorized users."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! check; then
        error_message "At authorization files are not compliant after remediation."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_CHANGED}"
}

validate() {
    check
}

cis_2_4_2_1_restore_file() {
    local path="${1:?Path is required}"
    local label="${2:?Label is required}"
    local original_state
    local access
    local owner
    local group
    local mode

    if ! IFS= read -r original_state < "${RLCH_CIS_2_4_2_1_STATE_DIR}/${label}.state"; then
        return 1
    fi

    case "${original_state}" in
        absent)
            rm -f -- "${path}"
            ;;
        present)
            if ! IFS= read -r access < "${RLCH_CIS_2_4_2_1_STATE_DIR}/${label}.access"; then
                return 1
            fi
            IFS=: read -r owner group mode <<< "${access}"
            if [[ ! "${owner}" =~ ^[0-9]+$ || ! "${group}" =~ ^[0-9]+$ ||
                  ! "${mode}" =~ ^[0-7]{3,4}$ ]] ||
               [[ ! -f "${RLCH_CIS_2_4_2_1_STATE_DIR}/${label}.content" ]] ||
               ! cp -- "${RLCH_CIS_2_4_2_1_STATE_DIR}/${label}.content" "${path}" ||
               ! chown "${owner}:${group}" -- "${path}" ||
               ! chmod "${mode}" -- "${path}"; then
                return 1
            fi
            ;;
        *)
            return 1
            ;;
    esac
}

rollback() {
    if [[ ! -e "${RLCH_CIS_2_4_2_1_STATE_FILE}" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    if ! cis_2_4_2_1_restore_file "${RLCH_CIS_2_4_2_1_ALLOW_FILE}" allow ||
       ! cis_2_4_2_1_restore_file "${RLCH_CIS_2_4_2_1_DENY_FILE}" deny ||
       ! rm -rf -- "${RLCH_CIS_2_4_2_1_STATE_DIR}"; then
        error_message "Unable to restore the original at authorization files."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_CHANGED}"
}
