#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
# CIS 5.1.3 - Ensure permissions on SSH public host key files are configured.
# SPDX-License-Identifier: MIT
#

RLCH_CIS_5_1_3_KEY_DIR="${RLCH_CIS_5_1_3_KEY_DIR:-/etc/ssh}"
RLCH_CIS_5_1_3_OWNER="${RLCH_CIS_5_1_3_OWNER:-0}"
RLCH_CIS_5_1_3_GROUP="${RLCH_CIS_5_1_3_GROUP:-0}"
RLCH_CIS_5_1_3_MODE="${RLCH_CIS_5_1_3_MODE:-0644}"
RLCH_CIS_5_1_3_STATE_DIR="${RLCH_CIS_5_1_3_STATE_DIR:-/var/lib/rlch/cis/5.1.3}"
RLCH_CIS_5_1_3_STATE_FILE="${RLCH_CIS_5_1_3_STATE_FILE:-${RLCH_CIS_5_1_3_STATE_DIR}/access}"
RLCH_CIS_5_1_3_ID_COMMAND="${RLCH_CIS_5_1_3_ID_COMMAND:-id}"

cis_5_1_3_require_root() {
    local effective_uid
    if ! effective_uid="$("${RLCH_CIS_5_1_3_ID_COMMAND}" -u 2>/dev/null)" || [[ "${effective_uid}" != "0" ]]; then
        error_message "CIS 5.1.3 remediation requires root privileges."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

cis_5_1_3_list_keys() {
    [[ -d "${RLCH_CIS_5_1_3_KEY_DIR}" ]] || return 1
    find "${RLCH_CIS_5_1_3_KEY_DIR}" -maxdepth 1 -type f -name '*.pub' -print0
}

cis_5_1_3_read_access() {
    local file="${1:-}" group mode owner
    [[ -f "${file}" ]] || return 1
    owner="$(stat -c '%u' -- "${file}")" &&
        group="$(stat -c '%g' -- "${file}")" &&
        mode="$(stat -c '%a' -- "${file}")" || return 1
    printf '%s:%s:%s\n' "${owner}" "${group}" "${mode}"
}

cis_5_1_3_capture_state() {
    local access file group mode owner temporary_state
    local -a keys=()

    [[ ! -e "${RLCH_CIS_5_1_3_STATE_FILE}" ]] || return "${RLCH_MODULE_RESULT_SUCCESS}"
    mapfile -d '' -t keys < <(cis_5_1_3_list_keys) || return "${RLCH_MODULE_RESULT_ERROR}"
    temporary_state="${RLCH_CIS_5_1_3_STATE_FILE}.tmp.$$"
    if ! mkdir -p -- "${RLCH_CIS_5_1_3_STATE_DIR}" || ! : > "${temporary_state}"; then
        error_message "Unable to initialize CIS 5.1.3 rollback state."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    for file in "${keys[@]}"; do
        if ! access="$(cis_5_1_3_read_access "${file}")"; then
            rm -f -- "${temporary_state}"
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
        IFS=: read -r owner group mode <<< "${access}"
        printf '%s\0%s\0%s\0%s\0' "${file}" "${owner}" "${group}" "${mode}" >> "${temporary_state}" || {
            rm -f -- "${temporary_state}"
            return "${RLCH_MODULE_RESULT_ERROR}"
        }
    done
    if ! chmod 0600 -- "${temporary_state}" || ! mv -- "${temporary_state}" "${RLCH_CIS_5_1_3_STATE_FILE}"; then
        rm -f -- "${temporary_state}"
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

check() {
    local access file group mode mode_value owner
    local -a keys=()

    if [[ ! -d "${RLCH_CIS_5_1_3_KEY_DIR}" ]]; then
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi
    mapfile -d '' -t keys < <(cis_5_1_3_list_keys) || return "${RLCH_MODULE_RESULT_ERROR}"
    [[ "${#keys[@]}" -gt 0 ]] || return "${RLCH_MODULE_RESULT_SUCCESS}"
    for file in "${keys[@]}"; do
        if ! access="$(cis_5_1_3_read_access "${file}")"; then
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
        IFS=: read -r owner group mode <<< "${access}"
        [[ "${mode}" =~ ^[0-7]{3,4}$ ]] || return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
        mode_value=$((8#${mode}))
        if [[ "${owner}" != "${RLCH_CIS_5_1_3_OWNER}" || "${group}" != "${RLCH_CIS_5_1_3_GROUP}" ]] ||
           (( (mode_value & 0133) != 0 )); then
            return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
        fi
    done
    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

apply() {
    local file result=0
    local -a keys=()

    check || result=$?
    [[ "${result}" -ne "${RLCH_MODULE_RESULT_SUCCESS}" ]] || return "${RLCH_MODULE_RESULT_SUCCESS}"
    [[ "${result}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]] || return "${RLCH_MODULE_RESULT_ERROR}"
    if [[ ! -d "${RLCH_CIS_5_1_3_KEY_DIR}" ]]; then
        error_message "Cannot inspect missing SSH directory: ${RLCH_CIS_5_1_3_KEY_DIR}"
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    cis_5_1_3_require_root || return "${RLCH_MODULE_RESULT_ERROR}"
    mapfile -d '' -t keys < <(cis_5_1_3_list_keys) || return "${RLCH_MODULE_RESULT_ERROR}"
    [[ "${#keys[@]}" -gt 0 ]] || return "${RLCH_MODULE_RESULT_SUCCESS}"
    cis_5_1_3_capture_state || return "${RLCH_MODULE_RESULT_ERROR}"

    for file in "${keys[@]}"; do
        if ! chown "${RLCH_CIS_5_1_3_OWNER}:${RLCH_CIS_5_1_3_GROUP}" -- "${file}" ||
           ! chmod "${RLCH_CIS_5_1_3_MODE}" -- "${file}"; then
            error_message "Unable to configure SSH public host key access: ${file}"
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
    done
    check || return "${RLCH_MODULE_RESULT_ERROR}"
    return "${RLCH_MODULE_RESULT_CHANGED}"
}

validate() { check; }

rollback() {
    local file group index mode owner
    local -a state=()

    [[ -e "${RLCH_CIS_5_1_3_STATE_FILE}" ]] || return "${RLCH_MODULE_RESULT_SUCCESS}"
    cis_5_1_3_require_root || return "${RLCH_MODULE_RESULT_ERROR}"
    mapfile -d '' -t state < "${RLCH_CIS_5_1_3_STATE_FILE}"
    if [[ "${#state[@]}" -eq 0 || $(( ${#state[@]} % 4 )) -ne 0 ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    for ((index = 0; index < ${#state[@]}; index += 4)); do
        file="${state[index]}"; owner="${state[index + 1]}"; group="${state[index + 2]}"; mode="${state[index + 3]}"
        if [[ "${file}" != "${RLCH_CIS_5_1_3_KEY_DIR}/"*.pub || ! -f "${file}" ||
              ! "${owner}" =~ ^[0-9]+$ || ! "${group}" =~ ^[0-9]+$ || ! "${mode}" =~ ^[0-7]{3,4}$ ]]; then
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
    done
    for ((index = 0; index < ${#state[@]}; index += 4)); do
        file="${state[index]}"; owner="${state[index + 1]}"; group="${state[index + 2]}"; mode="${state[index + 3]}"
        chown "${owner}:${group}" -- "${file}" && chmod "${mode}" -- "${file}" || return "${RLCH_MODULE_RESULT_ERROR}"
    done
    rm -f -- "${RLCH_CIS_5_1_3_STATE_FILE}" || return "${RLCH_MODULE_RESULT_ERROR}"
    return "${RLCH_MODULE_RESULT_CHANGED}"
}
