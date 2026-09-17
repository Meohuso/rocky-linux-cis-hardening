#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
# CIS 3.1.2 - Ensure wireless interfaces are disabled.
# SPDX-License-Identifier: MIT
#

RLCH_CIS_3_1_2_SYS_CLASS_NET="${RLCH_CIS_3_1_2_SYS_CLASS_NET:-/sys/class/net}"
RLCH_CIS_3_1_2_NMCLI_COMMAND="${RLCH_CIS_3_1_2_NMCLI_COMMAND:-nmcli}"
RLCH_CIS_3_1_2_ID_COMMAND="${RLCH_CIS_3_1_2_ID_COMMAND:-id}"
RLCH_CIS_3_1_2_STATE_DIR="${RLCH_CIS_3_1_2_STATE_DIR:-/var/lib/rlch/cis/3.1.2}"
RLCH_CIS_3_1_2_STATE_FILE="${RLCH_CIS_3_1_2_STATE_FILE:-${RLCH_CIS_3_1_2_STATE_DIR}/radio.state}"

cis_3_1_2_has_wireless_interface() {
    local wireless_dir

    for wireless_dir in "${RLCH_CIS_3_1_2_SYS_CLASS_NET}"/*/wireless; do
        if [[ -d "${wireless_dir}" ]]; then
            return 0
        fi
    done
    return 1
}

cis_3_1_2_wireless_interfaces_are_down() {
    local disable_file
    local flags
    local flags_value
    local wireless_dir

    for wireless_dir in "${RLCH_CIS_3_1_2_SYS_CLASS_NET}"/*/wireless; do
        [[ -d "${wireless_dir}" ]] || continue
        disable_file="$(dirname -- "${wireless_dir}")/flags"
        if [[ ! -f "${disable_file}" ]] || ! IFS= read -r flags < "${disable_file}" ||
           [[ ! "${flags}" =~ ^0[xX][0-9a-fA-F]+$ ]]; then
            return 2
        fi
        flags_value=$((16#${flags:2}))
        if (( (flags_value & 1) != 0 )); then
            return 1
        fi
    done
    return 0
}

cis_3_1_2_radio_state() {
    local radio="${1:?Radio name is required}"
    local state

    if ! state="$(LC_ALL=C "${RLCH_CIS_3_1_2_NMCLI_COMMAND}" radio "${radio}" 2>/dev/null)"; then
        return 1
    fi
    case "${state}" in
        enabled|disabled)
            printf '%s\n' "${state}"
            ;;
        *)
            return 1
            ;;
    esac
}

cis_3_1_2_require_root() {
    local effective_uid

    if ! effective_uid="$("${RLCH_CIS_3_1_2_ID_COMMAND}" -u 2>/dev/null)"; then
        error_message "Unable to determine the effective user ID for CIS 3.1.2."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    if [[ "${effective_uid}" != 0 ]]; then
        error_message "CIS 3.1.2 remediation requires root privileges."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

cis_3_1_2_capture_state() {
    local state_parent
    local temporary_dir
    local wifi_state
    local wwan_state

    if [[ -f "${RLCH_CIS_3_1_2_STATE_FILE}" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi
    if [[ -e "${RLCH_CIS_3_1_2_STATE_DIR}" ]]; then
        error_message "Incomplete CIS 3.1.2 rollback state already exists."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    if ! wifi_state="$(cis_3_1_2_radio_state wifi)" ||
       ! wwan_state="$(cis_3_1_2_radio_state wwan)"; then
        error_message "Unable to record the NetworkManager radio state for CIS 3.1.2."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    state_parent="$(dirname -- "${RLCH_CIS_3_1_2_STATE_DIR}")"
    if ! mkdir -p -- "${state_parent}" ||
       ! temporary_dir="$(mktemp -d "${RLCH_CIS_3_1_2_STATE_DIR}.tmp.XXXXXX")"; then
        error_message "Unable to create CIS 3.1.2 rollback state."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    if ! printf 'wifi=%s\nwwan=%s\n' "${wifi_state}" "${wwan_state}" > "${temporary_dir}/radio.state" ||
       ! chmod 0600 -- "${temporary_dir}/radio.state" ||
       ! mv -- "${temporary_dir}" "${RLCH_CIS_3_1_2_STATE_DIR}"; then
        rm -rf -- "${temporary_dir}"
        error_message "Unable to save CIS 3.1.2 rollback state."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

check() {
    local result=0

    if ! cis_3_1_2_has_wireless_interface; then
        return "${RLCH_MODULE_RESULT_NOT_APPLICABLE}"
    fi
    cis_3_1_2_wireless_interfaces_are_down || result=$?
    case "${result}" in
        0)
            return "${RLCH_MODULE_RESULT_SUCCESS}"
            ;;
        1)
            return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
            ;;
        *)
            error_message "Unable to inspect wireless interface flags for CIS 3.1.2."
            return "${RLCH_MODULE_RESULT_ERROR}"
            ;;
    esac
}

apply() {
    local result=0

    check || result=$?
    if [[ "${result}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ||
          "${result}" -eq "${RLCH_MODULE_RESULT_NOT_APPLICABLE}" ]]; then
        return "${result}"
    fi
    if [[ "${result}" -ne "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    cis_3_1_2_require_root || return "${RLCH_MODULE_RESULT_ERROR}"
    cis_3_1_2_capture_state || return "${RLCH_MODULE_RESULT_ERROR}"
    if ! LC_ALL=C "${RLCH_CIS_3_1_2_NMCLI_COMMAND}" radio all off >/dev/null 2>&1; then
        error_message "Unable to disable wireless interfaces for CIS 3.1.2."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    if ! check; then
        error_message "Wireless interfaces remain enabled after CIS 3.1.2 remediation."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    return "${RLCH_MODULE_RESULT_CHANGED}"
}

validate() {
    check
}

cis_3_1_2_read_state() {
    local line
    local wifi_state=""
    local wwan_state=""

    while IFS= read -r line; do
        case "${line}" in
            wifi=enabled|wifi=disabled)
                wifi_state="${line#wifi=}"
                ;;
            wwan=enabled|wwan=disabled)
                wwan_state="${line#wwan=}"
                ;;
            *)
                return 1
                ;;
        esac
    done < "${RLCH_CIS_3_1_2_STATE_FILE}" || return 1

    [[ -n "${wifi_state}" && -n "${wwan_state}" ]] || return 1
    printf '%s %s\n' "${wifi_state}" "${wwan_state}"
}

cis_3_1_2_restore_radio() {
    local radio="${1:?Radio name is required}"
    local state="${2:?Radio state is required}"
    local action=off

    if [[ "${state}" == enabled ]]; then
        action=on
    fi
    LC_ALL=C "${RLCH_CIS_3_1_2_NMCLI_COMMAND}" radio "${radio}" "${action}" >/dev/null 2>&1
}

rollback() {
    local current_state
    local saved_state
    local wifi_state
    local wwan_state

    if [[ ! -e "${RLCH_CIS_3_1_2_STATE_DIR}" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi
    if [[ ! -f "${RLCH_CIS_3_1_2_STATE_FILE}" ]] ||
       ! saved_state="$(cis_3_1_2_read_state)"; then
        error_message "CIS 3.1.2 rollback state is missing or invalid."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    read -r wifi_state wwan_state <<< "${saved_state}"

    cis_3_1_2_require_root || return "${RLCH_MODULE_RESULT_ERROR}"
    if ! cis_3_1_2_restore_radio wifi "${wifi_state}" ||
       ! cis_3_1_2_restore_radio wwan "${wwan_state}"; then
        error_message "Unable to restore the NetworkManager radio state for CIS 3.1.2."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    if ! current_state="$(cis_3_1_2_radio_state wifi)" || [[ "${current_state}" != "${wifi_state}" ]] ||
       ! current_state="$(cis_3_1_2_radio_state wwan)" || [[ "${current_state}" != "${wwan_state}" ]]; then
        error_message "NetworkManager radio state was not restored for CIS 3.1.2."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    if ! rm -- "${RLCH_CIS_3_1_2_STATE_FILE}" || ! rmdir -- "${RLCH_CIS_3_1_2_STATE_DIR}"; then
        error_message "Unable to remove completed CIS 3.1.2 rollback state."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    return "${RLCH_MODULE_RESULT_CHANGED}"
}
