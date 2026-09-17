#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
# CIS 3.1.3 - Ensure bluetooth services are not in use.
# SPDX-License-Identifier: MIT
#

RLCH_CIS_3_1_3_PACKAGE="${RLCH_CIS_3_1_3_PACKAGE:-bluez}"
RLCH_CIS_3_1_3_SERVICE="${RLCH_CIS_3_1_3_SERVICE:-bluetooth.service}"
RLCH_CIS_3_1_3_RPM_COMMAND="${RLCH_CIS_3_1_3_RPM_COMMAND:-rpm}"
RLCH_CIS_3_1_3_SYSTEMCTL_COMMAND="${RLCH_CIS_3_1_3_SYSTEMCTL_COMMAND:-systemctl}"
RLCH_CIS_3_1_3_ID_COMMAND="${RLCH_CIS_3_1_3_ID_COMMAND:-id}"
RLCH_CIS_3_1_3_STATE_DIR="${RLCH_CIS_3_1_3_STATE_DIR:-/var/lib/rlch/cis/3.1.3}"
RLCH_CIS_3_1_3_STATE_FILE="${RLCH_CIS_3_1_3_STATE_FILE:-${RLCH_CIS_3_1_3_STATE_DIR}/service.state}"

cis_3_1_3_package_installed() {
    "${RLCH_CIS_3_1_3_RPM_COMMAND}" -q "${RLCH_CIS_3_1_3_PACKAGE}" >/dev/null 2>&1
}

cis_3_1_3_active_state() {
    local state

    state="$(LC_ALL=C "${RLCH_CIS_3_1_3_SYSTEMCTL_COMMAND}" is-active "${RLCH_CIS_3_1_3_SERVICE}" 2>/dev/null || true)"
    case "${state}" in
        active|inactive)
            printf '%s\n' "${state}"
            ;;
        *)
            return 1
            ;;
    esac
}

cis_3_1_3_enabled_state() {
    local state

    state="$(LC_ALL=C "${RLCH_CIS_3_1_3_SYSTEMCTL_COMMAND}" is-enabled "${RLCH_CIS_3_1_3_SERVICE}" 2>/dev/null || true)"
    case "${state}" in
        enabled|enabled-runtime|disabled|masked|masked-runtime|static|indirect)
            printf '%s\n' "${state}"
            ;;
        *)
            return 1
            ;;
    esac
}

cis_3_1_3_require_root() {
    local effective_uid

    if ! effective_uid="$("${RLCH_CIS_3_1_3_ID_COMMAND}" -u 2>/dev/null)"; then
        error_message "Unable to determine the effective user ID for CIS 3.1.3."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    if [[ "${effective_uid}" != 0 ]]; then
        error_message "CIS 3.1.3 remediation requires root privileges."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

cis_3_1_3_capture_state() {
    local active_state
    local enabled_state
    local state_parent
    local temporary_dir

    if [[ -f "${RLCH_CIS_3_1_3_STATE_FILE}" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi
    if [[ -e "${RLCH_CIS_3_1_3_STATE_DIR}" ]]; then
        error_message "Incomplete CIS 3.1.3 rollback state already exists."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    if ! active_state="$(cis_3_1_3_active_state)" ||
       ! enabled_state="$(cis_3_1_3_enabled_state)"; then
        error_message "Unable to record the Bluetooth service state for CIS 3.1.3."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    state_parent="$(dirname -- "${RLCH_CIS_3_1_3_STATE_DIR}")"
    if ! mkdir -p -- "${state_parent}" ||
       ! temporary_dir="$(mktemp -d "${RLCH_CIS_3_1_3_STATE_DIR}.tmp.XXXXXX")"; then
        error_message "Unable to create CIS 3.1.3 rollback state."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    if ! printf 'enabled=%s\nactive=%s\n' "${enabled_state}" "${active_state}" > "${temporary_dir}/service.state" ||
       ! chmod 0600 -- "${temporary_dir}/service.state" ||
       ! mv -- "${temporary_dir}" "${RLCH_CIS_3_1_3_STATE_DIR}"; then
        rm -rf -- "${temporary_dir}"
        error_message "Unable to save CIS 3.1.3 rollback state."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

check() {
    local active_state
    local enabled_state

    if ! cis_3_1_3_package_installed; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi
    if ! active_state="$(cis_3_1_3_active_state)" ||
       ! enabled_state="$(cis_3_1_3_enabled_state)"; then
        error_message "Unable to inspect the Bluetooth service state for CIS 3.1.3."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    if [[ "${active_state}" == inactive &&
          ( "${enabled_state}" == masked || "${enabled_state}" == masked-runtime ) ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi
    return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
}

apply() {
    local result=0

    check || result=$?
    if [[ "${result}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi
    if [[ "${result}" -ne "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    cis_3_1_3_require_root || return "${RLCH_MODULE_RESULT_ERROR}"
    cis_3_1_3_capture_state || return "${RLCH_MODULE_RESULT_ERROR}"
    if ! "${RLCH_CIS_3_1_3_SYSTEMCTL_COMMAND}" stop "${RLCH_CIS_3_1_3_SERVICE}" >/dev/null 2>&1 ||
       ! "${RLCH_CIS_3_1_3_SYSTEMCTL_COMMAND}" disable "${RLCH_CIS_3_1_3_SERVICE}" >/dev/null 2>&1 ||
       ! "${RLCH_CIS_3_1_3_SYSTEMCTL_COMMAND}" mask "${RLCH_CIS_3_1_3_SERVICE}" >/dev/null 2>&1; then
        error_message "Unable to disable the Bluetooth service for CIS 3.1.3."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    if ! check; then
        error_message "The Bluetooth service remains enabled after CIS 3.1.3 remediation."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    return "${RLCH_MODULE_RESULT_CHANGED}"
}

validate() {
    check
}

cis_3_1_3_read_state() {
    local active_state=""
    local enabled_state=""
    local line

    while IFS= read -r line; do
        case "${line}" in
            enabled=enabled|enabled=enabled-runtime|enabled=disabled|enabled=masked|enabled=masked-runtime|enabled=static|enabled=indirect)
                enabled_state="${line#enabled=}"
                ;;
            active=active|active=inactive)
                active_state="${line#active=}"
                ;;
            *)
                return 1
                ;;
        esac
    done < "${RLCH_CIS_3_1_3_STATE_FILE}" || return 1

    [[ -n "${enabled_state}" && -n "${active_state}" ]] || return 1
    printf '%s %s\n' "${enabled_state}" "${active_state}"
}

cis_3_1_3_restore_enablement() {
    local enabled_state="${1:?Enabled state is required}"

    case "${enabled_state}" in
        enabled)
            "${RLCH_CIS_3_1_3_SYSTEMCTL_COMMAND}" enable "${RLCH_CIS_3_1_3_SERVICE}" >/dev/null 2>&1
            ;;
        enabled-runtime)
            "${RLCH_CIS_3_1_3_SYSTEMCTL_COMMAND}" enable --runtime "${RLCH_CIS_3_1_3_SERVICE}" >/dev/null 2>&1
            ;;
        disabled)
            "${RLCH_CIS_3_1_3_SYSTEMCTL_COMMAND}" disable "${RLCH_CIS_3_1_3_SERVICE}" >/dev/null 2>&1
            ;;
        static|indirect|masked|masked-runtime)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

cis_3_1_3_restore_mask() {
    local enabled_state="${1:?Enabled state is required}"

    case "${enabled_state}" in
        masked)
            "${RLCH_CIS_3_1_3_SYSTEMCTL_COMMAND}" mask "${RLCH_CIS_3_1_3_SERVICE}" >/dev/null 2>&1
            ;;
        masked-runtime)
            "${RLCH_CIS_3_1_3_SYSTEMCTL_COMMAND}" mask --runtime "${RLCH_CIS_3_1_3_SERVICE}" >/dev/null 2>&1
            ;;
        *)
            return 0
            ;;
    esac
}

rollback() {
    local active_state
    local current_state
    local enabled_state
    local saved_state

    if [[ ! -e "${RLCH_CIS_3_1_3_STATE_DIR}" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi
    if [[ ! -f "${RLCH_CIS_3_1_3_STATE_FILE}" ]] ||
       ! saved_state="$(cis_3_1_3_read_state)"; then
        error_message "CIS 3.1.3 rollback state is missing or invalid."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    read -r enabled_state active_state <<< "${saved_state}"

    cis_3_1_3_require_root || return "${RLCH_MODULE_RESULT_ERROR}"
    if ! "${RLCH_CIS_3_1_3_SYSTEMCTL_COMMAND}" unmask "${RLCH_CIS_3_1_3_SERVICE}" >/dev/null 2>&1 ||
       ! cis_3_1_3_restore_enablement "${enabled_state}"; then
        error_message "Unable to restore Bluetooth service enablement for CIS 3.1.3."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    if [[ "${active_state}" == active ]]; then
        if ! "${RLCH_CIS_3_1_3_SYSTEMCTL_COMMAND}" start "${RLCH_CIS_3_1_3_SERVICE}" >/dev/null 2>&1; then
            error_message "Unable to restore the active Bluetooth service for CIS 3.1.3."
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
    elif ! "${RLCH_CIS_3_1_3_SYSTEMCTL_COMMAND}" stop "${RLCH_CIS_3_1_3_SERVICE}" >/dev/null 2>&1; then
        error_message "Unable to restore the inactive Bluetooth service for CIS 3.1.3."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    if ! cis_3_1_3_restore_mask "${enabled_state}"; then
        error_message "Unable to restore Bluetooth service masking for CIS 3.1.3."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    if ! current_state="$(cis_3_1_3_enabled_state)" || [[ "${current_state}" != "${enabled_state}" ]] ||
       ! current_state="$(cis_3_1_3_active_state)" || [[ "${current_state}" != "${active_state}" ]]; then
        error_message "Bluetooth service state was not restored for CIS 3.1.3."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    if ! rm -- "${RLCH_CIS_3_1_3_STATE_FILE}" || ! rmdir -- "${RLCH_CIS_3_1_3_STATE_DIR}"; then
        error_message "Unable to remove completed CIS 3.1.3 rollback state."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    return "${RLCH_MODULE_RESULT_CHANGED}"
}
