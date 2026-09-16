#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
# CIS 2.4.1.1 - Ensure cron daemon is enabled and active.
# SPDX-License-Identifier: MIT
#

RLCH_CIS_2_4_1_1_PACKAGE="${RLCH_CIS_2_4_1_1_PACKAGE:-cronie}"
RLCH_CIS_2_4_1_1_SERVICE="${RLCH_CIS_2_4_1_1_SERVICE:-crond.service}"
RLCH_CIS_2_4_1_1_RPM_COMMAND="${RLCH_CIS_2_4_1_1_RPM_COMMAND:-rpm}"
RLCH_CIS_2_4_1_1_DNF_COMMAND="${RLCH_CIS_2_4_1_1_DNF_COMMAND:-dnf}"
RLCH_CIS_2_4_1_1_SYSTEMCTL_COMMAND="${RLCH_CIS_2_4_1_1_SYSTEMCTL_COMMAND:-systemctl}"
RLCH_CIS_2_4_1_1_ID_COMMAND="${RLCH_CIS_2_4_1_1_ID_COMMAND:-id}"
RLCH_CIS_2_4_1_1_STATE_DIR="${RLCH_CIS_2_4_1_1_STATE_DIR:-/var/lib/rlch/cis/2.4.1.1}"
RLCH_CIS_2_4_1_1_STATE_FILE="${RLCH_CIS_2_4_1_1_STATE_FILE:-${RLCH_CIS_2_4_1_1_STATE_DIR}/state}"
RLCH_CIS_2_4_1_1_PACKAGE_STATE_FILE="${RLCH_CIS_2_4_1_1_PACKAGE_STATE_FILE:-${RLCH_CIS_2_4_1_1_STATE_DIR}/package-state}"
RLCH_CIS_2_4_1_1_ENABLED_STATE_FILE="${RLCH_CIS_2_4_1_1_ENABLED_STATE_FILE:-${RLCH_CIS_2_4_1_1_STATE_DIR}/enabled-state}"
RLCH_CIS_2_4_1_1_ACTIVE_STATE_FILE="${RLCH_CIS_2_4_1_1_ACTIVE_STATE_FILE:-${RLCH_CIS_2_4_1_1_STATE_DIR}/active-state}"

cis_2_4_1_1_package_installed() {
    "${RLCH_CIS_2_4_1_1_RPM_COMMAND}" -q "${RLCH_CIS_2_4_1_1_PACKAGE}" >/dev/null 2>&1
}

cis_2_4_1_1_service_enabled_state() {
    "${RLCH_CIS_2_4_1_1_SYSTEMCTL_COMMAND}" is-enabled \
        "${RLCH_CIS_2_4_1_1_SERVICE}" 2>/dev/null || true
}

cis_2_4_1_1_service_enabled() {
    [[ "$(cis_2_4_1_1_service_enabled_state)" == "enabled" ]]
}

cis_2_4_1_1_service_active() {
    "${RLCH_CIS_2_4_1_1_SYSTEMCTL_COMMAND}" is-active --quiet \
        "${RLCH_CIS_2_4_1_1_SERVICE}"
}

cis_2_4_1_1_require_root() {
    local effective_uid

    if ! effective_uid="$("${RLCH_CIS_2_4_1_1_ID_COMMAND}" -u 2>/dev/null)"; then
        error_message "Unable to determine effective user ID for CIS 2.4.1.1."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if [[ "${effective_uid}" != "0" ]]; then
        error_message "CIS 2.4.1.1 requires root privileges."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

cis_2_4_1_1_capture_state() {
    local active_state="inactive"
    local enabled_state="absent"
    local package_state="absent"

    if [[ -e "${RLCH_CIS_2_4_1_1_STATE_FILE}" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    if cis_2_4_1_1_package_installed; then
        package_state="installed"
        enabled_state="$(cis_2_4_1_1_service_enabled_state)"
        if cis_2_4_1_1_service_active; then
            active_state="active"
        fi

        case "${enabled_state}" in
            enabled|disabled|masked)
                ;;
            *)
                error_message "Unable to capture the crond enablement state."
                return "${RLCH_MODULE_RESULT_ERROR}"
                ;;
        esac
    fi

    if ! mkdir -p "${RLCH_CIS_2_4_1_1_STATE_DIR}"; then
        error_message "Unable to create CIS 2.4.1.1 state directory."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! printf '%s\n' "${package_state}" > "${RLCH_CIS_2_4_1_1_PACKAGE_STATE_FILE}" ||
       ! printf '%s\n' "${enabled_state}" > "${RLCH_CIS_2_4_1_1_ENABLED_STATE_FILE}" ||
       ! printf '%s\n' "${active_state}" > "${RLCH_CIS_2_4_1_1_ACTIVE_STATE_FILE}" ||
       ! : > "${RLCH_CIS_2_4_1_1_STATE_FILE}"; then
        error_message "Unable to record CIS 2.4.1.1 rollback state."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

cis_2_4_1_1_remove_state() {
    if ! rm -rf "${RLCH_CIS_2_4_1_1_STATE_DIR}"; then
        error_message "Unable to remove CIS 2.4.1.1 rollback state."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

check() {
    if ! cis_2_4_1_1_package_installed; then
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi

    if ! cis_2_4_1_1_service_enabled; then
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi

    if ! cis_2_4_1_1_service_active; then
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi

    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

apply() {
    local enabled_state
    local result=0

    check || result=$?
    if [[ "${result}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    cis_2_4_1_1_require_root || return "${RLCH_MODULE_RESULT_ERROR}"
    cis_2_4_1_1_capture_state || return "${RLCH_MODULE_RESULT_ERROR}"

    if ! cis_2_4_1_1_package_installed; then
        if ! "${RLCH_CIS_2_4_1_1_DNF_COMMAND}" -y install "${RLCH_CIS_2_4_1_1_PACKAGE}"; then
            error_message "Unable to install package ${RLCH_CIS_2_4_1_1_PACKAGE}."
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi

        if ! cis_2_4_1_1_package_installed; then
            error_message "Package ${RLCH_CIS_2_4_1_1_PACKAGE} is not installed after remediation."
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
    fi

    enabled_state="$(cis_2_4_1_1_service_enabled_state)"
    if [[ "${enabled_state}" == "masked" ]] &&
       ! "${RLCH_CIS_2_4_1_1_SYSTEMCTL_COMMAND}" unmask "${RLCH_CIS_2_4_1_1_SERVICE}"; then
        error_message "Unable to unmask ${RLCH_CIS_2_4_1_1_SERVICE}."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! "${RLCH_CIS_2_4_1_1_SYSTEMCTL_COMMAND}" enable "${RLCH_CIS_2_4_1_1_SERVICE}"; then
        error_message "Unable to enable ${RLCH_CIS_2_4_1_1_SERVICE}."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! "${RLCH_CIS_2_4_1_1_SYSTEMCTL_COMMAND}" start "${RLCH_CIS_2_4_1_1_SERVICE}"; then
        error_message "Unable to start ${RLCH_CIS_2_4_1_1_SERVICE}."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! check; then
        error_message "Cron daemon is not compliant after remediation."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_CHANGED}"
}

validate() {
    check
}

rollback() {
    local active_state
    local enabled_state
    local package_state

    if [[ ! -e "${RLCH_CIS_2_4_1_1_STATE_FILE}" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    cis_2_4_1_1_require_root || return "${RLCH_MODULE_RESULT_ERROR}"

    if [[ ! -f "${RLCH_CIS_2_4_1_1_PACKAGE_STATE_FILE}" ]] ||
       [[ ! -f "${RLCH_CIS_2_4_1_1_ENABLED_STATE_FILE}" ]] ||
       [[ ! -f "${RLCH_CIS_2_4_1_1_ACTIVE_STATE_FILE}" ]] ||
       ! IFS= read -r package_state < "${RLCH_CIS_2_4_1_1_PACKAGE_STATE_FILE}" ||
       ! IFS= read -r enabled_state < "${RLCH_CIS_2_4_1_1_ENABLED_STATE_FILE}" ||
       ! IFS= read -r active_state < "${RLCH_CIS_2_4_1_1_ACTIVE_STATE_FILE}"; then
        error_message "Unable to read CIS 2.4.1.1 rollback state."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    case "${package_state}" in
        absent)
            if [[ "${enabled_state}" != "absent" ]] || [[ "${active_state}" != "inactive" ]]; then
                error_message "Invalid CIS 2.4.1.1 rollback state."
                return "${RLCH_MODULE_RESULT_ERROR}"
            fi

            if cis_2_4_1_1_package_installed; then
                if ! "${RLCH_CIS_2_4_1_1_SYSTEMCTL_COMMAND}" stop "${RLCH_CIS_2_4_1_1_SERVICE}" ||
                   ! "${RLCH_CIS_2_4_1_1_SYSTEMCTL_COMMAND}" disable "${RLCH_CIS_2_4_1_1_SERVICE}" ||
                   ! "${RLCH_CIS_2_4_1_1_DNF_COMMAND}" -y remove "${RLCH_CIS_2_4_1_1_PACKAGE}"; then
                    error_message "Unable to remove the cron service during rollback."
                    return "${RLCH_MODULE_RESULT_ERROR}"
                fi
            fi

            if cis_2_4_1_1_package_installed; then
                error_message "Package ${RLCH_CIS_2_4_1_1_PACKAGE} is still installed after rollback."
                return "${RLCH_MODULE_RESULT_ERROR}"
            fi
            ;;
        installed)
            if ! cis_2_4_1_1_package_installed; then
                error_message "Package ${RLCH_CIS_2_4_1_1_PACKAGE} is missing during rollback."
                return "${RLCH_MODULE_RESULT_ERROR}"
            fi

            case "${enabled_state}" in
                enabled|disabled|masked)
                    ;;
                *)
                    error_message "Invalid CIS 2.4.1.1 enablement rollback state."
                    return "${RLCH_MODULE_RESULT_ERROR}"
                    ;;
            esac

            case "${active_state}" in
                active|inactive)
                    ;;
                *)
                    error_message "Invalid CIS 2.4.1.1 activity rollback state."
                    return "${RLCH_MODULE_RESULT_ERROR}"
                    ;;
            esac

            if ! "${RLCH_CIS_2_4_1_1_SYSTEMCTL_COMMAND}" unmask "${RLCH_CIS_2_4_1_1_SERVICE}"; then
                error_message "Unable to unmask ${RLCH_CIS_2_4_1_1_SERVICE} during rollback."
                return "${RLCH_MODULE_RESULT_ERROR}"
            fi

            if [[ "${enabled_state}" == "enabled" ]]; then
                if ! "${RLCH_CIS_2_4_1_1_SYSTEMCTL_COMMAND}" enable "${RLCH_CIS_2_4_1_1_SERVICE}"; then
                    return "${RLCH_MODULE_RESULT_ERROR}"
                fi
            elif ! "${RLCH_CIS_2_4_1_1_SYSTEMCTL_COMMAND}" disable "${RLCH_CIS_2_4_1_1_SERVICE}"; then
                return "${RLCH_MODULE_RESULT_ERROR}"
            fi

            if [[ "${active_state}" == "active" ]]; then
                if ! "${RLCH_CIS_2_4_1_1_SYSTEMCTL_COMMAND}" start "${RLCH_CIS_2_4_1_1_SERVICE}"; then
                    return "${RLCH_MODULE_RESULT_ERROR}"
                fi
            elif ! "${RLCH_CIS_2_4_1_1_SYSTEMCTL_COMMAND}" stop "${RLCH_CIS_2_4_1_1_SERVICE}"; then
                return "${RLCH_MODULE_RESULT_ERROR}"
            fi

            if [[ "${enabled_state}" == "masked" ]] &&
               ! "${RLCH_CIS_2_4_1_1_SYSTEMCTL_COMMAND}" mask "${RLCH_CIS_2_4_1_1_SERVICE}"; then
                return "${RLCH_MODULE_RESULT_ERROR}"
            fi
            ;;
        *)
            error_message "Invalid CIS 2.4.1.1 package rollback state."
            return "${RLCH_MODULE_RESULT_ERROR}"
            ;;
    esac

    cis_2_4_1_1_remove_state || return "${RLCH_MODULE_RESULT_ERROR}"

    return "${RLCH_MODULE_RESULT_CHANGED}"
}
