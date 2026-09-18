#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
# CIS 4.1.2 - Ensure a single firewall configuration utility is in use.
# SPDX-License-Identifier: MIT
#

RLCH_CIS_4_1_2_FIREWALLD_PACKAGE="${RLCH_CIS_4_1_2_FIREWALLD_PACKAGE:-firewalld}"
RLCH_CIS_4_1_2_FIREWALLD_SERVICE="${RLCH_CIS_4_1_2_FIREWALLD_SERVICE:-firewalld.service}"
RLCH_CIS_4_1_2_NFTABLES_SERVICE="${RLCH_CIS_4_1_2_NFTABLES_SERVICE:-nftables.service}"
RLCH_CIS_4_1_2_RPM_COMMAND="${RLCH_CIS_4_1_2_RPM_COMMAND:-rpm}"
RLCH_CIS_4_1_2_DNF_COMMAND="${RLCH_CIS_4_1_2_DNF_COMMAND:-dnf}"
RLCH_CIS_4_1_2_SYSTEMCTL_COMMAND="${RLCH_CIS_4_1_2_SYSTEMCTL_COMMAND:-systemctl}"
RLCH_CIS_4_1_2_ID_COMMAND="${RLCH_CIS_4_1_2_ID_COMMAND:-id}"
RLCH_CIS_4_1_2_STATE_DIR="${RLCH_CIS_4_1_2_STATE_DIR:-/var/lib/rlch/cis/4.1.2}"
RLCH_CIS_4_1_2_STATE_FILE="${RLCH_CIS_4_1_2_STATE_FILE:-${RLCH_CIS_4_1_2_STATE_DIR}/state}"
RLCH_CIS_4_1_2_PACKAGE_STATE_FILE="${RLCH_CIS_4_1_2_PACKAGE_STATE_FILE:-${RLCH_CIS_4_1_2_STATE_DIR}/firewalld-package-state}"
RLCH_CIS_4_1_2_FIREWALLD_ENABLED_FILE="${RLCH_CIS_4_1_2_FIREWALLD_ENABLED_FILE:-${RLCH_CIS_4_1_2_STATE_DIR}/firewalld-enabled-state}"
RLCH_CIS_4_1_2_FIREWALLD_ACTIVE_FILE="${RLCH_CIS_4_1_2_FIREWALLD_ACTIVE_FILE:-${RLCH_CIS_4_1_2_STATE_DIR}/firewalld-active-state}"
RLCH_CIS_4_1_2_NFTABLES_ENABLED_FILE="${RLCH_CIS_4_1_2_NFTABLES_ENABLED_FILE:-${RLCH_CIS_4_1_2_STATE_DIR}/nftables-enabled-state}"
RLCH_CIS_4_1_2_NFTABLES_ACTIVE_FILE="${RLCH_CIS_4_1_2_NFTABLES_ACTIVE_FILE:-${RLCH_CIS_4_1_2_STATE_DIR}/nftables-active-state}"

cis_4_1_2_firewalld_installed() {
    "${RLCH_CIS_4_1_2_RPM_COMMAND}" -q "${RLCH_CIS_4_1_2_FIREWALLD_PACKAGE}" >/dev/null 2>&1
}

cis_4_1_2_service_enabled_state() {
    local service_name="${1:-}"
    "${RLCH_CIS_4_1_2_SYSTEMCTL_COMMAND}" is-enabled "${service_name}" 2>/dev/null || true
}

cis_4_1_2_service_active_state() {
    local service_name="${1:-}"

    if "${RLCH_CIS_4_1_2_SYSTEMCTL_COMMAND}" is-active --quiet "${service_name}"; then
        printf '%s\n' active
    else
        printf '%s\n' inactive
    fi
}

cis_4_1_2_valid_enabled_state() {
    case "${1:-}" in
        enabled|disabled|masked|masked-runtime)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

cis_4_1_2_require_root() {
    local effective_uid

    if ! effective_uid="$("${RLCH_CIS_4_1_2_ID_COMMAND}" -u 2>/dev/null)"; then
        error_message "Unable to determine effective user ID for CIS 4.1.2."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if [[ "${effective_uid}" != "0" ]]; then
        error_message "CIS 4.1.2 requires root privileges."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

cis_4_1_2_capture_state() {
    local firewalld_active="inactive"
    local firewalld_enabled="absent"
    local nftables_active
    local nftables_enabled
    local package_state="absent"

    if [[ -e "${RLCH_CIS_4_1_2_STATE_FILE}" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    nftables_enabled="$(cis_4_1_2_service_enabled_state "${RLCH_CIS_4_1_2_NFTABLES_SERVICE}")"
    nftables_active="$(cis_4_1_2_service_active_state "${RLCH_CIS_4_1_2_NFTABLES_SERVICE}")"
    if ! cis_4_1_2_valid_enabled_state "${nftables_enabled}"; then
        error_message "Unable to capture the nftables service enablement state."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if cis_4_1_2_firewalld_installed; then
        package_state="installed"
        firewalld_enabled="$(cis_4_1_2_service_enabled_state "${RLCH_CIS_4_1_2_FIREWALLD_SERVICE}")"
        firewalld_active="$(cis_4_1_2_service_active_state "${RLCH_CIS_4_1_2_FIREWALLD_SERVICE}")"
        if ! cis_4_1_2_valid_enabled_state "${firewalld_enabled}"; then
            error_message "Unable to capture the firewalld service enablement state."
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
    fi

    if ! mkdir -p -- "${RLCH_CIS_4_1_2_STATE_DIR}" ||
       ! printf '%s\n' "${package_state}" > "${RLCH_CIS_4_1_2_PACKAGE_STATE_FILE}" ||
       ! printf '%s\n' "${firewalld_enabled}" > "${RLCH_CIS_4_1_2_FIREWALLD_ENABLED_FILE}" ||
       ! printf '%s\n' "${firewalld_active}" > "${RLCH_CIS_4_1_2_FIREWALLD_ACTIVE_FILE}" ||
       ! printf '%s\n' "${nftables_enabled}" > "${RLCH_CIS_4_1_2_NFTABLES_ENABLED_FILE}" ||
       ! printf '%s\n' "${nftables_active}" > "${RLCH_CIS_4_1_2_NFTABLES_ACTIVE_FILE}" ||
       ! : > "${RLCH_CIS_4_1_2_STATE_FILE}"; then
        error_message "Unable to record CIS 4.1.2 rollback state."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

cis_4_1_2_restore_service() {
    local service_name="${1:-}"
    local enabled_state="${2:-}"
    local active_state="${3:-}"

    if ! cis_4_1_2_valid_enabled_state "${enabled_state}" ||
       [[ "${active_state}" != "active" && "${active_state}" != "inactive" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! "${RLCH_CIS_4_1_2_SYSTEMCTL_COMMAND}" unmask "${service_name}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if [[ "${enabled_state}" == "enabled" ]]; then
        "${RLCH_CIS_4_1_2_SYSTEMCTL_COMMAND}" enable "${service_name}" || return "${RLCH_MODULE_RESULT_ERROR}"
    else
        "${RLCH_CIS_4_1_2_SYSTEMCTL_COMMAND}" disable "${service_name}" || return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if [[ "${active_state}" == "active" ]]; then
        "${RLCH_CIS_4_1_2_SYSTEMCTL_COMMAND}" start "${service_name}" || return "${RLCH_MODULE_RESULT_ERROR}"
    else
        "${RLCH_CIS_4_1_2_SYSTEMCTL_COMMAND}" stop "${service_name}" || return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    case "${enabled_state}" in
        masked)
            "${RLCH_CIS_4_1_2_SYSTEMCTL_COMMAND}" mask "${service_name}" || return "${RLCH_MODULE_RESULT_ERROR}"
            ;;
        masked-runtime)
            "${RLCH_CIS_4_1_2_SYSTEMCTL_COMMAND}" mask --runtime "${service_name}" || return "${RLCH_MODULE_RESULT_ERROR}"
            ;;
    esac

    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

cis_4_1_2_remove_state() {
    local state_file

    for state_file in \
        "${RLCH_CIS_4_1_2_STATE_FILE}" \
        "${RLCH_CIS_4_1_2_PACKAGE_STATE_FILE}" \
        "${RLCH_CIS_4_1_2_FIREWALLD_ENABLED_FILE}" \
        "${RLCH_CIS_4_1_2_FIREWALLD_ACTIVE_FILE}" \
        "${RLCH_CIS_4_1_2_NFTABLES_ENABLED_FILE}" \
        "${RLCH_CIS_4_1_2_NFTABLES_ACTIVE_FILE}"; do
        rm -f -- "${state_file}" || return "${RLCH_MODULE_RESULT_ERROR}"
    done

    rmdir "${RLCH_CIS_4_1_2_STATE_DIR}" >/dev/null 2>&1 || true
    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

check() {
    local nftables_enabled

    if ! cis_4_1_2_firewalld_installed; then
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi

    if [[ "$(cis_4_1_2_service_enabled_state "${RLCH_CIS_4_1_2_FIREWALLD_SERVICE}")" != "enabled" ]] ||
       [[ "$(cis_4_1_2_service_active_state "${RLCH_CIS_4_1_2_FIREWALLD_SERVICE}")" != "active" ]]; then
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi

    nftables_enabled="$(cis_4_1_2_service_enabled_state "${RLCH_CIS_4_1_2_NFTABLES_SERVICE}")"
    if [[ "${nftables_enabled}" != "disabled" &&
          "${nftables_enabled}" != "masked" &&
          "${nftables_enabled}" != "masked-runtime" ]] ||
       [[ "$(cis_4_1_2_service_active_state "${RLCH_CIS_4_1_2_NFTABLES_SERVICE}")" != "inactive" ]]; then
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi

    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

apply() {
    local firewalld_enabled
    local result=0

    check || result=$?
    if [[ "${result}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    cis_4_1_2_require_root || return "${RLCH_MODULE_RESULT_ERROR}"
    cis_4_1_2_capture_state || return "${RLCH_MODULE_RESULT_ERROR}"

    if ! cis_4_1_2_firewalld_installed; then
        if ! "${RLCH_CIS_4_1_2_DNF_COMMAND}" -y install "${RLCH_CIS_4_1_2_FIREWALLD_PACKAGE}" ||
           ! cis_4_1_2_firewalld_installed; then
            error_message "Unable to install package ${RLCH_CIS_4_1_2_FIREWALLD_PACKAGE}."
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
    fi

    firewalld_enabled="$(cis_4_1_2_service_enabled_state "${RLCH_CIS_4_1_2_FIREWALLD_SERVICE}")"
    if [[ "${firewalld_enabled}" == "masked" || "${firewalld_enabled}" == "masked-runtime" ]]; then
        "${RLCH_CIS_4_1_2_SYSTEMCTL_COMMAND}" unmask "${RLCH_CIS_4_1_2_FIREWALLD_SERVICE}" || return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! "${RLCH_CIS_4_1_2_SYSTEMCTL_COMMAND}" enable "${RLCH_CIS_4_1_2_FIREWALLD_SERVICE}" ||
       ! "${RLCH_CIS_4_1_2_SYSTEMCTL_COMMAND}" start "${RLCH_CIS_4_1_2_FIREWALLD_SERVICE}" ||
       ! "${RLCH_CIS_4_1_2_SYSTEMCTL_COMMAND}" stop "${RLCH_CIS_4_1_2_NFTABLES_SERVICE}" ||
       ! "${RLCH_CIS_4_1_2_SYSTEMCTL_COMMAND}" disable "${RLCH_CIS_4_1_2_NFTABLES_SERVICE}"; then
        error_message "Unable to select firewalld as the single firewall configuration utility."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! check; then
        error_message "Firewall utility state is not compliant after remediation."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_CHANGED}"
}

validate() {
    check
}

rollback() {
    local firewalld_active
    local firewalld_enabled
    local nftables_active
    local nftables_enabled
    local package_state

    if [[ ! -e "${RLCH_CIS_4_1_2_STATE_FILE}" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    cis_4_1_2_require_root || return "${RLCH_MODULE_RESULT_ERROR}"

    if [[ ! -f "${RLCH_CIS_4_1_2_PACKAGE_STATE_FILE}" ||
          ! -f "${RLCH_CIS_4_1_2_FIREWALLD_ENABLED_FILE}" ||
          ! -f "${RLCH_CIS_4_1_2_FIREWALLD_ACTIVE_FILE}" ||
          ! -f "${RLCH_CIS_4_1_2_NFTABLES_ENABLED_FILE}" ||
          ! -f "${RLCH_CIS_4_1_2_NFTABLES_ACTIVE_FILE}" ]] ||
       ! IFS= read -r package_state < "${RLCH_CIS_4_1_2_PACKAGE_STATE_FILE}" ||
       ! IFS= read -r firewalld_enabled < "${RLCH_CIS_4_1_2_FIREWALLD_ENABLED_FILE}" ||
       ! IFS= read -r firewalld_active < "${RLCH_CIS_4_1_2_FIREWALLD_ACTIVE_FILE}" ||
       ! IFS= read -r nftables_enabled < "${RLCH_CIS_4_1_2_NFTABLES_ENABLED_FILE}" ||
       ! IFS= read -r nftables_active < "${RLCH_CIS_4_1_2_NFTABLES_ACTIVE_FILE}"; then
        error_message "Unable to read CIS 4.1.2 rollback state."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if [[ "${package_state}" == "installed" ]]; then
        if ! cis_4_1_2_firewalld_installed ||
           ! cis_4_1_2_restore_service "${RLCH_CIS_4_1_2_FIREWALLD_SERVICE}" "${firewalld_enabled}" "${firewalld_active}"; then
            error_message "Unable to restore the original firewalld state."
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
    elif [[ "${package_state}" == "absent" && "${firewalld_enabled}" == "absent" && "${firewalld_active}" == "inactive" ]]; then
        if cis_4_1_2_firewalld_installed; then
            if ! "${RLCH_CIS_4_1_2_SYSTEMCTL_COMMAND}" stop "${RLCH_CIS_4_1_2_FIREWALLD_SERVICE}" ||
               ! "${RLCH_CIS_4_1_2_SYSTEMCTL_COMMAND}" disable "${RLCH_CIS_4_1_2_FIREWALLD_SERVICE}" ||
               ! "${RLCH_CIS_4_1_2_DNF_COMMAND}" -y remove "${RLCH_CIS_4_1_2_FIREWALLD_PACKAGE}"; then
                error_message "Unable to remove firewalld during rollback."
                return "${RLCH_MODULE_RESULT_ERROR}"
            fi
        fi

        if cis_4_1_2_firewalld_installed; then
            error_message "Package firewalld is still installed after rollback."
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
    else
        error_message "Invalid CIS 4.1.2 firewalld rollback state."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! cis_4_1_2_restore_service "${RLCH_CIS_4_1_2_NFTABLES_SERVICE}" "${nftables_enabled}" "${nftables_active}"; then
        error_message "Unable to restore the original nftables service state."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    cis_4_1_2_remove_state || return "${RLCH_MODULE_RESULT_ERROR}"
    return "${RLCH_MODULE_RESULT_CHANGED}"
}
