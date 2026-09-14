#!/usr/bin/env bash
# Rocky Linux CIS Hardening Framework
# CIS 2.1.13 - Ensure rsync services are not in use.
# SPDX-License-Identifier: MIT

RLCH_CIS_2_1_13_PACKAGE="${RLCH_CIS_2_1_13_PACKAGE:-rsync}"
RLCH_CIS_2_1_13_RPM_COMMAND="${RLCH_CIS_2_1_13_RPM_COMMAND:-rpm}"
RLCH_CIS_2_1_13_DNF_COMMAND="${RLCH_CIS_2_1_13_DNF_COMMAND:-dnf}"
RLCH_CIS_2_1_13_STATE_DIR="${RLCH_CIS_2_1_13_STATE_DIR:-/var/lib/rlch/cis/2.1.13}"
RLCH_CIS_2_1_13_STATE_FILE="${RLCH_CIS_2_1_13_STATE_FILE:-${RLCH_CIS_2_1_13_STATE_DIR}/package-removed}"

cis_2_1_13_package_installed() {
    "${RLCH_CIS_2_1_13_RPM_COMMAND}" -q "${RLCH_CIS_2_1_13_PACKAGE}" >/dev/null 2>&1
}

cis_2_1_13_require_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        error_message "CIS 2.1.13 requires root privileges."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

cis_2_1_13_create_state() {
    if ! mkdir -p "${RLCH_CIS_2_1_13_STATE_DIR}"; then
        error_message "Unable to create CIS 2.1.13 state directory: ${RLCH_CIS_2_1_13_STATE_DIR}"
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    if ! printf '%s
' "${RLCH_CIS_2_1_13_PACKAGE}" > "${RLCH_CIS_2_1_13_STATE_FILE}"; then
        error_message "Unable to write CIS 2.1.13 rollback state: ${RLCH_CIS_2_1_13_STATE_FILE}"
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

cis_2_1_13_remove_state() {
    if [[ ! -e "${RLCH_CIS_2_1_13_STATE_FILE}" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi
    if ! rm -f "${RLCH_CIS_2_1_13_STATE_FILE}"; then
        error_message "Unable to remove CIS 2.1.13 rollback state: ${RLCH_CIS_2_1_13_STATE_FILE}"
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    if [[ -d "${RLCH_CIS_2_1_13_STATE_DIR}" ]]; then
        rmdir "${RLCH_CIS_2_1_13_STATE_DIR}" >/dev/null 2>&1 || true
    fi
    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

check() {
    if cis_2_1_13_package_installed; then
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi
    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

apply() {
    local state_result=0
    if ! cis_2_1_13_package_installed; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi
    cis_2_1_13_require_root || return "${RLCH_MODULE_RESULT_ERROR}"
    cis_2_1_13_create_state || state_result=$?
    if [[ "${state_result}" -ne "${RLCH_MODULE_RESULT_SUCCESS}" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    if ! "${RLCH_CIS_2_1_13_DNF_COMMAND}" -y remove "${RLCH_CIS_2_1_13_PACKAGE}"; then
        error_message "Unable to remove package ${RLCH_CIS_2_1_13_PACKAGE}."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    if cis_2_1_13_package_installed; then
        error_message "Package ${RLCH_CIS_2_1_13_PACKAGE} is still installed after remediation."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    return "${RLCH_MODULE_RESULT_CHANGED}"
}

validate() {
    check
}

rollback() {
    local package_name
    if [[ ! -e "${RLCH_CIS_2_1_13_STATE_FILE}" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi
    cis_2_1_13_require_root || return "${RLCH_MODULE_RESULT_ERROR}"
    if ! IFS= read -r package_name < "${RLCH_CIS_2_1_13_STATE_FILE}"; then
        error_message "Unable to read CIS 2.1.13 rollback state: ${RLCH_CIS_2_1_13_STATE_FILE}"
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    if [[ -z "${package_name}" ]]; then
        error_message "CIS 2.1.13 rollback state does not contain a package name."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    if ! "${RLCH_CIS_2_1_13_RPM_COMMAND}" -q "${package_name}" >/dev/null 2>&1; then
        if ! "${RLCH_CIS_2_1_13_DNF_COMMAND}" -y install "${package_name}"; then
            error_message "Unable to reinstall package ${package_name}."
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
    fi
    if ! "${RLCH_CIS_2_1_13_RPM_COMMAND}" -q "${package_name}" >/dev/null 2>&1; then
        error_message "Package ${package_name} is not installed after rollback."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    cis_2_1_13_remove_state || return "${RLCH_MODULE_RESULT_ERROR}"
    return "${RLCH_MODULE_RESULT_CHANGED}"
}
