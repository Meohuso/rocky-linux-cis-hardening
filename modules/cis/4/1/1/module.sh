#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
# CIS 4.1.1 - Ensure nftables is installed.
# SPDX-License-Identifier: MIT
#

RLCH_CIS_4_1_1_PACKAGE="${RLCH_CIS_4_1_1_PACKAGE:-nftables}"
RLCH_CIS_4_1_1_RPM_COMMAND="${RLCH_CIS_4_1_1_RPM_COMMAND:-rpm}"
RLCH_CIS_4_1_1_DNF_COMMAND="${RLCH_CIS_4_1_1_DNF_COMMAND:-dnf}"
RLCH_CIS_4_1_1_ID_COMMAND="${RLCH_CIS_4_1_1_ID_COMMAND:-id}"
RLCH_CIS_4_1_1_STATE_DIR="${RLCH_CIS_4_1_1_STATE_DIR:-/var/lib/rlch/cis/4.1.1}"
RLCH_CIS_4_1_1_STATE_FILE="${RLCH_CIS_4_1_1_STATE_FILE:-${RLCH_CIS_4_1_1_STATE_DIR}/package-installed}"

cis_4_1_1_package_installed() {
    "${RLCH_CIS_4_1_1_RPM_COMMAND}" -q "${RLCH_CIS_4_1_1_PACKAGE}" >/dev/null 2>&1
}

cis_4_1_1_require_root() {
    local effective_uid

    if ! effective_uid="$("${RLCH_CIS_4_1_1_ID_COMMAND}" -u 2>/dev/null)"; then
        error_message "Unable to determine effective user ID for CIS 4.1.1."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if [[ "${effective_uid}" != "0" ]]; then
        error_message "CIS 4.1.1 requires root privileges."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

cis_4_1_1_create_state() {
    if ! mkdir -p "${RLCH_CIS_4_1_1_STATE_DIR}" ||
       ! printf '%s\n' "${RLCH_CIS_4_1_1_PACKAGE}" > "${RLCH_CIS_4_1_1_STATE_FILE}"; then
        error_message "Unable to record CIS 4.1.1 rollback state."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

cis_4_1_1_remove_state() {
    if ! rm -f -- "${RLCH_CIS_4_1_1_STATE_FILE}"; then
        error_message "Unable to remove CIS 4.1.1 rollback state."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    rmdir "${RLCH_CIS_4_1_1_STATE_DIR}" >/dev/null 2>&1 || true
    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

check() {
    if cis_4_1_1_package_installed; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
}

apply() {
    if cis_4_1_1_package_installed; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    cis_4_1_1_require_root || return "${RLCH_MODULE_RESULT_ERROR}"
    cis_4_1_1_create_state || return "${RLCH_MODULE_RESULT_ERROR}"

    if ! "${RLCH_CIS_4_1_1_DNF_COMMAND}" -y install "${RLCH_CIS_4_1_1_PACKAGE}"; then
        error_message "Unable to install package ${RLCH_CIS_4_1_1_PACKAGE}."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! cis_4_1_1_package_installed; then
        error_message "Package ${RLCH_CIS_4_1_1_PACKAGE} is not installed after remediation."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_CHANGED}"
}

validate() {
    check
}

rollback() {
    local package_name

    if [[ ! -e "${RLCH_CIS_4_1_1_STATE_FILE}" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    cis_4_1_1_require_root || return "${RLCH_MODULE_RESULT_ERROR}"

    if ! IFS= read -r package_name < "${RLCH_CIS_4_1_1_STATE_FILE}" ||
       [[ "${package_name}" != "${RLCH_CIS_4_1_1_PACKAGE}" ]]; then
        error_message "Invalid CIS 4.1.1 rollback state."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if cis_4_1_1_package_installed &&
       ! "${RLCH_CIS_4_1_1_DNF_COMMAND}" -y remove "${package_name}"; then
        error_message "Unable to remove package ${package_name} during rollback."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if cis_4_1_1_package_installed; then
        error_message "Package ${package_name} is still installed after rollback."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    cis_4_1_1_remove_state || return "${RLCH_MODULE_RESULT_ERROR}"
    return "${RLCH_MODULE_RESULT_CHANGED}"
}
