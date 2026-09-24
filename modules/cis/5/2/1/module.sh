#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
# CIS 5.2.1 - Ensure sudo is installed.
# SPDX-License-Identifier: MIT
#

RLCH_CIS_5_2_1_PACKAGE="${RLCH_CIS_5_2_1_PACKAGE:-sudo}"
RLCH_CIS_5_2_1_RPM_COMMAND="${RLCH_CIS_5_2_1_RPM_COMMAND:-rpm}"
RLCH_CIS_5_2_1_DNF_COMMAND="${RLCH_CIS_5_2_1_DNF_COMMAND:-dnf}"
RLCH_CIS_5_2_1_ID_COMMAND="${RLCH_CIS_5_2_1_ID_COMMAND:-id}"
RLCH_CIS_5_2_1_STATE_DIR="${RLCH_CIS_5_2_1_STATE_DIR:-/var/lib/rlch/cis/5.2.1}"
RLCH_CIS_5_2_1_STATE_FILE="${RLCH_CIS_5_2_1_STATE_FILE:-${RLCH_CIS_5_2_1_STATE_DIR}/package-installed}"

cis_5_2_1_package_installed() {
    "${RLCH_CIS_5_2_1_RPM_COMMAND}" -q "${RLCH_CIS_5_2_1_PACKAGE}" >/dev/null 2>&1
}

cis_5_2_1_require_root() {
    local effective_uid

    effective_uid="$("${RLCH_CIS_5_2_1_ID_COMMAND}" -u 2>/dev/null)" || return "${RLCH_MODULE_RESULT_ERROR}"
    [[ "${effective_uid}" == 0 ]] || return "${RLCH_MODULE_RESULT_ERROR}"
}

cis_5_2_1_create_state() {
    mkdir -p -- "${RLCH_CIS_5_2_1_STATE_DIR}" &&
        printf '%s\n' "${RLCH_CIS_5_2_1_PACKAGE}" > "${RLCH_CIS_5_2_1_STATE_FILE}" &&
        chmod 0600 -- "${RLCH_CIS_5_2_1_STATE_FILE}"
}

cis_5_2_1_remove_state() {
    rm -f -- "${RLCH_CIS_5_2_1_STATE_FILE}" || return "${RLCH_MODULE_RESULT_ERROR}"
    rmdir -- "${RLCH_CIS_5_2_1_STATE_DIR}" >/dev/null 2>&1 || true
}

check() {
    cis_5_2_1_package_installed || return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

apply() {
    if cis_5_2_1_package_installed; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi
    cis_5_2_1_require_root || return "${RLCH_MODULE_RESULT_ERROR}"
    cis_5_2_1_create_state || return "${RLCH_MODULE_RESULT_ERROR}"
    "${RLCH_CIS_5_2_1_DNF_COMMAND}" -y install "${RLCH_CIS_5_2_1_PACKAGE}" || return "${RLCH_MODULE_RESULT_ERROR}"
    cis_5_2_1_package_installed || return "${RLCH_MODULE_RESULT_ERROR}"
    return "${RLCH_MODULE_RESULT_CHANGED}"
}

validate() { check; }

rollback() {
    local package_name

    [[ -e "${RLCH_CIS_5_2_1_STATE_FILE}" ]] || return "${RLCH_MODULE_RESULT_SUCCESS}"
    cis_5_2_1_require_root || return "${RLCH_MODULE_RESULT_ERROR}"
    IFS= read -r package_name < "${RLCH_CIS_5_2_1_STATE_FILE}" || return "${RLCH_MODULE_RESULT_ERROR}"
    [[ "${package_name}" == "${RLCH_CIS_5_2_1_PACKAGE}" ]] || return "${RLCH_MODULE_RESULT_ERROR}"
    if cis_5_2_1_package_installed; then
        "${RLCH_CIS_5_2_1_DNF_COMMAND}" -y remove "${package_name}" || return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    cis_5_2_1_package_installed && return "${RLCH_MODULE_RESULT_ERROR}"
    cis_5_2_1_remove_state || return "${RLCH_MODULE_RESULT_ERROR}"
    return "${RLCH_MODULE_RESULT_CHANGED}"
}
