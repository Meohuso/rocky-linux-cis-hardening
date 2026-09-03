#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
#
# CIS 2.1.3 - Ensure dhcp server services are not in use.
#
# SPDX-License-Identifier: MIT
#

RLCH_CIS_2_1_3_PACKAGE="${RLCH_CIS_2_1_3_PACKAGE:-dhcp-server}"
RLCH_CIS_2_1_3_RPM_COMMAND="${RLCH_CIS_2_1_3_RPM_COMMAND:-rpm}"
RLCH_CIS_2_1_3_DNF_COMMAND="${RLCH_CIS_2_1_3_DNF_COMMAND:-dnf}"
RLCH_CIS_2_1_3_STATE_DIR="${RLCH_CIS_2_1_3_STATE_DIR:-/var/lib/rlch/cis/2.1.3}"

cis_2_1_3_package_installed() {
    "${RLCH_CIS_2_1_3_RPM_COMMAND}" -q "${RLCH_CIS_2_1_3_PACKAGE}" >/dev/null 2>&1
}

cis_2_1_3_capture_state() {
    if [[ -e "${RLCH_CIS_2_1_3_STATE_DIR}/state" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    if ! mkdir -p -- "${RLCH_CIS_2_1_3_STATE_DIR}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! printf '%s\n' "${RLCH_CIS_2_1_3_PACKAGE}" \
        > "${RLCH_CIS_2_1_3_STATE_DIR}/package"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! : > "${RLCH_CIS_2_1_3_STATE_DIR}/state"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_CHANGED}"
}

check() {
    if cis_2_1_3_package_installed; then
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi

    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

apply() {
    local result

    check
    result=$?

    if [[ "${result}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    if [[ "${result}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    cis_2_1_3_capture_state
    result=$?

    if [[ "${result}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! "${RLCH_CIS_2_1_3_DNF_COMMAND}" -y remove "${RLCH_CIS_2_1_3_PACKAGE}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_CHANGED}"
}

validate() {
    check
}

rollback() {
    local package_name

    if [[ ! -e "${RLCH_CIS_2_1_3_STATE_DIR}/state" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    if [[ ! -f "${RLCH_CIS_2_1_3_STATE_DIR}/package" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    package_name="$(cat -- "${RLCH_CIS_2_1_3_STATE_DIR}/package")"

    if [[ -z "${package_name}" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! "${RLCH_CIS_2_1_3_DNF_COMMAND}" -y install "${package_name}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! rm -rf -- "${RLCH_CIS_2_1_3_STATE_DIR}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_CHANGED}"
}
