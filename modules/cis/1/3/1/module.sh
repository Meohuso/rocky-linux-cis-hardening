#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
#
# CIS 1.3.1 - Ensure AIDE is installed.
#
# SPDX-License-Identifier: MIT
#

readonly RLCH_CIS_1_3_1_PACKAGE="aide"
RLCH_CIS_1_3_1_INSTALLED_BY_MODULE="${RLCH_CIS_1_3_1_INSTALLED_BY_MODULE:-false}"

check() {
    rpm_package_is_installed "${RLCH_CIS_1_3_1_PACKAGE}"
}

apply() {
    local result

    dnf_install_package "${RLCH_CIS_1_3_1_PACKAGE}"
    result=$?

    if [[ "${result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]]; then
        RLCH_CIS_1_3_1_INSTALLED_BY_MODULE="true"
    fi

    return "${result}"
}

validate() {
    check
}

rollback() {
    if [[ "${RLCH_CIS_1_3_1_INSTALLED_BY_MODULE}" != "true" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    dnf_remove_package "${RLCH_CIS_1_3_1_PACKAGE}"
}
