#!/usr/bin/env bash
#
# Test helper for CIS 2.3.1.
# SPDX-License-Identifier: MIT
#

chrony_package_helper_setup() {
    export RLCH_CIS_2_3_1_TEST_ROOT="${BATS_TEST_TMPDIR}/cis-2.3.1"
    export RLCH_CIS_2_3_1_STATE_DIR="${RLCH_CIS_2_3_1_TEST_ROOT}/state"
    export RLCH_CIS_2_3_1_STATE_FILE="${RLCH_CIS_2_3_1_STATE_DIR}/package-installed"
    export RLCH_CIS_2_3_1_PACKAGE="chrony"
    export RLCH_CIS_2_3_1_RPM_COMMAND="rlch_test_chrony_package_rpm"
    export RLCH_CIS_2_3_1_DNF_COMMAND="rlch_test_chrony_package_dnf"
    export RLCH_CIS_2_3_1_ID_COMMAND="rlch_test_chrony_package_id"

    export RLCH_TEST_CHRONY_PACKAGE_INSTALLED="false"
    export RLCH_TEST_CHRONY_PACKAGE_EFFECTIVE_UID="0"
    export RLCH_TEST_CHRONY_PACKAGE_ID_FAIL="false"
    export RLCH_TEST_CHRONY_PACKAGE_DNF_INSTALL_FAIL="false"
    export RLCH_TEST_CHRONY_PACKAGE_DNF_REMOVE_FAIL="false"
    export RLCH_TEST_CHRONY_PACKAGE_KEEP_REMOVED_AFTER_INSTALL="false"
    export RLCH_TEST_CHRONY_PACKAGE_KEEP_INSTALLED_AFTER_REMOVE="false"

    mkdir -p "${RLCH_CIS_2_3_1_TEST_ROOT}"
}

rlch_test_chrony_package_rpm() {
    [[ "${1:-}" == "-q" ]] || return 1
    [[ "${2:-}" == "${RLCH_CIS_2_3_1_PACKAGE}" ]] || return 1
    [[ "${RLCH_TEST_CHRONY_PACKAGE_INSTALLED}" == "true" ]]
}

rlch_test_chrony_package_id() {
    [[ "${1:-}" == "-u" ]] || return 1
    [[ "${RLCH_TEST_CHRONY_PACKAGE_ID_FAIL}" != "true" ]] || return 1
    printf '%s\n' "${RLCH_TEST_CHRONY_PACKAGE_EFFECTIVE_UID}"
}

rlch_test_chrony_package_dnf() {
    local action="${2:-}"
    local package_name="${3:-}"

    [[ "${1:-}" == "-y" ]] || return 1
    [[ "${package_name}" == "${RLCH_CIS_2_3_1_PACKAGE}" ]] || return 1

    case "${action}" in
        install)
            [[ "${RLCH_TEST_CHRONY_PACKAGE_DNF_INSTALL_FAIL}" != "true" ]] || return 1
            if [[ "${RLCH_TEST_CHRONY_PACKAGE_KEEP_REMOVED_AFTER_INSTALL}" != "true" ]]; then
                export RLCH_TEST_CHRONY_PACKAGE_INSTALLED="true"
            fi
            ;;
        remove)
            [[ "${RLCH_TEST_CHRONY_PACKAGE_DNF_REMOVE_FAIL}" != "true" ]] || return 1
            if [[ "${RLCH_TEST_CHRONY_PACKAGE_KEEP_INSTALLED_AFTER_REMOVE}" != "true" ]]; then
                export RLCH_TEST_CHRONY_PACKAGE_INSTALLED="false"
            fi
            ;;
        *)
            return 1
            ;;
    esac
}
