#!/usr/bin/env bash
#
# Test helper for CIS 2.1.19.
# SPDX-License-Identifier: MIT
#

xinetd_server_helper_setup() {
    export RLCH_CIS_2_1_19_TEST_ROOT="${BATS_TEST_TMPDIR}/cis-2.1.19"
    export RLCH_CIS_2_1_19_STATE_DIR="${RLCH_CIS_2_1_19_TEST_ROOT}/state"
    export RLCH_CIS_2_1_19_STATE_FILE="${RLCH_CIS_2_1_19_STATE_DIR}/package-removed"
    export RLCH_CIS_2_1_19_PACKAGE="xinetd"
    export RLCH_CIS_2_1_19_RPM_COMMAND="rlch_test_xinetd_rpm"
    export RLCH_CIS_2_1_19_DNF_COMMAND="rlch_test_xinetd_dnf"
    export RLCH_CIS_2_1_19_ID_COMMAND="rlch_test_xinetd_id"

    export RLCH_TEST_XINETD_INSTALLED="false"
    export RLCH_TEST_XINETD_EFFECTIVE_UID="0"
    export RLCH_TEST_XINETD_ID_FAIL="false"
    export RLCH_TEST_XINETD_DNF_REMOVE_FAIL="false"
    export RLCH_TEST_XINETD_DNF_INSTALL_FAIL="false"
    export RLCH_TEST_XINETD_KEEP_INSTALLED_AFTER_REMOVE="false"
    export RLCH_TEST_XINETD_KEEP_REMOVED_AFTER_INSTALL="false"

    mkdir -p "${RLCH_CIS_2_1_19_TEST_ROOT}"
}

rlch_test_xinetd_rpm() {
    [[ "${1:-}" == "-q" ]] || return 1
    [[ "${2:-}" == "${RLCH_CIS_2_1_19_PACKAGE}" ]] || return 1
    [[ "${RLCH_TEST_XINETD_INSTALLED}" == "true" ]]
}

rlch_test_xinetd_id() {
    [[ "${1:-}" == "-u" ]] || return 1
    [[ "${RLCH_TEST_XINETD_ID_FAIL}" != "true" ]] || return 1
    printf '%s\n' "${RLCH_TEST_XINETD_EFFECTIVE_UID}"
}

rlch_test_xinetd_dnf() {
    local action="${2:-}"
    local package_name="${3:-}"

    [[ "${1:-}" == "-y" ]] || return 1
    [[ "${package_name}" == "${RLCH_CIS_2_1_19_PACKAGE}" ]] || return 1

    case "${action}" in
        remove)
            [[ "${RLCH_TEST_XINETD_DNF_REMOVE_FAIL}" != "true" ]] || return 1
            if [[ "${RLCH_TEST_XINETD_KEEP_INSTALLED_AFTER_REMOVE}" != "true" ]]; then
                export RLCH_TEST_XINETD_INSTALLED="false"
            fi
            ;;
        install)
            [[ "${RLCH_TEST_XINETD_DNF_INSTALL_FAIL}" != "true" ]] || return 1
            if [[ "${RLCH_TEST_XINETD_KEEP_REMOVED_AFTER_INSTALL}" != "true" ]]; then
                export RLCH_TEST_XINETD_INSTALLED="true"
            fi
            ;;
        *)
            return 1
            ;;
    esac
}
