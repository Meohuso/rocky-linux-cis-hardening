#!/usr/bin/env bash
#
# Test helper for CIS 2.2.5.
# SPDX-License-Identifier: MIT
#

tftp_client_helper_setup() {
    export RLCH_CIS_2_2_5_TEST_ROOT="${BATS_TEST_TMPDIR}/cis-2.2.5"
    export RLCH_CIS_2_2_5_STATE_DIR="${RLCH_CIS_2_2_5_TEST_ROOT}/state"
    export RLCH_CIS_2_2_5_STATE_FILE="${RLCH_CIS_2_2_5_STATE_DIR}/package-removed"
    export RLCH_CIS_2_2_5_PACKAGE="tftp"
    export RLCH_CIS_2_2_5_RPM_COMMAND="rlch_test_tftp_client_rpm"
    export RLCH_CIS_2_2_5_DNF_COMMAND="rlch_test_tftp_client_dnf"
    export RLCH_CIS_2_2_5_ID_COMMAND="rlch_test_tftp_client_id"

    export RLCH_TEST_TFTP_CLIENT_INSTALLED="false"
    export RLCH_TEST_TFTP_CLIENT_EFFECTIVE_UID="0"
    export RLCH_TEST_TFTP_CLIENT_ID_FAIL="false"
    export RLCH_TEST_TFTP_CLIENT_DNF_REMOVE_FAIL="false"
    export RLCH_TEST_TFTP_CLIENT_DNF_INSTALL_FAIL="false"
    export RLCH_TEST_TFTP_CLIENT_KEEP_INSTALLED_AFTER_REMOVE="false"
    export RLCH_TEST_TFTP_CLIENT_KEEP_REMOVED_AFTER_INSTALL="false"

    mkdir -p "${RLCH_CIS_2_2_5_TEST_ROOT}"
}
rlch_test_tftp_client_rpm() {
    [[ "${1:-}" == "-q" ]] || return 1
    [[ "${2:-}" == "${RLCH_CIS_2_2_5_PACKAGE}" ]] || return 1
    [[ "${RLCH_TEST_TFTP_CLIENT_INSTALLED}" == "true" ]]
}

rlch_test_tftp_client_id() {
    [[ "${1:-}" == "-u" ]] || return 1
    [[ "${RLCH_TEST_TFTP_CLIENT_ID_FAIL}" != "true" ]] || return 1
    printf '%s\n' "${RLCH_TEST_TFTP_CLIENT_EFFECTIVE_UID}"
}

rlch_test_tftp_client_dnf() {
    local action="${2:-}"
    local package_name="${3:-}"

    [[ "${1:-}" == "-y" ]] || return 1
    [[ "${package_name}" == "${RLCH_CIS_2_2_5_PACKAGE}" ]] || return 1

    case "${action}" in
        remove)
            [[ "${RLCH_TEST_TFTP_CLIENT_DNF_REMOVE_FAIL}" != "true" ]] || return 1
            if [[ "${RLCH_TEST_TFTP_CLIENT_KEEP_INSTALLED_AFTER_REMOVE}" != "true" ]]; then
                export RLCH_TEST_TFTP_CLIENT_INSTALLED="false"
            fi
            ;;
        install)
            [[ "${RLCH_TEST_TFTP_CLIENT_DNF_INSTALL_FAIL}" != "true" ]] || return 1
            if [[ "${RLCH_TEST_TFTP_CLIENT_KEEP_REMOVED_AFTER_INSTALL}" != "true" ]]; then
                export RLCH_TEST_TFTP_CLIENT_INSTALLED="true"
            fi
            ;;
        *)
            return 1
            ;;
    esac
}
