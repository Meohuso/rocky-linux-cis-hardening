#!/usr/bin/env bash
#
# Test helper for CIS 2.1.16.
#
# SPDX-License-Identifier: MIT
#

tftp_server_helper_setup() {
    export RLCH_CIS_2_1_16_TEST_ROOT="${BATS_TEST_TMPDIR}/cis-2.1.16"
    export RLCH_CIS_2_1_16_STATE_DIR="${RLCH_CIS_2_1_16_TEST_ROOT}/state"
    export RLCH_CIS_2_1_16_STATE_FILE="${RLCH_CIS_2_1_16_STATE_DIR}/package-removed"

    export RLCH_CIS_2_1_16_PACKAGE="tftp-server"
    export RLCH_CIS_2_1_16_RPM_COMMAND="rlch_test_tftp_rpm"
    export RLCH_CIS_2_1_16_DNF_COMMAND="rlch_test_tftp_dnf"
    export RLCH_CIS_2_1_16_ID_COMMAND="rlch_test_tftp_id"

    export RLCH_TEST_TFTP_INSTALLED="false"
    export RLCH_TEST_TFTP_EFFECTIVE_UID="0"
    export RLCH_TEST_TFTP_ID_FAIL="false"
    export RLCH_TEST_TFTP_DNF_REMOVE_FAIL="false"
    export RLCH_TEST_TFTP_DNF_INSTALL_FAIL="false"
    export RLCH_TEST_TFTP_KEEP_INSTALLED_AFTER_REMOVE="false"
    export RLCH_TEST_TFTP_KEEP_REMOVED_AFTER_INSTALL="false"

    mkdir -p "${RLCH_CIS_2_1_16_TEST_ROOT}"
}

rlch_test_tftp_rpm() {
    if [[ "${1:-}" != "-q" ]]; then
        return 1
    fi

    if [[ "${2:-}" != "${RLCH_CIS_2_1_16_PACKAGE}" ]]; then
        return 1
    fi

    [[ "${RLCH_TEST_TFTP_INSTALLED}" == "true" ]]
}

rlch_test_tftp_id() {
    if [[ "${1:-}" != "-u" ]]; then
        return 1
    fi

    if [[ "${RLCH_TEST_TFTP_ID_FAIL}" == "true" ]]; then
        return 1
    fi

    printf '%s\n' "${RLCH_TEST_TFTP_EFFECTIVE_UID}"
}

rlch_test_tftp_dnf() {
    local option="${1:-}"
    local action="${2:-}"
    local package="${3:-}"

    if [[ "${option}" != "-y" ]]; then
        return 1
    fi

    if [[ "${package}" != "${RLCH_CIS_2_1_16_PACKAGE}" ]]; then
        return 1
    fi

    case "${action}" in
        remove)
            if [[ "${RLCH_TEST_TFTP_DNF_REMOVE_FAIL}" == "true" ]]; then
                return 1
            fi

            if [[ "${RLCH_TEST_TFTP_KEEP_INSTALLED_AFTER_REMOVE}" != "true" ]]; then
                export RLCH_TEST_TFTP_INSTALLED="false"
            fi
            ;;
        install)
            if [[ "${RLCH_TEST_TFTP_DNF_INSTALL_FAIL}" == "true" ]]; then
                return 1
            fi

            if [[ "${RLCH_TEST_TFTP_KEEP_REMOVED_AFTER_INSTALL}" != "true" ]]; then
                export RLCH_TEST_TFTP_INSTALLED="true"
            fi
            ;;
        *)
            return 1
            ;;
    esac

    return 0
}
