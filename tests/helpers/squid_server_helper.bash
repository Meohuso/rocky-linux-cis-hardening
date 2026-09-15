#!/usr/bin/env bash
#
# Test helper for CIS 2.1.17.
# SPDX-License-Identifier: MIT
#

squid_server_helper_setup() {
    export RLCH_CIS_2_1_17_TEST_ROOT="${BATS_TEST_TMPDIR}/cis-2.1.17"
    export RLCH_CIS_2_1_17_STATE_DIR="${RLCH_CIS_2_1_17_TEST_ROOT}/state"
    export RLCH_CIS_2_1_17_STATE_FILE="${RLCH_CIS_2_1_17_STATE_DIR}/package-removed"
    export RLCH_CIS_2_1_17_PACKAGE="squid"
    export RLCH_CIS_2_1_17_RPM_COMMAND="rlch_test_squid_rpm"
    export RLCH_CIS_2_1_17_DNF_COMMAND="rlch_test_squid_dnf"
    export RLCH_CIS_2_1_17_ID_COMMAND="rlch_test_squid_id"

    export RLCH_TEST_SQUID_INSTALLED="false"
    export RLCH_TEST_SQUID_EFFECTIVE_UID="0"
    export RLCH_TEST_SQUID_ID_FAIL="false"
    export RLCH_TEST_SQUID_DNF_REMOVE_FAIL="false"
    export RLCH_TEST_SQUID_DNF_INSTALL_FAIL="false"
    export RLCH_TEST_SQUID_KEEP_INSTALLED_AFTER_REMOVE="false"
    export RLCH_TEST_SQUID_KEEP_REMOVED_AFTER_INSTALL="false"

    mkdir -p "${RLCH_CIS_2_1_17_TEST_ROOT}"
}

rlch_test_squid_rpm() {
    [[ "${1:-}" == "-q" ]] || return 1
    [[ "${2:-}" == "${RLCH_CIS_2_1_17_PACKAGE}" ]] || return 1
    [[ "${RLCH_TEST_SQUID_INSTALLED}" == "true" ]]
}

rlch_test_squid_id() {
    [[ "${1:-}" == "-u" ]] || return 1
    [[ "${RLCH_TEST_SQUID_ID_FAIL}" != "true" ]] || return 1
    printf '%s\n' "${RLCH_TEST_SQUID_EFFECTIVE_UID}"
}

rlch_test_squid_dnf() {
    local option="${1:-}"
    local action="${2:-}"
    local package="${3:-}"

    [[ "${option}" == "-y" ]] || return 1
    [[ "${package}" == "${RLCH_CIS_2_1_17_PACKAGE}" ]] || return 1

    case "${action}" in
        remove)
            [[ "${RLCH_TEST_SQUID_DNF_REMOVE_FAIL}" != "true" ]] || return 1
            if [[ "${RLCH_TEST_SQUID_KEEP_INSTALLED_AFTER_REMOVE}" != "true" ]]; then
                export RLCH_TEST_SQUID_INSTALLED="false"
            fi
            ;;
        install)
            [[ "${RLCH_TEST_SQUID_DNF_INSTALL_FAIL}" != "true" ]] || return 1
            if [[ "${RLCH_TEST_SQUID_KEEP_REMOVED_AFTER_INSTALL}" != "true" ]]; then
                export RLCH_TEST_SQUID_INSTALLED="true"
            fi
            ;;
        *)
            return 1
            ;;
    esac
}
