#!/usr/bin/env bash
#
# Test helper for CIS 2.1.15.
#
# SPDX-License-Identifier: MIT
#

telnet_server_helper_setup() {
    export RLCH_CIS_2_1_15_TEST_ROOT="${BATS_TEST_TMPDIR}/cis-2.1.15"
    export RLCH_CIS_2_1_15_STATE_DIR="${RLCH_CIS_2_1_15_TEST_ROOT}/state"
    export RLCH_CIS_2_1_15_STATE_FILE="${RLCH_CIS_2_1_15_STATE_DIR}/package-removed"

    export RLCH_CIS_2_1_15_PACKAGE="telnet-server"
    export RLCH_CIS_2_1_15_RPM_COMMAND="rlch_test_telnet_rpm"
    export RLCH_CIS_2_1_15_DNF_COMMAND="rlch_test_telnet_dnf"
    export RLCH_CIS_2_1_15_ID_COMMAND="rlch_test_telnet_id"

    export RLCH_TEST_TELNET_INSTALLED="false"
    export RLCH_TEST_TELNET_EFFECTIVE_UID="0"
    export RLCH_TEST_TELNET_ID_FAIL="false"
    export RLCH_TEST_TELNET_DNF_REMOVE_FAIL="false"
    export RLCH_TEST_TELNET_DNF_INSTALL_FAIL="false"
    export RLCH_TEST_TELNET_KEEP_INSTALLED_AFTER_REMOVE="false"
    export RLCH_TEST_TELNET_KEEP_REMOVED_AFTER_INSTALL="false"

    mkdir -p "${RLCH_CIS_2_1_15_TEST_ROOT}"
}

rlch_test_telnet_rpm() {
    if [[ "${1:-}" != "-q" ]]; then
        return 1
    fi

    if [[ "${2:-}" != "${RLCH_CIS_2_1_15_PACKAGE}" ]]; then
        return 1
    fi

    [[ "${RLCH_TEST_TELNET_INSTALLED}" == "true" ]]
}

rlch_test_telnet_id() {
    if [[ "${1:-}" != "-u" ]]; then
        return 1
    fi

    if [[ "${RLCH_TEST_TELNET_ID_FAIL}" == "true" ]]; then
        return 1
    fi

    printf '%s\n' "${RLCH_TEST_TELNET_EFFECTIVE_UID}"
}

rlch_test_telnet_dnf() {
    local option="${1:-}"
    local action="${2:-}"
    local package="${3:-}"

    if [[ "${option}" != "-y" ]]; then
        return 1
    fi

    if [[ "${package}" != "${RLCH_CIS_2_1_15_PACKAGE}" ]]; then
        return 1
    fi

    case "${action}" in
        remove)
            if [[ "${RLCH_TEST_TELNET_DNF_REMOVE_FAIL}" == "true" ]]; then
                return 1
            fi

            if [[ "${RLCH_TEST_TELNET_KEEP_INSTALLED_AFTER_REMOVE}" != "true" ]]; then
                export RLCH_TEST_TELNET_INSTALLED="false"
            fi
            ;;
        install)
            if [[ "${RLCH_TEST_TELNET_DNF_INSTALL_FAIL}" == "true" ]]; then
                return 1
            fi

            if [[ "${RLCH_TEST_TELNET_KEEP_REMOVED_AFTER_INSTALL}" != "true" ]]; then
                export RLCH_TEST_TELNET_INSTALLED="true"
            fi
            ;;
        *)
            return 1
            ;;
    esac

    return 0
}
