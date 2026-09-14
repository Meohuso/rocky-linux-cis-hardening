#!/usr/bin/env bash
# Test helper for CIS 2.1.13.
# SPDX-License-Identifier: MIT

rsync_server_helper_setup() {
    export RLCH_CIS_2_1_13_TEST_ROOT="${BATS_TEST_TMPDIR}/cis-2.1.13"
    export RLCH_CIS_2_1_13_STATE_DIR="${RLCH_CIS_2_1_13_TEST_ROOT}/state"
    export RLCH_CIS_2_1_13_STATE_FILE="${RLCH_CIS_2_1_13_STATE_DIR}/package-removed"
    export RLCH_CIS_2_1_13_PACKAGE="rsync"
    export RLCH_CIS_2_1_13_RPM_COMMAND="rlch_test_rpm"
    export RLCH_CIS_2_1_13_DNF_COMMAND="rlch_test_dnf"
    export RLCH_TEST_RSYNC_INSTALLED="false"
    export RLCH_TEST_RSYNC_DNF_REMOVE_FAIL="false"
    export RLCH_TEST_RSYNC_DNF_INSTALL_FAIL="false"
    export RLCH_TEST_RSYNC_KEEP_INSTALLED_AFTER_REMOVE="false"
    export RLCH_TEST_RSYNC_KEEP_REMOVED_AFTER_INSTALL="false"
    mkdir -p "${RLCH_CIS_2_1_13_TEST_ROOT}"
}

rlch_test_rpm() {
    [[ "${1:-}" == "-q" ]] || return 1
    [[ "${2:-}" == "${RLCH_CIS_2_1_13_PACKAGE}" ]] || return 1
    [[ "${RLCH_TEST_RSYNC_INSTALLED}" == "true" ]]
}

rlch_test_dnf() {
    local option="${1:-}"
    local action="${2:-}"
    local package="${3:-}"
    [[ "${option}" == "-y" ]] || return 1
    [[ "${package}" == "${RLCH_CIS_2_1_13_PACKAGE}" ]] || return 1
    case "${action}" in
        remove)
            [[ "${RLCH_TEST_RSYNC_DNF_REMOVE_FAIL}" == "true" ]] && return 1
            if [[ "${RLCH_TEST_RSYNC_KEEP_INSTALLED_AFTER_REMOVE}" != "true" ]]; then
                export RLCH_TEST_RSYNC_INSTALLED="false"
            fi
            ;;
        install)
            [[ "${RLCH_TEST_RSYNC_DNF_INSTALL_FAIL}" == "true" ]] && return 1
            if [[ "${RLCH_TEST_RSYNC_KEEP_REMOVED_AFTER_INSTALL}" != "true" ]]; then
                export RLCH_TEST_RSYNC_INSTALLED="true"
            fi
            ;;
        *) return 1 ;;
    esac
    return 0
}
