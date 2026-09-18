#!/usr/bin/env bash
# Test helper for CIS 4.1.1.
# SPDX-License-Identifier: MIT

nftables_package_helper_setup() {
    export RLCH_TEST_NFTABLES_ROOT="${BATS_TEST_TMPDIR}/cis-4.1.1"
    export RLCH_CIS_4_1_1_STATE_DIR="${RLCH_TEST_NFTABLES_ROOT}/state"
    export RLCH_CIS_4_1_1_STATE_FILE="${RLCH_CIS_4_1_1_STATE_DIR}/package-installed"
    export RLCH_CIS_4_1_1_PACKAGE="nftables"
    export RLCH_CIS_4_1_1_RPM_COMMAND="rlch_test_nftables_rpm"
    export RLCH_CIS_4_1_1_DNF_COMMAND="rlch_test_nftables_dnf"
    export RLCH_CIS_4_1_1_ID_COMMAND="rlch_test_nftables_id"

    export RLCH_TEST_NFTABLES_INSTALLED="false"
    export RLCH_TEST_NFTABLES_EFFECTIVE_UID="0"
    export RLCH_TEST_NFTABLES_ID_FAIL="false"
    export RLCH_TEST_NFTABLES_INSTALL_FAIL="false"
    export RLCH_TEST_NFTABLES_REMOVE_FAIL="false"
    export RLCH_TEST_NFTABLES_KEEP_ABSENT="false"
    export RLCH_TEST_NFTABLES_KEEP_INSTALLED="false"

    mkdir -p "${RLCH_TEST_NFTABLES_ROOT}"
}

rlch_test_nftables_rpm() {
    [[ "${1:-}" == "-q" ]] || return 1
    [[ "${2:-}" == "${RLCH_CIS_4_1_1_PACKAGE}" ]] || return 1
    [[ "${RLCH_TEST_NFTABLES_INSTALLED}" == "true" ]]
}

rlch_test_nftables_id() {
    [[ "${1:-}" == "-u" ]] || return 1
    [[ "${RLCH_TEST_NFTABLES_ID_FAIL}" != "true" ]] || return 1
    printf '%s\n' "${RLCH_TEST_NFTABLES_EFFECTIVE_UID}"
}

rlch_test_nftables_dnf() {
    [[ "${1:-}" == "-y" ]] || return 1
    [[ "${3:-}" == "${RLCH_CIS_4_1_1_PACKAGE}" ]] || return 1

    case "${2:-}" in
        install)
            [[ "${RLCH_TEST_NFTABLES_INSTALL_FAIL}" != "true" ]] || return 1
            if [[ "${RLCH_TEST_NFTABLES_KEEP_ABSENT}" != "true" ]]; then
                export RLCH_TEST_NFTABLES_INSTALLED="true"
            fi
            ;;
        remove)
            [[ "${RLCH_TEST_NFTABLES_REMOVE_FAIL}" != "true" ]] || return 1
            if [[ "${RLCH_TEST_NFTABLES_KEEP_INSTALLED}" != "true" ]]; then
                export RLCH_TEST_NFTABLES_INSTALLED="false"
            fi
            ;;
        *)
            return 1
            ;;
    esac
}
