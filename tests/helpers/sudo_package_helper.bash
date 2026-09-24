#!/usr/bin/env bash
# Test helper for CIS 5.2.1.
# SPDX-License-Identifier: MIT

sudo_package_helper_setup() {
    export RLCH_TEST_SUDO_ROOT="${BATS_TEST_TMPDIR}/cis-5.2.1"
    export RLCH_CIS_5_2_1_STATE_DIR="${RLCH_TEST_SUDO_ROOT}/state"
    export RLCH_CIS_5_2_1_STATE_FILE="${RLCH_CIS_5_2_1_STATE_DIR}/package-installed"
    export RLCH_CIS_5_2_1_PACKAGE="sudo"
    export RLCH_CIS_5_2_1_RPM_COMMAND="rlch_test_sudo_rpm"
    export RLCH_CIS_5_2_1_DNF_COMMAND="rlch_test_sudo_dnf"
    export RLCH_CIS_5_2_1_ID_COMMAND="rlch_test_sudo_id"
    export RLCH_TEST_SUDO_INSTALLED=false RLCH_TEST_SUDO_UID=0 RLCH_TEST_SUDO_ID_FAIL=false
    export RLCH_TEST_SUDO_INSTALL_FAIL=false RLCH_TEST_SUDO_REMOVE_FAIL=false
    export RLCH_TEST_SUDO_KEEP_ABSENT=false RLCH_TEST_SUDO_KEEP_INSTALLED=false
    mkdir -p -- "${RLCH_TEST_SUDO_ROOT}"
}

rlch_test_sudo_rpm() {
    [[ "${1:-}" == -q && "${2:-}" == "${RLCH_CIS_5_2_1_PACKAGE}" && "${RLCH_TEST_SUDO_INSTALLED}" == true ]]
}

rlch_test_sudo_id() {
    [[ "${1:-}" == -u && "${RLCH_TEST_SUDO_ID_FAIL}" != true ]] || return 1
    printf '%s\n' "${RLCH_TEST_SUDO_UID}"
}

rlch_test_sudo_dnf() {
    [[ "${1:-}" == -y && "${3:-}" == "${RLCH_CIS_5_2_1_PACKAGE}" ]] || return 1
    case "${2:-}" in
        install)
            [[ "${RLCH_TEST_SUDO_INSTALL_FAIL}" != true ]] || return 1
            [[ "${RLCH_TEST_SUDO_KEEP_ABSENT}" == true ]] || export RLCH_TEST_SUDO_INSTALLED=true
            ;;
        remove)
            [[ "${RLCH_TEST_SUDO_REMOVE_FAIL}" != true ]] || return 1
            [[ "${RLCH_TEST_SUDO_KEEP_INSTALLED}" == true ]] || export RLCH_TEST_SUDO_INSTALLED=false
            ;;
        *) return 1 ;;
    esac
}
