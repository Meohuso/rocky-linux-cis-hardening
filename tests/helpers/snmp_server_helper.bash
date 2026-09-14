#!/usr/bin/env bash
#
# Test helper for CIS 2.1.14.
#
# SPDX-License-Identifier: MIT
#

snmp_server_helper_setup() {
    export RLCH_CIS_2_1_14_TEST_ROOT="${BATS_TEST_TMPDIR}/cis-2.1.14"
    export RLCH_CIS_2_1_14_STATE_DIR="${RLCH_CIS_2_1_14_TEST_ROOT}/state"
    export RLCH_CIS_2_1_14_STATE_FILE="${RLCH_CIS_2_1_14_STATE_DIR}/package-removed"

    export RLCH_CIS_2_1_14_PACKAGE="net-snmp"
    export RLCH_CIS_2_1_14_RPM_COMMAND="rlch_test_snmp_rpm"
    export RLCH_CIS_2_1_14_DNF_COMMAND="rlch_test_snmp_dnf"
    export RLCH_CIS_2_1_14_ID_COMMAND="rlch_test_snmp_id"

    export RLCH_TEST_SNMP_INSTALLED="false"
    export RLCH_TEST_SNMP_EFFECTIVE_UID="0"
    export RLCH_TEST_SNMP_ID_FAIL="false"
    export RLCH_TEST_SNMP_DNF_REMOVE_FAIL="false"
    export RLCH_TEST_SNMP_DNF_INSTALL_FAIL="false"
    export RLCH_TEST_SNMP_KEEP_INSTALLED_AFTER_REMOVE="false"
    export RLCH_TEST_SNMP_KEEP_REMOVED_AFTER_INSTALL="false"

    mkdir -p "${RLCH_CIS_2_1_14_TEST_ROOT}"
}

rlch_test_snmp_rpm() {
    if [[ "${1:-}" != "-q" ]]; then
        return 1
    fi

    if [[ "${2:-}" != "${RLCH_CIS_2_1_14_PACKAGE}" ]]; then
        return 1
    fi

    [[ "${RLCH_TEST_SNMP_INSTALLED}" == "true" ]]
}

rlch_test_snmp_id() {
    if [[ "${1:-}" != "-u" ]]; then
        return 1
    fi

    if [[ "${RLCH_TEST_SNMP_ID_FAIL}" == "true" ]]; then
        return 1
    fi

    printf '%s\n' "${RLCH_TEST_SNMP_EFFECTIVE_UID}"
}

rlch_test_snmp_dnf() {
    local option="${1:-}"
    local action="${2:-}"
    local package="${3:-}"

    if [[ "${option}" != "-y" ]]; then
        return 1
    fi

    if [[ "${package}" != "${RLCH_CIS_2_1_14_PACKAGE}" ]]; then
        return 1
    fi

    case "${action}" in
        remove)
            if [[ "${RLCH_TEST_SNMP_DNF_REMOVE_FAIL}" == "true" ]]; then
                return 1
            fi

            if [[ "${RLCH_TEST_SNMP_KEEP_INSTALLED_AFTER_REMOVE}" != "true" ]]; then
                export RLCH_TEST_SNMP_INSTALLED="false"
            fi
            ;;
        install)
            if [[ "${RLCH_TEST_SNMP_DNF_INSTALL_FAIL}" == "true" ]]; then
                return 1
            fi

            if [[ "${RLCH_TEST_SNMP_KEEP_REMOVED_AFTER_INSTALL}" != "true" ]]; then
                export RLCH_TEST_SNMP_INSTALLED="true"
            fi
            ;;
        *)
            return 1
            ;;
    esac

    return 0
}
