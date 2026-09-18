#!/usr/bin/env bash
# Test helper for CIS 4.1.2.
# SPDX-License-Identifier: MIT

firewall_utility_helper_setup() {
    export RLCH_TEST_FIREWALL_ROOT="${BATS_TEST_TMPDIR}/cis-4.1.2"
    export RLCH_CIS_4_1_2_STATE_DIR="${RLCH_TEST_FIREWALL_ROOT}/state"
    export RLCH_CIS_4_1_2_STATE_FILE="${RLCH_CIS_4_1_2_STATE_DIR}/state"
    export RLCH_CIS_4_1_2_PACKAGE_STATE_FILE="${RLCH_CIS_4_1_2_STATE_DIR}/firewalld-package-state"
    export RLCH_CIS_4_1_2_FIREWALLD_ENABLED_FILE="${RLCH_CIS_4_1_2_STATE_DIR}/firewalld-enabled-state"
    export RLCH_CIS_4_1_2_FIREWALLD_ACTIVE_FILE="${RLCH_CIS_4_1_2_STATE_DIR}/firewalld-active-state"
    export RLCH_CIS_4_1_2_NFTABLES_ENABLED_FILE="${RLCH_CIS_4_1_2_STATE_DIR}/nftables-enabled-state"
    export RLCH_CIS_4_1_2_NFTABLES_ACTIVE_FILE="${RLCH_CIS_4_1_2_STATE_DIR}/nftables-active-state"
    export RLCH_CIS_4_1_2_RPM_COMMAND="rlch_test_firewall_rpm"
    export RLCH_CIS_4_1_2_DNF_COMMAND="rlch_test_firewall_dnf"
    export RLCH_CIS_4_1_2_SYSTEMCTL_COMMAND="rlch_test_firewall_systemctl"
    export RLCH_CIS_4_1_2_ID_COMMAND="rlch_test_firewall_id"

    export RLCH_TEST_FIREWALLD_INSTALLED="false"
    export RLCH_TEST_FIREWALLD_ENABLED="absent"
    export RLCH_TEST_FIREWALLD_ACTIVE="inactive"
    export RLCH_TEST_NFTABLES_ENABLED="disabled"
    export RLCH_TEST_NFTABLES_ACTIVE="inactive"
    export RLCH_TEST_FIREWALL_EFFECTIVE_UID="0"
    export RLCH_TEST_FIREWALL_ID_FAIL="false"
    export RLCH_TEST_FIREWALL_DNF_INSTALL_FAIL="false"
    export RLCH_TEST_FIREWALL_DNF_REMOVE_FAIL="false"
    export RLCH_TEST_FIREWALL_FAIL_ACTION=""

    mkdir -p "${RLCH_TEST_FIREWALL_ROOT}"
}

firewall_utility_helper_set_firewalld() {
    export RLCH_TEST_FIREWALLD_INSTALLED="true"
    export RLCH_TEST_FIREWALLD_ENABLED="${1:-disabled}"
    export RLCH_TEST_FIREWALLD_ACTIVE="${2:-inactive}"
}

firewall_utility_helper_set_nftables() {
    export RLCH_TEST_NFTABLES_ENABLED="${1:-disabled}"
    export RLCH_TEST_NFTABLES_ACTIVE="${2:-inactive}"
}

rlch_test_firewall_rpm() {
    [[ "${1:-}" == "-q" ]] || return 1
    [[ "${2:-}" == "firewalld" ]] || return 1
    [[ "${RLCH_TEST_FIREWALLD_INSTALLED}" == "true" ]]
}

rlch_test_firewall_id() {
    [[ "${1:-}" == "-u" ]] || return 1
    [[ "${RLCH_TEST_FIREWALL_ID_FAIL}" != "true" ]] || return 1
    printf '%s\n' "${RLCH_TEST_FIREWALL_EFFECTIVE_UID}"
}

rlch_test_firewall_dnf() {
    [[ "${1:-}" == "-y" ]] || return 1
    [[ "${3:-}" == "firewalld" ]] || return 1

    case "${2:-}" in
        install)
            [[ "${RLCH_TEST_FIREWALL_DNF_INSTALL_FAIL}" != "true" ]] || return 1
            export RLCH_TEST_FIREWALLD_INSTALLED="true"
            export RLCH_TEST_FIREWALLD_ENABLED="disabled"
            export RLCH_TEST_FIREWALLD_ACTIVE="inactive"
            ;;
        remove)
            [[ "${RLCH_TEST_FIREWALL_DNF_REMOVE_FAIL}" != "true" ]] || return 1
            export RLCH_TEST_FIREWALLD_INSTALLED="false"
            export RLCH_TEST_FIREWALLD_ENABLED="absent"
            export RLCH_TEST_FIREWALLD_ACTIVE="inactive"
            ;;
        *)
            return 1
            ;;
    esac
}

rlch_test_firewall_systemctl() {
    local action="${1:-}"
    local option=""
    local service_name="${2:-}"

    if [[ "${action}" == "is-active" && "${service_name}" == "--quiet" ]]; then
        service_name="${3:-}"
    elif [[ "${action}" == "mask" && "${service_name}" == "--runtime" ]]; then
        option="--runtime"
        service_name="${3:-}"
    fi

    [[ "${RLCH_TEST_FIREWALL_FAIL_ACTION}" != "${action}:${service_name}" ]] || return 1

    case "${action}:${service_name}" in
        is-enabled:firewalld.service)
            printf '%s\n' "${RLCH_TEST_FIREWALLD_ENABLED}"
            [[ "${RLCH_TEST_FIREWALLD_ENABLED}" == "enabled" ]]
            ;;
        is-enabled:nftables.service)
            printf '%s\n' "${RLCH_TEST_NFTABLES_ENABLED}"
            [[ "${RLCH_TEST_NFTABLES_ENABLED}" == "enabled" ]]
            ;;
        is-active:firewalld.service)
            [[ "${RLCH_TEST_FIREWALLD_ACTIVE}" == "active" ]]
            ;;
        is-active:nftables.service)
            [[ "${RLCH_TEST_NFTABLES_ACTIVE}" == "active" ]]
            ;;
        unmask:firewalld.service)
            export RLCH_TEST_FIREWALLD_ENABLED="disabled"
            ;;
        unmask:nftables.service)
            export RLCH_TEST_NFTABLES_ENABLED="disabled"
            ;;
        enable:firewalld.service)
            export RLCH_TEST_FIREWALLD_ENABLED="enabled"
            ;;
        enable:nftables.service)
            export RLCH_TEST_NFTABLES_ENABLED="enabled"
            ;;
        disable:firewalld.service)
            export RLCH_TEST_FIREWALLD_ENABLED="disabled"
            ;;
        disable:nftables.service)
            export RLCH_TEST_NFTABLES_ENABLED="disabled"
            ;;
        start:firewalld.service)
            export RLCH_TEST_FIREWALLD_ACTIVE="active"
            ;;
        start:nftables.service)
            export RLCH_TEST_NFTABLES_ACTIVE="active"
            ;;
        stop:firewalld.service)
            export RLCH_TEST_FIREWALLD_ACTIVE="inactive"
            ;;
        stop:nftables.service)
            export RLCH_TEST_NFTABLES_ACTIVE="inactive"
            ;;
        mask:firewalld.service)
            if [[ "${option}" == "--runtime" ]]; then
                export RLCH_TEST_FIREWALLD_ENABLED="masked-runtime"
            else
                export RLCH_TEST_FIREWALLD_ENABLED="masked"
            fi
            ;;
        mask:nftables.service)
            if [[ "${option}" == "--runtime" ]]; then
                export RLCH_TEST_NFTABLES_ENABLED="masked-runtime"
            else
                export RLCH_TEST_NFTABLES_ENABLED="masked"
            fi
            ;;
        *)
            return 1
            ;;
    esac
}
