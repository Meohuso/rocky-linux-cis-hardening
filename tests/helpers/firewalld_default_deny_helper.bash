#!/usr/bin/env bash
# Test helper for CIS 4.3.3.
# SPDX-License-Identifier: MIT

firewalld_default_deny_helper_setup() {
    export RLCH_TEST_DEFAULT_DENY_ROOT="${BATS_TEST_TMPDIR}/cis-4.3.3"
    export RLCH_TEST_DEFAULT_DENY_LOG="${RLCH_TEST_DEFAULT_DENY_ROOT}/commands"
    export RLCH_CIS_4_3_3_SYSTEMCTL_COMMAND="rlch_test_default_deny_systemctl"
    export RLCH_CIS_4_3_3_FIREWALL_CMD="rlch_test_default_deny_firewall_cmd"
    export RLCH_TEST_DEFAULT_DENY_FIREWALLD_ACTIVE="true"
    export RLCH_TEST_DEFAULT_DENY_FAIL=""
    export RLCH_TEST_DEFAULT_DENY_DEFAULT_ZONE="public"
    export RLCH_TEST_DEFAULT_DENY_ACTIVE_ZONES=$'public\n  interfaces: eth0\ntrusted\n  interfaces: lo'
    export RLCH_TEST_DEFAULT_DENY_PUBLIC_TARGET="default"
    export RLCH_TEST_DEFAULT_DENY_TRUSTED_TARGET="ACCEPT"
    export RLCH_TEST_DEFAULT_DENY_PUBLIC_INTERFACES="eth0"
    export RLCH_TEST_DEFAULT_DENY_PUBLIC_SOURCES=""
    export RLCH_TEST_DEFAULT_DENY_TRUSTED_INTERFACES="lo"
    export RLCH_TEST_DEFAULT_DENY_TRUSTED_SOURCES=""

    mkdir -p "${RLCH_TEST_DEFAULT_DENY_ROOT}"
}

rlch_test_default_deny_systemctl() {
    printf 'systemctl %s\n' "$*" >> "${RLCH_TEST_DEFAULT_DENY_LOG}"
    [[ "$*" == "is-active --quiet firewalld.service" ]] || return 2
    [[ "${RLCH_TEST_DEFAULT_DENY_FIREWALLD_ACTIVE}" == "true" ]]
}

rlch_test_default_deny_firewall_cmd() {
    printf 'firewall-cmd %s\n' "$*" >> "${RLCH_TEST_DEFAULT_DENY_LOG}"
    [[ "${RLCH_TEST_DEFAULT_DENY_FAIL}" != "$*" ]] || return 2

    case "$*" in
        --get-default-zone) printf '%s\n' "${RLCH_TEST_DEFAULT_DENY_DEFAULT_ZONE}" ;;
        --get-active-zones) printf '%s\n' "${RLCH_TEST_DEFAULT_DENY_ACTIVE_ZONES}" ;;
        "--zone=public --get-target") printf '%s\n' "${RLCH_TEST_DEFAULT_DENY_PUBLIC_TARGET}" ;;
        "--zone=trusted --get-target") printf '%s\n' "${RLCH_TEST_DEFAULT_DENY_TRUSTED_TARGET}" ;;
        "--zone=public --list-interfaces") printf '%s\n' "${RLCH_TEST_DEFAULT_DENY_PUBLIC_INTERFACES}" ;;
        "--zone=public --list-sources") printf '%s\n' "${RLCH_TEST_DEFAULT_DENY_PUBLIC_SOURCES}" ;;
        "--zone=trusted --list-interfaces") printf '%s\n' "${RLCH_TEST_DEFAULT_DENY_TRUSTED_INTERFACES}" ;;
        "--zone=trusted --list-sources") printf '%s\n' "${RLCH_TEST_DEFAULT_DENY_TRUSTED_SOURCES}" ;;
        *) return 2 ;;
    esac
}
