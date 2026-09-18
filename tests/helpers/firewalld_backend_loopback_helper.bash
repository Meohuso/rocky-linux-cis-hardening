#!/usr/bin/env bash
# Test helper for CIS 4.3.4.
# SPDX-License-Identifier: MIT

firewalld_backend_loopback_helper_setup() {
    export RLCH_TEST_BACKEND_LOOPBACK_ROOT="${BATS_TEST_TMPDIR}/cis-4.3.4"
    export RLCH_TEST_BACKEND_LOOPBACK_LOG="${RLCH_TEST_BACKEND_LOOPBACK_ROOT}/commands"
    export RLCH_CIS_4_3_4_SYSTEMCTL_COMMAND="rlch_test_backend_loopback_systemctl"
    export RLCH_CIS_4_3_4_FIREWALL_CMD="rlch_test_backend_loopback_firewall_cmd"
    export RLCH_CIS_4_3_4_NFT_COMMAND="rlch_test_backend_loopback_nft"
    export RLCH_TEST_BACKEND_LOOPBACK_FIREWALLD_ACTIVE="true"
    export RLCH_TEST_BACKEND_LOOPBACK_NFT_FAIL="false"
    export RLCH_TEST_BACKEND_LOOPBACK_TABLES="table inet firewalld"
    export RLCH_TEST_BACKEND_LOOPBACK_FAIL=""
    export RLCH_TEST_BACKEND_LOOPBACK_PERMANENT_INTERFACE="present"
    export RLCH_TEST_BACKEND_LOOPBACK_PERMANENT_IPV4="present"
    export RLCH_TEST_BACKEND_LOOPBACK_PERMANENT_IPV6="present"
    export RLCH_TEST_BACKEND_LOOPBACK_RUNTIME_INTERFACE="present"
    export RLCH_TEST_BACKEND_LOOPBACK_RUNTIME_IPV4="present"
    export RLCH_TEST_BACKEND_LOOPBACK_RUNTIME_IPV6="present"

    mkdir -p "${RLCH_TEST_BACKEND_LOOPBACK_ROOT}"
}

rlch_test_backend_loopback_systemctl() {
    printf 'systemctl %s\n' "$*" >> "${RLCH_TEST_BACKEND_LOOPBACK_LOG}"
    [[ "$*" == "is-active --quiet firewalld.service" ]] || return 2
    [[ "${RLCH_TEST_BACKEND_LOOPBACK_FIREWALLD_ACTIVE}" == "true" ]]
}

rlch_test_backend_loopback_nft() {
    printf 'nft %s\n' "$*" >> "${RLCH_TEST_BACKEND_LOOPBACK_LOG}"
    [[ "$*" == "list tables" ]] || return 2
    [[ "${RLCH_TEST_BACKEND_LOOPBACK_NFT_FAIL}" != "true" ]] || return 2
    printf '%s\n' "${RLCH_TEST_BACKEND_LOOPBACK_TABLES}"
}

rlch_test_backend_loopback_firewall_cmd() {
    local item scope=runtime state_variable
    local arguments=" $* "

    printf 'firewall-cmd %s\n' "$*" >> "${RLCH_TEST_BACKEND_LOOPBACK_LOG}"
    [[ "${arguments}" != *" --permanent "* ]] || scope=permanent

    case "${arguments}" in
        *" --query-interface=lo "*) item=interface ;;
        *" --query-rich-rule "*"family=ipv4"*) item=ipv4 ;;
        *" --query-rich-rule "*"family=ipv6"*) item=ipv6 ;;
        *) return 2 ;;
    esac

    [[ "${RLCH_TEST_BACKEND_LOOPBACK_FAIL}" != "${scope}:${item}" ]] || return 2
    state_variable="RLCH_TEST_BACKEND_LOOPBACK_${scope^^}_${item^^}"
    [[ "${!state_variable}" == "present" ]]
}
