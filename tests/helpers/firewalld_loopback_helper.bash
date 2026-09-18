#!/usr/bin/env bash
# Test helper for CIS 4.2.2.
# SPDX-License-Identifier: MIT

firewalld_loopback_helper_setup() {
    export RLCH_TEST_FIREWALLD_LOOPBACK_ROOT="${BATS_TEST_TMPDIR}/cis-4.2.2"
    export RLCH_TEST_FIREWALLD_LOOPBACK_LOG="${RLCH_TEST_FIREWALLD_LOOPBACK_ROOT}/commands"
    export RLCH_CIS_4_2_2_STATE_DIR="${RLCH_TEST_FIREWALLD_LOOPBACK_ROOT}/state"
    export RLCH_CIS_4_2_2_STATE_FILE="${RLCH_CIS_4_2_2_STATE_DIR}/state"
    export RLCH_CIS_4_2_2_FIREWALL_CMD="rlch_test_firewalld_loopback_cmd"
    export RLCH_CIS_4_2_2_ID_COMMAND="rlch_test_firewalld_loopback_id"
    export RLCH_TEST_FIREWALLD_LOOPBACK_UID="0"
    export RLCH_TEST_FIREWALLD_LOOPBACK_ID_FAIL="false"
    export RLCH_TEST_FIREWALLD_LOOPBACK_FAIL=""
    export RLCH_TEST_FIREWALLD_PERMANENT_INTERFACE="absent"
    export RLCH_TEST_FIREWALLD_PERMANENT_IPV4="absent"
    export RLCH_TEST_FIREWALLD_PERMANENT_IPV6="absent"
    export RLCH_TEST_FIREWALLD_RUNTIME_INTERFACE="absent"
    export RLCH_TEST_FIREWALLD_RUNTIME_IPV4="absent"
    export RLCH_TEST_FIREWALLD_RUNTIME_IPV6="absent"

    mkdir -p "${RLCH_TEST_FIREWALLD_LOOPBACK_ROOT}"
}

firewalld_loopback_helper_set_all() {
    local state="${1:-present}"
    export RLCH_TEST_FIREWALLD_PERMANENT_INTERFACE="${state}"
    export RLCH_TEST_FIREWALLD_PERMANENT_IPV4="${state}"
    export RLCH_TEST_FIREWALLD_PERMANENT_IPV6="${state}"
    export RLCH_TEST_FIREWALLD_RUNTIME_INTERFACE="${state}"
    export RLCH_TEST_FIREWALLD_RUNTIME_IPV4="${state}"
    export RLCH_TEST_FIREWALLD_RUNTIME_IPV6="${state}"
}

rlch_test_firewalld_loopback_id() {
    [[ "${1:-}" == "-u" ]] || return 1
    [[ "${RLCH_TEST_FIREWALLD_LOOPBACK_ID_FAIL}" != "true" ]] || return 1
    printf '%s\n' "${RLCH_TEST_FIREWALLD_LOOPBACK_UID}"
}

rlch_test_firewalld_loopback_cmd() {
    local action item scope=runtime state_variable
    local arguments=" $* "

    printf '%s\n' "$*" >> "${RLCH_TEST_FIREWALLD_LOOPBACK_LOG}"
    [[ "${arguments}" != *" --permanent "* ]] || scope=permanent

    case "${arguments}" in
        *" --query-interface=lo "*) action=query; item=interface ;;
        *" --add-interface=lo "*) action=add; item=interface ;;
        *" --remove-interface=lo "*) action=remove; item=interface ;;
        *" --query-rich-rule "*"family=ipv4"*) action=query; item=ipv4 ;;
        *" --add-rich-rule "*"family=ipv4"*) action=add; item=ipv4 ;;
        *" --remove-rich-rule "*"family=ipv4"*) action=remove; item=ipv4 ;;
        *" --query-rich-rule "*"family=ipv6"*) action=query; item=ipv6 ;;
        *" --add-rich-rule "*"family=ipv6"*) action=add; item=ipv6 ;;
        *" --remove-rich-rule "*"family=ipv6"*) action=remove; item=ipv6 ;;
        *) return 2 ;;
    esac

    [[ "${RLCH_TEST_FIREWALLD_LOOPBACK_FAIL}" != "${action}:${scope}:${item}" ]] || return 2
    state_variable="RLCH_TEST_FIREWALLD_${scope^^}_${item^^}"

    case "${action}" in
        query)
            [[ "${!state_variable}" == "present" ]]
            ;;
        add)
            printf -v "${state_variable}" '%s' present
            export "${state_variable?}"
            ;;
        remove)
            printf -v "${state_variable}" '%s' absent
            export "${state_variable?}"
            ;;
    esac
}
