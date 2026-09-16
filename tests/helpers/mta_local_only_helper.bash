#!/usr/bin/env bash
# Test helper for CIS 2.1.21.
# SPDX-License-Identifier: MIT

mta_local_only_helper_setup() {
    export RLCH_CIS_2_1_21_TEST_ROOT="${BATS_TEST_TMPDIR}/cis-2.1.21"
    export RLCH_CIS_2_1_21_POSTFIX_CONFIG="${RLCH_CIS_2_1_21_TEST_ROOT}/etc/postfix/main.cf"
    export RLCH_CIS_2_1_21_STATE_DIR="${RLCH_CIS_2_1_21_TEST_ROOT}/state"
    export RLCH_CIS_2_1_21_STATE_FILE="${RLCH_CIS_2_1_21_STATE_DIR}/state"
    export RLCH_CIS_2_1_21_BACKUP_FILE="${RLCH_CIS_2_1_21_STATE_DIR}/main.cf.backup"
    export RLCH_CIS_2_1_21_RPM_COMMAND="rlch_test_mta_rpm"
    export RLCH_CIS_2_1_21_SS_COMMAND="rlch_test_mta_ss"
    export RLCH_CIS_2_1_21_SYSTEMCTL_COMMAND="rlch_test_mta_systemctl"
    export RLCH_CIS_2_1_21_ID_COMMAND="rlch_test_mta_id"

    export RLCH_TEST_MTA_POSTFIX_INSTALLED="false"
    export RLCH_TEST_MTA_POSTFIX_ACTIVE="false"
    export RLCH_TEST_MTA_EFFECTIVE_UID="0"
    export RLCH_TEST_MTA_ID_FAIL="false"
    export RLCH_TEST_MTA_SS_FAIL="false"
    export RLCH_TEST_MTA_LISTENERS=""
    export RLCH_TEST_MTA_RESTART_FAIL="false"
    export RLCH_TEST_MTA_RESTART_COUNT="0"

    mkdir -p "$(dirname "${RLCH_CIS_2_1_21_POSTFIX_CONFIG}")"
}

rlch_test_mta_rpm() {
    [[ "${1:-}" == "-q" ]] || return 1
    [[ "${2:-}" == "postfix" ]] || return 1
    [[ "${RLCH_TEST_MTA_POSTFIX_INSTALLED}" == "true" ]]
}

rlch_test_mta_id() {
    [[ "${1:-}" == "-u" ]] || return 1
    [[ "${RLCH_TEST_MTA_ID_FAIL}" != "true" ]] || return 1
    printf '%s\n' "${RLCH_TEST_MTA_EFFECTIVE_UID}"
}

rlch_test_mta_ss() {
    [[ "${1:-}" == "-H" ]] || return 1
    [[ "${2:-}" == "-lnt" ]] || return 1
    [[ "${RLCH_TEST_MTA_SS_FAIL}" != "true" ]] || return 1
    printf '%s' "${RLCH_TEST_MTA_LISTENERS}"
}

rlch_test_mta_systemctl() {
    case "${1:-}" in
        is-active)
            [[ "${2:-}" == "--quiet" && "${3:-}" == "postfix" ]] || return 1
            [[ "${RLCH_TEST_MTA_POSTFIX_ACTIVE}" == "true" ]]
            ;;
        restart)
            [[ "${2:-}" == "postfix" ]] || return 1
            [[ "${RLCH_TEST_MTA_RESTART_FAIL}" != "true" ]] || return 1
            RLCH_TEST_MTA_RESTART_COUNT=$((RLCH_TEST_MTA_RESTART_COUNT + 1))
            export RLCH_TEST_MTA_RESTART_COUNT
            export RLCH_TEST_MTA_LISTENERS=""
            ;;
        *)
            return 1
            ;;
    esac
}
