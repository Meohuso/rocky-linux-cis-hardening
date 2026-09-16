#!/usr/bin/env bash
#
# Test helper for CIS 2.4.1.1.
# SPDX-License-Identifier: MIT
#

cron_daemon_helper_setup() {
    export RLCH_CIS_2_4_1_1_TEST_ROOT="${BATS_TEST_TMPDIR}/cis-2.4.1.1"
    export RLCH_CIS_2_4_1_1_STATE_DIR="${RLCH_CIS_2_4_1_1_TEST_ROOT}/state"
    export RLCH_CIS_2_4_1_1_STATE_FILE="${RLCH_CIS_2_4_1_1_STATE_DIR}/state"
    export RLCH_CIS_2_4_1_1_PACKAGE_STATE_FILE="${RLCH_CIS_2_4_1_1_STATE_DIR}/package-state"
    export RLCH_CIS_2_4_1_1_ENABLED_STATE_FILE="${RLCH_CIS_2_4_1_1_STATE_DIR}/enabled-state"
    export RLCH_CIS_2_4_1_1_ACTIVE_STATE_FILE="${RLCH_CIS_2_4_1_1_STATE_DIR}/active-state"
    export RLCH_CIS_2_4_1_1_PACKAGE="cronie"
    export RLCH_CIS_2_4_1_1_SERVICE="crond.service"
    export RLCH_CIS_2_4_1_1_RPM_COMMAND="rlch_test_cron_rpm"
    export RLCH_CIS_2_4_1_1_DNF_COMMAND="rlch_test_cron_dnf"
    export RLCH_CIS_2_4_1_1_SYSTEMCTL_COMMAND="rlch_test_cron_systemctl"
    export RLCH_CIS_2_4_1_1_ID_COMMAND="rlch_test_cron_id"

    export RLCH_TEST_CRON_PACKAGE_INSTALLED="false"
    export RLCH_TEST_CRON_ENABLED_STATE="disabled"
    export RLCH_TEST_CRON_ACTIVE_STATE="inactive"
    export RLCH_TEST_CRON_EFFECTIVE_UID="0"
    export RLCH_TEST_CRON_ID_FAIL="false"
    export RLCH_TEST_CRON_DNF_INSTALL_FAIL="false"
    export RLCH_TEST_CRON_DNF_REMOVE_FAIL="false"
    export RLCH_TEST_CRON_KEEP_ABSENT_AFTER_INSTALL="false"
    export RLCH_TEST_CRON_KEEP_INSTALLED_AFTER_REMOVE="false"
    export RLCH_TEST_CRON_SYSTEMCTL_FAIL=""

    mkdir -p "${RLCH_CIS_2_4_1_1_TEST_ROOT}"
}

rlch_test_cron_rpm() {
    [[ "${1:-}" == "-q" ]] || return 2
    [[ "${2:-}" == "${RLCH_CIS_2_4_1_1_PACKAGE}" ]] || return 2
    [[ "${RLCH_TEST_CRON_PACKAGE_INSTALLED}" == "true" ]]
}

rlch_test_cron_dnf() {
    local action="${2:-}"

    [[ "${1:-}" == "-y" ]] || return 2
    [[ "${3:-}" == "${RLCH_CIS_2_4_1_1_PACKAGE}" ]] || return 2

    case "${action}" in
        install)
            [[ "${RLCH_TEST_CRON_DNF_INSTALL_FAIL}" != "true" ]] || return 1
            if [[ "${RLCH_TEST_CRON_KEEP_ABSENT_AFTER_INSTALL}" != "true" ]]; then
                export RLCH_TEST_CRON_PACKAGE_INSTALLED="true"
            fi
            ;;
        remove)
            [[ "${RLCH_TEST_CRON_DNF_REMOVE_FAIL}" != "true" ]] || return 1
            if [[ "${RLCH_TEST_CRON_KEEP_INSTALLED_AFTER_REMOVE}" != "true" ]]; then
                export RLCH_TEST_CRON_PACKAGE_INSTALLED="false"
            fi
            ;;
        *)
            return 2
            ;;
    esac
}

rlch_test_cron_systemctl() {
    local action="${1:-}"
    local service

    if [[ "${RLCH_TEST_CRON_SYSTEMCTL_FAIL}" == "${action}" ]]; then
        return 1
    fi

    case "${action}" in
        is-active)
            [[ "${2:-}" == "--quiet" ]] || return 2
            service="${3:-}"
            [[ "${service}" == "${RLCH_CIS_2_4_1_1_SERVICE}" ]] || return 2
            [[ "${RLCH_TEST_CRON_ACTIVE_STATE}" == "active" ]]
            ;;
        is-enabled)
            service="${2:-}"
            [[ "${service}" == "${RLCH_CIS_2_4_1_1_SERVICE}" ]] || return 2
            printf '%s\n' "${RLCH_TEST_CRON_ENABLED_STATE}"
            [[ "${RLCH_TEST_CRON_ENABLED_STATE}" == "enabled" ]]
            ;;
        unmask)
            export RLCH_TEST_CRON_ENABLED_STATE="disabled"
            ;;
        enable)
            export RLCH_TEST_CRON_ENABLED_STATE="enabled"
            ;;
        disable)
            export RLCH_TEST_CRON_ENABLED_STATE="disabled"
            ;;
        mask)
            export RLCH_TEST_CRON_ENABLED_STATE="masked"
            ;;
        start)
            export RLCH_TEST_CRON_ACTIVE_STATE="active"
            ;;
        stop)
            export RLCH_TEST_CRON_ACTIVE_STATE="inactive"
            ;;
        *)
            return 2
            ;;
    esac
}

rlch_test_cron_id() {
    [[ "${1:-}" == "-u" ]] || return 1
    [[ "${RLCH_TEST_CRON_ID_FAIL}" != "true" ]] || return 1
    printf '%s\n' "${RLCH_TEST_CRON_EFFECTIVE_UID}"
}
