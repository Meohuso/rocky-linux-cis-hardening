#!/usr/bin/env bats

setup() {
    export RLCH_TEST_REPOSITORY_ROOT="${BATS_TEST_DIRNAME}/.."

    # shellcheck source=tests/test_helper.bash
    source "${RLCH_TEST_REPOSITORY_ROOT}/tests/test_helper.bash"
    # shellcheck source=lib/module_api.sh
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/module_api.sh"
    # shellcheck source=tests/helpers/xinetd_server_helper.bash
    source "${RLCH_TEST_REPOSITORY_ROOT}/tests/helpers/xinetd_server_helper.bash"

    xinetd_server_helper_setup

    # shellcheck source=modules/cis/2/1/19/module.sh
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/2/1/19/module.sh"
}

@test "check succeeds when xinetd is not installed" {
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check reports non-compliance when xinetd is installed" {
    RLCH_TEST_XINETD_INSTALLED="true"
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "apply removes xinetd when installed" {
    local apply_result=0
    RLCH_TEST_XINETD_INSTALLED="true"

    apply || apply_result=$?

    [ "${apply_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "${RLCH_TEST_XINETD_INSTALLED}" == "false" ]
    [ -f "${RLCH_CIS_2_1_19_STATE_FILE}" ]
    [ "$(cat "${RLCH_CIS_2_1_19_STATE_FILE}")" = "xinetd" ]
}

@test "apply is idempotent when xinetd is absent" {
    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
    [ ! -e "${RLCH_CIS_2_1_19_STATE_FILE}" ]
}

@test "apply requires root when remediation is needed" {
    RLCH_TEST_XINETD_INSTALLED="true"
    RLCH_TEST_XINETD_EFFECTIVE_UID="1000"

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [[ "${output}" == *"requires root privileges"* ]]
}

@test "apply errors when effective uid cannot be determined" {
    RLCH_TEST_XINETD_INSTALLED="true"
    RLCH_TEST_XINETD_ID_FAIL="true"

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [[ "${output}" == *"Unable to determine effective user ID"* ]]
}

@test "apply errors when dnf removal fails" {
    RLCH_TEST_XINETD_INSTALLED="true"
    RLCH_TEST_XINETD_DNF_REMOVE_FAIL="true"

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [ -e "${RLCH_CIS_2_1_19_STATE_FILE}" ]
}

@test "apply errors when xinetd remains installed" {
    RLCH_TEST_XINETD_INSTALLED="true"
    RLCH_TEST_XINETD_KEEP_INSTALLED_AFTER_REMOVE="true"

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [ -e "${RLCH_CIS_2_1_19_STATE_FILE}" ]
}

@test "validate delegates to check" {
    run validate
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]

    RLCH_TEST_XINETD_INSTALLED="true"
    run validate
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "rollback reinstalls xinetd when recorded" {
    local rollback_result=0
    mkdir -p "${RLCH_CIS_2_1_19_STATE_DIR}"
    printf '%s\n' "xinetd" > "${RLCH_CIS_2_1_19_STATE_FILE}"

    rollback || rollback_result=$?

    [ "${rollback_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "${RLCH_TEST_XINETD_INSTALLED}" == "true" ]
    [ ! -e "${RLCH_CIS_2_1_19_STATE_FILE}" ]
}

@test "rollback is idempotent without state" {
    run rollback
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "rollback requires root when restoration is needed" {
    RLCH_TEST_XINETD_EFFECTIVE_UID="1000"
    mkdir -p "${RLCH_CIS_2_1_19_STATE_DIR}"
    printf '%s\n' "xinetd" > "${RLCH_CIS_2_1_19_STATE_FILE}"

    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [ -e "${RLCH_CIS_2_1_19_STATE_FILE}" ]
}

@test "rollback errors when installation fails" {
    RLCH_TEST_XINETD_DNF_INSTALL_FAIL="true"
    mkdir -p "${RLCH_CIS_2_1_19_STATE_DIR}"
    printf '%s\n' "xinetd" > "${RLCH_CIS_2_1_19_STATE_FILE}"

    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [ -e "${RLCH_CIS_2_1_19_STATE_FILE}" ]
}

@test "rollback errors when xinetd remains absent" {
    RLCH_TEST_XINETD_KEEP_REMOVED_AFTER_INSTALL="true"
    mkdir -p "${RLCH_CIS_2_1_19_STATE_DIR}"
    printf '%s\n' "xinetd" > "${RLCH_CIS_2_1_19_STATE_FILE}"

    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [ -e "${RLCH_CIS_2_1_19_STATE_FILE}" ]
}

@test "metadata declares CIS 2.1.19" {
    # shellcheck source=/dev/null
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/2/1/19/metadata.conf"

    [ "${RLCH_MODULE_ID}" = "2.1.19" ]
    [ "${RLCH_MODULE_LEVEL}" = "1" ]
    [ "${RLCH_MODULE_ENABLED}" = "true" ]
    [ "${RLCH_MODULE_REQUIRES_REBOOT}" = "false" ]
    [ "${RLCH_MODULE_OPENSCAP_RULE}" = "manual" ]
}
