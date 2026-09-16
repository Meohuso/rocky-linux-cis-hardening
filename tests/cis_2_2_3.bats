#!/usr/bin/env bats

# Each Bats test runs in its own subshell; exported fixture variables are
# intentionally reset by setup for every test.
# shellcheck disable=SC2030,SC2031

setup() {
    export RLCH_TEST_REPOSITORY_ROOT="${BATS_TEST_DIRNAME}/.."
    source "${RLCH_TEST_REPOSITORY_ROOT}/tests/test_helper.bash"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/module_api.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/tests/helpers/nis_client_helper.bash"
    nis_client_helper_setup
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/2/2/3/module.sh"
}

@test "check succeeds when ypbind is not installed" {
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check reports non-compliance when ypbind is installed" {
    RLCH_TEST_NIS_CLIENT_INSTALLED="true"
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "apply removes ypbind when installed" {
    local apply_result=0
    RLCH_TEST_NIS_CLIENT_INSTALLED="true"

    apply || apply_result=$?

    [ "${apply_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "${RLCH_TEST_NIS_CLIENT_INSTALLED}" == "false" ]
    [ -f "${RLCH_CIS_2_2_3_STATE_FILE}" ]
    [ "$(cat "${RLCH_CIS_2_2_3_STATE_FILE}")" = "ypbind" ]
}

@test "apply is idempotent when ypbind is absent" {
    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
    [ ! -e "${RLCH_CIS_2_2_3_STATE_FILE}" ]
}

@test "apply requires root when remediation is needed" {
    RLCH_TEST_NIS_CLIENT_INSTALLED="true"
    RLCH_TEST_NIS_CLIENT_EFFECTIVE_UID="1000"

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [[ "${output}" == *"requires root privileges"* ]]
}

@test "apply errors when effective uid cannot be determined" {
    RLCH_TEST_NIS_CLIENT_INSTALLED="true"
    RLCH_TEST_NIS_CLIENT_ID_FAIL="true"

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [[ "${output}" == *"Unable to determine effective user ID"* ]]
}

@test "apply errors when dnf removal fails" {
    RLCH_TEST_NIS_CLIENT_INSTALLED="true"
    RLCH_TEST_NIS_CLIENT_DNF_REMOVE_FAIL="true"

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [ -e "${RLCH_CIS_2_2_3_STATE_FILE}" ]
}

@test "apply errors when ypbind remains installed" {
    RLCH_TEST_NIS_CLIENT_INSTALLED="true"
    RLCH_TEST_NIS_CLIENT_KEEP_INSTALLED_AFTER_REMOVE="true"

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [ -e "${RLCH_CIS_2_2_3_STATE_FILE}" ]
}

@test "validate delegates to check" {
    run validate
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]

    RLCH_TEST_NIS_CLIENT_INSTALLED="true"
    run validate
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "rollback reinstalls ypbind when recorded" {
    local rollback_result=0
    mkdir -p "${RLCH_CIS_2_2_3_STATE_DIR}"
    printf '%s\n' "ypbind" > "${RLCH_CIS_2_2_3_STATE_FILE}"

    rollback || rollback_result=$?

    [ "${rollback_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "${RLCH_TEST_NIS_CLIENT_INSTALLED}" == "true" ]
    [ ! -e "${RLCH_CIS_2_2_3_STATE_FILE}" ]
}

@test "rollback is idempotent without state" {
    run rollback
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "rollback requires root when restoration is needed" {
    RLCH_TEST_NIS_CLIENT_EFFECTIVE_UID="1000"
    mkdir -p "${RLCH_CIS_2_2_3_STATE_DIR}"
    printf '%s\n' "ypbind" > "${RLCH_CIS_2_2_3_STATE_FILE}"

    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [ -e "${RLCH_CIS_2_2_3_STATE_FILE}" ]
}

@test "rollback errors when installation fails" {
    RLCH_TEST_NIS_CLIENT_DNF_INSTALL_FAIL="true"
    mkdir -p "${RLCH_CIS_2_2_3_STATE_DIR}"
    printf '%s\n' "ypbind" > "${RLCH_CIS_2_2_3_STATE_FILE}"

    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [ -e "${RLCH_CIS_2_2_3_STATE_FILE}" ]
}

@test "rollback errors when ypbind remains absent" {
    RLCH_TEST_NIS_CLIENT_KEEP_REMOVED_AFTER_INSTALL="true"
    mkdir -p "${RLCH_CIS_2_2_3_STATE_DIR}"
    printf '%s\n' "ypbind" > "${RLCH_CIS_2_2_3_STATE_FILE}"

    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [ -e "${RLCH_CIS_2_2_3_STATE_FILE}" ]
}

@test "metadata declares CIS 2.2.3" {
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/2/2/3/metadata.conf"

    [ "${RLCH_MODULE_ID}" = "2.2.3" ]
    [ "${RLCH_MODULE_LEVEL}" = "1" ]
    [ "${RLCH_MODULE_ENABLED}" = "true" ]
    [ "${RLCH_MODULE_REQUIRES_REBOOT}" = "false" ]
    [ "${RLCH_MODULE_OPENSCAP_RULE}" = "manual" ]
}
