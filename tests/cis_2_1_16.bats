#!/usr/bin/env bats

setup() {
    export RLCH_TEST_REPOSITORY_ROOT="${BATS_TEST_DIRNAME}/.."

    # shellcheck source=tests/test_helper.bash
    source "${RLCH_TEST_REPOSITORY_ROOT}/tests/test_helper.bash"
    # shellcheck source=lib/module_api.sh
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/module_api.sh"
    # shellcheck source=tests/helpers/tftp_server_helper.bash
    source "${RLCH_TEST_REPOSITORY_ROOT}/tests/helpers/tftp_server_helper.bash"

    tftp_server_helper_setup

    # shellcheck source=modules/cis/2/1/16/module.sh
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/2/1/16/module.sh"
}

@test "check succeeds when tftp-server is not installed" {
    RLCH_TEST_TFTP_INSTALLED="false"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check reports non-compliance when tftp-server is installed" {
    RLCH_TEST_TFTP_INSTALLED="true"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "apply removes tftp-server when it is installed" {
    local apply_result=0

    RLCH_TEST_TFTP_INSTALLED="true"
    RLCH_TEST_TFTP_EFFECTIVE_UID="0"

    apply || apply_result=$?

    [ "${apply_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "${RLCH_TEST_TFTP_INSTALLED}" == "false" ]
    [ -f "${RLCH_CIS_2_1_16_STATE_FILE}" ]
    [ "$(cat "${RLCH_CIS_2_1_16_STATE_FILE}")" = "tftp-server" ]
}

@test "apply is idempotent when tftp-server is already absent" {
    RLCH_TEST_TFTP_INSTALLED="false"

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
    [ ! -e "${RLCH_CIS_2_1_16_STATE_FILE}" ]
}

@test "apply fails without root privileges when remediation is required" {
    RLCH_TEST_TFTP_INSTALLED="true"
    RLCH_TEST_TFTP_EFFECTIVE_UID="1000"

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [[ "${output}" == *"requires root privileges"* ]]
}

@test "apply returns error when effective uid cannot be determined" {
    RLCH_TEST_TFTP_INSTALLED="true"
    RLCH_TEST_TFTP_ID_FAIL="true"

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [[ "${output}" == *"Unable to determine effective user ID"* ]]
}

@test "apply returns error when dnf removal fails and keeps rollback state" {
    RLCH_TEST_TFTP_INSTALLED="true"
    RLCH_TEST_TFTP_EFFECTIVE_UID="0"
    RLCH_TEST_TFTP_DNF_REMOVE_FAIL="true"

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [ -f "${RLCH_CIS_2_1_16_STATE_FILE}" ]
}

@test "apply returns error when package remains installed after removal" {
    RLCH_TEST_TFTP_INSTALLED="true"
    RLCH_TEST_TFTP_EFFECTIVE_UID="0"
    RLCH_TEST_TFTP_KEEP_INSTALLED_AFTER_REMOVE="true"

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [ -f "${RLCH_CIS_2_1_16_STATE_FILE}" ]
}

@test "validate delegates to the compliance check" {
    RLCH_TEST_TFTP_INSTALLED="false"

    run validate

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]

    RLCH_TEST_TFTP_INSTALLED="true"

    run validate

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "rollback reinstalls tftp-server when this module removed it" {
    local rollback_result=0

    RLCH_TEST_TFTP_INSTALLED="false"
    RLCH_TEST_TFTP_EFFECTIVE_UID="0"

    mkdir -p "${RLCH_CIS_2_1_16_STATE_DIR}"
    printf '%s\n' "tftp-server" > "${RLCH_CIS_2_1_16_STATE_FILE}"

    rollback || rollback_result=$?

    [ "${rollback_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "${RLCH_TEST_TFTP_INSTALLED}" == "true" ]
    [ ! -e "${RLCH_CIS_2_1_16_STATE_FILE}" ]
}

@test "rollback is idempotent when no rollback state exists" {
    RLCH_TEST_TFTP_INSTALLED="false"

    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "rollback fails without root privileges when restoration is required" {
    RLCH_TEST_TFTP_INSTALLED="false"
    RLCH_TEST_TFTP_EFFECTIVE_UID="1000"

    mkdir -p "${RLCH_CIS_2_1_16_STATE_DIR}"
    printf '%s\n' "tftp-server" > "${RLCH_CIS_2_1_16_STATE_FILE}"

    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [ -e "${RLCH_CIS_2_1_16_STATE_FILE}" ]
}

@test "rollback returns error when dnf installation fails" {
    RLCH_TEST_TFTP_INSTALLED="false"
    RLCH_TEST_TFTP_EFFECTIVE_UID="0"
    RLCH_TEST_TFTP_DNF_INSTALL_FAIL="true"

    mkdir -p "${RLCH_CIS_2_1_16_STATE_DIR}"
    printf '%s\n' "tftp-server" > "${RLCH_CIS_2_1_16_STATE_FILE}"

    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [ -e "${RLCH_CIS_2_1_16_STATE_FILE}" ]
}

@test "rollback returns error when package is still absent after installation" {
    RLCH_TEST_TFTP_INSTALLED="false"
    RLCH_TEST_TFTP_EFFECTIVE_UID="0"
    RLCH_TEST_TFTP_KEEP_REMOVED_AFTER_INSTALL="true"

    mkdir -p "${RLCH_CIS_2_1_16_STATE_DIR}"
    printf '%s\n' "tftp-server" > "${RLCH_CIS_2_1_16_STATE_FILE}"

    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [ -e "${RLCH_CIS_2_1_16_STATE_FILE}" ]
}

@test "metadata declares the expected CIS control" {
    # shellcheck source=/dev/null
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/2/1/16/metadata.conf"

    [ "${RLCH_MODULE_ID}" = "2.1.16" ]
    [ "${RLCH_MODULE_LEVEL}" = "1" ]
    [ "${RLCH_MODULE_ENABLED}" = "true" ]
    [ "${RLCH_MODULE_REQUIRES_REBOOT}" = "false" ]
    [ "${RLCH_MODULE_OPENSCAP_RULE}" = "xccdf_org.ssgproject.content_rule_package_tftp-server_removed" ]
}
