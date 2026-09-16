#!/usr/bin/env bats

# Some tests call module functions directly so changes made by the command
# shims remain visible in the current Bats shell.
# shellcheck disable=SC2030,SC2031

setup() {
    export RLCH_TEST_REPOSITORY_ROOT="${BATS_TEST_DIRNAME}/.."
    source "${RLCH_TEST_REPOSITORY_ROOT}/tests/test_helper.bash"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/module_api.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/tests/helpers/cron_daemon_helper.bash"
    cron_daemon_helper_setup
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/2/4/1/1/module.sh"
}

@test "check reports non-compliance when cronie is absent" {
    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check succeeds when crond is enabled and active" {
    RLCH_TEST_CRON_PACKAGE_INSTALLED="true"
    RLCH_TEST_CRON_ENABLED_STATE="enabled"
    RLCH_TEST_CRON_ACTIVE_STATE="active"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check reports non-compliance when crond is disabled" {
    RLCH_TEST_CRON_PACKAGE_INSTALLED="true"
    RLCH_TEST_CRON_ACTIVE_STATE="active"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check reports non-compliance when crond is inactive" {
    RLCH_TEST_CRON_PACKAGE_INSTALLED="true"
    RLCH_TEST_CRON_ENABLED_STATE="enabled"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "apply installs cronie and enables and starts crond" {
    local apply_result=0

    apply || apply_result=$?

    [ "${apply_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "${RLCH_TEST_CRON_PACKAGE_INSTALLED}" == "true" ]
    [ "${RLCH_TEST_CRON_ENABLED_STATE}" == "enabled" ]
    [ "${RLCH_TEST_CRON_ACTIVE_STATE}" == "active" ]
    [ "$(cat "${RLCH_CIS_2_4_1_1_PACKAGE_STATE_FILE}")" == "absent" ]
}

@test "apply restores a masked installed service" {
    local apply_result=0
    RLCH_TEST_CRON_PACKAGE_INSTALLED="true"
    RLCH_TEST_CRON_ENABLED_STATE="masked"

    apply || apply_result=$?

    [ "${apply_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "${RLCH_TEST_CRON_ENABLED_STATE}" == "enabled" ]
    [ "${RLCH_TEST_CRON_ACTIVE_STATE}" == "active" ]
    [ "$(cat "${RLCH_CIS_2_4_1_1_ENABLED_STATE_FILE}")" == "masked" ]
}

@test "apply is idempotent when cron is compliant" {
    RLCH_TEST_CRON_PACKAGE_INSTALLED="true"
    RLCH_TEST_CRON_ENABLED_STATE="enabled"
    RLCH_TEST_CRON_ACTIVE_STATE="active"

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
    [ ! -e "${RLCH_CIS_2_4_1_1_STATE_FILE}" ]
}

@test "apply requires root when remediation is needed" {
    RLCH_TEST_CRON_EFFECTIVE_UID="1000"

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [[ "${output}" == *"requires root privileges"* ]]
}

@test "apply errors when effective uid cannot be determined" {
    RLCH_TEST_CRON_ID_FAIL="true"

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [[ "${output}" == *"Unable to determine effective user ID"* ]]
}

@test "apply keeps rollback state when package installation fails" {
    RLCH_TEST_CRON_DNF_INSTALL_FAIL="true"

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [ -e "${RLCH_CIS_2_4_1_1_STATE_FILE}" ]
}

@test "apply errors when cronie remains absent" {
    RLCH_TEST_CRON_KEEP_ABSENT_AFTER_INSTALL="true"

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [ -e "${RLCH_CIS_2_4_1_1_STATE_FILE}" ]
}

@test "apply errors when crond cannot be unmasked" {
    RLCH_TEST_CRON_PACKAGE_INSTALLED="true"
    RLCH_TEST_CRON_ENABLED_STATE="masked"
    RLCH_TEST_CRON_SYSTEMCTL_FAIL="unmask"

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
}

@test "apply errors when crond cannot be enabled" {
    RLCH_TEST_CRON_PACKAGE_INSTALLED="true"
    RLCH_TEST_CRON_SYSTEMCTL_FAIL="enable"

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
}

@test "apply errors when crond cannot be started" {
    RLCH_TEST_CRON_PACKAGE_INSTALLED="true"
    RLCH_TEST_CRON_SYSTEMCTL_FAIL="start"

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
}

@test "validate delegates to check" {
    run validate
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]

    RLCH_TEST_CRON_PACKAGE_INSTALLED="true"
    RLCH_TEST_CRON_ENABLED_STATE="enabled"
    RLCH_TEST_CRON_ACTIVE_STATE="active"
    run validate
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "rollback removes cronie when the module installed it" {
    local apply_result=0
    local rollback_result=0
    apply || apply_result=$?
    [ "${apply_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]

    rollback || rollback_result=$?

    [ "${rollback_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "${RLCH_TEST_CRON_PACKAGE_INSTALLED}" == "false" ]
    [ ! -e "${RLCH_CIS_2_4_1_1_STATE_DIR}" ]
}

@test "rollback restores a disabled and inactive installed service" {
    local apply_result=0
    local rollback_result=0
    RLCH_TEST_CRON_PACKAGE_INSTALLED="true"
    apply || apply_result=$?
    [ "${apply_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]

    rollback || rollback_result=$?

    [ "${rollback_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "${RLCH_TEST_CRON_PACKAGE_INSTALLED}" == "true" ]
    [ "${RLCH_TEST_CRON_ENABLED_STATE}" == "disabled" ]
    [ "${RLCH_TEST_CRON_ACTIVE_STATE}" == "inactive" ]
}

@test "rollback restores a masked and inactive installed service" {
    local apply_result=0
    local rollback_result=0
    RLCH_TEST_CRON_PACKAGE_INSTALLED="true"
    RLCH_TEST_CRON_ENABLED_STATE="masked"
    apply || apply_result=$?
    [ "${apply_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]

    rollback || rollback_result=$?

    [ "${rollback_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "${RLCH_TEST_CRON_ENABLED_STATE}" == "masked" ]
    [ "${RLCH_TEST_CRON_ACTIVE_STATE}" == "inactive" ]
}

@test "rollback is idempotent without state" {
    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "rollback requires root when state exists" {
    mkdir -p "${RLCH_CIS_2_4_1_1_STATE_DIR}"
    : > "${RLCH_CIS_2_4_1_1_STATE_FILE}"
    RLCH_TEST_CRON_EFFECTIVE_UID="1000"

    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
}

@test "rollback rejects incomplete state" {
    mkdir -p "${RLCH_CIS_2_4_1_1_STATE_DIR}"
    : > "${RLCH_CIS_2_4_1_1_STATE_FILE}"

    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
}

@test "rollback keeps state when package removal fails" {
    local apply_result=0
    apply || apply_result=$?
    [ "${apply_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    RLCH_TEST_CRON_DNF_REMOVE_FAIL="true"

    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [ -e "${RLCH_CIS_2_4_1_1_STATE_FILE}" ]
}

@test "rollback errors when cronie remains installed" {
    local apply_result=0
    apply || apply_result=$?
    [ "${apply_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    RLCH_TEST_CRON_KEEP_INSTALLED_AFTER_REMOVE="true"

    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [ -e "${RLCH_CIS_2_4_1_1_STATE_FILE}" ]
}

@test "metadata declares CIS 2.4.1.1 with manual multi-rule mapping" {
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/2/4/1/1/metadata.conf"

    [ "${RLCH_MODULE_ID}" = "2.4.1.1" ]
    [ "${RLCH_MODULE_LEVEL}" = "1" ]
    [ "${RLCH_MODULE_ENABLED}" = "true" ]
    [ "${RLCH_MODULE_REQUIRES_REBOOT}" = "false" ]
    [ "${RLCH_MODULE_OPENSCAP_RULE}" = "manual" ]
}
