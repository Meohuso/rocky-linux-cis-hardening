#!/usr/bin/env bats

setup() {
    export RLCH_TEST_REPOSITORY_ROOT="${BATS_TEST_DIRNAME}/.."
    source "${RLCH_TEST_REPOSITORY_ROOT}/tests/test_helper.bash"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/module_api.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/tests/helpers/bluetooth_service_helper.bash"
    bluetooth_service_helper_setup
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/3/1/3/module.sh"
}

@test "check succeeds when bluez is not installed" {
    printf '%s\n' false > "${RLCH_TEST_BLUETOOTH_INSTALLED}"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
    [ ! -s "${RLCH_TEST_BLUETOOTH_LOG}" ]
}

@test "check reports an active Bluetooth service" {
    printf '%s\n' masked > "${RLCH_TEST_BLUETOOTH_ENABLED}"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check reports an unmasked Bluetooth service" {
    printf '%s\n' inactive > "${RLCH_TEST_BLUETOOTH_ACTIVE}"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check succeeds when Bluetooth is inactive and masked" {
    printf '%s\n' inactive > "${RLCH_TEST_BLUETOOTH_ACTIVE}"
    printf '%s\n' masked > "${RLCH_TEST_BLUETOOTH_ENABLED}"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check reports an unsupported service state as an error" {
    printf '%s\n' failed > "${RLCH_TEST_BLUETOOTH_ACTIVE}"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
}

@test "apply stops disables and masks Bluetooth with exact saved state" {
    local result=0

    apply || result=$?

    [ "${result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "$(cat "${RLCH_TEST_BLUETOOTH_ACTIVE}")" = inactive ]
    [ "$(cat "${RLCH_TEST_BLUETOOTH_ENABLED}")" = masked ]
    [ "$(cat "${RLCH_CIS_3_1_3_STATE_FILE}")" = $'enabled=enabled\nactive=active' ]
}

@test "apply is idempotent when Bluetooth is already compliant" {
    printf '%s\n' inactive > "${RLCH_TEST_BLUETOOTH_ACTIVE}"
    printf '%s\n' masked > "${RLCH_TEST_BLUETOOTH_ENABLED}"

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
    [ ! -e "${RLCH_CIS_3_1_3_STATE_DIR}" ]
}

@test "apply requires root only when remediation is needed" {
    RLCH_TEST_BLUETOOTH_UID=1000

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [ ! -e "${RLCH_CIS_3_1_3_STATE_DIR}" ]
}

@test "apply retains rollback state when systemctl fails" {
    RLCH_TEST_BLUETOOTH_FAIL_ACTION="mask bluetooth.service"

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [ "$(cat "${RLCH_CIS_3_1_3_STATE_FILE}")" = $'enabled=enabled\nactive=active' ]
}

@test "rollback restores enabled and active service state" {
    local apply_result=0
    local rollback_result=0

    apply || apply_result=$?
    rollback || rollback_result=$?

    [ "${apply_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "${rollback_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "$(cat "${RLCH_TEST_BLUETOOTH_ACTIVE}")" = active ]
    [ "$(cat "${RLCH_TEST_BLUETOOTH_ENABLED}")" = enabled ]
    [ ! -e "${RLCH_CIS_3_1_3_STATE_DIR}" ]
}

@test "rollback restores disabled and inactive service state" {
    local apply_result=0
    local rollback_result=0

    printf '%s\n' inactive > "${RLCH_TEST_BLUETOOTH_ACTIVE}"
    printf '%s\n' disabled > "${RLCH_TEST_BLUETOOTH_ENABLED}"
    apply || apply_result=$?
    rollback || rollback_result=$?

    [ "${apply_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "${rollback_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "$(cat "${RLCH_TEST_BLUETOOTH_ACTIVE}")" = inactive ]
    [ "$(cat "${RLCH_TEST_BLUETOOTH_ENABLED}")" = disabled ]
}

@test "rollback restores runtime enablement exactly" {
    local apply_result=0
    local rollback_result=0

    printf '%s\n' enabled-runtime > "${RLCH_TEST_BLUETOOTH_ENABLED}"
    apply || apply_result=$?
    rollback || rollback_result=$?

    [ "${apply_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "${rollback_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "$(cat "${RLCH_TEST_BLUETOOTH_ENABLED}")" = enabled-runtime ]
}

@test "rollback restores an originally masked active service in safe order" {
    local apply_result=0
    local rollback_result=0

    printf '%s\n' masked > "${RLCH_TEST_BLUETOOTH_ENABLED}"
    apply || apply_result=$?
    rollback || rollback_result=$?

    [ "${apply_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "${rollback_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "$(cat "${RLCH_TEST_BLUETOOTH_ACTIVE}")" = active ]
    [ "$(cat "${RLCH_TEST_BLUETOOTH_ENABLED}")" = masked ]
}

@test "rollback is idempotent without saved state" {
    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "rollback rejects invalid saved state" {
    mkdir -p "${RLCH_CIS_3_1_3_STATE_DIR}"
    printf '%s\n' invalid > "${RLCH_CIS_3_1_3_STATE_FILE}"

    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [ -f "${RLCH_CIS_3_1_3_STATE_FILE}" ]
}

@test "validate delegates to check" {
    run validate

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "metadata declares the exact CIS 3.1.3 OpenSCAP rule" {
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/3/1/3/metadata.conf"

    [ "${RLCH_MODULE_ID}" = "3.1.3" ]
    [ "${RLCH_MODULE_LEVEL}" = "1" ]
    [ "${RLCH_MODULE_ENABLED}" = "true" ]
    [ "${RLCH_MODULE_REQUIRES_REBOOT}" = "false" ]
    [ "${RLCH_MODULE_OPENSCAP_RULE}" = "xccdf_org.ssgproject.content_rule_service_bluetooth_disabled" ]
}
