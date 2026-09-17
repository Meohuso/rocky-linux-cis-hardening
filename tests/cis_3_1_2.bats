#!/usr/bin/env bats

setup() {
    export RLCH_TEST_REPOSITORY_ROOT="${BATS_TEST_DIRNAME}/.."
    source "${RLCH_TEST_REPOSITORY_ROOT}/tests/test_helper.bash"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/module_api.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/tests/helpers/wireless_interfaces_helper.bash"
    wireless_interfaces_helper_setup
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/3/1/2/module.sh"
}

@test "check is not applicable without a physical wireless interface" {
    rm -rf "${RLCH_TEST_WIRELESS_SYS_CLASS_NET}/wlan0/wireless"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NOT_APPLICABLE}" ]
}

@test "check succeeds when every wireless interface is down" {
    printf '%s\n' 0x1002 > "${RLCH_TEST_WIRELESS_FLAGS}"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check reports an enabled wireless interface" {
    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check evaluates every physical wireless interface" {
    mkdir -p "${RLCH_TEST_WIRELESS_SYS_CLASS_NET}/wlan1/wireless"
    printf '%s\n' 0x0 > "${RLCH_TEST_WIRELESS_FLAGS}"
    printf '%s\n' 0x1 > "${RLCH_TEST_WIRELESS_SYS_CLASS_NET}/wlan1/flags"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check reports an error for unreadable interface state" {
    rm -f "${RLCH_TEST_WIRELESS_FLAGS}"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [[ "${output}" == *"Unable to inspect wireless interface flags"* ]]
}

@test "apply disables all radios and records exact initial states" {
    local result=0

    apply || result=$?

    [ "${result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "$(cat "${RLCH_TEST_WIRELESS_WIFI_STATE}")" = disabled ]
    [ "$(cat "${RLCH_TEST_WIRELESS_WWAN_STATE}")" = disabled ]
    [ "$(cat "${RLCH_CIS_3_1_2_STATE_FILE}")" = $'wifi=enabled\nwwan=disabled' ]
    [[ "$(cat "${RLCH_TEST_WIRELESS_NMCLI_LOG}")" == *"radio all off"* ]]
}

@test "apply is idempotent when wireless interfaces are already down" {
    printf '%s\n' 0x0 > "${RLCH_TEST_WIRELESS_FLAGS}"

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
    [ ! -e "${RLCH_CIS_3_1_2_STATE_DIR}" ]
    [ ! -s "${RLCH_TEST_WIRELESS_NMCLI_LOG}" ]
}

@test "apply preserves not applicable result without creating state" {
    rm -rf "${RLCH_TEST_WIRELESS_SYS_CLASS_NET}/wlan0/wireless"

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NOT_APPLICABLE}" ]
    [ ! -e "${RLCH_CIS_3_1_2_STATE_DIR}" ]
}

@test "apply requires root when remediation is needed" {
    RLCH_TEST_WIRELESS_UID=1000

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [ ! -e "${RLCH_CIS_3_1_2_STATE_DIR}" ]
}

@test "apply retains rollback state when nmcli fails" {
    RLCH_TEST_WIRELESS_NMCLI_FAIL_ACTION="radio all off"

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [ "$(cat "${RLCH_CIS_3_1_2_STATE_FILE}")" = $'wifi=enabled\nwwan=disabled' ]
}

@test "apply does not create incomplete state when radio inspection fails" {
    RLCH_TEST_WIRELESS_NMCLI_FAIL=true

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [ ! -e "${RLCH_CIS_3_1_2_STATE_DIR}" ]
}

@test "rollback restores Wi-Fi and WWAN states independently" {
    local apply_result=0
    local rollback_result=0

    apply || apply_result=$?
    rollback || rollback_result=$?

    [ "${apply_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "${rollback_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "$(cat "${RLCH_TEST_WIRELESS_WIFI_STATE}")" = enabled ]
    [ "$(cat "${RLCH_TEST_WIRELESS_WWAN_STATE}")" = disabled ]
    [ ! -e "${RLCH_CIS_3_1_2_STATE_DIR}" ]
    [[ "$(cat "${RLCH_TEST_WIRELESS_NMCLI_LOG}")" == *"radio wifi on"* ]]
    [[ "$(cat "${RLCH_TEST_WIRELESS_NMCLI_LOG}")" == *"radio wwan off"* ]]
}

@test "rollback is idempotent without saved state" {
    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "rollback rejects invalid saved state" {
    mkdir -p "${RLCH_CIS_3_1_2_STATE_DIR}"
    printf '%s\n' invalid > "${RLCH_CIS_3_1_2_STATE_FILE}"

    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [ -f "${RLCH_CIS_3_1_2_STATE_FILE}" ]
}

@test "validate delegates to check" {
    run validate

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "metadata declares the exact CIS 3.1.2 OpenSCAP rule" {
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/3/1/2/metadata.conf"

    [ "${RLCH_MODULE_ID}" = "3.1.2" ]
    [ "${RLCH_MODULE_LEVEL}" = "1" ]
    [ "${RLCH_MODULE_ENABLED}" = "true" ]
    [ "${RLCH_MODULE_REQUIRES_REBOOT}" = "false" ]
    [ "${RLCH_MODULE_OPENSCAP_RULE}" = "xccdf_org.ssgproject.content_rule_wireless_disable_interfaces" ]
}
