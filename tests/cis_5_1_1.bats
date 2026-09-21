#!/usr/bin/env bats

setup() {
    export RLCH_TEST_REPOSITORY_ROOT="${BATS_TEST_DIRNAME}/.."
    source "${RLCH_TEST_REPOSITORY_ROOT}/tests/test_helper.bash"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/module_api.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/tests/helpers/sshd_config_access_helper.bash"
    sshd_config_access_helper_setup
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/5/1/1/module.sh"
}

@test "check accepts root root and mode 0600" {
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check accepts more restrictive permissions" {
    sshd_config_access_helper_set 0 0 400
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check rejects an incorrect owner" {
    sshd_config_access_helper_set 1000 0 600
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check rejects an incorrect group" {
    sshd_config_access_helper_set 0 100 600
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check rejects group or other permissions" {
    sshd_config_access_helper_set 0 0 640
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check reports a missing sshd_config as non-compliant" {
    rm -f -- "${RLCH_CIS_5_1_1_PATH}"
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check reports stat failures as errors" {
    RLCH_TEST_SSHD_ACCESS_FAIL="stat"
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
}

@test "apply changes only access metadata and records exact original values" {
    sshd_config_access_helper_set 1000 100 664
    printf '%s\n' "# preserved" > "${RLCH_CIS_5_1_1_PATH}"
    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "$(cat "${RLCH_CIS_5_1_1_STATE_FILE}")" = "1000:100:664" ]
    [ "$(cat "${RLCH_CIS_5_1_1_PATH}")" = "# preserved" ]
    [ "$(cat "${RLCH_TEST_SSHD_ACCESS_METADATA}.owner")" = "0" ]
    [ "$(cat "${RLCH_TEST_SSHD_ACCESS_METADATA}.group")" = "0" ]
    [ "$(cat "${RLCH_TEST_SSHD_ACCESS_METADATA}.mode")" = "600" ]
}

@test "apply is idempotent when already compliant" {
    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
    [ ! -e "${RLCH_CIS_5_1_1_STATE_FILE}" ]
    ! grep -E '^chown |^chmod 0600 ' "${RLCH_TEST_SSHD_ACCESS_LOG}"
}

@test "apply requires root before creating rollback state" {
    sshd_config_access_helper_set 1000 100 664
    RLCH_TEST_SSHD_ACCESS_UID="1000"
    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [ ! -e "${RLCH_CIS_5_1_1_STATE_FILE}" ]
}

@test "apply reports effective uid lookup errors" {
    sshd_config_access_helper_set 1000 100 664
    RLCH_TEST_SSHD_ACCESS_ID_FAIL="true"
    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
}

@test "apply retains rollback state when access changes fail" {
    sshd_config_access_helper_set 1000 100 664
    RLCH_TEST_SSHD_ACCESS_FAIL="chown"
    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [ "$(cat "${RLCH_CIS_5_1_1_STATE_FILE}")" = "1000:100:664" ]
}

@test "validate delegates to check" {
    sshd_config_access_helper_set 0 100 600
    run validate
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "rollback restores exact numeric owner group and mode" {
    local apply_result=0 rollback_result=0
    sshd_config_access_helper_set 1000 100 664
    apply || apply_result=$?
    rollback || rollback_result=$?
    [ "${apply_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "${rollback_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "$(cat "${RLCH_TEST_SSHD_ACCESS_METADATA}.owner")" = "1000" ]
    [ "$(cat "${RLCH_TEST_SSHD_ACCESS_METADATA}.group")" = "100" ]
    [ "$(cat "${RLCH_TEST_SSHD_ACCESS_METADATA}.mode")" = "664" ]
    [ ! -e "${RLCH_CIS_5_1_1_STATE_FILE}" ]
}

@test "rollback is idempotent without saved state" {
    run rollback
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "rollback rejects malformed state without changing the target" {
    mkdir -p -- "${RLCH_CIS_5_1_1_STATE_DIR}"
    printf '%s\n' "invalid" > "${RLCH_CIS_5_1_1_STATE_FILE}"
    run rollback
    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [ -e "${RLCH_CIS_5_1_1_STATE_FILE}" ]
}

@test "metadata records the three-rule mapping as manual" {
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/5/1/1/metadata.conf"
    [ "${RLCH_MODULE_ID}" = "5.1.1" ]
    [ "${RLCH_MODULE_LEVEL}" = "1" ]
    [ "${RLCH_MODULE_ENABLED}" = "true" ]
    [ "${RLCH_MODULE_OPENSCAP_RULE}" = "manual" ]
}
