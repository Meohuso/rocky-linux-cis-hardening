#!/usr/bin/env bats

setup() {
    source "${BATS_TEST_DIRNAME}/test_helper.bash"
    source "${BATS_TEST_DIRNAME}/helpers/nis_server_helper.bash"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/common.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/modules.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/module_api.sh"
    setup_nis_server_test_environment
    RLCH_CIS_2_1_10_STATE_DIR="${RLCH_TEST_NIS_SERVER_STATE}/2.1.10"
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/2/1/10/module.sh"
}

teardown() { teardown_nis_server_test_environment; }

@test "check succeeds when ypserv is not installed" {
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check reports non-compliance when ypserv is installed" {
    add_nis_server_test_package "ypserv"
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "apply removes ypserv when installed" {
    add_nis_server_test_package "ypserv"
    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    ! grep -Fxq -- "ypserv" "${RLCH_TEST_NIS_SERVER_PACKAGES}"
}

@test "apply is idempotent when ypserv is already absent" {
    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
    [ ! -e "${RLCH_CIS_2_1_10_STATE_DIR}" ]
}

@test "apply reports error when package removal fails" {
    add_nis_server_test_package "ypserv"
    set_nis_server_test_dnf_status 1
    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
}

@test "rollback reinstalls ypserv when removed by module" {
    add_nis_server_test_package "ypserv"
    apply_result=0
    apply || apply_result=$?
    [ "${apply_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    run rollback
    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    grep -Fxq -- "ypserv" "${RLCH_TEST_NIS_SERVER_PACKAGES}"
    [ ! -e "${RLCH_CIS_2_1_10_STATE_DIR}" ]
}

@test "rollback is idempotent without saved state" {
    run rollback
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "rollback reports error when package installation fails" {
    add_nis_server_test_package "ypserv"
    apply_result=0
    apply || apply_result=$?
    [ "${apply_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    set_nis_server_test_dnf_status 1
    run rollback
    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [ -e "${RLCH_CIS_2_1_10_STATE_DIR}/state" ]
}

@test "metadata declares the expected CIS control" {
    clear_module_metadata_variables
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/2/1/10/metadata.conf"
    [ "${RLCH_MODULE_ID}" = "2.1.10" ]
    [ "${RLCH_MODULE_LEVEL}" = "1" ]
    [ "${RLCH_MODULE_ENABLED}" = "true" ]
    [ "${RLCH_MODULE_REQUIRES_REBOOT}" = "false" ]
    [ "${RLCH_MODULE_OPENSCAP_RULE}" = "manual" ]
}
