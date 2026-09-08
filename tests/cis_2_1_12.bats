#!/usr/bin/env bats
setup() {
    source "${BATS_TEST_DIRNAME}/test_helper.bash"
    source "${BATS_TEST_DIRNAME}/helpers/rpcbind_server_helper.bash"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/common.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/modules.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/module_api.sh"
    setup_rpcbind_server_test_environment
    RLCH_CIS_2_1_12_STATE_DIR="${RLCH_TEST_RPCBIND_STATE}/2.1.12"
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/2/1/12/module.sh"
}
teardown() { teardown_rpcbind_server_test_environment; }

@test "check succeeds when rpcbind is absent" {
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}
@test "check fails when service is active" {
    add_rpcbind_package
    set_rpcbind_unit_state rpcbind.service enabled active
    set_rpcbind_unit_state rpcbind.socket masked inactive
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}
@test "check fails when socket is not masked" {
    add_rpcbind_package
    set_rpcbind_unit_state rpcbind.service masked inactive
    set_rpcbind_unit_state rpcbind.socket disabled inactive
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}
@test "check succeeds when both units are inactive and masked" {
    add_rpcbind_package
    set_rpcbind_unit_state rpcbind.service masked inactive
    set_rpcbind_unit_state rpcbind.socket masked inactive
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}
@test "apply hardens both rpcbind units" {
    add_rpcbind_package
    set_rpcbind_unit_state rpcbind.service enabled active
    set_rpcbind_unit_state rpcbind.socket enabled active
    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "$(get_rpcbind_enabled rpcbind.service)" = masked ]
    [ "$(get_rpcbind_active rpcbind.service)" = inactive ]
    [ "$(get_rpcbind_enabled rpcbind.socket)" = masked ]
    [ "$(get_rpcbind_active rpcbind.socket)" = inactive ]
}
@test "apply is idempotent" {
    add_rpcbind_package
    set_rpcbind_unit_state rpcbind.service masked inactive
    set_rpcbind_unit_state rpcbind.socket masked inactive
    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}
@test "rollback restores original states" {
    add_rpcbind_package
    set_rpcbind_unit_state rpcbind.service enabled active
    set_rpcbind_unit_state rpcbind.socket disabled inactive
    apply_result=0
    apply || apply_result=$?
    [ "${apply_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    run rollback
    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "$(get_rpcbind_enabled rpcbind.service)" = enabled ]
    [ "$(get_rpcbind_active rpcbind.service)" = active ]
    [ "$(get_rpcbind_enabled rpcbind.socket)" = disabled ]
    [ "$(get_rpcbind_active rpcbind.socket)" = inactive ]
}
@test "rollback is idempotent without state" {
    run rollback
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}
@test "metadata is correct" {
    clear_module_metadata_variables
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/2/1/12/metadata.conf"
    [ "${RLCH_MODULE_ID}" = "2.1.12" ]
    [ "${RLCH_MODULE_LEVEL}" = "1" ]
    [ "${RLCH_MODULE_OPENSCAP_RULE}" = "xccdf_org.ssgproject.content_rule_service_rpcbind_disabled" ]
}
