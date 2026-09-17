#!/usr/bin/env bats

setup() {
    export RLCH_TEST_REPOSITORY_ROOT="${BATS_TEST_DIRNAME}/.."
    source "${RLCH_TEST_REPOSITORY_ROOT}/tests/test_helper.bash"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/module_api.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/tests/helpers/sysctl_control_helper.bash"
    sysctl_control_helper_setup
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/sysctl_control.sh"
    export RLCH_CIS_3_3_7_CONFIG="${RLCH_TEST_SYSCTL_CONTROL_CONFIG_DIR}/60-rlch-cis-3.3.7.conf"
    export RLCH_CIS_3_3_7_STATE_DIR="${RLCH_TEST_SYSCTL_CONTROL_ROOT}/state/3.3.7"
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/3/3/7/module.sh"
    sysctl_control_helper_set_runtime net.ipv4.conf.all.rp_filter 0
    sysctl_control_helper_set_runtime net.ipv4.conf.default.rp_filter 0
}

cis_3_3_7_write_compliant_config() {
    sysctl_control_helper_write_config "${RLCH_CIS_3_3_7_CONFIG}" <<'EOF'
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
EOF
}

@test "check requires both runtime and persistent values" {
    cis_3_3_7_write_compliant_config
    sysctl_control_helper_set_runtime net.ipv4.conf.all.rp_filter 1
    sysctl_control_helper_set_runtime net.ipv4.conf.default.rp_filter 1
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check reports a non-compliant runtime value" {
    cis_3_3_7_write_compliant_config
    sysctl_control_helper_set_runtime net.ipv4.conf.all.rp_filter 1
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check reports missing persistent configuration" {
    sysctl_control_helper_set_runtime net.ipv4.conf.all.rp_filter 1
    sysctl_control_helper_set_runtime net.ipv4.conf.default.rp_filter 1
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "apply enables strict reverse path filtering" {
    local result=0
    apply || result=$?
    [ "${result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "$(sysctl_control_helper_runtime_value net.ipv4.conf.all.rp_filter)" = 1 ]
    [ "$(sysctl_control_helper_runtime_value net.ipv4.conf.default.rp_filter)" = 1 ]
    grep -Fqx 'net.ipv4.conf.all.rp_filter = 1' "${RLCH_CIS_3_3_7_CONFIG}"
    grep -Fqx 'net.ipv4.conf.default.rp_filter = 1' "${RLCH_CIS_3_3_7_CONFIG}"
}

@test "apply is idempotent when already compliant" {
    cis_3_3_7_write_compliant_config
    sysctl_control_helper_set_runtime net.ipv4.conf.all.rp_filter 1
    sysctl_control_helper_set_runtime net.ipv4.conf.default.rp_filter 1
    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
    [ ! -e "${RLCH_CIS_3_3_7_STATE_DIR}" ]
}

@test "rollback restores both values and removes only its file" {
    local apply_result=0 rollback_result=0
    apply || apply_result=$?
    rollback || rollback_result=$?
    [ "${apply_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "${rollback_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "$(sysctl_control_helper_runtime_value net.ipv4.conf.all.rp_filter)" = 0 ]
    [ "$(sysctl_control_helper_runtime_value net.ipv4.conf.default.rp_filter)" = 0 ]
    [ ! -e "${RLCH_CIS_3_3_7_CONFIG}" ]
}

@test "validate delegates to check" {
    run validate
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "metadata uses manual mapping for two ComplianceAsCode rules" {
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/3/3/7/metadata.conf"
    [ "${RLCH_MODULE_ID}" = 3.3.7 ]
    [ "${RLCH_MODULE_LEVEL}" = 1 ]
    [ "${RLCH_MODULE_OPENSCAP_RULE}" = manual ]
}
