#!/usr/bin/env bats

setup() {
    export RLCH_TEST_REPOSITORY_ROOT="${BATS_TEST_DIRNAME}/.."
    source "${RLCH_TEST_REPOSITORY_ROOT}/tests/test_helper.bash"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/module_api.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/tests/helpers/sysctl_control_helper.bash"
    sysctl_control_helper_setup
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/sysctl_control.sh"
    export RLCH_CIS_3_3_4_CONFIG="${RLCH_TEST_SYSCTL_CONTROL_CONFIG_DIR}/60-rlch-cis-3.3.4.conf"
    export RLCH_CIS_3_3_4_STATE_DIR="${RLCH_TEST_SYSCTL_CONTROL_ROOT}/state/3.3.4"
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/3/3/4/module.sh"
    sysctl_control_helper_set_runtime net.ipv4.icmp_echo_ignore_broadcasts 0
}

cis_3_3_4_write_compliant_config() {
    sysctl_control_helper_write_config "${RLCH_CIS_3_3_4_CONFIG}" <<'EOF'
net.ipv4.icmp_echo_ignore_broadcasts = 1
EOF
}

@test "check requires compliant runtime and persistent values" {
    cis_3_3_4_write_compliant_config
    sysctl_control_helper_set_runtime net.ipv4.icmp_echo_ignore_broadcasts 1
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check reports non-compliance for the runtime value" {
    cis_3_3_4_write_compliant_config
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check reports non-compliance without persistent configuration" {
    sysctl_control_helper_set_runtime net.ipv4.icmp_echo_ignore_broadcasts 1
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "apply ignores broadcast ICMP requests" {
    local result=0
    apply || result=$?
    [ "${result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "$(sysctl_control_helper_runtime_value net.ipv4.icmp_echo_ignore_broadcasts)" = 1 ]
    grep -Fqx 'net.ipv4.icmp_echo_ignore_broadcasts = 1' "${RLCH_CIS_3_3_4_CONFIG}"
}

@test "apply is idempotent when already compliant" {
    cis_3_3_4_write_compliant_config
    sysctl_control_helper_set_runtime net.ipv4.icmp_echo_ignore_broadcasts 1
    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
    [ ! -e "${RLCH_CIS_3_3_4_STATE_DIR}" ]
}

@test "rollback restores the value and removes only its file" {
    local apply_result=0 rollback_result=0
    apply || apply_result=$?
    rollback || rollback_result=$?
    [ "${apply_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "${rollback_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "$(sysctl_control_helper_runtime_value net.ipv4.icmp_echo_ignore_broadcasts)" = 0 ]
    [ ! -e "${RLCH_CIS_3_3_4_CONFIG}" ]
}

@test "validate delegates to check" {
    run validate
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "metadata uses the exact ComplianceAsCode rule" {
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/3/3/4/metadata.conf"
    [ "${RLCH_MODULE_ID}" = 3.3.4 ]
    [ "${RLCH_MODULE_LEVEL}" = 1 ]
    [ "${RLCH_MODULE_OPENSCAP_RULE}" = xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_icmp_echo_ignore_broadcasts ]
}
