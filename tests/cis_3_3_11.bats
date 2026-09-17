#!/usr/bin/env bats

setup() {
    export RLCH_TEST_REPOSITORY_ROOT="${BATS_TEST_DIRNAME}/.."
    source "${RLCH_TEST_REPOSITORY_ROOT}/tests/test_helper.bash"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/module_api.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/tests/helpers/sysctl_control_helper.bash"
    sysctl_control_helper_setup
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/sysctl_control.sh"
    export RLCH_CIS_3_3_11_CONFIG="${RLCH_TEST_SYSCTL_CONTROL_CONFIG_DIR}/60-rlch-cis-3.3.11.conf"
    export RLCH_CIS_3_3_11_STATE_DIR="${RLCH_TEST_SYSCTL_CONTROL_ROOT}/state/3.3.11"
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/3/3/11/module.sh"
    sysctl_control_helper_set_runtime net.ipv6.conf.all.accept_ra 1
    sysctl_control_helper_set_runtime net.ipv6.conf.default.accept_ra 1
}

cis_3_3_11_write_compliant_config() {
    sysctl_control_helper_write_config "${RLCH_CIS_3_3_11_CONFIG}" <<'EOF'
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
EOF
}

@test "check requires both runtime and persistent IPv6 values" {
    cis_3_3_11_write_compliant_config
    sysctl_control_helper_set_runtime net.ipv6.conf.all.accept_ra 0
    sysctl_control_helper_set_runtime net.ipv6.conf.default.accept_ra 0
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check reports a non-compliant runtime value" {
    cis_3_3_11_write_compliant_config
    sysctl_control_helper_set_runtime net.ipv6.conf.all.accept_ra 0
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check reports missing persistent configuration" {
    sysctl_control_helper_set_runtime net.ipv6.conf.all.accept_ra 0
    sysctl_control_helper_set_runtime net.ipv6.conf.default.accept_ra 0
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "missing IPv6 parameter is an error rather than not-applicable" {
    grep -v '^net.ipv6.conf.default.accept_ra=' "${RLCH_TEST_SYSCTL_CONTROL_RUNTIME}" > "${RLCH_TEST_SYSCTL_CONTROL_RUNTIME}.tmp"
    mv "${RLCH_TEST_SYSCTL_CONTROL_RUNTIME}.tmp" "${RLCH_TEST_SYSCTL_CONTROL_RUNTIME}"
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
}

@test "apply disables router-advertisement acceptance" {
    local result=0
    apply || result=$?
    [ "${result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "$(sysctl_control_helper_runtime_value net.ipv6.conf.all.accept_ra)" = 0 ]
    [ "$(sysctl_control_helper_runtime_value net.ipv6.conf.default.accept_ra)" = 0 ]
    grep -Fqx 'net.ipv6.conf.all.accept_ra = 0' "${RLCH_CIS_3_3_11_CONFIG}"
    grep -Fqx 'net.ipv6.conf.default.accept_ra = 0' "${RLCH_CIS_3_3_11_CONFIG}"
}

@test "apply is idempotent when already compliant" {
    cis_3_3_11_write_compliant_config
    sysctl_control_helper_set_runtime net.ipv6.conf.all.accept_ra 0
    sysctl_control_helper_set_runtime net.ipv6.conf.default.accept_ra 0
    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
    [ ! -e "${RLCH_CIS_3_3_11_STATE_DIR}" ]
}

@test "rollback restores both values and removes only its file" {
    local apply_result=0 rollback_result=0
    apply || apply_result=$?
    rollback || rollback_result=$?
    [ "${apply_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "${rollback_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "$(sysctl_control_helper_runtime_value net.ipv6.conf.all.accept_ra)" = 1 ]
    [ "$(sysctl_control_helper_runtime_value net.ipv6.conf.default.accept_ra)" = 1 ]
    [ ! -e "${RLCH_CIS_3_3_11_CONFIG}" ]
}

@test "validate delegates to check" {
    run validate
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "metadata uses manual mapping for two ComplianceAsCode rules" {
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/3/3/11/metadata.conf"
    [ "${RLCH_MODULE_ID}" = 3.3.11 ]
    [ "${RLCH_MODULE_LEVEL}" = 1 ]
    [ "${RLCH_MODULE_OPENSCAP_RULE}" = manual ]
}
