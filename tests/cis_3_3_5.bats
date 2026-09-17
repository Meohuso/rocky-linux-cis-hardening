#!/usr/bin/env bats

setup() {
    export RLCH_TEST_REPOSITORY_ROOT="${BATS_TEST_DIRNAME}/.."
    source "${RLCH_TEST_REPOSITORY_ROOT}/tests/test_helper.bash"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/module_api.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/tests/helpers/sysctl_control_helper.bash"
    sysctl_control_helper_setup
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/sysctl_control.sh"
    export RLCH_CIS_3_3_5_CONFIG="${RLCH_TEST_SYSCTL_CONTROL_CONFIG_DIR}/60-rlch-cis-3.3.5.conf"
    export RLCH_CIS_3_3_5_STATE_DIR="${RLCH_TEST_SYSCTL_CONTROL_ROOT}/state/3.3.5"
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/3/3/5/module.sh"
    local parameter
    for parameter in "${RLCH_CIS_3_3_5_PARAMETERS[@]}"; do
        sysctl_control_helper_set_runtime "${parameter}" 1
    done
}

cis_3_3_5_write_compliant_config() {
    sysctl_control_helper_write_config "${RLCH_CIS_3_3_5_CONFIG}" <<'EOF'
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
EOF
}

@test "check requires all runtime and persistent redirect values" {
    cis_3_3_5_write_compliant_config
    local parameter
    for parameter in "${RLCH_CIS_3_3_5_PARAMETERS[@]}"; do
        sysctl_control_helper_set_runtime "${parameter}" 0
    done
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check reports non-compliance for a runtime redirect value" {
    cis_3_3_5_write_compliant_config
    sysctl_control_helper_set_runtime net.ipv4.conf.all.accept_redirects 0
    sysctl_control_helper_set_runtime net.ipv4.conf.default.accept_redirects 0
    sysctl_control_helper_set_runtime net.ipv6.conf.all.accept_redirects 0
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check reports non-compliance without persistent configuration" {
    local parameter
    for parameter in "${RLCH_CIS_3_3_5_PARAMETERS[@]}"; do
        sysctl_control_helper_set_runtime "${parameter}" 0
    done
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "missing IPv6 parameter is an error rather than not-applicable" {
    grep -v '^net.ipv6.conf.default.accept_redirects=' "${RLCH_TEST_SYSCTL_CONTROL_RUNTIME}" > "${RLCH_TEST_SYSCTL_CONTROL_RUNTIME}.tmp"
    mv "${RLCH_TEST_SYSCTL_CONTROL_RUNTIME}.tmp" "${RLCH_TEST_SYSCTL_CONTROL_RUNTIME}"
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
}

@test "apply disables IPv4 and IPv6 redirect acceptance" {
    local result=0 parameter
    apply || result=$?
    [ "${result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    for parameter in "${RLCH_CIS_3_3_5_PARAMETERS[@]}"; do
        [ "$(sysctl_control_helper_runtime_value "${parameter}")" = 0 ]
        grep -Fqx "${parameter} = 0" "${RLCH_CIS_3_3_5_CONFIG}"
    done
}

@test "apply is idempotent when already compliant" {
    cis_3_3_5_write_compliant_config
    local parameter
    for parameter in "${RLCH_CIS_3_3_5_PARAMETERS[@]}"; do
        sysctl_control_helper_set_runtime "${parameter}" 0
    done
    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
    [ ! -e "${RLCH_CIS_3_3_5_STATE_DIR}" ]
}

@test "rollback restores all values and removes only its file" {
    local apply_result=0 rollback_result=0 parameter
    apply || apply_result=$?
    rollback || rollback_result=$?
    [ "${apply_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "${rollback_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    for parameter in "${RLCH_CIS_3_3_5_PARAMETERS[@]}"; do
        [ "$(sysctl_control_helper_runtime_value "${parameter}")" = 1 ]
    done
    [ ! -e "${RLCH_CIS_3_3_5_CONFIG}" ]
}

@test "validate delegates to check" {
    run validate
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "metadata uses manual mapping for four ComplianceAsCode rules" {
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/3/3/5/metadata.conf"
    [ "${RLCH_MODULE_ID}" = 3.3.5 ]
    [ "${RLCH_MODULE_LEVEL}" = 1 ]
    [ "${RLCH_MODULE_OPENSCAP_RULE}" = manual ]
}
