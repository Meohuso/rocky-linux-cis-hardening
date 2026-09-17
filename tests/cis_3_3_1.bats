#!/usr/bin/env bats

setup() {
    export RLCH_TEST_REPOSITORY_ROOT="${BATS_TEST_DIRNAME}/.."
    source "${RLCH_TEST_REPOSITORY_ROOT}/tests/test_helper.bash"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/module_api.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/tests/helpers/sysctl_control_helper.bash"
    sysctl_control_helper_setup
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/sysctl_control.sh"

    export RLCH_CIS_3_3_1_CONFIG="${RLCH_TEST_SYSCTL_CONTROL_CONFIG_DIR}/60-rlch-cis-3.3.1.conf"
    export RLCH_CIS_3_3_1_STATE_DIR="${RLCH_TEST_SYSCTL_CONTROL_ROOT}/state/3.3.1"
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/3/3/1/module.sh"
    sysctl_control_helper_set_runtime net.ipv4.ip_forward 1
    sysctl_control_helper_set_runtime net.ipv6.conf.all.forwarding 1
}

cis_3_3_1_write_compliant_config() {
    sysctl_control_helper_write_config "${RLCH_CIS_3_3_1_CONFIG}" <<'EOF'
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0
EOF
}

@test "check requires compliant IPv4 and IPv6 runtime and persistent values" {
    cis_3_3_1_write_compliant_config
    sysctl_control_helper_set_runtime net.ipv4.ip_forward 0
    sysctl_control_helper_set_runtime net.ipv6.conf.all.forwarding 0

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check reports non-compliance for enabled IPv4 forwarding" {
    cis_3_3_1_write_compliant_config
    sysctl_control_helper_set_runtime net.ipv6.conf.all.forwarding 0

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check reports non-compliance when persistent configuration is missing" {
    sysctl_control_helper_set_runtime net.ipv4.ip_forward 0
    sysctl_control_helper_set_runtime net.ipv6.conf.all.forwarding 0

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "missing IPv6 parameter is an error and not not-applicable" {
    grep -v '^net.ipv6.conf.all.forwarding=' "${RLCH_TEST_SYSCTL_CONTROL_RUNTIME}" > "${RLCH_TEST_SYSCTL_CONTROL_RUNTIME}.tmp"
    mv "${RLCH_TEST_SYSCTL_CONTROL_RUNTIME}.tmp" "${RLCH_TEST_SYSCTL_CONTROL_RUNTIME}"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
}

@test "apply disables IPv4 and IPv6 forwarding" {
    local result=0

    apply || result=$?

    [ "${result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "$(sysctl_control_helper_runtime_value net.ipv4.ip_forward)" = 0 ]
    [ "$(sysctl_control_helper_runtime_value net.ipv6.conf.all.forwarding)" = 0 ]
    grep -Fqx 'net.ipv4.ip_forward = 0' "${RLCH_CIS_3_3_1_CONFIG}"
    grep -Fqx 'net.ipv6.conf.all.forwarding = 0' "${RLCH_CIS_3_3_1_CONFIG}"
}

@test "apply is idempotent when forwarding is already disabled" {
    cis_3_3_1_write_compliant_config
    sysctl_control_helper_set_runtime net.ipv4.ip_forward 0
    sysctl_control_helper_set_runtime net.ipv6.conf.all.forwarding 0

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
    [ ! -e "${RLCH_CIS_3_3_1_STATE_DIR}" ]
}

@test "rollback restores both forwarding values and removes only its file" {
    local apply_result=0
    local rollback_result=0

    apply || apply_result=$?
    rollback || rollback_result=$?

    [ "${apply_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "${rollback_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "$(sysctl_control_helper_runtime_value net.ipv4.ip_forward)" = 1 ]
    [ "$(sysctl_control_helper_runtime_value net.ipv6.conf.all.forwarding)" = 1 ]
    [ ! -e "${RLCH_CIS_3_3_1_CONFIG}" ]
}

@test "validate delegates to check" {
    run validate

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "metadata uses manual mapping for the multi-rule CIS control" {
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/3/3/1/metadata.conf"

    [ "${RLCH_MODULE_ID}" = 3.3.1 ]
    [ "${RLCH_MODULE_LEVEL}" = 1 ]
    [ "${RLCH_MODULE_OPENSCAP_RULE}" = manual ]
}
