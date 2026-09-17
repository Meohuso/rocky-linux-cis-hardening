#!/usr/bin/env bats

setup() {
    export RLCH_TEST_REPOSITORY_ROOT="${BATS_TEST_DIRNAME}/.."
    source "${RLCH_TEST_REPOSITORY_ROOT}/tests/test_helper.bash"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/module_api.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/tests/helpers/sysctl_control_helper.bash"
    sysctl_control_helper_setup
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/sysctl_control.sh"

    export RLCH_CIS_3_3_2_CONFIG="${RLCH_TEST_SYSCTL_CONTROL_CONFIG_DIR}/60-rlch-cis-3.3.2.conf"
    export RLCH_CIS_3_3_2_STATE_DIR="${RLCH_TEST_SYSCTL_CONTROL_ROOT}/state/3.3.2"
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/3/3/2/module.sh"
    sysctl_control_helper_set_runtime net.ipv4.conf.all.send_redirects 1
    sysctl_control_helper_set_runtime net.ipv4.conf.default.send_redirects 1
}

cis_3_3_2_write_compliant_config() {
    sysctl_control_helper_write_config "${RLCH_CIS_3_3_2_CONFIG}" <<'EOF'
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
EOF
}

@test "check requires compliant runtime and persistent redirect settings" {
    cis_3_3_2_write_compliant_config
    sysctl_control_helper_set_runtime net.ipv4.conf.all.send_redirects 0
    sysctl_control_helper_set_runtime net.ipv4.conf.default.send_redirects 0

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check reports non-compliance for runtime redirect sending" {
    cis_3_3_2_write_compliant_config
    sysctl_control_helper_set_runtime net.ipv4.conf.default.send_redirects 0

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check reports non-compliance when persistent configuration is missing" {
    sysctl_control_helper_set_runtime net.ipv4.conf.all.send_redirects 0
    sysctl_control_helper_set_runtime net.ipv4.conf.default.send_redirects 0

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "apply disables redirect sending for all and default interfaces" {
    local result=0

    apply || result=$?

    [ "${result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "$(sysctl_control_helper_runtime_value net.ipv4.conf.all.send_redirects)" = 0 ]
    [ "$(sysctl_control_helper_runtime_value net.ipv4.conf.default.send_redirects)" = 0 ]
    grep -Fqx 'net.ipv4.conf.all.send_redirects = 0' "${RLCH_CIS_3_3_2_CONFIG}"
    grep -Fqx 'net.ipv4.conf.default.send_redirects = 0' "${RLCH_CIS_3_3_2_CONFIG}"
}

@test "apply is idempotent when redirect sending is already disabled" {
    cis_3_3_2_write_compliant_config
    sysctl_control_helper_set_runtime net.ipv4.conf.all.send_redirects 0
    sysctl_control_helper_set_runtime net.ipv4.conf.default.send_redirects 0

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
    [ ! -e "${RLCH_CIS_3_3_2_STATE_DIR}" ]
}

@test "rollback restores redirect values and removes only its file" {
    local apply_result=0
    local rollback_result=0

    apply || apply_result=$?
    rollback || rollback_result=$?

    [ "${apply_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "${rollback_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "$(sysctl_control_helper_runtime_value net.ipv4.conf.all.send_redirects)" = 1 ]
    [ "$(sysctl_control_helper_runtime_value net.ipv4.conf.default.send_redirects)" = 1 ]
    [ ! -e "${RLCH_CIS_3_3_2_CONFIG}" ]
}

@test "validate delegates to check" {
    run validate

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "metadata uses manual mapping for the multi-rule CIS control" {
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/3/3/2/metadata.conf"

    [ "${RLCH_MODULE_ID}" = 3.3.2 ]
    [ "${RLCH_MODULE_LEVEL}" = 1 ]
    [ "${RLCH_MODULE_OPENSCAP_RULE}" = manual ]
}
