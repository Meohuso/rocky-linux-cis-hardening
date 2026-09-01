#!/usr/bin/env bats
# SPDX-License-Identifier: MIT

setup() {
    source "${BATS_TEST_DIRNAME}/test_helper.bash"
    source "${BATS_TEST_DIRNAME}/helpers/rpm_helper.bash"
    source "${BATS_TEST_DIRNAME}/helpers/aide_helper.bash"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/common.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/modules.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/module_api.sh"
    setup_rpm_test_environment
    setup_aide_test_environment
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/rpm.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/aide.sh"
    RLCH_CIS_1_3_3_AIDE_CONFIG="${RLCH_TEST_AIDE_CONFIG}"
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/1/3/3/module.sh"
}

teardown() {
    teardown_aide_test_environment
    teardown_rpm_test_environment
}

add_compliant_audit_tool_rules() {
    local tool
    for tool in /usr/sbin/auditctl /usr/sbin/auditd /usr/sbin/ausearch /usr/sbin/aureport /usr/sbin/autrace /usr/sbin/augenrules; do
        printf '%s %s\n' "${tool}" "p+i+n+u+g+s+b+acl+xattrs+sha512" >> "${RLCH_TEST_AIDE_CONFIG}"
    done
}

@test "check succeeds when all audit tools are protected" {
    add_rpm_test_package "aide"; add_compliant_audit_tool_rules
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check reports non-compliance when AIDE is not installed" {
    add_compliant_audit_tool_rules
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check reports non-compliance when an audit tool rule is missing" {
    add_rpm_test_package "aide"
    printf '%s\n' "/usr/sbin/auditctl p+i+n+u+g+s+b+acl+xattrs+sha512" >> "${RLCH_TEST_AIDE_CONFIG}"
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "apply configures all required audit tool rules" {
    add_rpm_test_package "aide"
    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "apply is idempotent" {
    add_rpm_test_package "aide"; add_compliant_audit_tool_rules
    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "apply fails when AIDE is not installed" {
    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [[ "${output}" == *"AIDE must be installed"* ]]
}

@test "apply requires root privileges" {
    add_rpm_test_package "aide"; set_aide_test_effective_uid "1000"
    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
}

@test "validate delegates to check" {
    add_rpm_test_package "aide"; add_compliant_audit_tool_rules
    run validate
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "rollback restores original AIDE configuration" {
    add_rpm_test_package "aide"
    printf '%s\n' "# Original configuration" > "${RLCH_TEST_AIDE_CONFIG}"
    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    run rollback
    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    grep -Fqx "# Original configuration" "${RLCH_TEST_AIDE_CONFIG}"
    ! grep -Fq "/usr/sbin/auditctl" "${RLCH_TEST_AIDE_CONFIG}"
}

@test "rollback is idempotent without a backup" {
    run rollback
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "metadata declares the expected CIS control" {
    clear_module_metadata_variables
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/1/3/3/metadata.conf"
    [ "${RLCH_MODULE_ID}" = "1.3.3" ]
    [ "${RLCH_MODULE_LEVEL}" = "1" ]
    [ "${RLCH_MODULE_ENABLED}" = "true" ]
    [ "${RLCH_MODULE_REQUIRES_REBOOT}" = "false" ]
    [ "${RLCH_MODULE_OPENSCAP_RULE}" = "xccdf_org.ssgproject.content_rule_aide_check_audit_tools" ]
}
