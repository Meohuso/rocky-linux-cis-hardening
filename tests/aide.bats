#!/usr/bin/env bats
# SPDX-License-Identifier: MIT

setup() {
    source "${BATS_TEST_DIRNAME}/test_helper.bash"
    source "${BATS_TEST_DIRNAME}/helpers/aide_helper.bash"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/common.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/modules.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/module_api.sh"
    setup_aide_test_environment
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/aide.sh"
}

teardown() { teardown_aide_test_environment; }

@test "aide_rule_is_configured succeeds for the expected rule" {
    printf '%s\n' "/usr/sbin/auditctl p+i+n+u+g+s+b+acl+xattrs+sha512" > "${RLCH_TEST_AIDE_CONFIG}"
    run aide_rule_is_configured "/usr/sbin/auditctl" "p+i+n+u+g+s+b+acl+xattrs+sha512" "${RLCH_TEST_AIDE_CONFIG}"
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "aide_rule_is_configured reports non-compliance for incorrect attributes" {
    printf '%s\n' "/usr/sbin/auditctl p+i+n+u+g+s+b" > "${RLCH_TEST_AIDE_CONFIG}"
    run aide_rule_is_configured "/usr/sbin/auditctl" "p+i+n+u+g+s+b+acl+xattrs+sha512" "${RLCH_TEST_AIDE_CONFIG}"
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "aide_rule_is_configured ignores commented rules" {
    printf '%s\n' "#/usr/sbin/auditctl p+i+n+u+g+s+b+acl+xattrs+sha512" > "${RLCH_TEST_AIDE_CONFIG}"
    run aide_rule_is_configured "/usr/sbin/auditctl" "p+i+n+u+g+s+b+acl+xattrs+sha512" "${RLCH_TEST_AIDE_CONFIG}"
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "aide_set_rule adds a missing rule and creates a backup" {
    run aide_set_rule "/usr/sbin/auditctl" "p+i+n+u+g+s+b+acl+xattrs+sha512" "${RLCH_TEST_AIDE_CONFIG}"
    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    grep -Fqx "/usr/sbin/auditctl p+i+n+u+g+s+b+acl+xattrs+sha512" "${RLCH_TEST_AIDE_CONFIG}"
    [ -f "${RLCH_TEST_AIDE_CONFIG}${RLCH_AIDE_CONFIG_BACKUP_SUFFIX}" ]
}

@test "aide_set_rule replaces an existing active rule" {
    printf '%s\n' "/usr/sbin/auditctl p+i+n+u+g+s+b" > "${RLCH_TEST_AIDE_CONFIG}"
    run aide_set_rule "/usr/sbin/auditctl" "p+i+n+u+g+s+b+acl+xattrs+sha512" "${RLCH_TEST_AIDE_CONFIG}"
    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    grep -Fqx "/usr/sbin/auditctl p+i+n+u+g+s+b+acl+xattrs+sha512" "${RLCH_TEST_AIDE_CONFIG}"
}

@test "aide_set_rule is idempotent" {
    printf '%s\n' "/usr/sbin/auditctl p+i+n+u+g+s+b+acl+xattrs+sha512" > "${RLCH_TEST_AIDE_CONFIG}"
    run aide_set_rule "/usr/sbin/auditctl" "p+i+n+u+g+s+b+acl+xattrs+sha512" "${RLCH_TEST_AIDE_CONFIG}"
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
    [ ! -e "${RLCH_TEST_AIDE_CONFIG}${RLCH_AIDE_CONFIG_BACKUP_SUFFIX}" ]
}

@test "aide_set_rule requires root privileges" {
    set_aide_test_effective_uid "1000"
    run aide_set_rule "/usr/sbin/auditctl" "p+i+n+u+g+s+b+acl+xattrs+sha512" "${RLCH_TEST_AIDE_CONFIG}"
    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
}

@test "aide_rollback_config restores the original configuration" {
    printf '%s\n' "# Original AIDE configuration" > "${RLCH_TEST_AIDE_CONFIG}"
    create_aide_test_backup
    printf '%s\n' "/usr/sbin/auditctl p+i+n+u+g+s+b+acl+xattrs+sha512" >> "${RLCH_TEST_AIDE_CONFIG}"
    run aide_rollback_config "${RLCH_TEST_AIDE_CONFIG}"
    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    grep -Fqx "# Original AIDE configuration" "${RLCH_TEST_AIDE_CONFIG}"
}

@test "aide_rollback_config is idempotent without a backup" {
    run aide_rollback_config "${RLCH_TEST_AIDE_CONFIG}"
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}
