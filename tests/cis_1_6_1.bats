#!/usr/bin/env bats
#
# Rocky Linux CIS Hardening Framework
#
# CIS 1.6.1 tests.
#
# SPDX-License-Identifier: MIT
#

setup() {
    source "${BATS_TEST_DIRNAME}/test_helper.bash"
    source "${BATS_TEST_DIRNAME}/helpers/crypto_policy_helper.bash"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/common.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/modules.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/module_api.sh"
    setup_crypto_policy_test_environment
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/crypto_policy.sh"

    RLCH_CIS_1_6_1_TARGET_POLICY="DEFAULT"
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/1/6/1/module.sh"
}

teardown() {
    teardown_crypto_policy_test_environment
}

@test "check succeeds when crypto policy is DEFAULT" {
    set_crypto_policy_test_current "DEFAULT"
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check succeeds for an existing non-legacy custom policy" {
    set_crypto_policy_test_current "DEFAULT:CUSTOM"
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check reports non-compliance when crypto policy is LEGACY" {
    set_crypto_policy_test_current "LEGACY"
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "apply replaces LEGACY with DEFAULT" {
    set_crypto_policy_test_current "LEGACY"
    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "$(cat "${RLCH_TEST_CRYPTO_POLICY_RUNTIME_STATE}")" = "DEFAULT" ]
    [ "$(cat "${RLCH_CRYPTO_POLICY_BACKUP_FILE}")" = "LEGACY" ]
}

@test "apply preserves an existing compliant custom policy" {
    set_crypto_policy_test_current "DEFAULT:CUSTOM"
    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
    [ "$(cat "${RLCH_TEST_CRYPTO_POLICY_RUNTIME_STATE}")" = "DEFAULT:CUSTOM" ]
    [ ! -e "${RLCH_CRYPTO_POLICY_BACKUP_FILE}" ]
}

@test "apply is idempotent when crypto policy is DEFAULT" {
    set_crypto_policy_test_current "DEFAULT"
    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "apply requires root privileges when remediation is needed" {
    set_crypto_policy_test_current "LEGACY"
    set_crypto_policy_test_effective_uid "1000"
    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
}

@test "validate delegates to the compliance check" {
    set_crypto_policy_test_current "DEFAULT"
    run validate
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "rollback restores the previous crypto policy" {
    set_crypto_policy_test_current "LEGACY"
    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    run rollback
    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "$(cat "${RLCH_TEST_CRYPTO_POLICY_RUNTIME_STATE}")" = "LEGACY" ]
}

@test "rollback is idempotent when no backup exists" {
    set_crypto_policy_test_current "DEFAULT"
    run rollback
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "metadata declares the expected CIS control" {
    clear_module_metadata_variables
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/1/6/1/metadata.conf"
    [ "${RLCH_MODULE_ID}" = "1.6.1" ]
    [ "${RLCH_MODULE_LEVEL}" = "1" ]
    [ "${RLCH_MODULE_ENABLED}" = "true" ]
    [ "${RLCH_MODULE_REQUIRES_REBOOT}" = "false" ]
    [ "${RLCH_MODULE_OPENSCAP_RULE}" = "xccdf_org.ssgproject.content_rule_configure_custom_crypto_policy_cis" ]
}
