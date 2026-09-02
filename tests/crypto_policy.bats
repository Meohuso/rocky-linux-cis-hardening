#!/usr/bin/env bats
#
# Rocky Linux CIS Hardening Framework
#
# System-wide cryptographic policy library tests.
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
}

teardown() {
    teardown_crypto_policy_test_environment
}

@test "crypto_policy_current returns the active policy" {
    set_crypto_policy_test_current "DEFAULT"
    run crypto_policy_current
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
    [ "${output}" = "DEFAULT" ]
}

@test "crypto_policy_is_legacy reports non-compliance for LEGACY" {
    set_crypto_policy_test_current "LEGACY"
    run crypto_policy_is_legacy
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "crypto_policy_is_legacy reports non-compliance for a LEGACY subpolicy" {
    set_crypto_policy_test_current "LEGACY:TEST"
    run crypto_policy_is_legacy
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "crypto_policy_is_legacy succeeds for DEFAULT" {
    set_crypto_policy_test_current "DEFAULT"
    run crypto_policy_is_legacy
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "crypto_policy_is_legacy preserves a non-legacy custom policy" {
    set_crypto_policy_test_current "DEFAULT:CUSTOM"
    run crypto_policy_is_legacy
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "crypto_policy_set changes policy and records previous value" {
    set_crypto_policy_test_current "LEGACY"
    run crypto_policy_set "DEFAULT"
    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "$(cat "${RLCH_TEST_CRYPTO_POLICY_RUNTIME_STATE}")" = "DEFAULT" ]
    [ "$(cat "${RLCH_CRYPTO_POLICY_BACKUP_FILE}")" = "LEGACY" ]
}

@test "crypto_policy_set is idempotent" {
    set_crypto_policy_test_current "DEFAULT"
    run crypto_policy_set "DEFAULT"
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
    [ ! -e "${RLCH_CRYPTO_POLICY_BACKUP_FILE}" ]
}

@test "crypto_policy_set requires root privileges" {
    set_crypto_policy_test_current "LEGACY"
    set_crypto_policy_test_effective_uid "1000"
    run crypto_policy_set "DEFAULT"
    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
}

@test "crypto_policy_rollback restores previous policy and consumes backup" {
    set_crypto_policy_test_current "LEGACY"
    run crypto_policy_set "DEFAULT"
    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    run crypto_policy_rollback
    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "$(cat "${RLCH_TEST_CRYPTO_POLICY_RUNTIME_STATE}")" = "LEGACY" ]
    [ ! -e "${RLCH_CRYPTO_POLICY_BACKUP_FILE}" ]
}

@test "crypto_policy_rollback is idempotent after rollback" {
    set_crypto_policy_test_current "LEGACY"
    run crypto_policy_set "DEFAULT"
    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    run crypto_policy_rollback
    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    run crypto_policy_rollback
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}
