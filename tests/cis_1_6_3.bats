#!/usr/bin/env bats
#
# Rocky Linux CIS Hardening Framework
#
# CIS 1.6.3 tests.
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

    RLCH_CIS_1_6_3_SUBPOLICY="NO-SHA1"
    RLCH_CIS_1_6_3_MODULE_FILE="${RLCH_TEST_CRYPTO_POLICY_MODULE_DIR}/NO-SHA1.pmod"
    RLCH_CIS_1_6_3_CURRENT_FILE="${RLCH_TEST_CRYPTO_POLICY_CURRENT_FILE}"
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/1/6/3/module.sh"
}

teardown() { teardown_crypto_policy_test_environment; }

create_compliant_sha1_policy() {
    set_crypto_policy_test_current "DEFAULT:NO-SHA1"
    write_crypto_policy_test_current_file <<'POLICY'
hash = SHA2-256 SHA2-384 SHA2-512
sign = RSA-SHA2-256 RSA-SHA2-384 RSA-SHA2-512
sha1_in_certs = 0
POLICY
}

create_non_compliant_sha1_policy() {
    set_crypto_policy_test_current "DEFAULT"
    write_crypto_policy_test_current_file <<'POLICY'
hash = SHA1 SHA2-256 SHA2-384 SHA2-512
sign = RSA-SHA1 RSA-SHA2-256 RSA-SHA2-384 RSA-SHA2-512
sha1_in_certs = 1
POLICY
}

@test "check succeeds when SHA1 hash and signatures are disabled" {
    create_compliant_sha1_policy
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check reports non-compliance when SHA1 signatures remain enabled" {
    create_non_compliant_sha1_policy
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "apply installs NO-SHA1 and preserves the base policy" {
    create_non_compliant_sha1_policy
    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "$(cat "${RLCH_TEST_CRYPTO_POLICY_RUNTIME_STATE}")" = "DEFAULT:NO-SHA1" ]
    grep -Fqx "hash = -SHA1" "${RLCH_CIS_1_6_3_MODULE_FILE}"
    grep -Fqx "sign = -*-SHA1" "${RLCH_CIS_1_6_3_MODULE_FILE}"
    grep -Fqx "sha1_in_certs = 0" "${RLCH_CIS_1_6_3_MODULE_FILE}"
}

@test "apply preserves existing crypto subpolicies" {
    create_non_compliant_sha1_policy
    set_crypto_policy_test_current "DEFAULT:CUSTOM"
    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "$(cat "${RLCH_TEST_CRYPTO_POLICY_RUNTIME_STATE}")" = "DEFAULT:CUSTOM:NO-SHA1" ]
}

@test "apply is idempotent when generated crypto policy is compliant" {
    create_compliant_sha1_policy
    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "validate succeeds after remediation" {
    create_non_compliant_sha1_policy
    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    run validate
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "rollback restores previous policy and removes framework module" {
    create_non_compliant_sha1_policy
    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    run rollback
    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "$(cat "${RLCH_TEST_CRYPTO_POLICY_RUNTIME_STATE}")" = "DEFAULT" ]
    [ ! -e "${RLCH_CIS_1_6_3_MODULE_FILE}" ]
}

@test "rollback is idempotent when no managed state exists" {
    create_compliant_sha1_policy
    run rollback
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "metadata declares the expected CIS control" {
    clear_module_metadata_variables
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/1/6/3/metadata.conf"
    [ "${RLCH_MODULE_ID}" = "1.6.3" ]
    [ "${RLCH_MODULE_LEVEL}" = "1" ]
    [ "${RLCH_MODULE_ENABLED}" = "true" ]
    [ "${RLCH_MODULE_REQUIRES_REBOOT}" = "true" ]
    [ "${RLCH_MODULE_OPENSCAP_RULE}" = "xccdf_org.ssgproject.content_rule_configure_custom_crypto_policy_cis" ]
}
