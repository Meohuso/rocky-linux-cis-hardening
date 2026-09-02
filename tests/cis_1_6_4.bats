#!/usr/bin/env bats
#
# Rocky Linux CIS Hardening Framework
#
# CIS 1.6.4 tests.
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

    RLCH_CIS_1_6_4_SUBPOLICY="NO-WEAKMAC"
    RLCH_CIS_1_6_4_MODULE_FILE="${RLCH_TEST_CRYPTO_POLICY_MODULE_DIR}/NO-WEAKMAC.pmod"
    RLCH_CIS_1_6_4_CURRENT_FILE="${RLCH_TEST_CRYPTO_POLICY_CURRENT_FILE}"

    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/1/6/4/module.sh"
}

teardown() {
    teardown_crypto_policy_test_environment
}

create_compliant_mac_policy() {
    set_crypto_policy_test_current "DEFAULT:NO-WEAKMAC"
    write_crypto_policy_test_current_file <<'EOF'
mac = HMAC-SHA2-256 HMAC-SHA2-384 HMAC-SHA2-512 UMAC-128
EOF
}

create_non_compliant_mac_policy() {
    set_crypto_policy_test_current "DEFAULT"
    write_crypto_policy_test_current_file <<'EOF'
mac = HMAC-SHA2-256 HMAC-SHA2-512 UMAC-64
EOF
}

@test "check succeeds when MACs below 128 bits are disabled" {
    create_compliant_mac_policy

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check reports non-compliance when a 64-bit MAC remains enabled" {
    create_non_compliant_mac_policy

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check reports error when generated crypto policy is unavailable" {
    create_compliant_mac_policy
    rm -f "${RLCH_CIS_1_6_4_CURRENT_FILE}"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
}

@test "apply creates NO-WEAKMAC and preserves the current crypto policy" {
    create_non_compliant_mac_policy

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "$(cat "${RLCH_TEST_CRYPTO_POLICY_RUNTIME_STATE}")" = "DEFAULT:NO-WEAKMAC" ]
    grep -Fqx "mac = -*-64*" "${RLCH_CIS_1_6_4_MODULE_FILE}"
    [ "$(cat "${RLCH_CRYPTO_POLICY_BACKUP_FILE}")" = "DEFAULT" ]
}

@test "apply preserves existing crypto subpolicies" {
    create_non_compliant_mac_policy
    set_crypto_policy_test_current "DEFAULT:NO-SHA1"

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "$(cat "${RLCH_TEST_CRYPTO_POLICY_RUNTIME_STATE}")" = "DEFAULT:NO-SHA1:NO-WEAKMAC" ]
}

@test "apply is idempotent when generated crypto policy is compliant" {
    create_compliant_mac_policy

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
    [ ! -e "${RLCH_CRYPTO_POLICY_BACKUP_FILE}" ]
}

@test "rollback restores previous crypto policy and removes framework module" {
    create_non_compliant_mac_policy

    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]

    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "$(cat "${RLCH_TEST_CRYPTO_POLICY_RUNTIME_STATE}")" = "DEFAULT" ]
    [ ! -e "${RLCH_CIS_1_6_4_MODULE_FILE}" ]
    [ ! -e "${RLCH_CRYPTO_POLICY_BACKUP_FILE}" ]
}

@test "rollback is idempotent when no managed state exists" {
    create_compliant_mac_policy

    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "metadata declares the expected CIS control" {
    clear_module_metadata_variables
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/1/6/4/metadata.conf"

    [ "${RLCH_MODULE_ID}" = "1.6.4" ]
    [ "${RLCH_MODULE_LEVEL}" = "1" ]
    [ "${RLCH_MODULE_ENABLED}" = "true" ]
    [ "${RLCH_MODULE_REQUIRES_REBOOT}" = "true" ]
    [ "${RLCH_MODULE_OPENSCAP_RULE}" = "xccdf_org.ssgproject.content_rule_configure_custom_crypto_policy_cis" ]
}
