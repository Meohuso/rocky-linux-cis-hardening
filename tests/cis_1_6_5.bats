#!/usr/bin/env bats
#
# Rocky Linux CIS Hardening Framework
#
# CIS 1.6.5 tests.
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

    RLCH_CIS_1_6_5_SUBPOLICY="NO-SSHCBC"
    RLCH_CIS_1_6_5_MODULE_FILE="${RLCH_TEST_CRYPTO_POLICY_MODULE_DIR}/NO-SSHCBC.pmod"
    RLCH_CIS_1_6_5_CURRENT_FILE="${RLCH_TEST_CRYPTO_POLICY_CURRENT_FILE}"

    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/1/6/5/module.sh"
}

teardown() {
    teardown_crypto_policy_test_environment
}

create_compliant_ssh_cipher_policy() {
    set_crypto_policy_test_current "DEFAULT:NO-SHA1:NO-WEAKMAC:NO-SSHCBC"
    write_crypto_policy_test_current_file <<'EOF'
cipher@SSH = AES-256-GCM AES-128-GCM AES-256-CTR AES-128-CTR
EOF
}

create_non_compliant_ssh_cipher_policy() {
    set_crypto_policy_test_current "DEFAULT:NO-SHA1:NO-WEAKMAC"
    write_crypto_policy_test_current_file <<'EOF'
cipher@SSH = AES-256-GCM AES-128-GCM AES-256-CBC AES-128-CBC
EOF
}

@test "check succeeds when CBC ciphers are disabled for SSH" {
    create_compliant_ssh_cipher_policy

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check reports non-compliance when an SSH CBC cipher is enabled" {
    create_non_compliant_ssh_cipher_policy

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check reports error when generated crypto policy is unavailable" {
    create_compliant_ssh_cipher_policy
    rm -f "${RLCH_CIS_1_6_5_CURRENT_FILE}"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
}

@test "apply creates NO-SSHCBC and preserves existing subpolicies" {
    create_non_compliant_ssh_cipher_policy

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "$(cat "${RLCH_TEST_CRYPTO_POLICY_RUNTIME_STATE}")" = "DEFAULT:NO-SHA1:NO-WEAKMAC:NO-SSHCBC" ]
    grep -Fqx "cipher@SSH = -*-CBC" "${RLCH_CIS_1_6_5_MODULE_FILE}"
    [ "$(cat "${RLCH_CRYPTO_POLICY_BACKUP_FILE}")" = "DEFAULT:NO-SHA1:NO-WEAKMAC" ]
}

@test "apply is idempotent when generated crypto policy is compliant" {
    create_compliant_ssh_cipher_policy

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
    [ ! -e "${RLCH_CRYPTO_POLICY_BACKUP_FILE}" ]
}

@test "rollback restores previous crypto policy and removes framework module" {
    create_non_compliant_ssh_cipher_policy

    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]

    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "$(cat "${RLCH_TEST_CRYPTO_POLICY_RUNTIME_STATE}")" = "DEFAULT:NO-SHA1:NO-WEAKMAC" ]
    [ ! -e "${RLCH_CIS_1_6_5_MODULE_FILE}" ]
    [ ! -e "${RLCH_CRYPTO_POLICY_BACKUP_FILE}" ]
}

@test "rollback is idempotent when no managed state exists" {
    create_compliant_ssh_cipher_policy

    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "metadata declares the expected CIS control" {
    clear_module_metadata_variables
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/1/6/5/metadata.conf"

    [ "${RLCH_MODULE_ID}" = "1.6.5" ]
    [ "${RLCH_MODULE_LEVEL}" = "1" ]
    [ "${RLCH_MODULE_ENABLED}" = "true" ]
    [ "${RLCH_MODULE_REQUIRES_REBOOT}" = "true" ]
    [ "${RLCH_MODULE_OPENSCAP_RULE}" = "xccdf_org.ssgproject.content_rule_configure_custom_crypto_policy_cis" ]
}
