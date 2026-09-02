#!/usr/bin/env bats
#
# Rocky Linux CIS Hardening Framework
#
# CIS 1.6.7 tests.
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

    RLCH_CIS_1_6_7_SUBPOLICY="NO-SSHETM"
    RLCH_CIS_1_6_7_MODULE_FILE="${RLCH_TEST_CRYPTO_POLICY_MODULE_DIR}/NO-SSHETM.pmod"
    RLCH_CIS_1_6_7_CURRENT_FILE="${RLCH_TEST_CRYPTO_POLICY_CURRENT_FILE}"

    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/1/6/7/module.sh"
}

teardown() {
    teardown_crypto_policy_test_environment
}

create_compliant_etm_policy() {
    set_crypto_policy_test_current "DEFAULT:NO-SHA1:NO-WEAKMAC:NO-SSHCBC:NO-SSHCHACHA20:NO-SSHETM"
    write_crypto_policy_test_current_file <<'EOF'
etm@SSH = DISABLE_ETM
EOF
}

create_non_compliant_etm_policy() {
    set_crypto_policy_test_current "DEFAULT:NO-SHA1:NO-WEAKMAC:NO-SSHCBC:NO-SSHCHACHA20"
    write_crypto_policy_test_current_file <<'EOF'
etm@SSH = ANY
EOF
}

@test "check succeeds when EtM is disabled for SSH" {
    create_compliant_etm_policy
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check reports non-compliance when EtM is enabled for SSH" {
    create_non_compliant_etm_policy
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check reports non-compliance when SSH EtM setting is absent" {
    set_crypto_policy_test_current "DEFAULT"
    write_crypto_policy_test_current_file <<'EOF'
cipher@SSH = AES-256-GCM AES-128-GCM
EOF
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check reports error when generated crypto policy is unavailable" {
    create_compliant_etm_policy
    rm -f "${RLCH_CIS_1_6_7_CURRENT_FILE}"
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
}

@test "apply creates NO-SSHETM and preserves existing subpolicies" {
    create_non_compliant_etm_policy
    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "$(cat "${RLCH_TEST_CRYPTO_POLICY_RUNTIME_STATE}")" = "DEFAULT:NO-SHA1:NO-WEAKMAC:NO-SSHCBC:NO-SSHCHACHA20:NO-SSHETM" ]
    grep -Fqx "etm@SSH = DISABLE_ETM" "${RLCH_CIS_1_6_7_MODULE_FILE}"
    [ "$(cat "${RLCH_CRYPTO_POLICY_BACKUP_FILE}")" = "DEFAULT:NO-SHA1:NO-WEAKMAC:NO-SSHCBC:NO-SSHCHACHA20" ]
}

@test "apply is idempotent when generated crypto policy is compliant" {
    create_compliant_etm_policy
    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
    [ ! -e "${RLCH_CRYPTO_POLICY_BACKUP_FILE}" ]
}

@test "rollback restores previous crypto policy and removes framework module" {
    create_non_compliant_etm_policy
    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]

    run rollback
    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "$(cat "${RLCH_TEST_CRYPTO_POLICY_RUNTIME_STATE}")" = "DEFAULT:NO-SHA1:NO-WEAKMAC:NO-SSHCBC:NO-SSHCHACHA20" ]
    [ ! -e "${RLCH_CIS_1_6_7_MODULE_FILE}" ]
    [ ! -e "${RLCH_CRYPTO_POLICY_BACKUP_FILE}" ]
}

@test "rollback is idempotent when no managed state exists" {
    create_compliant_etm_policy
    run rollback
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "metadata declares CIS 1.6.7 as a manual OpenSCAP control" {
    clear_module_metadata_variables
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/1/6/7/metadata.conf"

    [ "${RLCH_MODULE_ID}" = "1.6.7" ]
    [ "${RLCH_MODULE_LEVEL}" = "1" ]
    [ "${RLCH_MODULE_ENABLED}" = "true" ]
    [ "${RLCH_MODULE_REQUIRES_REBOOT}" = "true" ]
    [ "${RLCH_MODULE_OPENSCAP_RULE}" = "manual" ]
}
