#!/usr/bin/env bats

setup() {
    source "${BATS_TEST_DIRNAME}/test_helper.bash"
    source "${BATS_TEST_DIRNAME}/helpers/crypto_policy_helper.bash"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/common.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/modules.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/module_api.sh"
    setup_crypto_policy_test_environment
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/crypto_policy.sh"
    RLCH_CIS_5_1_5_CURRENT_FILE="${RLCH_TEST_CRYPTO_POLICY_CURRENT_FILE}"
    RLCH_CIS_5_1_5_STATE_DIR="${RLCH_TEST_CRYPTO_POLICY_STATE_DIR}/5.1.5"
    RLCH_CIS_5_1_5_POLICY_STATE="${RLCH_CIS_5_1_5_STATE_DIR}/crypto-policy.backup"
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/5/1/5/module.sh"
}

teardown() { teardown_crypto_policy_test_environment; }
compliant_policy() { set_crypto_policy_test_current 'DEFAULT:NO-SHA1'; write_crypto_policy_test_current_file <<'EOF'
hash = SHA2-256 SHA2-384 SHA2-512
EOF
}
noncompliant_policy() { set_crypto_policy_test_current 'DEFAULT'; write_crypto_policy_test_current_file <<'EOF'
hash = SHA1 SHA2-256 SHA2-384 SHA2-512
EOF
}

@test "check accepts an SSH policy without SHA1" { compliant_policy; run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; }
@test "check rejects SHA1 in the effective hash policy" { noncompliant_policy; run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]; }
@test "check honors an SSH-scoped hash policy" { set_crypto_policy_test_current DEFAULT; write_crypto_policy_test_current_file <<'EOF'
hash = SHA1 SHA2-256
hash@SSH = SHA2-256 SHA2-512
EOF
run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; }
@test "check reports a missing or malformed generated policy as error" { compliant_policy; rm -f "$RLCH_CIS_5_1_5_CURRENT_FILE"; run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]; write_crypto_policy_test_current_file <<< 'cipher = AES-256-GCM'; run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]; }
@test "apply adds the benchmark NO-SHA1 policy with isolated state" { noncompliant_policy; local r=0; apply || r=$?; [ "$r" -eq "$RLCH_MODULE_RESULT_CHANGED" ]; [ "$(cat "$RLCH_TEST_CRYPTO_POLICY_RUNTIME_STATE")" = 'DEFAULT:NO-SHA1' ]; [ "$(cat "$RLCH_CIS_5_1_5_POLICY_STATE")" = DEFAULT ]; }
@test "apply is idempotent" { compliant_policy; run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; [ ! -e "$RLCH_CIS_5_1_5_POLICY_STATE" ]; }
@test "apply requires root when remediation is needed" { noncompliant_policy; set_crypto_policy_test_effective_uid 1000; run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]; }
@test "rollback restores only this control policy state" { noncompliant_policy; local a=0 b=0; apply || a=$?; rollback || b=$?; [ "$a" -eq "$RLCH_MODULE_RESULT_CHANGED" ]; [ "$b" -eq "$RLCH_MODULE_RESULT_CHANGED" ]; [ "$(cat "$RLCH_TEST_CRYPTO_POLICY_RUNTIME_STATE")" = DEFAULT ]; [ ! -e "$RLCH_CIS_5_1_5_POLICY_STATE" ]; }
@test "rollback is idempotent without state" { compliant_policy; run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; }
@test "metadata uses the exact ComplianceAsCode rule" { clear_module_metadata_variables; source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/5/1/5/metadata.conf"; [ "$RLCH_MODULE_ID" = 5.1.5 ]; [ "$RLCH_MODULE_LEVEL" = 1 ]; [ "$RLCH_MODULE_OPENSCAP_RULE" = configure_custom_crypto_policy_cis ]; }
