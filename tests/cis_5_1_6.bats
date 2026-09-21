#!/usr/bin/env bats

setup() {
    source "${BATS_TEST_DIRNAME}/test_helper.bash"
    source "${BATS_TEST_DIRNAME}/helpers/crypto_policy_helper.bash"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/common.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/modules.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/module_api.sh"
    setup_crypto_policy_test_environment
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/crypto_policy.sh"
    RLCH_CIS_5_1_6_MODULE_FILE="${RLCH_TEST_CRYPTO_POLICY_MODULE_DIR}/NO-SSHWEAKMACS.pmod"
    RLCH_CIS_5_1_6_CURRENT_FILE="${RLCH_TEST_CRYPTO_POLICY_CURRENT_FILE}"
    RLCH_CIS_5_1_6_STATE_DIR="${RLCH_TEST_CRYPTO_POLICY_STATE_DIR}/5.1.6"
    RLCH_CIS_5_1_6_POLICY_STATE="${RLCH_CIS_5_1_6_STATE_DIR}/crypto-policy.backup"
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/5/1/6/module.sh"
}
teardown() { teardown_crypto_policy_test_environment; }
compliant_policy() { set_crypto_policy_test_current 'DEFAULT:NO-SHA1:NO-SSHWEAKMACS'; write_crypto_policy_test_current_file <<'EOF'
mac@SSH = HMAC-SHA2-256 HMAC-SHA2-512
EOF
}
noncompliant_policy() { set_crypto_policy_test_current 'DEFAULT:NO-SHA1'; export RLCH_TEST_CRYPTO_POLICY_MACS='HMAC-SHA2-256 HMAC-MD5 UMAC-64'; write_crypto_policy_test_current_file <<EOF
mac@SSH = ${RLCH_TEST_CRYPTO_POLICY_MACS}
EOF
}

@test "check accepts strong SSH MACs" { compliant_policy; run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; }
@test "check rejects each weak MAC family" { for mac in HMAC-MD5 HMAC-MD5-96 UMAC-64 UMAC-64-ETM UMAC-128 UMAC-128-ETM; do write_crypto_policy_test_current_file <<< "mac@SSH = HMAC-SHA2-256 $mac"; run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]; done; }
@test "check reports missing generated policy as error" { compliant_policy; rm -f "$RLCH_CIS_5_1_6_CURRENT_FILE"; run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]; }
@test "apply installs the exact ComplianceAsCode subpolicy" { noncompliant_policy; local r=0; apply || r=$?; [ "$r" -eq "$RLCH_MODULE_RESULT_CHANGED" ]; [ "$(cat "$RLCH_TEST_CRYPTO_POLICY_RUNTIME_STATE")" = 'DEFAULT:NO-SHA1:NO-SSHWEAKMACS' ]; grep -Fqx 'mac@SSH = -HMAC-MD5* -UMAC-64* -UMAC-128*' "$RLCH_CIS_5_1_6_MODULE_FILE"; }
@test "apply is idempotent" { compliant_policy; run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; [ ! -e "$RLCH_CIS_5_1_6_POLICY_STATE" ]; }
@test "apply requires root through the crypto helper" { noncompliant_policy; set_crypto_policy_test_effective_uid 1000; run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]; }
@test "validate confirms generated policy" { noncompliant_policy; local r=0; apply || r=$?; [ "$r" -eq "$RLCH_MODULE_RESULT_CHANGED" ]; run validate; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; }
@test "rollback restores only this control policy and module" { noncompliant_policy; local a=0 b=0; apply || a=$?; rollback || b=$?; [ "$a" -eq "$RLCH_MODULE_RESULT_CHANGED" ]; [ "$b" -eq "$RLCH_MODULE_RESULT_CHANGED" ]; [ "$(cat "$RLCH_TEST_CRYPTO_POLICY_RUNTIME_STATE")" = 'DEFAULT:NO-SHA1' ]; [ ! -e "$RLCH_CIS_5_1_6_MODULE_FILE" ]; [ ! -e "$RLCH_CIS_5_1_6_POLICY_STATE" ]; }
@test "rollback is idempotent without state" { compliant_policy; run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; }
@test "metadata uses the exact ComplianceAsCode rule" { clear_module_metadata_variables; source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/5/1/6/metadata.conf"; [ "$RLCH_MODULE_ID" = 5.1.6 ]; [ "$RLCH_MODULE_LEVEL" = 1 ]; [ "$RLCH_MODULE_OPENSCAP_RULE" = configure_custom_crypto_policy_cis ]; }
