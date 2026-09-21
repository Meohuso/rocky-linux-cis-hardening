#!/usr/bin/env bats

setup() {
    export RLCH_TEST_REPOSITORY_ROOT="${BATS_TEST_DIRNAME}/.."
    source "${RLCH_TEST_REPOSITORY_ROOT}/tests/test_helper.bash"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/module_api.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/tests/helpers/sshd_directive_helper.bash"
    sshd_directive_helper_setup
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/sshd.sh"
    export RLCH_CIS_5_1_8_DROPIN="${RLCH_TEST_SSHD_ROOT}/etc/ssh/sshd_config.d/00-rlch-cis-5.1.8.conf"
    export RLCH_CIS_5_1_8_STATE_DIR="${RLCH_TEST_SSHD_ROOT}/state/5.1.8"
    export RLCH_CIS_5_1_8_STATE_FILE="${RLCH_CIS_5_1_8_STATE_DIR}/dropin.state"
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/5/1/8/module.sh"
}

@test "check accepts the effective issue.net banner" { sshd_directive_effective banner /etc/issue.net; run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; }
@test "check rejects Banner none or another path" { for value in none /etc/issue; do sshd_directive_effective banner "$value"; run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]; done; }
@test "check reports sshd query failure as error" { RLCH_TEST_SSHD_FAIL=query; run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]; }
@test "apply writes only the control-specific Banner drop-in" { sshd_directive_effective banner none; rm -f "$RLCH_TEST_SSHD_EFFECTIVE"; local r=0; apply || r=$?; [ "$r" -eq "$RLCH_MODULE_RESULT_CHANGED" ]; [ "$(cat "$RLCH_CIS_5_1_8_DROPIN")" = 'Banner /etc/issue.net' ]; [ "$(find "$RLCH_TEST_SSHD_ROOT/etc/ssh/sshd_config.d" -type f | wc -l)" -eq 1 ]; }
@test "apply is idempotent when effective configuration complies" { sshd_directive_effective banner /etc/issue.net; run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; [ ! -e "$RLCH_CIS_5_1_8_STATE_FILE" ]; }
@test "apply requires root and captures no state on refusal" { sshd_directive_effective banner none; RLCH_TEST_SSHD_UID=1000; run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]; [ ! -e "$RLCH_CIS_5_1_8_STATE_FILE" ]; }
@test "apply retains rollback state if sshd validation fails" { sshd_directive_effective banner none; RLCH_TEST_SSHD_FAIL=validate; run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]; [ -e "$RLCH_CIS_5_1_8_STATE_FILE" ]; }
@test "validate delegates to effective configuration check" { sshd_directive_effective banner /etc/issue.net; run validate; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; }
@test "rollback removes a drop-in created by this control" { sshd_directive_effective banner none; rm -f "$RLCH_TEST_SSHD_EFFECTIVE"; local a=0 b=0; apply || a=$?; rollback || b=$?; [ "$a" -eq "$RLCH_MODULE_RESULT_CHANGED" ]; [ "$b" -eq "$RLCH_MODULE_RESULT_CHANGED" ]; [ ! -e "$RLCH_CIS_5_1_8_DROPIN" ]; [ ! -e "$RLCH_CIS_5_1_8_STATE_FILE" ]; }
@test "rollback restores an exact pre-existing drop-in" { printf 'Banner /custom/banner\n# retained\n' > "$RLCH_CIS_5_1_8_DROPIN"; sshd_directive_effective banner none; rm -f "$RLCH_TEST_SSHD_EFFECTIVE"; local a=0 b=0; apply || a=$?; rollback || b=$?; [ "$a" -eq "$RLCH_MODULE_RESULT_CHANGED" ]; [ "$b" -eq "$RLCH_MODULE_RESULT_CHANGED" ]; [ "$(cat "$RLCH_CIS_5_1_8_DROPIN")" = $'Banner /custom/banner\n# retained' ]; }
@test "rollback is idempotent without state" { run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; }
@test "metadata uses the exact primary ComplianceAsCode rule" { source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/5/1/8/metadata.conf"; [ "$RLCH_MODULE_ID" = 5.1.8 ]; [ "$RLCH_MODULE_LEVEL" = 1 ]; [ "$RLCH_MODULE_OPENSCAP_RULE" = sshd_enable_warning_banner_net ]; }
