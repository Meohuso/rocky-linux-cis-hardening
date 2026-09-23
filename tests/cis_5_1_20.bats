#!/usr/bin/env bats
setup() {
 export RLCH_TEST_REPOSITORY_ROOT="${BATS_TEST_DIRNAME}/.."; source "${RLCH_TEST_REPOSITORY_ROOT}/tests/test_helper.bash"; source "${RLCH_TEST_REPOSITORY_ROOT}/lib/module_api.sh"
 source "${RLCH_TEST_REPOSITORY_ROOT}/tests/helpers/sshd_directive_helper.bash"; sshd_directive_helper_setup; source "${RLCH_TEST_REPOSITORY_ROOT}/lib/sshd.sh"
 export RLCH_CIS_5_1_20_DROPIN="${RLCH_TEST_SSHD_ROOT}/etc/ssh/sshd_config.d/00-rlch-cis-5.1.20.conf" RLCH_CIS_5_1_20_STATE_FILE="${RLCH_TEST_SSHD_ROOT}/state/5.1.20/dropin.state"
 source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/5/1/20/module.sh"
}
@test "check accepts root login disabled" { sshd_directive_effective permitrootlogin no; run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; }
@test "check rejects root login enabled or restricted" { for value in yes prohibit-password; do sshd_directive_effective permitrootlogin "$value"; run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]; done; }
@test "check reports query failure" { RLCH_TEST_SSHD_FAIL=query; run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]; }
@test "apply writes only PermitRootLogin" { sshd_directive_effective permitrootlogin yes; rm -f "$RLCH_TEST_SSHD_EFFECTIVE"; local r=0; apply || r=$?; [ "$r" -eq "$RLCH_MODULE_RESULT_CHANGED" ]; [ "$(cat "$RLCH_CIS_5_1_20_DROPIN")" = 'PermitRootLogin no' ]; }
@test "apply is idempotent" { sshd_directive_effective permitrootlogin no; run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; [ ! -e "$RLCH_CIS_5_1_20_STATE_FILE" ]; }
@test "apply requires root" { sshd_directive_effective permitrootlogin yes; RLCH_TEST_SSHD_UID=1000; run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]; }
@test "apply retains state on validation failure" { sshd_directive_effective permitrootlogin yes; RLCH_TEST_SSHD_FAIL=validate; run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]; [ -e "$RLCH_CIS_5_1_20_STATE_FILE" ]; }
@test "validate delegates to check" { sshd_directive_effective permitrootlogin no; run validate; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; }
@test "rollback removes new drop-in" { sshd_directive_effective permitrootlogin yes; rm -f "$RLCH_TEST_SSHD_EFFECTIVE"; local a=0 b=0; apply || a=$?; rollback || b=$?; [ "$a" -eq "$RLCH_MODULE_RESULT_CHANGED" ]; [ "$b" -eq "$RLCH_MODULE_RESULT_CHANGED" ]; [ ! -e "$RLCH_CIS_5_1_20_DROPIN" ]; }
@test "rollback restores exact prior drop-in" { printf 'PermitRootLogin prohibit-password\n# keep\n' > "$RLCH_CIS_5_1_20_DROPIN"; sshd_directive_effective permitrootlogin yes; rm -f "$RLCH_TEST_SSHD_EFFECTIVE"; local a=0 b=0; apply || a=$?; rollback || b=$?; [ "$a" -eq "$RLCH_MODULE_RESULT_CHANGED" ]; [ "$b" -eq "$RLCH_MODULE_RESULT_CHANGED" ]; [ "$(cat "$RLCH_CIS_5_1_20_DROPIN")" = $'PermitRootLogin prohibit-password\n# keep' ]; }
@test "rollback is idempotent" { run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; }
@test "metadata uses exact ComplianceAsCode rule" { source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/5/1/20/metadata.conf"; [ "$RLCH_MODULE_OPENSCAP_RULE" = sshd_disable_root_login ]; }
