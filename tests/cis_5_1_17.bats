#!/usr/bin/env bats
setup() {
 export RLCH_TEST_REPOSITORY_ROOT="${BATS_TEST_DIRNAME}/.."; source "${RLCH_TEST_REPOSITORY_ROOT}/tests/test_helper.bash"; source "${RLCH_TEST_REPOSITORY_ROOT}/lib/module_api.sh"
 source "${RLCH_TEST_REPOSITORY_ROOT}/tests/helpers/sshd_directive_helper.bash"; sshd_directive_helper_setup; source "${RLCH_TEST_REPOSITORY_ROOT}/lib/sshd.sh"
 export RLCH_CIS_5_1_17_DROPIN="${RLCH_TEST_SSHD_ROOT}/etc/ssh/sshd_config.d/00-rlch-cis-5.1.17.conf" RLCH_CIS_5_1_17_STATE_FILE="${RLCH_TEST_SSHD_ROOT}/state/5.1.17/dropin.state"
 source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/5/1/17/module.sh"
}
@test "check accepts tailored MaxStartups" { sshd_directive_effective maxstartups 10:30:60; run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; }
@test "check rejects another value" { sshd_directive_effective maxstartups 10:30:100; run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]; }
@test "check reports query failure" { RLCH_TEST_SSHD_FAIL=query; run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]; }
@test "apply writes only MaxStartups" { sshd_directive_effective maxstartups 10:30:100; rm -f "$RLCH_TEST_SSHD_EFFECTIVE"; local r=0; apply || r=$?; [ "$r" -eq "$RLCH_MODULE_RESULT_CHANGED" ]; [ "$(cat "$RLCH_CIS_5_1_17_DROPIN")" = 'MaxStartups 10:30:60' ]; }
@test "apply is idempotent" { sshd_directive_effective maxstartups 10:30:60; run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; [ ! -e "$RLCH_CIS_5_1_17_STATE_FILE" ]; }
@test "apply requires root" { sshd_directive_effective maxstartups 10:30:100; RLCH_TEST_SSHD_UID=1000; run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]; }
@test "apply retains state on validation failure" { sshd_directive_effective maxstartups 10:30:100; RLCH_TEST_SSHD_FAIL=validate; run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]; [ -e "$RLCH_CIS_5_1_17_STATE_FILE" ]; }
@test "validate delegates to check" { sshd_directive_effective maxstartups 10:30:60; run validate; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; }
@test "rollback removes new drop-in" { sshd_directive_effective maxstartups 10:30:100; rm -f "$RLCH_TEST_SSHD_EFFECTIVE"; local a=0 b=0; apply || a=$?; rollback || b=$?; [ "$a" -eq "$RLCH_MODULE_RESULT_CHANGED" ]; [ "$b" -eq "$RLCH_MODULE_RESULT_CHANGED" ]; [ ! -e "$RLCH_CIS_5_1_17_DROPIN" ]; }
@test "rollback restores exact prior drop-in" { printf 'MaxStartups 5:20:40\n# keep\n' > "$RLCH_CIS_5_1_17_DROPIN"; sshd_directive_effective maxstartups 10:30:100; rm -f "$RLCH_TEST_SSHD_EFFECTIVE"; local a=0 b=0; apply || a=$?; rollback || b=$?; [ "$a" -eq "$RLCH_MODULE_RESULT_CHANGED" ]; [ "$b" -eq "$RLCH_MODULE_RESULT_CHANGED" ]; [ "$(cat "$RLCH_CIS_5_1_17_DROPIN")" = $'MaxStartups 5:20:40\n# keep' ]; }
@test "rollback is idempotent" { run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; }
@test "metadata records composite mapping as manual" { source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/5/1/17/metadata.conf"; [ "$RLCH_MODULE_OPENSCAP_RULE" = manual ]; }
