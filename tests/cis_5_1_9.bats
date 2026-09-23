#!/usr/bin/env bats

setup() {
    export RLCH_TEST_REPOSITORY_ROOT="${BATS_TEST_DIRNAME}/.."
    source "${RLCH_TEST_REPOSITORY_ROOT}/tests/test_helper.bash"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/module_api.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/tests/helpers/sshd_directive_helper.bash"
    sshd_directive_helper_setup
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/sshd.sh"
    export RLCH_CIS_5_1_9_DROPIN="${RLCH_TEST_SSHD_ROOT}/etc/ssh/sshd_config.d/00-rlch-cis-5.1.9.conf"
    export RLCH_CIS_5_1_9_STATE_DIR="${RLCH_TEST_SSHD_ROOT}/state/5.1.9"
    export RLCH_CIS_5_1_9_STATE_FILE="${RLCH_CIS_5_1_9_STATE_DIR}/dropin.state"
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/5/1/9/module.sh"
}

compliant() { printf '%s\n' 'clientaliveinterval 300' 'clientalivecountmax 1' > "$RLCH_TEST_SSHD_EFFECTIVE"; }
noncompliant() { printf '%s\n' 'clientaliveinterval 0' 'clientalivecountmax 3' > "$RLCH_TEST_SSHD_EFFECTIVE"; }

@test "check accepts tailored interval and count" { compliant; run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; }
@test "check rejects an incorrect interval" { compliant; sed -i 's/300/600/' "$RLCH_TEST_SSHD_EFFECTIVE"; run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]; }
@test "check rejects an incorrect count" { compliant; sed -i 's/countmax 1/countmax 0/' "$RLCH_TEST_SSHD_EFFECTIVE"; run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]; }
@test "check reports sshd query failure as error" { compliant; RLCH_TEST_SSHD_FAIL=query; run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]; }
@test "apply writes both directives in one isolated drop-in" { noncompliant; rm -f "$RLCH_TEST_SSHD_EFFECTIVE"; local r=0; apply || r=$?; [ "$r" -eq "$RLCH_MODULE_RESULT_CHANGED" ]; [ "$(cat "$RLCH_CIS_5_1_9_DROPIN")" = $'ClientAliveInterval 300\nClientAliveCountMax 1' ]; }
@test "apply is idempotent" { compliant; run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; [ ! -e "$RLCH_CIS_5_1_9_STATE_FILE" ]; }
@test "apply requires root" { noncompliant; RLCH_TEST_SSHD_UID=1000; run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]; [ ! -e "$RLCH_CIS_5_1_9_STATE_FILE" ]; }
@test "apply retains rollback state on validation failure" { noncompliant; RLCH_TEST_SSHD_FAIL=validate; run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]; [ -e "$RLCH_CIS_5_1_9_STATE_FILE" ]; }
@test "validate delegates to check" { compliant; run validate; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; }
@test "rollback removes a newly created drop-in" { noncompliant; rm -f "$RLCH_TEST_SSHD_EFFECTIVE"; local a=0 b=0; apply || a=$?; rollback || b=$?; [ "$a" -eq "$RLCH_MODULE_RESULT_CHANGED" ]; [ "$b" -eq "$RLCH_MODULE_RESULT_CHANGED" ]; [ ! -e "$RLCH_CIS_5_1_9_DROPIN" ]; }
@test "rollback restores a pre-existing drop-in exactly" { printf 'ClientAliveInterval 120\n# keep\n' > "$RLCH_CIS_5_1_9_DROPIN"; noncompliant; rm -f "$RLCH_TEST_SSHD_EFFECTIVE"; local a=0 b=0; apply || a=$?; rollback || b=$?; [ "$a" -eq "$RLCH_MODULE_RESULT_CHANGED" ]; [ "$b" -eq "$RLCH_MODULE_RESULT_CHANGED" ]; [ "$(cat "$RLCH_CIS_5_1_9_DROPIN")" = $'ClientAliveInterval 120\n# keep' ]; }
@test "rollback is idempotent without state" { run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; }
@test "metadata records the multi-rule mapping as manual" { source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/5/1/9/metadata.conf"; [ "$RLCH_MODULE_ID" = 5.1.9 ]; [ "$RLCH_MODULE_LEVEL" = 1 ]; [ "$RLCH_MODULE_OPENSCAP_RULE" = manual ]; }
