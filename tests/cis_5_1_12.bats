#!/usr/bin/env bats

setup() {
    export RLCH_TEST_REPOSITORY_ROOT="${BATS_TEST_DIRNAME}/.."
    source "${RLCH_TEST_REPOSITORY_ROOT}/tests/test_helper.bash"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/module_api.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/tests/helpers/sshd_directive_helper.bash"
    sshd_directive_helper_setup
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/sshd.sh"
    export RLCH_CIS_5_1_12_DROPIN="${RLCH_TEST_SSHD_ROOT}/etc/ssh/sshd_config.d/00-rlch-cis-5.1.12.conf"
    export RLCH_CIS_5_1_12_STATE_DIR="${RLCH_TEST_SSHD_ROOT}/state/5.1.12"
    export RLCH_CIS_5_1_12_STATE_FILE="${RLCH_CIS_5_1_12_STATE_DIR}/dropin.state"
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/5/1/12/module.sh"
}

@test "check accepts disabled host-based authentication" { sshd_directive_effective hostbasedauthentication no; run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; }
@test "check rejects enabled host-based authentication" { sshd_directive_effective hostbasedauthentication yes; run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]; }
@test "check reports sshd query failure as error" { RLCH_TEST_SSHD_FAIL=query; run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]; }
@test "apply writes only the control-specific directive" { sshd_directive_effective hostbasedauthentication yes; rm -f "$RLCH_TEST_SSHD_EFFECTIVE"; local r=0; apply || r=$?; [ "$r" -eq "$RLCH_MODULE_RESULT_CHANGED" ]; [ "$(cat "$RLCH_CIS_5_1_12_DROPIN")" = 'HostbasedAuthentication no' ]; [ "$(find "$RLCH_TEST_SSHD_ROOT/etc/ssh/sshd_config.d" -type f | wc -l)" -eq 1 ]; }
@test "apply is idempotent when effective configuration complies" { sshd_directive_effective hostbasedauthentication no; run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; [ ! -e "$RLCH_CIS_5_1_12_STATE_FILE" ]; }
@test "apply requires root and captures no state on refusal" { sshd_directive_effective hostbasedauthentication yes; RLCH_TEST_SSHD_UID=1000; run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]; [ ! -e "$RLCH_CIS_5_1_12_STATE_FILE" ]; }
@test "apply retains rollback state if sshd validation fails" { sshd_directive_effective hostbasedauthentication yes; RLCH_TEST_SSHD_FAIL=validate; run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]; [ -e "$RLCH_CIS_5_1_12_STATE_FILE" ]; }
@test "validate delegates to effective configuration check" { sshd_directive_effective hostbasedauthentication no; run validate; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; }
@test "rollback removes a drop-in created by this control" { sshd_directive_effective hostbasedauthentication yes; rm -f "$RLCH_TEST_SSHD_EFFECTIVE"; local a=0 b=0; apply || a=$?; rollback || b=$?; [ "$a" -eq "$RLCH_MODULE_RESULT_CHANGED" ]; [ "$b" -eq "$RLCH_MODULE_RESULT_CHANGED" ]; [ ! -e "$RLCH_CIS_5_1_12_DROPIN" ]; [ ! -e "$RLCH_CIS_5_1_12_STATE_FILE" ]; }
@test "rollback restores an exact pre-existing drop-in" { printf 'HostbasedAuthentication yes\n# retained\n' > "$RLCH_CIS_5_1_12_DROPIN"; sshd_directive_effective hostbasedauthentication yes; rm -f "$RLCH_TEST_SSHD_EFFECTIVE"; local a=0 b=0; apply || a=$?; rollback || b=$?; [ "$a" -eq "$RLCH_MODULE_RESULT_CHANGED" ]; [ "$b" -eq "$RLCH_MODULE_RESULT_CHANGED" ]; [ "$(cat "$RLCH_CIS_5_1_12_DROPIN")" = $'HostbasedAuthentication yes\n# retained' ]; }
@test "rollback is idempotent without state" { run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; }
@test "metadata uses the exact ComplianceAsCode rule" { source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/5/1/12/metadata.conf"; [ "$RLCH_MODULE_ID" = 5.1.12 ]; [ "$RLCH_MODULE_LEVEL" = 1 ]; [ "$RLCH_MODULE_OPENSCAP_RULE" = disable_host_auth ]; }
