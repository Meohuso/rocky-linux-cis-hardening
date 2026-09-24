#!/usr/bin/env bats

setup() {
    export RLCH_TEST_REPOSITORY_ROOT="${BATS_TEST_DIRNAME}/.."
    source "${RLCH_TEST_REPOSITORY_ROOT}/tests/test_helper.bash"; source "${RLCH_TEST_REPOSITORY_ROOT}/lib/module_api.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/tests/helpers/sudoers_helper.bash"; sudoers_helper_setup
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/sudoers.sh"
    export RLCH_CIS_5_2_2_DROPIN="${RLCH_SUDOERS_INCLUDE_DIR}/00-rlch-cis-5-2-2"
    export RLCH_CIS_5_2_2_STATE_FILE="${RLCH_TEST_SUDOERS_ROOT}/state/5.2.2/dropin.state"
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/5/2/2/module.sh"
}

@test "check accepts global use_pty in sudoers" { printf 'Defaults env_reset,use_pty\n' >> "$RLCH_SUDOERS_MAIN_FILE"; run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; }
@test "check accepts global use_pty in an included file" { printf 'Defaults use_pty\n' > "$RLCH_SUDOERS_INCLUDE_DIR/policy"; run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; }
@test "check rejects absent use_pty" { run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]; }
@test "check rejects explicit global negation" { printf 'Defaults use_pty\nDefaults !use_pty\n' >> "$RLCH_SUDOERS_MAIN_FILE"; run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]; }
@test "check rejects a scoped exception" { printf 'Defaults use_pty\nDefaults:admin !use_pty\n' >> "$RLCH_SUDOERS_MAIN_FILE"; run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]; }
@test "check does not mistake comments or targeted enablement for global policy" { printf '# Defaults use_pty\nDefaults:admin use_pty\n' >> "$RLCH_SUDOERS_MAIN_FILE"; run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]; }
@test "check supports continued Defaults lines" { printf 'Defaults env_reset, \\\n use_pty\n' >> "$RLCH_SUDOERS_MAIN_FILE"; run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; }
@test "check reports invalid sudoers as error" { RLCH_TEST_SUDOERS_FAIL=validate; run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]; }
@test "apply writes isolated valid sudoers file" { local r=0; apply || r=$?; [ "$r" -eq "$RLCH_MODULE_RESULT_CHANGED" ]; [ "$(cat "$RLCH_CIS_5_2_2_DROPIN")" = 'Defaults use_pty' ]; [ "$(stat -c %a "$RLCH_CIS_5_2_2_DROPIN")" = 440 ]; }
@test "apply is idempotent when effective policy complies" { printf 'Defaults use_pty\n' >> "$RLCH_SUDOERS_MAIN_FILE"; run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; [ ! -e "$RLCH_CIS_5_2_2_STATE_FILE" ]; }
@test "apply requires root" { RLCH_TEST_SUDOERS_UID=1000; run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]; [ ! -e "$RLCH_CIS_5_2_2_STATE_FILE" ]; }
@test "apply restores the prior file immediately when visudo rejects the change" { printf 'Defaults !use_pty\n# keep\n' > "$RLCH_CIS_5_2_2_DROPIN"; RLCH_TEST_SUDOERS_FAIL=post_write; local r=0; apply || r=$?; [ "$r" -eq "$RLCH_MODULE_RESULT_ERROR" ]; [ "$(cat "$RLCH_CIS_5_2_2_DROPIN")" = $'Defaults !use_pty\n# keep' ]; [ ! -e "$RLCH_CIS_5_2_2_STATE_FILE" ]; }
@test "validate delegates to check" { run validate; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]; }
@test "rollback removes a file created by this control" { local a=0 b=0; apply || a=$?; rollback || b=$?; [ "$a" -eq "$RLCH_MODULE_RESULT_CHANGED" ]; [ "$b" -eq "$RLCH_MODULE_RESULT_CHANGED" ]; [ ! -e "$RLCH_CIS_5_2_2_DROPIN" ]; }
@test "rollback restores an exact pre-existing file" { printf 'Defaults !use_pty\n# keep\n' > "$RLCH_CIS_5_2_2_DROPIN"; local a=0 b=0; apply || a=$?; rollback || b=$?; [ "$a" -eq "$RLCH_MODULE_RESULT_CHANGED" ]; [ "$b" -eq "$RLCH_MODULE_RESULT_CHANGED" ]; [ "$(cat "$RLCH_CIS_5_2_2_DROPIN")" = $'Defaults !use_pty\n# keep' ]; }
@test "rollback is idempotent without state" { run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; }
@test "metadata uses exact ComplianceAsCode rule" { source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/5/2/2/metadata.conf"; [ "$RLCH_MODULE_OPENSCAP_RULE" = xccdf_org.ssgproject.content_rule_sudo_add_use_pty ]; }
