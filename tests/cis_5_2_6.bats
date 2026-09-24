#!/usr/bin/env bats
setup() {
 export RLCH_TEST_REPOSITORY_ROOT="${BATS_TEST_DIRNAME}/.."; source "${RLCH_TEST_REPOSITORY_ROOT}/tests/test_helper.bash"; source "${RLCH_TEST_REPOSITORY_ROOT}/lib/module_api.sh"
 source "${RLCH_TEST_REPOSITORY_ROOT}/tests/helpers/sudoers_helper.bash"; sudoers_helper_setup; source "${RLCH_TEST_REPOSITORY_ROOT}/lib/sudoers.sh"
 export RLCH_CIS_5_2_6_TIMEOUT=15 RLCH_CIS_5_2_6_DROPIN="${RLCH_SUDOERS_INCLUDE_DIR}/99-rlch-cis-5-2-6" RLCH_CIS_5_2_6_STATE_FILE="${RLCH_TEST_SUDOERS_ROOT}/state/5.2.6/dropin.state"
 source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/5/2/6/module.sh"
}
@test "check accepts the tailored timeout" { printf 'Defaults timestamp_timeout=15\n' >> "$RLCH_SUDOERS_MAIN_FILE"; run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; }
@test "check accepts quoted tailored timeout" { printf 'Defaults timestamp_timeout="15"\n' > "$RLCH_SUDOERS_INCLUDE_DIR/policy"; run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; }
@test "check rejects an absent timeout" { run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]; }
@test "check rejects zero negative lower and higher values" { for value in 0 -1 5 30; do printf 'Defaults timestamp_timeout=%s\n' "$value" > "$RLCH_SUDOERS_INCLUDE_DIR/policy"; run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]; done; }
@test "check rejects only targeted configuration" { printf 'Defaults:admin timestamp_timeout=15\n' >> "$RLCH_SUDOERS_MAIN_FILE"; run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]; }
@test "check rejects a targeted conflicting timeout" { printf 'Defaults timestamp_timeout=15\nDefaults:admin timestamp_timeout=5\n' >> "$RLCH_SUDOERS_MAIN_FILE"; run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]; }
@test "check reports invalid sudoers as error" { RLCH_TEST_SUDOERS_FAIL=validate; run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]; }
@test "apply writes exactly the tailored timeout" { local r=0; apply || r=$?; [ "$r" -eq "$RLCH_MODULE_RESULT_CHANGED" ]; [ "$(cat "$RLCH_CIS_5_2_6_DROPIN")" = 'Defaults timestamp_timeout=15' ]; [ "$(stat -c %a "$RLCH_CIS_5_2_6_DROPIN")" = 440 ]; }
@test "apply is idempotent when compliant" { printf 'Defaults timestamp_timeout=15\n' >> "$RLCH_SUDOERS_MAIN_FILE"; run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; [ ! -e "$RLCH_CIS_5_2_6_STATE_FILE" ]; }
@test "apply requires root" { RLCH_TEST_SUDOERS_UID=1000; run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]; }
@test "apply restores prior file after post-write validation failure" { printf 'Defaults timestamp_timeout=5\n# keep\n' > "$RLCH_CIS_5_2_6_DROPIN"; RLCH_TEST_SUDOERS_FAIL=post_write; local r=0; apply || r=$?; [ "$r" -eq "$RLCH_MODULE_RESULT_ERROR" ]; [ "$(cat "$RLCH_CIS_5_2_6_DROPIN")" = $'Defaults timestamp_timeout=5\n# keep' ]; [ ! -e "$RLCH_CIS_5_2_6_STATE_FILE" ]; }
@test "apply removes its own ineffective change when another conflict remains" { printf 'Defaults:admin timestamp_timeout=5\n' > "$RLCH_SUDOERS_INCLUDE_DIR/zz-admin"; run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]; [ ! -e "$RLCH_CIS_5_2_6_DROPIN" ]; [ ! -e "$RLCH_CIS_5_2_6_STATE_FILE" ]; }
@test "validate delegates to check" { run validate; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]; }
@test "rollback removes a newly created drop-in" { local a=0 b=0; apply || a=$?; rollback || b=$?; [ "$a" -eq "$RLCH_MODULE_RESULT_CHANGED" ]; [ "$b" -eq "$RLCH_MODULE_RESULT_CHANGED" ]; [ ! -e "$RLCH_CIS_5_2_6_DROPIN" ]; }
@test "rollback restores an exact pre-existing drop-in" { printf 'Defaults timestamp_timeout=5\n# keep\n' > "$RLCH_CIS_5_2_6_DROPIN"; local a=0 b=0; apply || a=$?; rollback || b=$?; [ "$a" -eq "$RLCH_MODULE_RESULT_CHANGED" ]; [ "$b" -eq "$RLCH_MODULE_RESULT_CHANGED" ]; [ "$(cat "$RLCH_CIS_5_2_6_DROPIN")" = $'Defaults timestamp_timeout=5\n# keep' ]; }
@test "rollback is idempotent without state" { run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; }
@test "metadata records rule plus tailoring as manual" { source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/5/2/6/metadata.conf"; [ "$RLCH_MODULE_ID" = 5.2.6 ]; [ "$RLCH_MODULE_OPENSCAP_RULE" = manual ]; }
