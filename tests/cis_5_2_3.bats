#!/usr/bin/env bats

setup() {
    export RLCH_TEST_REPOSITORY_ROOT="${BATS_TEST_DIRNAME}/.."
    source "${RLCH_TEST_REPOSITORY_ROOT}/tests/test_helper.bash"; source "${RLCH_TEST_REPOSITORY_ROOT}/lib/module_api.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/tests/helpers/sudoers_helper.bash"; sudoers_helper_setup
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/sudoers.sh"
    export RLCH_CIS_5_2_3_LOGFILE=/var/log/sudo.log
    export RLCH_CIS_5_2_3_DROPIN="${RLCH_SUDOERS_INCLUDE_DIR}/00-rlch-cis-5-2-3"
    export RLCH_CIS_5_2_3_STATE_FILE="${RLCH_TEST_SUDOERS_ROOT}/state/5.2.3/dropin.state"
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/5/2/3/module.sh"
}

@test "check accepts the quoted default logfile" { printf 'Defaults logfile="/var/log/sudo.log"\n' >> "$RLCH_SUDOERS_MAIN_FILE"; run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; }
@test "check accepts spacing and multiple Defaults options" { printf 'Defaults env_reset, logfile = /var/log/sudo.log,use_pty\n' >> "$RLCH_SUDOERS_MAIN_FILE"; run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; }
@test "check accepts the logfile in an included file" { printf 'Defaults logfile=/var/log/sudo.log\n' > "$RLCH_SUDOERS_INCLUDE_DIR/logging"; run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; }
@test "check rejects an absent logfile directive" { run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]; }
@test "check rejects a wrong global logfile" { printf 'Defaults logfile=/tmp/sudo.log\n' >> "$RLCH_SUDOERS_MAIN_FILE"; run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]; }
@test "check rejects a scoped conflicting logfile" { printf 'Defaults logfile=/var/log/sudo.log\nDefaults:admin logfile=/tmp/admin.log\n' >> "$RLCH_SUDOERS_MAIN_FILE"; run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]; }
@test "check does not accept only a targeted logfile" { printf 'Defaults:admin logfile=/var/log/sudo.log\n' >> "$RLCH_SUDOERS_MAIN_FILE"; run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]; }
@test "check reports invalid sudoers as error" { RLCH_TEST_SUDOERS_FAIL=validate; run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]; }
@test "apply writes only the configured logfile directive" { local r=0; apply || r=$?; [ "$r" -eq "$RLCH_MODULE_RESULT_CHANGED" ]; [ "$(cat "$RLCH_CIS_5_2_3_DROPIN")" = 'Defaults logfile="/var/log/sudo.log"' ]; [ ! -e "${RLCH_TEST_SUDOERS_ROOT}/var/log/sudo.log" ]; }
@test "apply is idempotent when configuration complies" { printf 'Defaults logfile=/var/log/sudo.log\n' >> "$RLCH_SUDOERS_MAIN_FILE"; run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; [ ! -e "$RLCH_CIS_5_2_3_STATE_FILE" ]; }
@test "apply requires root" { RLCH_TEST_SUDOERS_UID=1000; run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]; }
@test "apply restores prior file after post-write visudo failure" { printf 'Defaults logfile=/tmp/old.log\n# keep\n' > "$RLCH_CIS_5_2_3_DROPIN"; RLCH_TEST_SUDOERS_FAIL=post_write; local r=0; apply || r=$?; [ "$r" -eq "$RLCH_MODULE_RESULT_ERROR" ]; [ "$(cat "$RLCH_CIS_5_2_3_DROPIN")" = $'Defaults logfile=/tmp/old.log\n# keep' ]; [ ! -e "$RLCH_CIS_5_2_3_STATE_FILE" ]; }
@test "validate delegates to check" { run validate; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]; }
@test "rollback removes a newly created drop-in" { local a=0 b=0; apply || a=$?; rollback || b=$?; [ "$a" -eq "$RLCH_MODULE_RESULT_CHANGED" ]; [ "$b" -eq "$RLCH_MODULE_RESULT_CHANGED" ]; [ ! -e "$RLCH_CIS_5_2_3_DROPIN" ]; }
@test "rollback restores an exact pre-existing drop-in" { printf 'Defaults logfile=/tmp/old.log\n# keep\n' > "$RLCH_CIS_5_2_3_DROPIN"; local a=0 b=0; apply || a=$?; rollback || b=$?; [ "$a" -eq "$RLCH_MODULE_RESULT_CHANGED" ]; [ "$b" -eq "$RLCH_MODULE_RESULT_CHANGED" ]; [ "$(cat "$RLCH_CIS_5_2_3_DROPIN")" = $'Defaults logfile=/tmp/old.log\n# keep' ]; }
@test "rollback is idempotent without state" { run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; }
@test "metadata uses exact ComplianceAsCode rule" { source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/5/2/3/metadata.conf"; [ "$RLCH_MODULE_OPENSCAP_RULE" = xccdf_org.ssgproject.content_rule_sudo_custom_logfile ]; }
