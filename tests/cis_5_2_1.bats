#!/usr/bin/env bats

# shellcheck disable=SC2030,SC2031 # Bats setup exports fixture state per test.

setup() {
    export RLCH_TEST_REPOSITORY_ROOT="${BATS_TEST_DIRNAME}/.."
    source "${RLCH_TEST_REPOSITORY_ROOT}/tests/test_helper.bash"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/module_api.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/tests/helpers/sudo_package_helper.bash"
    sudo_package_helper_setup
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/5/2/1/module.sh"
}

@test "check succeeds when sudo is installed" { RLCH_TEST_SUDO_INSTALLED=true; run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; }
@test "check reports absent sudo" { run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]; }
@test "apply installs sudo and records isolated state" { local r=0; apply || r=$?; [ "$r" -eq "$RLCH_MODULE_RESULT_CHANGED" ]; [ "$RLCH_TEST_SUDO_INSTALLED" = true ]; [ "$(cat "$RLCH_CIS_5_2_1_STATE_FILE")" = sudo ]; }
@test "apply is idempotent for pre-existing sudo" { RLCH_TEST_SUDO_INSTALLED=true; run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; [ ! -e "$RLCH_CIS_5_2_1_STATE_FILE" ]; }
@test "apply requires root only for remediation" { RLCH_TEST_SUDO_UID=1000; run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]; [ ! -e "$RLCH_CIS_5_2_1_STATE_FILE" ]; }
@test "apply reports uid lookup failure" { RLCH_TEST_SUDO_ID_FAIL=true; run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]; }
@test "apply retains state on installation failure" { RLCH_TEST_SUDO_INSTALL_FAIL=true; run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]; [ -e "$RLCH_CIS_5_2_1_STATE_FILE" ]; }
@test "apply verifies installation" { RLCH_TEST_SUDO_KEEP_ABSENT=true; run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]; [ -e "$RLCH_CIS_5_2_1_STATE_FILE" ]; }
@test "validate delegates to check" { run validate; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]; }
@test "rollback removes sudo only when this control installed it" { RLCH_TEST_SUDO_INSTALLED=true; mkdir -p "$RLCH_CIS_5_2_1_STATE_DIR"; printf 'sudo\n' > "$RLCH_CIS_5_2_1_STATE_FILE"; local r=0; rollback || r=$?; [ "$r" -eq "$RLCH_MODULE_RESULT_CHANGED" ]; [ "$RLCH_TEST_SUDO_INSTALLED" = false ]; [ ! -e "$RLCH_CIS_5_2_1_STATE_FILE" ]; }
@test "rollback preserves pre-existing sudo without state" { RLCH_TEST_SUDO_INSTALLED=true; run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; [ "$RLCH_TEST_SUDO_INSTALLED" = true ]; }
@test "rollback rejects invalid state" { mkdir -p "$RLCH_CIS_5_2_1_STATE_DIR"; printf 'wheel\n' > "$RLCH_CIS_5_2_1_STATE_FILE"; run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]; }
@test "rollback retains state on removal failure" { RLCH_TEST_SUDO_INSTALLED=true RLCH_TEST_SUDO_REMOVE_FAIL=true; mkdir -p "$RLCH_CIS_5_2_1_STATE_DIR"; printf 'sudo\n' > "$RLCH_CIS_5_2_1_STATE_FILE"; run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]; [ -e "$RLCH_CIS_5_2_1_STATE_FILE" ]; }
@test "rollback verifies removal" { RLCH_TEST_SUDO_INSTALLED=true RLCH_TEST_SUDO_KEEP_INSTALLED=true; mkdir -p "$RLCH_CIS_5_2_1_STATE_DIR"; printf 'sudo\n' > "$RLCH_CIS_5_2_1_STATE_FILE"; run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]; }
@test "metadata declares exact ComplianceAsCode rule" { source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/5/2/1/metadata.conf"; [ "$RLCH_MODULE_ID" = 5.2.1 ]; [ "$RLCH_MODULE_LEVEL" = 1 ]; [ "$RLCH_MODULE_OPENSCAP_RULE" = xccdf_org.ssgproject.content_rule_package_sudo_installed ]; }
