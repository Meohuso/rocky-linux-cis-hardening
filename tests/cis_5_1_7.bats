#!/usr/bin/env bats

setup() {
    export RLCH_TEST_REPOSITORY_ROOT="${BATS_TEST_DIRNAME}/.."
    source "${RLCH_TEST_REPOSITORY_ROOT}/tests/test_helper.bash"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/module_api.sh"
    export RLCH_CIS_5_1_7_CONFIG_ROOT="${BATS_TEST_TMPDIR}/ssh"
    mkdir -p "${RLCH_CIS_5_1_7_CONFIG_ROOT}/sshd_config.d"
    : > "${RLCH_CIS_5_1_7_CONFIG_ROOT}/sshd_config"
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/5/1/7/module.sh"
}

@test "check accepts each supported access directive" { for directive in AllowUsers AllowGroups DenyUsers DenyGroups; do printf '%s approved\n' "$directive" > "$RLCH_CIS_5_1_7_CONFIG_ROOT/sshd_config"; run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; [[ "$output" == *"$directive approved"* ]]; done; }
@test "check discovers access policy in an included configuration file" { printf 'AllowGroups ssh-admins\n' > "$RLCH_CIS_5_1_7_CONFIG_ROOT/sshd_config.d/50-access.conf"; run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; [[ "$output" == *'AllowGroups ssh-admins'* ]]; }
@test "check accepts multiple account or group entries and trailing comment" { printf 'DenyUsers guest test@host # approved policy\n' > "$RLCH_CIS_5_1_7_CONFIG_ROOT/sshd_config"; run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; }
@test "check ignores comments and empty directives" { printf '# AllowGroups admins\nAllowUsers   # empty\n' > "$RLCH_CIS_5_1_7_CONFIG_ROOT/sshd_config"; run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]; }
@test "check reports no configured policy as non-compliant" { run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]; [[ "$output" == *'organization-approved'* ]]; }
@test "check reports an inaccessible configuration root as error" { rm -rf "$RLCH_CIS_5_1_7_CONFIG_ROOT"; run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]; }
@test "apply refuses to invent organization account policy" { run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]; [[ "$output" == *'organization-specific'* ]]; [ -z "$(find "$RLCH_CIS_5_1_7_CONFIG_ROOT" -type f -size +0c)" ]; }
@test "validate delegates to check" { printf 'AllowGroups admins\n' > "$RLCH_CIS_5_1_7_CONFIG_ROOT/sshd_config"; run validate; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; }
@test "rollback is an isolated no-op" { run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; [ -z "$(find "$RLCH_CIS_5_1_7_CONFIG_ROOT" -type f -size +0c)" ]; }
@test "metadata uses the exact ComplianceAsCode rule" { source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/5/1/7/metadata.conf"; [ "$RLCH_MODULE_ID" = 5.1.7 ]; [ "$RLCH_MODULE_LEVEL" = 1 ]; [ "$RLCH_MODULE_OPENSCAP_RULE" = sshd_limit_user_access ]; }
