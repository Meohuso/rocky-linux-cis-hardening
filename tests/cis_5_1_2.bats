#!/usr/bin/env bats

setup() {
    export RLCH_TEST_REPOSITORY_ROOT="${BATS_TEST_DIRNAME}/.."
    source "${RLCH_TEST_REPOSITORY_ROOT}/tests/test_helper.bash"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/module_api.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/tests/helpers/sshd_private_key_access_helper.bash"
    sshd_private_key_access_helper_setup
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/5/1/2/module.sh"
}

@test "check accepts multiple compliant private host keys" { sshd_private_key_add ssh_host_rsa_key 0 997 600; sshd_private_key_add ssh_host_ed25519_key 0 997 400; run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; }
@test "check ignores public keys and unrelated files" { sshd_private_key_add ssh_host_rsa_key 0 997 600; : > "${RLCH_CIS_5_1_2_KEY_DIR}/ssh_host_rsa_key.pub"; : > "${RLCH_CIS_5_1_2_KEY_DIR}/config"; run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; }
@test "check accepts no private host keys without creating one" { run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; [ -z "$(find "${RLCH_CIS_5_1_2_KEY_DIR}" -type f)" ]; }
@test "check rejects incorrect owner" { sshd_private_key_add ssh_host_rsa_key 1000 997 600; run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]; }
@test "check rejects incorrect dedicated group" { sshd_private_key_add ssh_host_rsa_key 0 0 600; run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]; }
@test "check rejects permissive mode" { sshd_private_key_add ssh_host_rsa_key 0 997 640; run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]; }
@test "check reports missing ssh directory as non-compliant" { rmdir "${RLCH_CIS_5_1_2_KEY_DIR}"; run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]; }
@test "check reports unresolved ssh_keys group as error" { sshd_private_key_add ssh_host_rsa_key 0 997 600; RLCH_TEST_PRIVATE_KEY_FAIL=getent; run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]; }
@test "apply remediates every discovered key and preserves contents" { sshd_private_key_add ssh_host_rsa_key 1000 0 664; sshd_private_key_add ssh_host_ed25519_key 0 100 640; printf secret > "${RLCH_CIS_5_1_2_KEY_DIR}/ssh_host_rsa_key"; local r=0; apply || r=$?; [ "$r" -eq "$RLCH_MODULE_RESULT_CHANGED" ]; [ "$(sshd_private_key_value ssh_host_rsa_key owner):$(sshd_private_key_value ssh_host_rsa_key group):$(sshd_private_key_value ssh_host_rsa_key mode)" = 0:997:600 ]; [ "$(sshd_private_key_value ssh_host_ed25519_key owner):$(sshd_private_key_value ssh_host_ed25519_key group):$(sshd_private_key_value ssh_host_ed25519_key mode)" = 0:997:600 ]; [ "$(cat "${RLCH_CIS_5_1_2_KEY_DIR}/ssh_host_rsa_key")" = secret ]; }
@test "apply is idempotent" { sshd_private_key_add ssh_host_rsa_key 0 997 600; run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; [ ! -e "$RLCH_CIS_5_1_2_STATE_FILE" ]; }
@test "apply requires root before state capture" { sshd_private_key_add ssh_host_rsa_key 1000 0 664; RLCH_TEST_PRIVATE_KEY_UID=1000; run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]; [ ! -e "$RLCH_CIS_5_1_2_STATE_FILE" ]; }
@test "apply does not recreate a missing SSH directory" { rmdir "$RLCH_CIS_5_1_2_KEY_DIR"; run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]; [ ! -e "$RLCH_CIS_5_1_2_KEY_DIR" ]; [ ! -e "$RLCH_CIS_5_1_2_STATE_FILE" ]; }
@test "apply retains complete state when one key change fails" { sshd_private_key_add ssh_host_rsa_key 1000 0 664; sshd_private_key_add ssh_host_ed25519_key 1001 100 640; RLCH_TEST_PRIVATE_KEY_FAIL=chown:ssh_host_ed25519_key; run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]; [ "$(tr '\0' '\n' < "$RLCH_CIS_5_1_2_STATE_FILE" | wc -l)" -eq 8 ]; }
@test "validate delegates to check" { sshd_private_key_add ssh_host_rsa_key 0 0 600; run validate; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]; }
@test "rollback restores each key exact access metadata" { sshd_private_key_add ssh_host_rsa_key 1000 0 664; sshd_private_key_add ssh_host_ed25519_key 1001 100 640; local a=0 b=0; apply || a=$?; rollback || b=$?; [ "$a" -eq "$RLCH_MODULE_RESULT_CHANGED" ]; [ "$b" -eq "$RLCH_MODULE_RESULT_CHANGED" ]; [ "$(sshd_private_key_value ssh_host_rsa_key owner):$(sshd_private_key_value ssh_host_rsa_key group):$(sshd_private_key_value ssh_host_rsa_key mode)" = 1000:0:664 ]; [ "$(sshd_private_key_value ssh_host_ed25519_key owner):$(sshd_private_key_value ssh_host_ed25519_key group):$(sshd_private_key_value ssh_host_ed25519_key mode)" = 1001:100:640 ]; [ ! -e "$RLCH_CIS_5_1_2_STATE_FILE" ]; }
@test "rollback is idempotent without state" { run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; }
@test "rollback rejects incomplete state without changing keys" { sshd_private_key_add ssh_host_rsa_key 0 997 600; mkdir -p "$RLCH_CIS_5_1_2_STATE_DIR"; printf 'broken\0' > "$RLCH_CIS_5_1_2_STATE_FILE"; run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]; [ -e "$RLCH_CIS_5_1_2_STATE_FILE" ]; }
@test "metadata records the three-rule mapping as manual" { source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/5/1/2/metadata.conf"; [ "$RLCH_MODULE_ID" = 5.1.2 ]; [ "$RLCH_MODULE_LEVEL" = 1 ]; [ "$RLCH_MODULE_OPENSCAP_RULE" = manual ]; }
