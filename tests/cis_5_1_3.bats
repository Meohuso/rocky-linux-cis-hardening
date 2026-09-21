#!/usr/bin/env bats

setup() {
    export RLCH_TEST_REPOSITORY_ROOT="${BATS_TEST_DIRNAME}/.."
    source "${RLCH_TEST_REPOSITORY_ROOT}/tests/test_helper.bash"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/module_api.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/tests/helpers/sshd_public_key_access_helper.bash"
    sshd_public_key_access_helper_setup
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/5/1/3/module.sh"
}

@test "check accepts multiple compliant public host keys" { sshd_public_key_add ssh_host_rsa_key.pub 0 0 644; sshd_public_key_add ssh_host_ed25519_key.pub 0 0 400; run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; }
@test "check ignores private keys and unrelated files" { sshd_public_key_add ssh_host_rsa_key.pub 0 0 644; : > "${RLCH_CIS_5_1_3_KEY_DIR}/ssh_host_rsa_key"; : > "${RLCH_CIS_5_1_3_KEY_DIR}/config"; run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; }
@test "check accepts no public host keys without creating one" { run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; [ -z "$(find "${RLCH_CIS_5_1_3_KEY_DIR}" -type f)" ]; }
@test "check rejects incorrect owner" { sshd_public_key_add ssh_host_rsa_key.pub 1000 0 644; run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]; }
@test "check rejects incorrect group" { sshd_public_key_add ssh_host_rsa_key.pub 0 100 644; run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]; }
@test "check rejects group write permission" { sshd_public_key_add ssh_host_rsa_key.pub 0 0 664; run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]; }
@test "check rejects execute permission" { sshd_public_key_add ssh_host_rsa_key.pub 0 0 744; run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]; }
@test "check reports missing ssh directory as non-compliant" { rmdir "${RLCH_CIS_5_1_3_KEY_DIR}"; run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]; }
@test "apply remediates every discovered key and preserves contents" { sshd_public_key_add ssh_host_rsa_key.pub 1000 100 666; sshd_public_key_add ssh_host_ed25519_key.pub 0 100 744; printf public > "${RLCH_CIS_5_1_3_KEY_DIR}/ssh_host_rsa_key.pub"; local r=0; apply || r=$?; [ "$r" -eq "$RLCH_MODULE_RESULT_CHANGED" ]; [ "$(sshd_public_key_value ssh_host_rsa_key.pub owner):$(sshd_public_key_value ssh_host_rsa_key.pub group):$(sshd_public_key_value ssh_host_rsa_key.pub mode)" = 0:0:644 ]; [ "$(sshd_public_key_value ssh_host_ed25519_key.pub owner):$(sshd_public_key_value ssh_host_ed25519_key.pub group):$(sshd_public_key_value ssh_host_ed25519_key.pub mode)" = 0:0:644 ]; [ "$(cat "${RLCH_CIS_5_1_3_KEY_DIR}/ssh_host_rsa_key.pub")" = public ]; }
@test "apply is idempotent" { sshd_public_key_add ssh_host_rsa_key.pub 0 0 644; run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; [ ! -e "$RLCH_CIS_5_1_3_STATE_FILE" ]; }
@test "apply requires root before state capture" { sshd_public_key_add ssh_host_rsa_key.pub 1000 100 666; RLCH_TEST_PUBLIC_KEY_UID=1000; run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]; [ ! -e "$RLCH_CIS_5_1_3_STATE_FILE" ]; }
@test "apply does not recreate a missing SSH directory" { rmdir "$RLCH_CIS_5_1_3_KEY_DIR"; run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]; [ ! -e "$RLCH_CIS_5_1_3_KEY_DIR" ]; [ ! -e "$RLCH_CIS_5_1_3_STATE_FILE" ]; }
@test "apply retains complete state when one key change fails" { sshd_public_key_add ssh_host_rsa_key.pub 1000 100 666; sshd_public_key_add ssh_host_ed25519_key.pub 1001 100 744; RLCH_TEST_PUBLIC_KEY_FAIL=chown:ssh_host_ed25519_key.pub; run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]; [ "$(tr '\0' '\n' < "$RLCH_CIS_5_1_3_STATE_FILE" | wc -l)" -eq 8 ]; }
@test "validate delegates to check" { sshd_public_key_add ssh_host_rsa_key.pub 0 100 644; run validate; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]; }
@test "rollback restores each key exact access metadata" { sshd_public_key_add ssh_host_rsa_key.pub 1000 100 666; sshd_public_key_add ssh_host_ed25519_key.pub 1001 100 744; local a=0 b=0; apply || a=$?; rollback || b=$?; [ "$a" -eq "$RLCH_MODULE_RESULT_CHANGED" ]; [ "$b" -eq "$RLCH_MODULE_RESULT_CHANGED" ]; [ "$(sshd_public_key_value ssh_host_rsa_key.pub owner):$(sshd_public_key_value ssh_host_rsa_key.pub group):$(sshd_public_key_value ssh_host_rsa_key.pub mode)" = 1000:100:666 ]; [ "$(sshd_public_key_value ssh_host_ed25519_key.pub owner):$(sshd_public_key_value ssh_host_ed25519_key.pub group):$(sshd_public_key_value ssh_host_ed25519_key.pub mode)" = 1001:100:744 ]; [ ! -e "$RLCH_CIS_5_1_3_STATE_FILE" ]; }
@test "rollback is idempotent without state" { run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; }
@test "rollback rejects incomplete state without changing keys" { sshd_public_key_add ssh_host_rsa_key.pub 0 0 644; mkdir -p "$RLCH_CIS_5_1_3_STATE_DIR"; printf 'broken\0' > "$RLCH_CIS_5_1_3_STATE_FILE"; run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]; [ -e "$RLCH_CIS_5_1_3_STATE_FILE" ]; }
@test "metadata records the three-rule mapping as manual" { source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/5/1/3/metadata.conf"; [ "$RLCH_MODULE_ID" = 5.1.3 ]; [ "$RLCH_MODULE_LEVEL" = 1 ]; [ "$RLCH_MODULE_OPENSCAP_RULE" = manual ]; }
