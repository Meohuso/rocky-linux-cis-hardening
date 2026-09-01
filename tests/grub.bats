#!/usr/bin/env bats
#
# Rocky Linux CIS Hardening Framework
#
# GRUB2 library tests.
#
# SPDX-License-Identifier: MIT
#

setup() {
    source "${BATS_TEST_DIRNAME}/test_helper.bash"
    source "${BATS_TEST_DIRNAME}/helpers/grub_helper.bash"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/common.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/modules.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/module_api.sh"

    setup_grub_test_environment
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/grub.sh"
}

teardown() {
    teardown_grub_test_environment
}

@test "grub_password_is_configured succeeds for a PBKDF2 SHA-512 password" {
    write_grub_test_user_config <<'EOF'
GRUB2_PASSWORD=grub.pbkdf2.sha512.10000.0123456789ABCDEF.0123456789ABCDEF
EOF
    run grub_password_is_configured "${RLCH_TEST_GRUB_USER_CONFIG}"
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "grub_password_is_configured accepts surrounding whitespace" {
    write_grub_test_user_config <<'EOF'
   GRUB2_PASSWORD=grub.pbkdf2.sha512.10000.0123456789ABCDEF.0123456789ABCDEF
EOF
    run grub_password_is_configured "${RLCH_TEST_GRUB_USER_CONFIG}"
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "grub_password_is_configured reports non-compliance for a missing file" {
    run grub_password_is_configured "${RLCH_TEST_GRUB_USER_CONFIG}"
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "grub_password_is_configured reports non-compliance for an empty file" {
    : > "${RLCH_TEST_GRUB_USER_CONFIG}"
    run grub_password_is_configured "${RLCH_TEST_GRUB_USER_CONFIG}"
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "grub_password_is_configured reports non-compliance for a plaintext password" {
    write_grub_test_user_config <<'EOF'
GRUB2_PASSWORD=Password123
EOF
    run grub_password_is_configured "${RLCH_TEST_GRUB_USER_CONFIG}"
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "grub_password_is_configured reports non-compliance for an unsupported hash" {
    write_grub_test_user_config <<'EOF'
GRUB2_PASSWORD=grub.pbkdf2.sha256.10000.0123456789ABCDEF.0123456789ABCDEF
EOF
    run grub_password_is_configured "${RLCH_TEST_GRUB_USER_CONFIG}"
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "grub_password_is_configured ignores commented password entries" {
    write_grub_test_user_config <<'EOF'
# GRUB2_PASSWORD=grub.pbkdf2.sha512.10000.0123456789ABCDEF.0123456789ABCDEF
EOF
    run grub_password_is_configured "${RLCH_TEST_GRUB_USER_CONFIG}"
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "grub_file_access_is_configured succeeds for root root 0600" {
    printf '%s\n' "test" > "${RLCH_TEST_GRUB_CONFIG}"
    chmod 0600 "${RLCH_TEST_GRUB_CONFIG}"
    run grub_file_access_is_configured "${RLCH_TEST_GRUB_CONFIG}"
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "grub_file_access_is_configured reports non-compliance for permissive mode" {
    printf '%s\n' "test" > "${RLCH_TEST_GRUB_CONFIG}"
    chmod 0644 "${RLCH_TEST_GRUB_CONFIG}"
    run grub_file_access_is_configured "${RLCH_TEST_GRUB_CONFIG}"
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "grub_file_access_is_configured reports non-compliance for non-root ownership" {
    printf '%s\n' "test" > "${RLCH_TEST_GRUB_CONFIG}"
    chmod 0600 "${RLCH_TEST_GRUB_CONFIG}"
    set_grub_test_default_ownership "1000" "1000"
    run grub_file_access_is_configured "${RLCH_TEST_GRUB_CONFIG}"
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "grub_file_access_is_configured treats a missing optional file as compliant" {
    run grub_file_access_is_configured "${RLCH_TEST_GRUB_CONFIG}"
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "grub_set_file_access changes permissions and creates a backup" {
    printf '%s\n' "test" > "${RLCH_TEST_GRUB_CONFIG}"
    chmod 0644 "${RLCH_TEST_GRUB_CONFIG}"
    set_grub_test_default_ownership "1000" "1000"
    run grub_set_file_access "${RLCH_TEST_GRUB_CONFIG}"
    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "$(stat -Lc '%a' "${RLCH_TEST_GRUB_CONFIG}")" = "600" ]
    [ "$(stat -Lc '%u' "${RLCH_TEST_GRUB_CONFIG}")" = "0" ]
    [ "$(stat -Lc '%g' "${RLCH_TEST_GRUB_CONFIG}")" = "0" ]
    [ -e "${RLCH_TEST_GRUB_CONFIG}${RLCH_GRUB_BACKUP_SUFFIX}" ]
}

@test "grub_set_file_access is idempotent" {
    printf '%s\n' "test" > "${RLCH_TEST_GRUB_CONFIG}"
    chmod 0600 "${RLCH_TEST_GRUB_CONFIG}"
    run grub_set_file_access "${RLCH_TEST_GRUB_CONFIG}"
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
    [ ! -e "${RLCH_TEST_GRUB_CONFIG}${RLCH_GRUB_BACKUP_SUFFIX}" ]
}

@test "grub_set_file_access requires root privileges for changes" {
    printf '%s\n' "test" > "${RLCH_TEST_GRUB_CONFIG}"
    chmod 0644 "${RLCH_TEST_GRUB_CONFIG}"
    set_grub_test_effective_uid "1000"
    run grub_set_file_access "${RLCH_TEST_GRUB_CONFIG}"
    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
}

@test "grub_rollback_file_access restores original permissions" {
    printf '%s\n' "test" > "${RLCH_TEST_GRUB_CONFIG}"
    chmod 0644 "${RLCH_TEST_GRUB_CONFIG}"
    run grub_set_file_access "${RLCH_TEST_GRUB_CONFIG}"
    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    run grub_rollback_file_access "${RLCH_TEST_GRUB_CONFIG}"
    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "$(stat -Lc '%a' "${RLCH_TEST_GRUB_CONFIG}")" = "644" ]
}

@test "grub_rollback_file_access is idempotent without a backup" {
    run grub_rollback_file_access "${RLCH_TEST_GRUB_CONFIG}"
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}
