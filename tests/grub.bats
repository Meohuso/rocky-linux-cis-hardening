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
