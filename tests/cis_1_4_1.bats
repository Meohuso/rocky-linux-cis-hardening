#!/usr/bin/env bats
#
# Rocky Linux CIS Hardening Framework
#
# CIS 1.4.1 tests.
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

    RLCH_CIS_1_4_1_USER_CONFIG="${RLCH_TEST_GRUB_USER_CONFIG}"
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/1/4/1/module.sh"
}

teardown() {
    teardown_grub_test_environment
}

@test "check succeeds when the bootloader password is configured" {
    write_grub_test_user_config <<'EOF'
GRUB2_PASSWORD=grub.pbkdf2.sha512.10000.0123456789ABCDEF.0123456789ABCDEF
EOF

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check reports non-compliance when the bootloader password is missing" {
    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "apply refuses automatic bootloader password configuration" {
    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [[ "${output}" == *"site-specific GRUB2 bootloader password"* ]]
    [[ "${output}" == *"grub2-setpassword"* ]]
}

@test "validate delegates to the compliance check" {
    write_grub_test_user_config <<'EOF'
GRUB2_PASSWORD=grub.pbkdf2.sha512.10000.0123456789ABCDEF.0123456789ABCDEF
EOF

    run validate

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "rollback succeeds because the module does not modify the system" {
    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "metadata declares the expected CIS control" {
    clear_module_metadata_variables
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/1/4/1/metadata.conf"

    [ "${RLCH_MODULE_ID}" = "1.4.1" ]
    [ "${RLCH_MODULE_LEVEL}" = "1" ]
    [ "${RLCH_MODULE_ENABLED}" = "true" ]
    [ "${RLCH_MODULE_REQUIRES_REBOOT}" = "false" ]
    [ "${RLCH_MODULE_OPENSCAP_RULE}" = "xccdf_org.ssgproject.content_rule_grub2_password" ]
}
