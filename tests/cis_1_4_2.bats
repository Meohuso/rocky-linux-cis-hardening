#!/usr/bin/env bats
#
# Rocky Linux CIS Hardening Framework
#
# CIS 1.4.2 tests.
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

    RLCH_CIS_1_4_2_GRUB_CONFIG="${RLCH_TEST_GRUB_CONFIG}"
    RLCH_CIS_1_4_2_USER_CONFIG="${RLCH_TEST_GRUB_USER_CONFIG}"
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/1/4/2/module.sh"
}

teardown() {
    teardown_grub_test_environment
}

create_compliant_grub_files() {
    printf '%s\n' "grub configuration" > "${RLCH_TEST_GRUB_CONFIG}"
    printf '%s\n' "user configuration" > "${RLCH_TEST_GRUB_USER_CONFIG}"
    chmod 0600 "${RLCH_TEST_GRUB_CONFIG}" "${RLCH_TEST_GRUB_USER_CONFIG}"
}

@test "check succeeds when bootloader files have restricted access" {
    create_compliant_grub_files

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check reports non-compliance for permissive grub.cfg permissions" {
    create_compliant_grub_files
    chmod 0644 "${RLCH_TEST_GRUB_CONFIG}"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check reports non-compliance for permissive user.cfg permissions" {
    create_compliant_grub_files
    chmod 0640 "${RLCH_TEST_GRUB_USER_CONFIG}"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check succeeds when user.cfg is absent and grub.cfg is compliant" {
    printf '%s\n' "grub configuration" > "${RLCH_TEST_GRUB_CONFIG}"
    chmod 0600 "${RLCH_TEST_GRUB_CONFIG}"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "apply restricts access to bootloader configuration files" {
    printf '%s\n' "grub configuration" > "${RLCH_TEST_GRUB_CONFIG}"
    printf '%s\n' "user configuration" > "${RLCH_TEST_GRUB_USER_CONFIG}"
    chmod 0644 "${RLCH_TEST_GRUB_CONFIG}" "${RLCH_TEST_GRUB_USER_CONFIG}"

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "$(stat -Lc '%a' "${RLCH_TEST_GRUB_CONFIG}")" = "600" ]
    [ "$(stat -Lc '%a' "${RLCH_TEST_GRUB_USER_CONFIG}")" = "600" ]
}

@test "apply is idempotent when bootloader files are already compliant" {
    create_compliant_grub_files

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "apply requires root privileges when a change is needed" {
    printf '%s\n' "grub configuration" > "${RLCH_TEST_GRUB_CONFIG}"
    chmod 0644 "${RLCH_TEST_GRUB_CONFIG}"
    set_grub_test_effective_uid "1000"

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
}

@test "validate delegates to the compliance check" {
    create_compliant_grub_files

    run validate

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "rollback restores original bootloader file access" {
    printf '%s\n' "grub configuration" > "${RLCH_TEST_GRUB_CONFIG}"
    printf '%s\n' "user configuration" > "${RLCH_TEST_GRUB_USER_CONFIG}"
    chmod 0644 "${RLCH_TEST_GRUB_CONFIG}"
    chmod 0640 "${RLCH_TEST_GRUB_USER_CONFIG}"

    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]

    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "$(stat -Lc '%a' "${RLCH_TEST_GRUB_CONFIG}")" = "644" ]
    [ "$(stat -Lc '%a' "${RLCH_TEST_GRUB_USER_CONFIG}")" = "640" ]
}

@test "rollback is idempotent when no backup exists" {
    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "metadata declares the expected CIS control" {
    clear_module_metadata_variables
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/1/4/2/metadata.conf"

    [ "${RLCH_MODULE_ID}" = "1.4.2" ]
    [ "${RLCH_MODULE_LEVEL}" = "1" ]
    [ "${RLCH_MODULE_ENABLED}" = "true" ]
    [ "${RLCH_MODULE_REQUIRES_REBOOT}" = "false" ]
    [ "${RLCH_MODULE_OPENSCAP_RULE}" = "xccdf_org.ssgproject.content_rule_file_permissions_grub2_cfg" ]
}
