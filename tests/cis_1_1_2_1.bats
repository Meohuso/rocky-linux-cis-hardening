#!/usr/bin/env bats
#
# Rocky Linux CIS Hardening Framework
#
# CIS 1.1.2.1 tests.
#
# SPDX-License-Identifier: MIT
#

setup() {
    # shellcheck source=tests/test_helper.bash
    source "${BATS_TEST_DIRNAME}/test_helper.bash"

    # shellcheck source=tests/helpers/mount_helper.bash
    source "${BATS_TEST_DIRNAME}/helpers/mount_helper.bash"

    # shellcheck source=lib/common.sh
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/common.sh"

    # shellcheck source=lib/modules.sh
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/modules.sh"

    # shellcheck source=lib/module_api.sh
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/module_api.sh"

    setup_mount_test_environment

    # shellcheck source=lib/mount.sh
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/mount.sh"

    RLCH_CIS_1_1_2_1_FSTAB="${RLCH_TEST_FSTAB}"

    # shellcheck source=modules/cis/1/1/2/1/module.sh
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/1/1/2/1/module.sh"
}

teardown() {
    teardown_mount_test_environment
}

@test "check succeeds when /tmp has persistent and runtime mount entries" {
    add_mount_test_fstab_entry "/tmp"
    add_mount_test_runtime_entry "/tmp"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check reports non-compliance when /tmp is absent from fstab" {
    add_mount_test_runtime_entry "/tmp"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check reports non-compliance when /tmp is not mounted at runtime" {
    add_mount_test_fstab_entry "/tmp"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check ignores a parent filesystem mounted on root" {
    add_mount_test_fstab_entry "/"
    add_mount_test_runtime_entry "/"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "apply refuses automatic partition provisioning" {
    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [[ "${output}" == *"Automatic partition creation is intentionally unsupported"* ]]
}

@test "validate delegates to the compliance check" {
    add_mount_test_fstab_entry "/tmp"
    add_mount_test_runtime_entry "/tmp"

    run validate

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "rollback restores the framework-managed fstab backup" {
    local original_content

    original_content=$'# original fstab\n/dev/mapper/root\t/\txfs\tdefaults\t0\t0\n'

    add_mount_test_fstab_entry "/tmp"
    create_mount_test_fstab_backup "${original_content}"

    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "$(cat "${RLCH_TEST_FSTAB}")" = "${original_content%$'\n'}" ]
    [ ! -e "${RLCH_TEST_FSTAB}${RLCH_MOUNT_BACKUP_SUFFIX}" ]
}

@test "rollback remounts /tmp when it is mounted at runtime" {
    local original_content

    original_content=$'# original fstab\n/dev/mapper/tmp\t/tmp\txfs\tdefaults\t0\t0\n'

    add_mount_test_fstab_entry "/tmp"
    add_mount_test_runtime_entry "/tmp"
    create_mount_test_fstab_backup "${original_content}"

    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "$(cat "${RLCH_TEST_MOUNT_LOG}")" = "-o remount /tmp" ]
}

@test "rollback is idempotent when no backup exists" {
    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "rollback fails without root privileges" {
    create_mount_test_fstab_backup "# original fstab"$'\n'
    set_mount_test_effective_uid "1000"

    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [[ "${output}" == *"Root privileges are required"* ]]
    [ -f "${RLCH_TEST_FSTAB}${RLCH_MOUNT_BACKUP_SUFFIX}" ]
}

@test "metadata declares the expected CIS control" {
    local metadata_file

    metadata_file="${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/1/1/2/1/metadata.conf"

    clear_module_metadata_variables

    # shellcheck source=modules/cis/1/1/2/1/metadata.conf
    source "${metadata_file}"

    [ "${RLCH_MODULE_ID}" = "1.1.2.1" ]
    [ "${RLCH_MODULE_LEVEL}" = "1" ]
    [ "${RLCH_MODULE_ENABLED}" = "true" ]
    [ "${RLCH_MODULE_REQUIRES_REBOOT}" = "false" ]
    [ "${RLCH_MODULE_OPENSCAP_RULE}" = "xccdf_org.ssgproject.content_rule_partition_for_tmp" ]
}
