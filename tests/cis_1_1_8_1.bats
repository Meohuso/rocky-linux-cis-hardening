#!/usr/bin/env bats
#
# Rocky Linux CIS Hardening Framework
#
# CIS 1.1.8.1 tests.
#
# SPDX-License-Identifier: MIT
#

setup() {
    source "${BATS_TEST_DIRNAME}/test_helper.bash"
    source "${BATS_TEST_DIRNAME}/helpers/mount_helper.bash"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/common.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/modules.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/module_api.sh"

    setup_mount_test_environment

    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/mount.sh"

    RLCH_CIS_1_1_8_1_FSTAB="${RLCH_TEST_FSTAB}"

    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/1/1/8/1/module.sh"
}

teardown() {
    teardown_mount_test_environment
}

@test "check succeeds when /dev/shm has persistent and runtime mount entries" {
    add_mount_test_fstab_entry "/dev/shm"
    add_mount_test_runtime_entry "/dev/shm"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check reports non-compliance when /dev/shm is absent from fstab" {
    add_mount_test_runtime_entry "/dev/shm"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check reports non-compliance when /dev/shm is not mounted at runtime" {
    add_mount_test_fstab_entry "/dev/shm"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check ignores the /dev parent mount" {
    add_mount_test_fstab_entry "/dev"
    add_mount_test_runtime_entry "/dev"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "apply refuses automatic partition provisioning" {
    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [[ "${output}" == *"Automatic partition creation is intentionally unsupported"* ]]
}

@test "validate delegates to the compliance check" {
    add_mount_test_fstab_entry "/dev/shm"
    add_mount_test_runtime_entry "/dev/shm"

    run validate

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "rollback restores the framework-managed fstab backup" {
    local original_content

    original_content=$'# original fstab\ntmpfs\t/dev/shm\ttmpfs\tdefaults\t0\t0\n'

    add_mount_test_fstab_entry "/dev/shm"
    create_mount_test_fstab_backup "${original_content}"

    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "$(cat "${RLCH_TEST_FSTAB}")" = "${original_content%$'\n'}" ]
    [ ! -e "${RLCH_TEST_FSTAB}${RLCH_MOUNT_BACKUP_SUFFIX}" ]
}

@test "rollback remounts /dev/shm when it is mounted at runtime" {
    local original_content

    original_content=$'# original fstab\ntmpfs\t/dev/shm\ttmpfs\tdefaults\t0\t0\n'

    add_mount_test_fstab_entry "/dev/shm"
    add_mount_test_runtime_entry "/dev/shm"
    create_mount_test_fstab_backup "${original_content}"

    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "$(cat "${RLCH_TEST_MOUNT_LOG}")" = "-o remount /dev/shm" ]
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

    metadata_file="${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/1/1/8/1/metadata.conf"

    clear_module_metadata_variables
    source "${metadata_file}"

    [ "${RLCH_MODULE_ID}" = "1.1.8.1" ]
    [ "${RLCH_MODULE_LEVEL}" = "1" ]
    [ "${RLCH_MODULE_ENABLED}" = "true" ]
    [ "${RLCH_MODULE_REQUIRES_REBOOT}" = "false" ]
    [ "${RLCH_MODULE_OPENSCAP_RULE}" = "xccdf_org.ssgproject.content_rule_partition_for_dev_shm" ]
}
