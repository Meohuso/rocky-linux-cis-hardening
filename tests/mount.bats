#!/usr/bin/env bats
#
# Rocky Linux CIS Hardening Framework
#
# Shared mount library tests.
#
# SPDX-License-Identifier: MIT
#

setup() {
    # shellcheck source=tests/test_helper.bash
    source "${BATS_TEST_DIRNAME}/test_helper.bash"

    # shellcheck source=tests/helpers/mount_helper.bash
    source "${BATS_TEST_DIRNAME}/helpers/mount_helper.bash"

    # shellcheck source=lib/module_api.sh
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/module_api.sh"

    # shellcheck source=lib/mount.sh
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/mount.sh"

    log_warning() {
        return 0
    }

    setup_mount_test_environment
}

teardown() {
    teardown_mount_test_environment
}

@test "mount_option_list_contains matches a complete option" {
    run mount_option_list_contains "rw,nodev,nosuid" "nodev"
    [ "${status}" -eq 0 ]
}

@test "mount_option_list_contains rejects partial option matches" {
    run mount_option_list_contains "rw,nodevice" "nodev"
    [ "${status}" -eq 1 ]
}

@test "mount_check_partition succeeds for a separate persistent mount" {
    run mount_check_partition "/tmp" "${RLCH_TEST_MOUNT_FSTAB}"
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "mount_check_partition reports missing fstab entry" {
    remove_mount_fstab_entry

    run mount_check_partition "/tmp" "${RLCH_TEST_MOUNT_FSTAB}"
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "mount_check_partition reports inherited parent mount" {
    set_mount_runtime_state "/" "rw,relatime"

    run mount_check_partition "/tmp" "${RLCH_TEST_MOUNT_FSTAB}"
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "mount_check_option succeeds when option is persistent and active" {
    set_mount_fstab_entry "/tmp" "defaults,nodev"
    set_mount_runtime_state "/tmp" "rw,nodev,relatime"

    run mount_check_option "/tmp" "nodev" "${RLCH_TEST_MOUNT_FSTAB}"
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "mount_check_option reports missing persistent option" {
    set_mount_runtime_state "/tmp" "rw,nodev,relatime"

    run mount_check_option "/tmp" "nodev" "${RLCH_TEST_MOUNT_FSTAB}"
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "mount_check_option reports missing runtime option" {
    set_mount_fstab_entry "/tmp" "defaults,nodev"

    run mount_check_option "/tmp" "nodev" "${RLCH_TEST_MOUNT_FSTAB}"
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "mount_write_fstab_option adds an option atomically" {
    run mount_write_fstab_option "/tmp" "nodev" "${RLCH_TEST_MOUNT_FSTAB}"
    [ "${status}" -eq 0 ]
    grep -Eq '^/dev/mapper/rl-tmp[[:space:]]+/tmp[[:space:]]+xfs[[:space:]]+defaults,nodev[[:space:]]' "${RLCH_TEST_MOUNT_FSTAB}"
}

@test "mount_write_fstab_option is idempotent" {
    set_mount_fstab_entry "/tmp" "defaults,nodev"

    run mount_write_fstab_option "/tmp" "nodev" "${RLCH_TEST_MOUNT_FSTAB}"
    [ "${status}" -eq 0 ]
    [ "$(grep -o 'nodev' "${RLCH_TEST_MOUNT_FSTAB}" | wc -l)" -eq 1 ]
}

@test "mount_apply_option updates fstab and remounts" {
    run mount_apply_option \
        "1.1.2.2" "/tmp" "nodev" \
        "${RLCH_TEST_MOUNT_FSTAB}" "${RLCH_TEST_MOUNT_BACKUP}" "0"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ -f "${RLCH_TEST_MOUNT_BACKUP}" ]
    grep -q 'defaults,nodev' "${RLCH_TEST_MOUNT_FSTAB}"
    grep -Fxq -- '-o remount,nodev /tmp' "${RLCH_TEST_MOUNT_LOG}"
}

@test "mount_apply_option is idempotent" {
    set_mount_fstab_entry "/tmp" "defaults,nodev"
    set_mount_runtime_state "/tmp" "rw,nodev,relatime"

    run mount_apply_option \
        "1.1.2.2" "/tmp" "nodev" \
        "${RLCH_TEST_MOUNT_FSTAB}" "${RLCH_TEST_MOUNT_BACKUP}" "0"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
    [ ! -e "${RLCH_TEST_MOUNT_BACKUP}" ]
    [ ! -s "${RLCH_TEST_MOUNT_LOG}" ]
}

@test "mount_apply_option fails without root privileges" {
    run mount_apply_option \
        "1.1.2.2" "/tmp" "nodev" \
        "${RLCH_TEST_MOUNT_FSTAB}" "${RLCH_TEST_MOUNT_BACKUP}" "1000"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [[ "${output}" == *"Root privileges are required"* ]]
}

@test "mount_apply_partition does not create storage automatically" {
    set_mount_runtime_state "/" "rw,relatime"

    run mount_apply_partition "1.1.2.1" "/tmp" "${RLCH_TEST_MOUNT_FSTAB}" "0"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [[ "${output}" == *"Automatic partition creation is not supported"* ]]
}

@test "mount_rollback restores fstab and removes backup" {
    mkdir -p "$(dirname "${RLCH_TEST_MOUNT_BACKUP}")"
    cp -p "${RLCH_TEST_MOUNT_FSTAB}" "${RLCH_TEST_MOUNT_BACKUP}.source"
    cp -p "${RLCH_TEST_MOUNT_FSTAB}" "${RLCH_TEST_MOUNT_BACKUP}"
    mount_write_fstab_option "/tmp" "nodev" "${RLCH_TEST_MOUNT_FSTAB}"

    run mount_rollback \
        "1.1.2.2" "/tmp" \
        "${RLCH_TEST_MOUNT_FSTAB}" "${RLCH_TEST_MOUNT_BACKUP}" "0"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    cmp -s "${RLCH_TEST_MOUNT_FSTAB}" "${RLCH_TEST_MOUNT_BACKUP}.source"
    [ ! -e "${RLCH_TEST_MOUNT_BACKUP}" ]
    grep -Fxq -- '-o remount /tmp' "${RLCH_TEST_MOUNT_LOG}"
}

@test "mount_rollback is idempotent without a backup" {
    run mount_rollback \
        "1.1.2.2" "/tmp" \
        "${RLCH_TEST_MOUNT_FSTAB}" "${RLCH_TEST_MOUNT_BACKUP}" "0"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}
