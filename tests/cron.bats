#!/usr/bin/env bats
#
# Rocky Linux CIS Hardening Framework
#
# Cron library tests.
#
# SPDX-License-Identifier: MIT
#

setup() {
    source "${BATS_TEST_DIRNAME}/test_helper.bash"
    source "${BATS_TEST_DIRNAME}/helpers/cron_helper.bash"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/common.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/modules.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/module_api.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/filesystem.sh"

    setup_cron_test_environment
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/cron.sh"
}

teardown() {
    teardown_cron_test_environment
}

@test "cron_file_has_entry succeeds for an exact active entry" {
    printf '%s\n' \
        "05 4 * * 0 root /usr/sbin/aide --check" >> "${RLCH_TEST_CRONTAB}"

    run cron_file_has_entry \
        "${RLCH_TEST_CRONTAB}" \
        "05 4 * * 0 root /usr/sbin/aide --check"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "cron_file_has_entry reports non-compliance for a missing entry" {
    run cron_file_has_entry \
        "${RLCH_TEST_CRONTAB}" \
        "05 4 * * 0 root /usr/sbin/aide --check"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "cron_file_has_entry rejects an invalid request" {
    run cron_file_has_entry "" ""

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
}

@test "cron_ensure_entry appends a missing entry and creates a backup" {
    run cron_ensure_entry \
        "${RLCH_TEST_CRONTAB}" \
        "05 4 * * 0 root /usr/sbin/aide --check" \
        '^[[:space:]]*[^#].*[[:space:]]/usr/sbin/aide[[:space:]]+--check([[:space:]]|$)'

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    grep -Fqx \
        "05 4 * * 0 root /usr/sbin/aide --check" \
        "${RLCH_TEST_CRONTAB}"
    [ -f "${RLCH_TEST_CRONTAB}${RLCH_CRON_BACKUP_SUFFIX}" ]
}

@test "cron_ensure_entry replaces an existing AIDE check entry" {
    printf '%s\n' \
        "30 2 * * * root /usr/sbin/aide --check" >> "${RLCH_TEST_CRONTAB}"

    run cron_ensure_entry \
        "${RLCH_TEST_CRONTAB}" \
        "05 4 * * 0 root /usr/sbin/aide --check" \
        '^[[:space:]]*[^#].*[[:space:]]/usr/sbin/aide[[:space:]]+--check([[:space:]]|$)'

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    grep -Fqx \
        "05 4 * * 0 root /usr/sbin/aide --check" \
        "${RLCH_TEST_CRONTAB}"
    ! grep -Fqx \
        "30 2 * * * root /usr/sbin/aide --check" \
        "${RLCH_TEST_CRONTAB}"
}

@test "cron_ensure_entry is idempotent for the desired entry" {
    printf '%s\n' \
        "05 4 * * 0 root /usr/sbin/aide --check" >> "${RLCH_TEST_CRONTAB}"

    run cron_ensure_entry \
        "${RLCH_TEST_CRONTAB}" \
        "05 4 * * 0 root /usr/sbin/aide --check" \
        '^[[:space:]]*[^#].*[[:space:]]/usr/sbin/aide[[:space:]]+--check([[:space:]]|$)'

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
    [ ! -e "${RLCH_TEST_CRONTAB}${RLCH_CRON_BACKUP_SUFFIX}" ]
}

@test "cron_ensure_entry requires root privileges" {
    set_cron_test_effective_uid "1000"

    run cron_ensure_entry \
        "${RLCH_TEST_CRONTAB}" \
        "05 4 * * 0 root /usr/sbin/aide --check" \
        '^[[:space:]]*[^#].*[[:space:]]/usr/sbin/aide[[:space:]]+--check([[:space:]]|$)'

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
}

@test "cron_rollback_file restores the original crontab" {
    create_cron_test_backup
    printf '%s\n' \
        "05 4 * * 0 root /usr/sbin/aide --check" >> "${RLCH_TEST_CRONTAB}"

    run cron_rollback_file "${RLCH_TEST_CRONTAB}"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    ! grep -Fqx \
        "05 4 * * 0 root /usr/sbin/aide --check" \
        "${RLCH_TEST_CRONTAB}"
}

@test "cron_rollback_file is idempotent when no backup exists" {
    run cron_rollback_file "${RLCH_TEST_CRONTAB}"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "cron_rollback_file requires root privileges" {
    create_cron_test_backup
    set_cron_test_effective_uid "1000"

    run cron_rollback_file "${RLCH_TEST_CRONTAB}"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
}
