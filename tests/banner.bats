#!/usr/bin/env bats
#
# Rocky Linux CIS Hardening Framework
#
# Warning banner library tests.
#
# SPDX-License-Identifier: MIT
#

setup() {
    source "${BATS_TEST_DIRNAME}/test_helper.bash"
    source "${BATS_TEST_DIRNAME}/helpers/banner_helper.bash"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/module_api.sh"

    setup_banner_test_environment
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/banner.sh"

    TEST_BANNER_FILE="${RLCH_TEST_BANNER_ETC}/motd"
}

teardown() {
    teardown_banner_test_environment
}

@test "banner_contains_system_information accepts a safe banner" {
    printf '%s\n' "Authorized users only." > "${TEST_BANNER_FILE}"

    run banner_contains_system_information "${TEST_BANNER_FILE}" "rocky"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "banner_contains_system_information rejects escape sequences" {
    printf '%s\n' 'System release: \r' > "${TEST_BANNER_FILE}"

    run banner_contains_system_information "${TEST_BANNER_FILE}" "rocky"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "banner_contains_system_information rejects the operating system ID" {
    printf '%s\n' "Welcome to Rocky" > "${TEST_BANNER_FILE}"

    run banner_contains_system_information "${TEST_BANNER_FILE}" "rocky"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "banner_write_file creates the requested banner" {
    run banner_write_file "${TEST_BANNER_FILE}" "Authorized users only."

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "$(cat "${TEST_BANNER_FILE}")" = "Authorized users only." ]
}

@test "banner_write_file is idempotent" {
    printf '%s\n' "Authorized users only." > "${TEST_BANNER_FILE}"

    run banner_write_file "${TEST_BANNER_FILE}" "Authorized users only."

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "banner_write_file refuses non-root execution" {
    set_banner_test_effective_uid 1000

    run banner_write_file "${TEST_BANNER_FILE}" "Authorized users only."

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
}

@test "banner_rollback_file restores the previous banner" {
    printf '%s\n' "Original banner" > "${TEST_BANNER_FILE}"

    run banner_write_file "${TEST_BANNER_FILE}" "Authorized users only."
    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]

    run banner_rollback_file "${TEST_BANNER_FILE}"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "$(cat "${TEST_BANNER_FILE}")" = "Original banner" ]
}

@test "banner_rollback_file is idempotent without a backup" {
    run banner_rollback_file "${TEST_BANNER_FILE}"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}
