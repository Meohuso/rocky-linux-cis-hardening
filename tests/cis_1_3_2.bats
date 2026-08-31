#!/usr/bin/env bats
#
# Rocky Linux CIS Hardening Framework
#
# CIS 1.3.2 tests.
#
# SPDX-License-Identifier: MIT
#

setup() {
    source "${BATS_TEST_DIRNAME}/test_helper.bash"
    source "${BATS_TEST_DIRNAME}/helpers/rpm_helper.bash"
    source "${BATS_TEST_DIRNAME}/helpers/cron_helper.bash"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/common.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/modules.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/module_api.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/filesystem.sh"

    setup_rpm_test_environment
    setup_cron_test_environment

    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/rpm.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/cron.sh"

    RLCH_CIS_1_3_2_CRONTAB="${RLCH_TEST_CRONTAB}"
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/1/3/2/module.sh"
}

teardown() {
    teardown_cron_test_environment
    teardown_rpm_test_environment
}

@test "check succeeds when AIDE is installed and scheduled weekly" {
    add_rpm_test_package "aide"
    printf '%s\n' \
        "05 4 * * 0 root /usr/sbin/aide --check" >> "${RLCH_TEST_CRONTAB}"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check reports non-compliance when AIDE is not installed" {
    printf '%s\n' \
        "05 4 * * 0 root /usr/sbin/aide --check" >> "${RLCH_TEST_CRONTAB}"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check reports non-compliance when the AIDE schedule is missing" {
    add_rpm_test_package "aide"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "apply configures the weekly AIDE integrity check" {
    add_rpm_test_package "aide"

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    grep -Fqx \
        "05 4 * * 0 root /usr/sbin/aide --check" \
        "${RLCH_TEST_CRONTAB}"
}

@test "apply is idempotent when the weekly AIDE check is already configured" {
    add_rpm_test_package "aide"
    printf '%s\n' \
        "05 4 * * 0 root /usr/sbin/aide --check" >> "${RLCH_TEST_CRONTAB}"

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "apply fails when AIDE is not installed" {
    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [[ "${output}" == *"AIDE must be installed"* ]]
}

@test "apply requires root privileges" {
    add_rpm_test_package "aide"
    set_cron_test_effective_uid "1000"

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
}

@test "validate delegates to the compliance check" {
    add_rpm_test_package "aide"
    printf '%s\n' \
        "05 4 * * 0 root /usr/sbin/aide --check" >> "${RLCH_TEST_CRONTAB}"

    run validate

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "rollback restores the original crontab" {
    add_rpm_test_package "aide"

    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]

    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    ! grep -Fqx \
        "05 4 * * 0 root /usr/sbin/aide --check" \
        "${RLCH_TEST_CRONTAB}"
}

@test "rollback is idempotent when no backup exists" {
    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "metadata declares the expected CIS control" {
    local metadata_file

    metadata_file="${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/1/3/2/metadata.conf"

    clear_module_metadata_variables
    source "${metadata_file}"

    [ "${RLCH_MODULE_ID}" = "1.3.2" ]
    [ "${RLCH_MODULE_LEVEL}" = "1" ]
    [ "${RLCH_MODULE_ENABLED}" = "true" ]
    [ "${RLCH_MODULE_REQUIRES_REBOOT}" = "false" ]
    [ "${RLCH_MODULE_OPENSCAP_RULE}" = "xccdf_org.ssgproject.content_rule_aide_periodic_cron_checking" ]
}
