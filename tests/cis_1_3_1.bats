#!/usr/bin/env bats
#
# Rocky Linux CIS Hardening Framework
#
# CIS 1.3.1 tests.
#
# SPDX-License-Identifier: MIT
#

setup() {
    source "${BATS_TEST_DIRNAME}/test_helper.bash"
    source "${BATS_TEST_DIRNAME}/helpers/rpm_helper.bash"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/common.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/modules.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/module_api.sh"

    setup_rpm_test_environment
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/rpm.sh"

    RLCH_CIS_1_3_1_INSTALLED_BY_MODULE="false"
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/1/3/1/module.sh"
}

teardown() {
    teardown_rpm_test_environment
}

@test "check succeeds when AIDE is installed" {
    add_rpm_test_package "aide"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check reports non-compliance when AIDE is not installed" {
    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "apply installs AIDE when it is missing" {
    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    grep -Fxq "aide" "${RLCH_TEST_RPM_PACKAGES}"
}

@test "apply is idempotent when AIDE is already installed" {
    add_rpm_test_package "aide"

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "apply requires root when AIDE is missing" {
    set_rpm_test_effective_uid "1000"

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
}

@test "validate succeeds after AIDE is installed" {
    add_rpm_test_package "aide"

    run validate

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "rollback removes AIDE when this module installed it" {
    apply_result=0

    apply || apply_result=$?

    [ "${apply_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "${RLCH_CIS_1_3_1_INSTALLED_BY_MODULE}" = "true" ]
    grep -Fxq "aide" "${RLCH_TEST_RPM_PACKAGES}"

    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    ! grep -Fxq "aide" "${RLCH_TEST_RPM_PACKAGES}"
}

@test "rollback does not remove a pre-existing AIDE installation" {
    add_rpm_test_package "aide"

    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]

    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
    grep -Fxq "aide" "${RLCH_TEST_RPM_PACKAGES}"
}

@test "metadata declares the expected CIS control" {
    local metadata_file

    metadata_file="${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/1/3/1/metadata.conf"

    clear_module_metadata_variables
    source "${metadata_file}"

    [ "${RLCH_MODULE_ID}" = "1.3.1" ]
    [ "${RLCH_MODULE_LEVEL}" = "1" ]
    [ "${RLCH_MODULE_ENABLED}" = "true" ]
    [ "${RLCH_MODULE_REQUIRES_REBOOT}" = "false" ]
    [ "${RLCH_MODULE_OPENSCAP_RULE}" = "xccdf_org.ssgproject.content_rule_package_aide_installed" ]
}
