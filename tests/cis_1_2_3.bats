#!/usr/bin/env bats
#
# Rocky Linux CIS Hardening Framework
#
# CIS 1.2.3 tests.
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
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/1/2/3/module.sh"
}

teardown() {
    teardown_rpm_test_environment
}

@test "check succeeds when at least one repository is enabled" {
    add_dnf_test_repository "baseos" "Rocky Linux BaseOS"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check reports non-compliance when no repository is enabled" {
    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check reports non-compliance when dnf query fails" {
    set_dnf_test_exit_status "1"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "apply refuses automatic repository configuration" {
    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [[ "${output}" == *"manual validation"* ]]
    [[ "${output}" == *"intentionally unsupported"* ]]
}

@test "validate delegates to the compliance check" {
    add_dnf_test_repository "baseos" "Rocky Linux BaseOS"

    run validate

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "rollback succeeds because the module does not modify repositories" {
    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "metadata declares the expected CIS control" {
    local metadata_file

    metadata_file="${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/1/2/3/metadata.conf"

    clear_module_metadata_variables
    source "${metadata_file}"

    [ "${RLCH_MODULE_ID}" = "1.2.3" ]
    [ "${RLCH_MODULE_LEVEL}" = "1" ]
    [ "${RLCH_MODULE_ENABLED}" = "true" ]
    [ "${RLCH_MODULE_REQUIRES_REBOOT}" = "false" ]
    [ "${RLCH_MODULE_OPENSCAP_RULE}" = "manual" ]
}
