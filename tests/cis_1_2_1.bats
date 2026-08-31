#!/usr/bin/env bats
#
# Rocky Linux CIS Hardening Framework
#
# CIS 1.2.1 tests.
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
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/1/2/1/module.sh"
}

teardown() {
    teardown_rpm_test_environment
}

@test "check succeeds when at least one RPM GPG key is installed" {
    add_rpm_test_gpg_key "gpg-pubkey-350d275d-6279464b"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check reports non-compliance when no RPM GPG key is installed" {
    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check reports non-compliance when the RPM query fails" {
    set_rpm_test_exit_status "1"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "apply refuses automatic GPG key import" {
    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [[ "${output}" == *"intentionally unsupported"* ]]
}

@test "validate delegates to the compliance check" {
    add_rpm_test_gpg_key "gpg-pubkey-350d275d-6279464b"

    run validate

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "rollback succeeds because the module does not modify the system" {
    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
    [[ "${output}" == *"no rollback action is required"* ]]
}

@test "metadata declares the expected CIS control" {
    local metadata_file

    metadata_file="${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/1/2/1/metadata.conf"

    clear_module_metadata_variables
    source "${metadata_file}"

    [ "${RLCH_MODULE_ID}" = "1.2.1" ]
    [ "${RLCH_MODULE_LEVEL}" = "1" ]
    [ "${RLCH_MODULE_ENABLED}" = "true" ]
    [ "${RLCH_MODULE_REQUIRES_REBOOT}" = "false" ]
    [ "${RLCH_MODULE_OPENSCAP_RULE}" = "manual" ]
}
