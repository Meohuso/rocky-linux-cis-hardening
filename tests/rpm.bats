#!/usr/bin/env bats
#
# Rocky Linux CIS Hardening Framework
#
# RPM library tests.
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
}

teardown() {
    teardown_rpm_test_environment
}

@test "rpm_list_gpg_keys lists installed RPM GPG public keys" {
    add_rpm_test_gpg_key "gpg-pubkey-350d275d-6279464b"
    add_rpm_test_gpg_key "gpg-pubkey-702d426d-6382fa7c"

    run rpm_list_gpg_keys

    [ "${status}" -eq 0 ]
    [[ "${output}" == *"gpg-pubkey-350d275d-6279464b"* ]]
    [[ "${output}" == *"gpg-pubkey-702d426d-6382fa7c"* ]]
}

@test "rpm_has_gpg_keys is compliant when at least one GPG key is installed" {
    add_rpm_test_gpg_key "gpg-pubkey-350d275d-6279464b"
    run rpm_has_gpg_keys
    [ "${status}" -eq "${RLCH_MODULE_RESULT_COMPLIANT}" ]
}

@test "rpm_has_gpg_keys is non-compliant when no GPG key is installed" {
    run rpm_has_gpg_keys
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "rpm_has_gpg_keys is non-compliant when rpm query fails" {
    set_rpm_test_exit_status "1"
    run rpm_has_gpg_keys
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}
