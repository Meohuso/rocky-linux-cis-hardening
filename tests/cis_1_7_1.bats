#!/usr/bin/env bats
#
# Rocky Linux CIS Hardening Framework
#
# CIS 1.7.1 tests.
#
# SPDX-License-Identifier: MIT
#

setup() {
    source "${BATS_TEST_DIRNAME}/test_helper.bash"
    source "${BATS_TEST_DIRNAME}/helpers/banner_helper.bash"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/common.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/modules.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/module_api.sh"

    setup_banner_test_environment
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/banner.sh"

    RLCH_CIS_1_7_1_MOTD_FILE="${RLCH_TEST_BANNER_ETC}/motd"
    RLCH_CIS_1_7_1_OS_RELEASE_FILE="${RLCH_TEST_BANNER_ETC}/os-release"
    RLCH_CIS_1_7_1_BANNER="Authorized users only. All activity may be monitored and reported."

    write_banner_test_os_release <<'EOF'
NAME="Rocky Linux"
ID="rocky"
VERSION_ID="10.2"
EOF

    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/1/7/1/module.sh"
}

teardown() {
    teardown_banner_test_environment
}

@test "check succeeds for the approved banner" {
    printf '%s\n' "${RLCH_CIS_1_7_1_BANNER}" > "${RLCH_CIS_1_7_1_MOTD_FILE}"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check reports non-compliance when motd is absent" {
    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check rejects operating system escape sequences" {
    printf '%s\n' 'Authorized users only. Kernel: \r' > "${RLCH_CIS_1_7_1_MOTD_FILE}"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check rejects operating system references" {
    printf '%s\n' "Authorized users only. Rocky systems." > "${RLCH_CIS_1_7_1_MOTD_FILE}"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "apply installs the approved banner" {
    printf '%s\n' 'Welcome to Rocky Linux \r' > "${RLCH_CIS_1_7_1_MOTD_FILE}"

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "$(cat "${RLCH_CIS_1_7_1_MOTD_FILE}")" = "${RLCH_CIS_1_7_1_BANNER}" ]
}

@test "validate succeeds after apply" {
    printf '%s\n' 'Welcome to Rocky Linux \r' > "${RLCH_CIS_1_7_1_MOTD_FILE}"

    apply_result=0
    apply || apply_result=$?
    [ "${apply_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]

    run validate

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "apply is idempotent for the approved banner" {
    printf '%s\n' "${RLCH_CIS_1_7_1_BANNER}" > "${RLCH_CIS_1_7_1_MOTD_FILE}"

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "rollback restores the original motd" {
    printf '%s\n' "Original site message" > "${RLCH_CIS_1_7_1_MOTD_FILE}"

    apply_result=0
    apply || apply_result=$?
    [ "${apply_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]

    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "$(cat "${RLCH_CIS_1_7_1_MOTD_FILE}")" = "Original site message" ]
}

@test "metadata declares the expected CIS control" {
    clear_module_metadata_variables
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/1/7/1/metadata.conf"

    [ "${RLCH_MODULE_ID}" = "1.7.1" ]
    [ "${RLCH_MODULE_LEVEL}" = "1" ]
    [ "${RLCH_MODULE_ENABLED}" = "true" ]
    [ "${RLCH_MODULE_REQUIRES_REBOOT}" = "false" ]
    [ "${RLCH_MODULE_OPENSCAP_RULE}" = "xccdf_org.ssgproject.content_rule_banner_etc_motd_cis" ]
}
