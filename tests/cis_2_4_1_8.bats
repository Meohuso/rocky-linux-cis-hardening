#!/usr/bin/env bats
#
# Rocky Linux CIS Hardening Framework
# CIS 2.4.1.8 tests.
# SPDX-License-Identifier: MIT
#

setup() {
    source "${BATS_TEST_DIRNAME}/test_helper.bash"
    source "${BATS_TEST_DIRNAME}/helpers/cron_authorization_helper.bash"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/common.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/modules.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/module_api.sh"

    RLCH_TEST_CRON_AUTH_DIR="${BATS_TEST_TMPDIR}/cron-auth"
    RLCH_CIS_2_4_1_8_ALLOW_FILE="${RLCH_TEST_CRON_AUTH_DIR}/etc/cron.allow"
    RLCH_CIS_2_4_1_8_DENY_FILE="${RLCH_TEST_CRON_AUTH_DIR}/etc/cron.deny"
    RLCH_CIS_2_4_1_8_STATE_DIR="${RLCH_TEST_CRON_AUTH_DIR}/state/2.4.1.8"
    RLCH_CIS_2_4_1_8_STATE_FILE="${RLCH_CIS_2_4_1_8_STATE_DIR}/state"
    mkdir -p "${RLCH_TEST_CRON_AUTH_DIR}/etc" "${RLCH_TEST_CRON_AUTH_DIR}/state"
    setup_cron_authorization_commands

    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/2/4/1/8/module.sh"
}

teardown() {
    rm -rf "${RLCH_TEST_CRON_AUTH_DIR}"
}

create_compliant_allow_file() {
    printf '%s\n' root > "${RLCH_CIS_2_4_1_8_ALLOW_FILE}"
    chown 0:0 "${RLCH_CIS_2_4_1_8_ALLOW_FILE}"
    chmod 0640 "${RLCH_CIS_2_4_1_8_ALLOW_FILE}"
}

@test "check succeeds when only a compliant cron.allow exists" {
    create_compliant_allow_file
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check accepts more restrictive cron.allow permissions" {
    create_compliant_allow_file
    chmod 0400 "${RLCH_CIS_2_4_1_8_ALLOW_FILE}"
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check rejects an existing cron.deny" {
    create_compliant_allow_file
    : > "${RLCH_CIS_2_4_1_8_DENY_FILE}"
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check rejects a missing cron.allow" {
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check rejects permissive cron.allow access" {
    create_compliant_allow_file
    chmod 0664 "${RLCH_CIS_2_4_1_8_ALLOW_FILE}"
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "apply removes cron.deny and creates a restricted cron.allow" {
    printf '%s\n' legacy > "${RLCH_CIS_2_4_1_8_DENY_FILE}"
    chmod 0666 "${RLCH_CIS_2_4_1_8_DENY_FILE}"

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ ! -e "${RLCH_CIS_2_4_1_8_DENY_FILE}" ]
    [ -f "${RLCH_CIS_2_4_1_8_ALLOW_FILE}" ]
    [ "$(stat -c '%u:%g:%a' "${RLCH_CIS_2_4_1_8_ALLOW_FILE}")" = "0:0:640" ]
}

@test "apply preserves existing cron.allow content" {
    printf '%s\n' admin > "${RLCH_CIS_2_4_1_8_ALLOW_FILE}"
    chmod 0666 "${RLCH_CIS_2_4_1_8_ALLOW_FILE}"

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "$(cat "${RLCH_CIS_2_4_1_8_ALLOW_FILE}")" = admin ]
}

@test "apply records exact initial existence content and access" {
    printf '%s\n' admin > "${RLCH_CIS_2_4_1_8_ALLOW_FILE}"
    printf '%s\n' legacy > "${RLCH_CIS_2_4_1_8_DENY_FILE}"
    chown 65534:65534 "${RLCH_CIS_2_4_1_8_ALLOW_FILE}"
    chown 1:1 "${RLCH_CIS_2_4_1_8_DENY_FILE}"
    chmod 0664 "${RLCH_CIS_2_4_1_8_ALLOW_FILE}"
    chmod 0604 "${RLCH_CIS_2_4_1_8_DENY_FILE}"

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "$(cat "${RLCH_CIS_2_4_1_8_STATE_DIR}/allow.state")" = present ]
    [ "$(cat "${RLCH_CIS_2_4_1_8_STATE_DIR}/allow.access")" = "65534:65534:664" ]
    [ "$(cat "${RLCH_CIS_2_4_1_8_STATE_DIR}/allow.content")" = admin ]
    [ "$(cat "${RLCH_CIS_2_4_1_8_STATE_DIR}/deny.state")" = present ]
    [ "$(cat "${RLCH_CIS_2_4_1_8_STATE_DIR}/deny.access")" = "1:1:604" ]
    [ "$(cat "${RLCH_CIS_2_4_1_8_STATE_DIR}/deny.content")" = legacy ]
}

@test "apply is idempotent when cron authorization is compliant" {
    create_compliant_allow_file
    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
    [ ! -e "${RLCH_CIS_2_4_1_8_STATE_FILE}" ]
}

@test "rollback restores both original files exactly" {
    printf '%s\n' admin > "${RLCH_CIS_2_4_1_8_ALLOW_FILE}"
    printf '%s\n' legacy > "${RLCH_CIS_2_4_1_8_DENY_FILE}"
    chown 65534:65534 "${RLCH_CIS_2_4_1_8_ALLOW_FILE}"
    chown 1:1 "${RLCH_CIS_2_4_1_8_DENY_FILE}"
    chmod 0664 "${RLCH_CIS_2_4_1_8_ALLOW_FILE}"
    chmod 0604 "${RLCH_CIS_2_4_1_8_DENY_FILE}"
    apply || [ "$?" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]

    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "$(cat "${RLCH_CIS_2_4_1_8_ALLOW_FILE}")" = admin ]
    [ "$(stat -c '%u' "${RLCH_CIS_2_4_1_8_ALLOW_FILE}"):$(stat -c '%g' "${RLCH_CIS_2_4_1_8_ALLOW_FILE}"):$(stat -c '%a' "${RLCH_CIS_2_4_1_8_ALLOW_FILE}")" = "65534:65534:664" ]
    [ "$(cat "${RLCH_CIS_2_4_1_8_DENY_FILE}")" = legacy ]
    [ "$(stat -c '%u' "${RLCH_CIS_2_4_1_8_DENY_FILE}"):$(stat -c '%g' "${RLCH_CIS_2_4_1_8_DENY_FILE}"):$(stat -c '%a' "${RLCH_CIS_2_4_1_8_DENY_FILE}")" = "1:1:604" ]
    [ ! -e "${RLCH_CIS_2_4_1_8_STATE_DIR}" ]
}

@test "rollback removes cron.allow when it was originally absent" {
    : > "${RLCH_CIS_2_4_1_8_DENY_FILE}"
    apply || [ "$?" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]

    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ ! -e "${RLCH_CIS_2_4_1_8_ALLOW_FILE}" ]
    [ -f "${RLCH_CIS_2_4_1_8_DENY_FILE}" ]
}

@test "rollback is idempotent without saved state" {
    run rollback
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "metadata declares CIS 2.4.1.8 as a manual composite mapping" {
    clear_module_metadata_variables
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/2/4/1/8/metadata.conf"
    [ "${RLCH_MODULE_ID}" = "2.4.1.8" ]
    [ "${RLCH_MODULE_LEVEL}" = "1" ]
    [ "${RLCH_MODULE_ENABLED}" = "true" ]
    [ "${RLCH_MODULE_REQUIRES_REBOOT}" = "false" ]
    [ "${RLCH_MODULE_OPENSCAP_RULE}" = "manual" ]
}
