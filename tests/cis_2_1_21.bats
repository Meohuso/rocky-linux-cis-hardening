#!/usr/bin/env bats

# Each Bats test runs in its own subshell; exported fixture variables are
# intentionally reset by setup for every test.
# shellcheck disable=SC2030,SC2031

setup() {
    export RLCH_TEST_REPOSITORY_ROOT="${BATS_TEST_DIRNAME}/.."
    source "${RLCH_TEST_REPOSITORY_ROOT}/tests/test_helper.bash"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/module_api.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/tests/helpers/mta_local_only_helper.bash"
    mta_local_only_helper_setup
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/2/1/21/module.sh"
}

write_postfix_config() {
    export RLCH_TEST_MTA_POSTFIX_INSTALLED="true"
    printf '%s\n' "${1}" > "${RLCH_CIS_2_1_21_POSTFIX_CONFIG}"
}

@test "check succeeds without Postfix or MTA listeners" {
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check accepts loopback listeners on all MTA ports" {
    RLCH_TEST_MTA_LISTENERS=$'LISTEN 0 100 127.0.0.1:25 0.0.0.0:*\nLISTEN 0 100 [::1]:465 [::]:*\nLISTEN 0 100 127.0.0.1:587 0.0.0.0:*\n'
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check rejects non-loopback listeners on ports 25 465 and 587" {
    local port
    for port in 25 465 587; do
        RLCH_TEST_MTA_LISTENERS="LISTEN 0 100 0.0.0.0:${port} 0.0.0.0:*"
        run check
        [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
    done
}

@test "check ignores unrelated listening ports" {
    RLCH_TEST_MTA_LISTENERS="LISTEN 0 100 0.0.0.0:22 0.0.0.0:*"
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check reports socket inspection errors" {
    RLCH_TEST_MTA_SS_FAIL="true"
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [[ "${output}" == *"Unable to inspect listening TCP sockets"* ]]
}

@test "check accepts exactly one active loopback-only Postfix setting" {
    write_postfix_config "inet_interfaces = loopback-only"
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check rejects missing incorrect or duplicate Postfix settings" {
    export RLCH_TEST_MTA_POSTFIX_INSTALLED="true"
    : > "${RLCH_CIS_2_1_21_POSTFIX_CONFIG}"
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]

    printf '%s\n' "inet_interfaces = all" > "${RLCH_CIS_2_1_21_POSTFIX_CONFIG}"
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]

    printf '%s\n' "inet_interfaces = loopback-only" "inet_interfaces = loopback-only" > "${RLCH_CIS_2_1_21_POSTFIX_CONFIG}"
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "apply configures Postfix and preserves unrelated content" {
    local apply_result=0
    write_postfix_config $'myhostname = host.example\ninet_interfaces = all\n# inet_interfaces = localhost'

    apply || apply_result=$?

    [ "${apply_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    grep -Fxq "myhostname = host.example" "${RLCH_CIS_2_1_21_POSTFIX_CONFIG}"
    grep -Fxq "inet_interfaces = loopback-only" "${RLCH_CIS_2_1_21_POSTFIX_CONFIG}"
    grep -Fxq "# inet_interfaces = localhost" "${RLCH_CIS_2_1_21_POSTFIX_CONFIG}"
    [ -f "${RLCH_CIS_2_1_21_BACKUP_FILE}" ]
}

@test "apply restarts active Postfix and clears its external listener" {
    local apply_result=0
    write_postfix_config "inet_interfaces = all"
    RLCH_TEST_MTA_POSTFIX_ACTIVE="true"
    RLCH_TEST_MTA_LISTENERS="LISTEN 0 100 0.0.0.0:25 0.0.0.0:*"

    apply || apply_result=$?

    [ "${apply_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "${RLCH_TEST_MTA_RESTART_COUNT}" -eq 1 ]
}

@test "apply is idempotent when Postfix is already compliant" {
    write_postfix_config "inet_interfaces = loopback-only"
    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
    [ ! -e "${RLCH_CIS_2_1_21_STATE_FILE}" ]
}

@test "apply requires root when remediation is needed" {
    write_postfix_config "inet_interfaces = all"
    RLCH_TEST_MTA_EFFECTIVE_UID="1000"
    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [[ "${output}" == *"requires root privileges"* ]]
}

@test "apply reports an unknown non-Postfix MTA listener" {
    RLCH_TEST_MTA_LISTENERS="LISTEN 0 100 0.0.0.0:25 0.0.0.0:*"
    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [[ "${output}" == *"manual remediation is required"* ]]
}

@test "apply keeps rollback state when Postfix restart fails" {
    write_postfix_config "inet_interfaces = all"
    RLCH_TEST_MTA_POSTFIX_ACTIVE="true"
    RLCH_TEST_MTA_RESTART_FAIL="true"
    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [ -e "${RLCH_CIS_2_1_21_STATE_FILE}" ]
}

@test "validate delegates to check" {
    write_postfix_config "inet_interfaces = loopback-only"
    run validate
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "rollback restores the original configuration and active service" {
    local apply_result=0
    local rollback_result=0
    write_postfix_config "inet_interfaces = all"
    RLCH_TEST_MTA_POSTFIX_ACTIVE="true"
    apply || apply_result=$?
    [ "${apply_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]

    rollback || rollback_result=$?

    [ "${rollback_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "$(cat "${RLCH_CIS_2_1_21_POSTFIX_CONFIG}")" = "inet_interfaces = all" ]
    [ "${RLCH_TEST_MTA_RESTART_COUNT}" -eq 2 ]
    [ ! -e "${RLCH_CIS_2_1_21_STATE_FILE}" ]
}

@test "rollback removes a configuration created by apply" {
    local rollback_result=0
    export RLCH_TEST_MTA_POSTFIX_INSTALLED="true"
    mkdir -p "${RLCH_CIS_2_1_21_STATE_DIR}"
    printf '%s\n' "file_existed=false" "service_active=false" > "${RLCH_CIS_2_1_21_STATE_FILE}"
    printf '%s\n' "inet_interfaces = loopback-only" > "${RLCH_CIS_2_1_21_POSTFIX_CONFIG}"

    rollback || rollback_result=$?

    [ "${rollback_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ ! -e "${RLCH_CIS_2_1_21_POSTFIX_CONFIG}" ]
}

@test "rollback is idempotent without state" {
    run rollback
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "rollback rejects missing backups and invalid state" {
    mkdir -p "${RLCH_CIS_2_1_21_STATE_DIR}"
    printf '%s\n' "file_existed=true" "service_active=false" > "${RLCH_CIS_2_1_21_STATE_FILE}"
    run rollback
    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]

    printf '%s\n' "file_existed=invalid" "service_active=false" > "${RLCH_CIS_2_1_21_STATE_FILE}"
    run rollback
    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
}

@test "metadata declares CIS 2.1.21 with manual multi-rule mapping" {
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/2/1/21/metadata.conf"
    [ "${RLCH_MODULE_ID}" = "2.1.21" ]
    [ "${RLCH_MODULE_LEVEL}" = "1" ]
    [ "${RLCH_MODULE_ENABLED}" = "true" ]
    [ "${RLCH_MODULE_REQUIRES_REBOOT}" = "false" ]
    [ "${RLCH_MODULE_OPENSCAP_RULE}" = "manual" ]
}
