#!/usr/bin/env bats

setup() {
    export RLCH_TEST_REPOSITORY_ROOT="${BATS_TEST_DIRNAME}/.."
    source "${RLCH_TEST_REPOSITORY_ROOT}/tests/test_helper.bash"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/module_api.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/tests/helpers/chrony_config_helper.bash"
    chrony_config_helper_setup
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/2/3/2/module.sh"
}

@test "check succeeds for a server in chrony.conf" {
    printf '%s\n' "server time.example.test iburst" > "${RLCH_CIS_2_3_2_CONFIG}"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check succeeds for a pool with leading whitespace" {
    printf '%s\n' "  pool time.example.test iburst" > "${RLCH_CIS_2_3_2_CONFIG}"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check ignores commented server directives" {
    printf '%s\n' "# server time.example.test iburst" > "${RLCH_CIS_2_3_2_CONFIG}"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check succeeds for a source in sourcedir" {
    local source_directory="${RLCH_CIS_2_3_2_TEST_ROOT}/sources.d"
    mkdir -p "${source_directory}"
    printf 'sourcedir %s\n' "${source_directory}" > "${RLCH_CIS_2_3_2_CONFIG}"
    printf '%s\n' "server source.example.test iburst" > "${source_directory}/remote.sources"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check succeeds for a source in confdir" {
    local config_directory="${RLCH_CIS_2_3_2_TEST_ROOT}/conf.d"
    mkdir -p "${config_directory}"
    printf 'confdir %s\n' "${config_directory}" > "${RLCH_CIS_2_3_2_CONFIG}"
    printf '%s\n' "pool pool.example.test iburst" > "${config_directory}/remote.conf"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check ignores unsupported files in included directories" {
    local source_directory="${RLCH_CIS_2_3_2_TEST_ROOT}/sources.d"
    mkdir -p "${source_directory}"
    printf 'sourcedir %s\n' "${source_directory}" > "${RLCH_CIS_2_3_2_CONFIG}"
    printf '%s\n' "server ignored.example.test iburst" > "${source_directory}/remote.conf"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check reports non-compliance when the configuration is absent" {
    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "apply adds the four RHEL pools and saves existing configuration" {
    local apply_result=0
    printf '%s\n' "driftfile /var/lib/chrony/drift" > "${RLCH_CIS_2_3_2_CONFIG}"

    apply || apply_result=$?

    [ "${apply_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "$(grep -c '^pool [0-3]\.rhel\.pool\.ntp\.org iburst$' "${RLCH_CIS_2_3_2_CONFIG}")" -eq 4 ]
    [ "$(cat "${RLCH_CIS_2_3_2_STATE_FILE}")" = "existing" ]
    grep -Fxq "driftfile /var/lib/chrony/drift" "${RLCH_CIS_2_3_2_BACKUP_FILE}"
}

@test "apply is idempotent when a remote source exists" {
    printf '%s\n' "pool time.example.test iburst" > "${RLCH_CIS_2_3_2_CONFIG}"

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
    [ ! -e "${RLCH_CIS_2_3_2_STATE_FILE}" ]
}

@test "apply requires root when remediation is needed" {
    RLCH_TEST_CHRONY_CONFIG_EFFECTIVE_UID="1000"

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [[ "${output}" == *"requires root privileges"* ]]
}

@test "apply errors when effective uid cannot be determined" {
    RLCH_TEST_CHRONY_CONFIG_ID_FAIL="true"

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [[ "${output}" == *"Unable to determine effective user ID"* ]]
}

@test "validate delegates to check" {
    run validate
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]

    printf '%s\n' "server time.example.test iburst" > "${RLCH_CIS_2_3_2_CONFIG}"
    run validate
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "rollback restores an existing configuration" {
    local apply_result=0
    printf '%s\n' "driftfile /original/drift" > "${RLCH_CIS_2_3_2_CONFIG}"
    apply || apply_result=$?
    [ "${apply_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]

    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "$(cat "${RLCH_CIS_2_3_2_CONFIG}")" = "driftfile /original/drift" ]
    [ ! -e "${RLCH_CIS_2_3_2_STATE_DIR}" ]
}

@test "rollback removes a configuration created by apply" {
    local apply_result=0
    apply || apply_result=$?
    [ "${apply_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "$(cat "${RLCH_CIS_2_3_2_STATE_FILE}")" = "absent" ]

    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ ! -e "${RLCH_CIS_2_3_2_CONFIG}" ]
    [ ! -e "${RLCH_CIS_2_3_2_STATE_DIR}" ]
}

@test "rollback is idempotent without state" {
    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "rollback rejects invalid state" {
    mkdir -p "${RLCH_CIS_2_3_2_STATE_DIR}"
    printf '%s\n' "invalid" > "${RLCH_CIS_2_3_2_STATE_FILE}"

    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [ -e "${RLCH_CIS_2_3_2_STATE_FILE}" ]
}

@test "metadata declares CIS 2.3.2" {
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/2/3/2/metadata.conf"

    [ "${RLCH_MODULE_ID}" = "2.3.2" ]
    [ "${RLCH_MODULE_LEVEL}" = "1" ]
    [ "${RLCH_MODULE_ENABLED}" = "true" ]
    [ "${RLCH_MODULE_REQUIRES_REBOOT}" = "false" ]
    [ "${RLCH_MODULE_OPENSCAP_RULE}" = "xccdf_org.ssgproject.content_rule_chronyd_specify_remote_server" ]
}
