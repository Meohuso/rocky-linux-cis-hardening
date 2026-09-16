#!/usr/bin/env bats

setup() {
    export RLCH_TEST_REPOSITORY_ROOT="${BATS_TEST_DIRNAME}/.."
    source "${RLCH_TEST_REPOSITORY_ROOT}/tests/test_helper.bash"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/module_api.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/tests/helpers/chrony_user_helper.bash"
    chrony_user_helper_setup
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/2/3/3/module.sh"
}

@test "check succeeds when the sysconfig file is absent" {
    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check succeeds when OPTIONS is absent" {
    printf '%s\n' "# chronyd service options" > "${RLCH_CIS_2_3_3_CONFIG}"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check succeeds for empty OPTIONS" {
    printf '%s\n' 'OPTIONS=""' > "${RLCH_CIS_2_3_3_CONFIG}"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check succeeds without a user override" {
    printf '%s\n' 'OPTIONS="-F 2"' > "${RLCH_CIS_2_3_3_CONFIG}"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check succeeds for the chrony user" {
    printf '%s\n' 'OPTIONS="-u chrony"' > "${RLCH_CIS_2_3_3_CONFIG}"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check succeeds for a compact chrony user option" {
    printf '%s\n' 'OPTIONS="-g -uchrony"' > "${RLCH_CIS_2_3_3_CONFIG}"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check ignores commented overrides" {
    printf '%s\n' '# OPTIONS="-u root"' 'OPTIONS="-F 2" # -u root' > "${RLCH_CIS_2_3_3_CONFIG}"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check reports a separated root override" {
    printf '%s\n' 'OPTIONS="-u root:root"' > "${RLCH_CIS_2_3_3_CONFIG}"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check reports a compact root override" {
    printf '%s\n' 'OPTIONS="-g -uroot"' > "${RLCH_CIS_2_3_3_CONFIG}"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check reports any invalid active OPTIONS assignment" {
    printf '%s\n' 'OPTIONS="-u chrony"' ' OPTIONS="-u daemon"' > "${RLCH_CIS_2_3_3_CONFIG}"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "apply removes user overrides and preserves other options" {
    local apply_result=0
    printf '%s\n' 'OPTIONS="-g -u root -F 2" # retained comment' > "${RLCH_CIS_2_3_3_CONFIG}"

    apply || apply_result=$?

    [ "${apply_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    grep -Fq -- '-g' "${RLCH_CIS_2_3_3_CONFIG}"
    grep -Fq -- '-F 2' "${RLCH_CIS_2_3_3_CONFIG}"
    grep -Fq -- '# retained comment' "${RLCH_CIS_2_3_3_CONFIG}"
    ! grep -Fq -- '-u root' "${RLCH_CIS_2_3_3_CONFIG}"
    [ "$(cat "${RLCH_CIS_2_3_3_STATE_FILE}")" = "existing" ]
    grep -Fq -- '-u root' "${RLCH_CIS_2_3_3_BACKUP_FILE}"
}

@test "apply removes compact user overrides" {
    local apply_result=0
    printf '%s\n' "OPTIONS='-g -uroot'" > "${RLCH_CIS_2_3_3_CONFIG}"

    apply || apply_result=$?

    [ "${apply_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    grep -Fq -- '-g' "${RLCH_CIS_2_3_3_CONFIG}"
    ! grep -Fq -- '-uroot' "${RLCH_CIS_2_3_3_CONFIG}"
}

@test "apply is idempotent when no invalid override exists" {
    printf '%s\n' 'OPTIONS="-F 2"' > "${RLCH_CIS_2_3_3_CONFIG}"

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
    [ ! -e "${RLCH_CIS_2_3_3_STATE_FILE}" ]
}

@test "apply requires root when remediation is needed" {
    printf '%s\n' 'OPTIONS="-u root"' > "${RLCH_CIS_2_3_3_CONFIG}"
    RLCH_TEST_CHRONY_USER_EFFECTIVE_UID="1000"

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [[ "${output}" == *"requires root privileges"* ]]
}

@test "apply errors when effective uid cannot be determined" {
    printf '%s\n' 'OPTIONS="-u root"' > "${RLCH_CIS_2_3_3_CONFIG}"
    RLCH_TEST_CHRONY_USER_ID_FAIL="true"

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [[ "${output}" == *"Unable to determine effective user ID"* ]]
}

@test "validate delegates to check" {
    printf '%s\n' 'OPTIONS="-u root"' > "${RLCH_CIS_2_3_3_CONFIG}"
    run validate
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]

    printf '%s\n' 'OPTIONS="-u chrony"' > "${RLCH_CIS_2_3_3_CONFIG}"
    run validate
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "rollback restores the original sysconfig" {
    local apply_result=0
    printf '%s\n' 'OPTIONS="-u root -F 2"' > "${RLCH_CIS_2_3_3_CONFIG}"
    apply || apply_result=$?
    [ "${apply_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]

    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "$(cat "${RLCH_CIS_2_3_3_CONFIG}")" = 'OPTIONS="-u root -F 2"' ]
    [ ! -e "${RLCH_CIS_2_3_3_STATE_DIR}" ]
}

@test "rollback is idempotent without state" {
    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "rollback rejects invalid state" {
    mkdir -p "${RLCH_CIS_2_3_3_STATE_DIR}"
    printf '%s\n' "invalid" > "${RLCH_CIS_2_3_3_STATE_FILE}"

    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [ -e "${RLCH_CIS_2_3_3_STATE_FILE}" ]
}

@test "metadata declares CIS 2.3.3" {
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/2/3/3/metadata.conf"

    [ "${RLCH_MODULE_ID}" = "2.3.3" ]
    [ "${RLCH_MODULE_LEVEL}" = "1" ]
    [ "${RLCH_MODULE_ENABLED}" = "true" ]
    [ "${RLCH_MODULE_REQUIRES_REBOOT}" = "false" ]
    [ "${RLCH_MODULE_OPENSCAP_RULE}" = "xccdf_org.ssgproject.content_rule_chronyd_run_as_chrony_user" ]
}
