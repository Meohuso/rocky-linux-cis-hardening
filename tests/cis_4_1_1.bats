#!/usr/bin/env bats

# shellcheck disable=SC2030,SC2031 # Bats setup exports fixture state per test.

setup() {
    export RLCH_TEST_REPOSITORY_ROOT="${BATS_TEST_DIRNAME}/.."
    source "${RLCH_TEST_REPOSITORY_ROOT}/tests/test_helper.bash"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/module_api.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/tests/helpers/nftables_package_helper.bash"
    nftables_package_helper_setup
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/4/1/1/module.sh"
}

@test "check succeeds when nftables is installed" {
    RLCH_TEST_NFTABLES_INSTALLED="true"
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check reports non-compliance when nftables is absent" {
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "apply installs nftables and records isolated rollback state" {
    local result=0
    apply || result=$?
    [ "${result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "${RLCH_TEST_NFTABLES_INSTALLED}" = "true" ]
    [ "$(cat "${RLCH_CIS_4_1_1_STATE_FILE}")" = "nftables" ]
}

@test "apply is idempotent when nftables is installed" {
    RLCH_TEST_NFTABLES_INSTALLED="true"
    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
    [ ! -e "${RLCH_CIS_4_1_1_STATE_FILE}" ]
}

@test "apply requires root only when remediation is needed" {
    RLCH_TEST_NFTABLES_EFFECTIVE_UID="1000"
    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [ ! -e "${RLCH_CIS_4_1_1_STATE_FILE}" ]
}

@test "apply reports an effective uid lookup failure" {
    RLCH_TEST_NFTABLES_ID_FAIL="true"
    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
}

@test "apply retains rollback state when package installation fails" {
    RLCH_TEST_NFTABLES_INSTALL_FAIL="true"
    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [ -e "${RLCH_CIS_4_1_1_STATE_FILE}" ]
}

@test "apply verifies nftables is installed" {
    RLCH_TEST_NFTABLES_KEEP_ABSENT="true"
    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [ -e "${RLCH_CIS_4_1_1_STATE_FILE}" ]
}

@test "validate delegates to check" {
    run validate
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "rollback removes nftables only when this control installed it" {
    local result=0
    RLCH_TEST_NFTABLES_INSTALLED="true"
    mkdir -p "${RLCH_CIS_4_1_1_STATE_DIR}"
    printf '%s\n' nftables > "${RLCH_CIS_4_1_1_STATE_FILE}"
    rollback || result=$?
    [ "${result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "${RLCH_TEST_NFTABLES_INSTALLED}" = "false" ]
    [ ! -e "${RLCH_CIS_4_1_1_STATE_FILE}" ]
}

@test "rollback is idempotent without state and preserves a pre-existing package" {
    RLCH_TEST_NFTABLES_INSTALLED="true"
    run rollback
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
    [ "${RLCH_TEST_NFTABLES_INSTALLED}" = "true" ]
}

@test "rollback rejects invalid state" {
    mkdir -p "${RLCH_CIS_4_1_1_STATE_DIR}"
    printf '%s\n' firewalld > "${RLCH_CIS_4_1_1_STATE_FILE}"
    run rollback
    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [ -e "${RLCH_CIS_4_1_1_STATE_FILE}" ]
}

@test "rollback retains state when package removal fails" {
    RLCH_TEST_NFTABLES_INSTALLED="true"
    RLCH_TEST_NFTABLES_REMOVE_FAIL="true"
    mkdir -p "${RLCH_CIS_4_1_1_STATE_DIR}"
    printf '%s\n' nftables > "${RLCH_CIS_4_1_1_STATE_FILE}"
    run rollback
    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [ -e "${RLCH_CIS_4_1_1_STATE_FILE}" ]
}

@test "rollback verifies nftables was removed" {
    RLCH_TEST_NFTABLES_INSTALLED="true"
    RLCH_TEST_NFTABLES_KEEP_INSTALLED="true"
    mkdir -p "${RLCH_CIS_4_1_1_STATE_DIR}"
    printf '%s\n' nftables > "${RLCH_CIS_4_1_1_STATE_FILE}"
    run rollback
    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [ -e "${RLCH_CIS_4_1_1_STATE_FILE}" ]
}

@test "metadata declares the exact ComplianceAsCode rule" {
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/4/1/1/metadata.conf"
    [ "${RLCH_MODULE_ID}" = "4.1.1" ]
    [ "${RLCH_MODULE_LEVEL}" = "1" ]
    [ "${RLCH_MODULE_OPENSCAP_RULE}" = "xccdf_org.ssgproject.content_rule_package_nftables_installed" ]
}
