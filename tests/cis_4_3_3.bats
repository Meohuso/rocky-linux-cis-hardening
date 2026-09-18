#!/usr/bin/env bats

# shellcheck disable=SC2030,SC2031 # Bats setup exports fixture state per test.

setup() {
    export RLCH_TEST_REPOSITORY_ROOT="${BATS_TEST_DIRNAME}/.."
    source "${RLCH_TEST_REPOSITORY_ROOT}/tests/test_helper.bash"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/module_api.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/tests/helpers/firewalld_default_deny_helper.bash"
    firewalld_default_deny_helper_setup
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/4/3/3/module.sh"
}

@test "check accepts default-deny public and loopback-only trusted zones" {
    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check accepts explicit DROP and REJECT zone targets" {
    RLCH_TEST_DEFAULT_DENY_PUBLIC_TARGET="DROP"
    RLCH_TEST_DEFAULT_DENY_TRUSTED_TARGET="REJECT"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check accepts firewalld encoded reject target" {
    RLCH_TEST_DEFAULT_DENY_PUBLIC_TARGET="%%REJECT%%"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check reports an ACCEPT target on an exposed zone" {
    RLCH_TEST_DEFAULT_DENY_PUBLIC_TARGET="ACCEPT"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check rejects trusted zone access from a non-loopback interface" {
    RLCH_TEST_DEFAULT_DENY_TRUSTED_INTERFACES="lo eth1"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check rejects trusted zone access from a source binding" {
    RLCH_TEST_DEFAULT_DENY_TRUSTED_SOURCES="10.0.0.0/8"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check does not exempt trusted when it is the default zone" {
    RLCH_TEST_DEFAULT_DENY_DEFAULT_ZONE="trusted"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check reports non-compliance when firewalld is inactive" {
    RLCH_TEST_DEFAULT_DENY_FIREWALLD_ACTIVE="false"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check validates the default zone even without active bindings" {
    RLCH_TEST_DEFAULT_DENY_ACTIVE_ZONES=""

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
    grep -F -- 'firewall-cmd --zone=public --get-target' "${RLCH_TEST_DEFAULT_DENY_LOG}"
}

@test "check ignores indented active-zone detail lines" {
    RLCH_TEST_DEFAULT_DENY_ACTIVE_ZONES=$'public\n  interfaces: eth0\n  sources: 192.0.2.0/24'

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
    [ "$(grep -c -- '--get-target' "${RLCH_TEST_DEFAULT_DENY_LOG}")" -eq 1 ]
}

@test "check reports malformed default-zone output as an error" {
    RLCH_TEST_DEFAULT_DENY_DEFAULT_ZONE="public zone"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
}

@test "check reports firewall-cmd errors" {
    RLCH_TEST_DEFAULT_DENY_FAIL="--get-active-zones"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [[ "${output}" == *"Unable to determine active firewalld zones"* ]]
}

@test "apply is idempotent for compliant firewalld policy" {
    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
    ! grep -E -- ' --(set-|add-|remove-|reload|complete-reload)' "${RLCH_TEST_DEFAULT_DENY_LOG}"
}

@test "apply refuses automatic target changes that could cut access" {
    RLCH_TEST_DEFAULT_DENY_PUBLIC_TARGET="ACCEPT"

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [[ "${output}" == *"role-aware firewalld policy review"* ]]
    ! grep -E -- ' --(set-|add-|remove-|reload|complete-reload)' "${RLCH_TEST_DEFAULT_DENY_LOG}"
}

@test "validate delegates to check" {
    RLCH_TEST_DEFAULT_DENY_PUBLIC_TARGET="ACCEPT"

    run validate

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "rollback makes no firewalld or nftables change" {
    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
    [[ "${output}" == *"read-only firewalld policy check"* ]]
    [ ! -e "${RLCH_TEST_DEFAULT_DENY_LOG}" ]
}

@test "metadata records the incompatible related rule as manual" {
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/4/3/3/metadata.conf"

    [ "${RLCH_MODULE_ID}" = "4.3.3" ]
    [ "${RLCH_MODULE_LEVEL}" = "1" ]
    [ "${RLCH_MODULE_ENABLED}" = "true" ]
    [ "${RLCH_MODULE_OPENSCAP_RULE}" = "manual" ]
}
