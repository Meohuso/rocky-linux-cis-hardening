#!/usr/bin/env bats
#
# Rocky Linux CIS Hardening Framework
#
# Execution engine tests.
#
# SPDX-License-Identifier: MIT
#

setup() {
    # shellcheck source=tests/test_helper.bash
    source "${BATS_TEST_DIRNAME}/test_helper.bash"

    # shellcheck source=lib/common.sh
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/common.sh"

    # shellcheck source=lib/modules.sh
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/modules.sh"

    # shellcheck source=lib/module_api.sh
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/module_api.sh"

    # shellcheck source=lib/execution.sh
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/execution.sh"

    RLCH_TEST_TEMPORARY_DIRECTORY="$(
        mktemp -d "${BATS_TEST_TMPDIR}/rlch-execution.XXXXXX"
    )"

    RLCH_MODULE_ROOT="${RLCH_TEST_TEMPORARY_DIRECTORY}/modules"
    RLCH_MODULE_NAMESPACE="cis"
    RLCH_MODULE_DEFAULT_FILTER="*"
    RLCH_MODULE_METADATA_FILENAME="metadata.conf"
    RLCH_MODULE_IMPLEMENTATION_FILENAME="module.sh"
    RLCH_MODULE_DISCOVERY_ENABLED="true"

    mkdir -p "${RLCH_MODULE_ROOT}/${RLCH_MODULE_NAMESPACE}"
}

teardown() {
    reset_execution_context
    reset_module_context
    clear_module_metadata_variables

    if [[ -n "${RLCH_TEST_TEMPORARY_DIRECTORY:-}" ]]; then
        rm -rf "${RLCH_TEST_TEMPORARY_DIRECTORY}"
    fi
}

create_execution_test_module() {
    local module_identifier="${1:?Module identifier is required.}"
    local enabled="${2:-true}"
    local check_result="${3:-${RLCH_MODULE_RESULT_SUCCESS}}"
    local apply_result="${4:-${RLCH_MODULE_RESULT_CHANGED}}"
    local validate_result="${5:-${RLCH_MODULE_RESULT_SUCCESS}}"
    local rollback_result="${6:-${RLCH_MODULE_RESULT_CHANGED}}"
    local module_directory

    module_directory="${RLCH_MODULE_ROOT}/${RLCH_MODULE_NAMESPACE}/${module_identifier//./\/}"

    mkdir -p "${module_directory}"

    cat >"${module_directory}/metadata.conf" <<EOF
RLCH_MODULE_ID="${module_identifier}"
RLCH_MODULE_TITLE="Execution test module ${module_identifier}"
RLCH_MODULE_DESCRIPTION="Execution engine test module."
RLCH_MODULE_RATIONALE="Validate execution engine behavior."
RLCH_MODULE_LEVEL="1"
RLCH_MODULE_ENABLED="${enabled}"
RLCH_MODULE_REQUIRES_REBOOT="false"
RLCH_MODULE_OPENSCAP_RULE="xccdf_test_rule_${module_identifier//./_}"
EOF

    cat >"${module_directory}/module.sh" <<EOF
#!/usr/bin/env bash

check() {
    return "${check_result}"
}

apply() {
    return "${apply_result}"
}

validate() {
    return "${validate_result}"
}

rollback() {
    return "${rollback_result}"
}
EOF

    chmod 0755 "${module_directory}/module.sh"

    printf '%s\n' "${module_directory}"
}

@test "is_valid_module_action accepts check" {
    run is_valid_module_action "check"

    [ "${status}" -eq 0 ]
}

@test "is_valid_module_action accepts apply" {
    run is_valid_module_action "apply"

    [ "${status}" -eq 0 ]
}

@test "is_valid_module_action accepts validate" {
    run is_valid_module_action "validate"

    [ "${status}" -eq 0 ]
}

@test "is_valid_module_action accepts rollback" {
    run is_valid_module_action "rollback"

    [ "${status}" -eq 0 ]
}

@test "is_valid_module_action rejects an unsupported action" {
    run is_valid_module_action "invalid"

    [ "${status}" -eq 1 ]
}

@test "module_action_requires_enabled_module accepts apply" {
    run module_action_requires_enabled_module "apply"

    [ "${status}" -eq 0 ]
}

@test "module_action_requires_enabled_module accepts rollback" {
    run module_action_requires_enabled_module "rollback"

    [ "${status}" -eq 0 ]
}

@test "module_action_requires_enabled_module rejects check" {
    run module_action_requires_enabled_module "check"

    [ "${status}" -eq 1 ]
}

@test "module_action_requires_enabled_module rejects validate" {
    run module_action_requires_enabled_module "validate"

    [ "${status}" -eq 1 ]
}

@test "execute_current_module_action fails without a loaded module" {
    run execute_current_module_action "check"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [[ "${output}" == *"No module is currently loaded"* ]]
}

@test "execute_current_module_action rejects an unsupported action" {
    local module_directory

    module_directory="$(create_execution_test_module "1.1.1")"
    load_module "${module_directory}"

    run execute_current_module_action "invalid"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [[ "${output}" == *"Unsupported module action"* ]]
}

@test "execute_module_action rejects an empty module directory" {
    run execute_module_action "" "check"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [[ "${output}" == *"Module directory must not be empty"* ]]
}

@test "execute_module_action rejects an unsupported action" {
    local module_directory

    module_directory="$(create_execution_test_module "1.1.1")"

    run execute_module_action "${module_directory}" "invalid"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [[ "${output}" == *"Unsupported module action"* ]]
}

@test "check_module returns compliant result" {
    local module_directory

    module_directory="$(
        create_execution_test_module \
            "1.1.1" \
            "true" \
            "${RLCH_MODULE_RESULT_SUCCESS}"
    )"

    run check_module "${module_directory}"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check_module returns non-compliant result" {
    local module_directory

    module_directory="$(
        create_execution_test_module \
            "1.1.1" \
            "true" \
            "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    )"

    run check_module "${module_directory}"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "apply_module returns changed result" {
    local module_directory

    module_directory="$(
        create_execution_test_module \
            "1.1.1" \
            "true" \
            "${RLCH_MODULE_RESULT_SUCCESS}" \
            "${RLCH_MODULE_RESULT_CHANGED}"
    )"

    run apply_module "${module_directory}"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
}

@test "validate_module returns compliant result" {
    local module_directory

    module_directory="$(
        create_execution_test_module \
            "1.1.1" \
            "true" \
            "${RLCH_MODULE_RESULT_SUCCESS}" \
            "${RLCH_MODULE_RESULT_CHANGED}" \
            "${RLCH_MODULE_RESULT_SUCCESS}"
    )"

    run validate_module "${module_directory}"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "rollback_module returns changed result" {
    local module_directory

    module_directory="$(
        create_execution_test_module \
            "1.1.1" \
            "true" \
            "${RLCH_MODULE_RESULT_SUCCESS}" \
            "${RLCH_MODULE_RESULT_CHANGED}" \
            "${RLCH_MODULE_RESULT_SUCCESS}" \
            "${RLCH_MODULE_RESULT_CHANGED}"
    )"

    run rollback_module "${module_directory}"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
}

@test "apply_module skips a disabled module" {
    local module_directory

    module_directory="$(
        create_execution_test_module \
            "1.1.1" \
            "false"
    )"

    run apply_module "${module_directory}"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NOT_APPLICABLE}" ]
    [[ "${output}" == *"Skipping apply for disabled module 1.1.1"* ]]
}

@test "rollback_module skips a disabled module" {
    local module_directory

    module_directory="$(
        create_execution_test_module \
            "1.1.1" \
            "false"
    )"

    run rollback_module "${module_directory}"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NOT_APPLICABLE}" ]
    [[ "${output}" == *"Skipping rollback for disabled module 1.1.1"* ]]
}

@test "check_module executes for a disabled module" {
    local module_directory

    module_directory="$(
        create_execution_test_module \
            "1.1.1" \
            "false" \
            "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    )"

    run check_module "${module_directory}"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "validate_module executes for a disabled module" {
    local module_directory

    module_directory="$(
        create_execution_test_module \
            "1.1.1" \
            "false" \
            "${RLCH_MODULE_RESULT_SUCCESS}" \
            "${RLCH_MODULE_RESULT_CHANGED}" \
            "${RLCH_MODULE_RESULT_SUCCESS}"
    )"

    run validate_module "${module_directory}"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "execute_module_action converts an unsupported result to error" {
    local module_directory

    module_directory="$(
        create_execution_test_module \
            "1.1.1" \
            "true" \
            "99"
    )"

    run check_module "${module_directory}"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [[ "${output}" == *"returned unsupported result code 99"* ]]
}

@test "store_execution_result stores a compliant result" {
    store_execution_result \
        "1.1.1" \
        "check" \
        "${RLCH_MODULE_RESULT_SUCCESS}"

    [ "${RLCH_EXECUTION_MODULE_ID}" = "1.1.1" ]
    [ "${RLCH_EXECUTION_ACTION}" = "check" ]
    [ "${RLCH_EXECUTION_RESULT}" = "${RLCH_MODULE_RESULT_SUCCESS}" ]
    [ "${RLCH_EXECUTION_STATUS}" = "${RLCH_MODULE_STATUS_COMPLIANT}" ]
}

@test "store_execution_result stores a changed result" {
    store_execution_result \
        "1.1.1" \
        "apply" \
        "${RLCH_MODULE_RESULT_CHANGED}"

    [ "${RLCH_EXECUTION_MODULE_ID}" = "1.1.1" ]
    [ "${RLCH_EXECUTION_ACTION}" = "apply" ]
    [ "${RLCH_EXECUTION_RESULT}" = "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "${RLCH_EXECUTION_STATUS}" = "${RLCH_MODULE_STATUS_CHANGED}" ]
}

@test "store_execution_result rejects an empty identifier" {
    run store_execution_result \
        "" \
        "check" \
        "${RLCH_MODULE_RESULT_SUCCESS}"

    [ "${status}" -eq 1 ]
    [[ "${output}" == *"Execution module identifier must not be empty"* ]]
}

@test "store_execution_result rejects an invalid action" {
    run store_execution_result \
        "1.1.1" \
        "invalid" \
        "${RLCH_MODULE_RESULT_SUCCESS}"

    [ "${status}" -eq 1 ]
    [[ "${output}" == *"Unsupported module action"* ]]
}

@test "store_execution_result rejects an invalid result" {
    run store_execution_result \
        "1.1.1" \
        "check" \
        "99"

    [ "${status}" -eq 1 ]
    [[ "${output}" == *"returned unsupported result code"* ]]
}

@test "reset_execution_context clears the latest result" {
    RLCH_EXECUTION_MODULE_ID="1.1.1"
    RLCH_EXECUTION_ACTION="check"
    RLCH_EXECUTION_RESULT="${RLCH_MODULE_RESULT_SUCCESS}"
    RLCH_EXECUTION_STATUS="${RLCH_MODULE_STATUS_COMPLIANT}"

    reset_execution_context

    [ -z "${RLCH_EXECUTION_MODULE_ID}" ]
    [ -z "${RLCH_EXECUTION_ACTION}" ]
    [ -z "${RLCH_EXECUTION_RESULT}" ]
    [ -z "${RLCH_EXECUTION_STATUS}" ]
}