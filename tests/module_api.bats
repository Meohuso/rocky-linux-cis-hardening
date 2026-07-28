#!/usr/bin/env bats
#
# Rocky Linux CIS Hardening Framework
#
# Module API tests
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

    RLCH_TEST_TEMPORARY_DIRECTORY="$(
        mktemp -d "${BATS_TEST_TMPDIR}/rlch-module-api.XXXXXX"
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
    reset_module_context
    clear_module_metadata_variables

    if [[ -n "${RLCH_TEST_TEMPORARY_DIRECTORY:-}" ]]; then
        rm -rf "${RLCH_TEST_TEMPORARY_DIRECTORY}"
    fi
}

create_api_test_module() {
    local module_identifier="${1:?Module identifier is required.}"
    local enabled="${2:-true}"
    local requires_reboot="${3:-false}"
    local module_directory

    module_directory="${
        RLCH_MODULE_ROOT
    }/${RLCH_MODULE_NAMESPACE}/${module_identifier//./\/}"

    mkdir -p "${module_directory}"

    cat >"${module_directory}/metadata.conf" <<EOF
RLCH_MODULE_ID="${module_identifier}"
RLCH_MODULE_TITLE="Test module ${module_identifier}"
RLCH_MODULE_DESCRIPTION="Test description."
RLCH_MODULE_RATIONALE="Test rationale."
RLCH_MODULE_LEVEL="1"
RLCH_MODULE_ENABLED="${enabled}"
RLCH_MODULE_REQUIRES_REBOOT="${requires_reboot}"
RLCH_MODULE_OPENSCAP_RULE="xccdf_test_rule_${module_identifier//./_}"
EOF

    cat >"${module_directory}/module.sh" <<'EOF'
#!/usr/bin/env bash

check() {
    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

apply() {
    return "${RLCH_MODULE_RESULT_CHANGED}"
}

validate() {
    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

rollback() {
    return "${RLCH_MODULE_RESULT_CHANGED}"
}
EOF

    chmod 0755 "${module_directory}/module.sh"

    printf '%s\n' "${module_directory}"
}

@test "is_valid_module_identifier accepts a numeric dotted identifier" {
    run is_valid_module_identifier "1.1.1"

    [ "${status}" -eq 0 ]
}

@test "is_valid_module_identifier rejects an incomplete identifier" {
    run is_valid_module_identifier "1"

    [ "${status}" -eq 1 ]
}

@test "is_valid_module_identifier rejects a wildcard identifier" {
    run is_valid_module_identifier "1.1.*"

    [ "${status}" -eq 1 ]
}

@test "is_valid_module_level accepts level 1" {
    run is_valid_module_level "1"

    [ "${status}" -eq 0 ]
}

@test "is_valid_module_level accepts level 2" {
    run is_valid_module_level "2"

    [ "${status}" -eq 0 ]
}

@test "is_valid_module_level rejects an unsupported level" {
    run is_valid_module_level "3"

    [ "${status}" -eq 1 ]
}

@test "is_valid_module_result accepts every supported result" {
    is_valid_module_result "${RLCH_MODULE_RESULT_SUCCESS}"
    is_valid_module_result "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    is_valid_module_result "${RLCH_MODULE_RESULT_ERROR}"
    is_valid_module_result "${RLCH_MODULE_RESULT_NOT_APPLICABLE}"
    is_valid_module_result "${RLCH_MODULE_RESULT_CHANGED}"
}

@test "is_valid_module_result rejects an unsupported result" {
    run is_valid_module_result "99"

    [ "${status}" -eq 1 ]
}

@test "module_status_from_result converts success to compliant" {
    run module_status_from_result "${RLCH_MODULE_RESULT_SUCCESS}"

    [ "${status}" -eq 0 ]
    [ "${output}" = "${RLCH_MODULE_STATUS_COMPLIANT}" ]
}

@test "module_status_from_result converts non-compliant result" {
    run module_status_from_result "${RLCH_MODULE_RESULT_NON_COMPLIANT}"

    [ "${status}" -eq 0 ]
    [ "${output}" = "${RLCH_MODULE_STATUS_NON_COMPLIANT}" ]
}

@test "module_status_from_result converts changed result" {
    run module_status_from_result "${RLCH_MODULE_RESULT_CHANGED}"

    [ "${status}" -eq 0 ]
    [ "${output}" = "${RLCH_MODULE_STATUS_CHANGED}" ]
}

@test "module_status_from_result rejects an unsupported result" {
    run module_status_from_result "99"

    [ "${status}" -eq 1 ]
    [ -z "${output}" ]
}

@test "load_module loads valid metadata and implementation" {
    local module_directory

    module_directory="$(create_api_test_module "1.1.1")"

    load_module "${module_directory}"

    [ "${RLCH_CURRENT_MODULE_ID}" = "1.1.1" ]
    [ "${RLCH_CURRENT_MODULE_TITLE}" = "Test module 1.1.1" ]
    [ "${RLCH_CURRENT_MODULE_DESCRIPTION}" = "Test description." ]
    [ "${RLCH_CURRENT_MODULE_RATIONALE}" = "Test rationale." ]
    [ "${RLCH_CURRENT_MODULE_LEVEL}" = "1" ]
    [ "${RLCH_CURRENT_MODULE_ENABLED}" = "true" ]
    [ "${RLCH_CURRENT_MODULE_REQUIRES_REBOOT}" = "false" ]
    [ "${RLCH_CURRENT_MODULE_DIRECTORY}" = "${module_directory}" ]

    declare -F check >/dev/null
    declare -F apply >/dev/null
    declare -F validate >/dev/null
    declare -F rollback >/dev/null
}

@test "load_module rejects an empty module directory" {
    run load_module ""

    [ "${status}" -eq 1 ]
    [[ "${output}" == *"Module directory must not be empty"* ]]
}

@test "load_module rejects a module with an invalid identifier" {
    local module_directory

    module_directory="$(create_api_test_module "1.1.1")"
    sed -i \
        's/RLCH_MODULE_ID="1.1.1"/RLCH_MODULE_ID="invalid"/' \
        "${module_directory}/metadata.conf"

    run load_module "${module_directory}"

    [ "${status}" -eq 1 ]
    [[ "${output}" == *"Invalid module identifier"* ]]
}

@test "load_module rejects metadata that does not match the directory" {
    local module_directory

    module_directory="$(create_api_test_module "1.1.1")"
    sed -i \
        's/RLCH_MODULE_ID="1.1.1"/RLCH_MODULE_ID="1.1.2"/' \
        "${module_directory}/metadata.conf"

    run load_module "${module_directory}"

    [ "${status}" -eq 1 ]
    [[ "${output}" == *"does not match its directory identifier"* ]]
}

@test "load_module rejects a missing title" {
    local module_directory

    module_directory="$(create_api_test_module "1.1.1")"
    sed -i \
        's/RLCH_MODULE_TITLE=.*/RLCH_MODULE_TITLE=""/' \
        "${module_directory}/metadata.conf"

    run load_module "${module_directory}"

    [ "${status}" -eq 1 ]
    [[ "${output}" == *"RLCH_MODULE_TITLE must not be empty"* ]]
}

@test "load_module rejects an invalid enabled value" {
    local module_directory

    module_directory="$(create_api_test_module "1.1.1" "invalid")"

    run load_module "${module_directory}"

    [ "${status}" -eq 1 ]
    [[ "${output}" == *"RLCH_MODULE_ENABLED must be a boolean value"* ]]
}

@test "load_module rejects an invalid reboot value" {
    local module_directory

    module_directory="$(
        create_api_test_module "1.1.1" "true" "invalid"
    )"

    run load_module "${module_directory}"

    [ "${status}" -eq 1 ]
    [[ "${output}" == *"RLCH_MODULE_REQUIRES_REBOOT must be a boolean value"* ]]
}

@test "load_module rejects a missing required function" {
    local module_directory

    module_directory="$(create_api_test_module "1.1.1")"

    sed -i '/^rollback()/,$d' "${module_directory}/module.sh"

    run load_module "${module_directory}"

    [ "${status}" -eq 1 ]
    [[ "${output}" == *"does not implement required function: rollback"* ]]
}

@test "loading a second module replaces the current context" {
    local first_module
    local second_module

    first_module="$(create_api_test_module "1.1.1")"
    second_module="$(create_api_test_module "1.1.2")"

    load_module "${first_module}"
    load_module "${second_module}"

    [ "${RLCH_CURRENT_MODULE_ID}" = "1.1.2" ]
    [ "${RLCH_CURRENT_MODULE_DIRECTORY}" = "${second_module}" ]
}

@test "current_module_is_enabled succeeds for an enabled module" {
    local module_directory

    module_directory="$(create_api_test_module "1.1.1" "true")"
    load_module "${module_directory}"

    run current_module_is_enabled

    [ "${status}" -eq 0 ]
}

@test "current_module_is_enabled fails for a disabled module" {
    local module_directory

    module_directory="$(create_api_test_module "1.1.1" "false")"
    load_module "${module_directory}"

    run current_module_is_enabled

    [ "${status}" -eq 1 ]
}

@test "current_module_requires_reboot succeeds when reboot is required" {
    local module_directory

    module_directory="$(
        create_api_test_module "1.1.1" "true" "true"
    )"

    load_module "${module_directory}"

    run current_module_requires_reboot

    [ "${status}" -eq 0 ]
}

@test "reset_module_context clears metadata and functions" {
    local module_directory

    module_directory="$(create_api_test_module "1.1.1")"
    load_module "${module_directory}"

    reset_module_context

    [ -z "${RLCH_CURRENT_MODULE_ID}" ]
    [ -z "${RLCH_CURRENT_MODULE_TITLE}" ]
    [ -z "${RLCH_CURRENT_MODULE_DIRECTORY}" ]

    ! declare -F check >/dev/null
    ! declare -F apply >/dev/null
    ! declare -F validate >/dev/null
    ! declare -F rollback >/dev/null
}