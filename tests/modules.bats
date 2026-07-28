#!/usr/bin/env bats
#
# Rocky Linux CIS Hardening Framework
#
# Module discovery tests
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

    RLCH_TEST_TEMPORARY_DIRECTORY="$(
        mktemp -d "${BATS_TEST_TMPDIR}/rlch-modules.XXXXXX"
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
    if [[ -n "${RLCH_TEST_TEMPORARY_DIRECTORY:-}" ]]; then
        rm -rf "${RLCH_TEST_TEMPORARY_DIRECTORY}"
    fi
}

@test "module_namespace_directory returns the configured namespace path" {
    run module_namespace_directory

    [ "${status}" -eq 0 ]
    [ "${output}" = "${RLCH_MODULE_ROOT}/cis" ]
}

@test "module_namespace_directory fails when the module root is empty" {
    RLCH_MODULE_ROOT=""

    run module_namespace_directory

    [ "${status}" -eq 1 ]
    [ -z "${output}" ]
}

@test "module_namespace_directory fails when the namespace is empty" {
    RLCH_MODULE_NAMESPACE=""

    run module_namespace_directory

    [ "${status}" -eq 1 ]
    [ -z "${output}" ]
}

@test "module_identifier_from_path converts a module path to an identifier" {
    local module_directory

    module_directory="${RLCH_MODULE_ROOT}/${RLCH_MODULE_NAMESPACE}/1/1/1"

    run module_identifier_from_path "${module_directory}"

    [ "${status}" -eq 0 ]
    [ "${output}" = "1.1.1" ]
}

@test "module_identifier_from_path rejects a path outside the namespace" {
    run module_identifier_from_path "/tmp/outside/1/1/1"

    [ "${status}" -eq 1 ]
    [ -z "${output}" ]
}

@test "module_matches_filter matches an exact identifier" {
    run module_matches_filter "1.1.1" "1.1.1"

    [ "${status}" -eq 0 ]
}

@test "module_matches_filter matches a wildcard identifier" {
    run module_matches_filter "1.1.12" "1.1.*"

    [ "${status}" -eq 0 ]
}

@test "module_matches_filter rejects a non-matching identifier" {
    run module_matches_filter "2.1.1" "1.*"

    [ "${status}" -eq 1 ]
}

@test "is_valid_module_directory accepts a complete module" {
    local module_directory

    module_directory="$(
        create_test_module \
            "${RLCH_MODULE_ROOT}/${RLCH_MODULE_NAMESPACE}" \
            "1.1.1"
    )"

    run is_valid_module_directory "${module_directory}"

    [ "${status}" -eq 0 ]
}

@test "is_valid_module_directory rejects an incomplete module" {
    local module_directory

    module_directory="$(
        create_incomplete_test_module \
            "${RLCH_MODULE_ROOT}/${RLCH_MODULE_NAMESPACE}" \
            "1.1.2"
    )"

    run is_valid_module_directory "${module_directory}"

    [ "${status}" -eq 1 ]
}

@test "discover_modules discovers complete modules in sorted order" {
    create_test_module \
        "${RLCH_MODULE_ROOT}/${RLCH_MODULE_NAMESPACE}" \
        "2.1.1" >/dev/null

    create_test_module \
        "${RLCH_MODULE_ROOT}/${RLCH_MODULE_NAMESPACE}" \
        "1.2.1" >/dev/null

    create_test_module \
        "${RLCH_MODULE_ROOT}/${RLCH_MODULE_NAMESPACE}" \
        "1.1.1" >/dev/null

    discover_modules "*"

    [ "${#RLCH_DISCOVERED_MODULES[@]}" -eq 3 ]

    [ "$(
        module_identifier_from_path "${RLCH_DISCOVERED_MODULES[0]}"
    )" = "1.1.1" ]

    [ "$(
        module_identifier_from_path "${RLCH_DISCOVERED_MODULES[1]}"
    )" = "1.2.1" ]

    [ "$(
        module_identifier_from_path "${RLCH_DISCOVERED_MODULES[2]}"
    )" = "2.1.1" ]
}

@test "discover_modules applies the requested module filter" {
    create_test_module \
        "${RLCH_MODULE_ROOT}/${RLCH_MODULE_NAMESPACE}" \
        "1.1.1" >/dev/null

    create_test_module \
        "${RLCH_MODULE_ROOT}/${RLCH_MODULE_NAMESPACE}" \
        "1.2.1" >/dev/null

    create_test_module \
        "${RLCH_MODULE_ROOT}/${RLCH_MODULE_NAMESPACE}" \
        "2.1.1" >/dev/null

    discover_modules "1.*"

    [ "${#RLCH_DISCOVERED_MODULES[@]}" -eq 2 ]

    [ "$(
        module_identifier_from_path "${RLCH_DISCOVERED_MODULES[0]}"
    )" = "1.1.1" ]

    [ "$(
        module_identifier_from_path "${RLCH_DISCOVERED_MODULES[1]}"
    )" = "1.2.1" ]
}

@test "discover_modules ignores incomplete module directories" {
    create_test_module \
        "${RLCH_MODULE_ROOT}/${RLCH_MODULE_NAMESPACE}" \
        "1.1.1" >/dev/null

    create_incomplete_test_module \
        "${RLCH_MODULE_ROOT}/${RLCH_MODULE_NAMESPACE}" \
        "1.1.2" >/dev/null

    discover_modules "*"

    [ "${#RLCH_DISCOVERED_MODULES[@]}" -eq 1 ]

    [ "$(
        module_identifier_from_path "${RLCH_DISCOVERED_MODULES[0]}"
    )" = "1.1.1" ]
}

@test "discover_modules returns an empty list when discovery is disabled" {
    create_test_module \
        "${RLCH_MODULE_ROOT}/${RLCH_MODULE_NAMESPACE}" \
        "1.1.1" >/dev/null

    RLCH_MODULE_DISCOVERY_ENABLED="false"

    discover_modules "*"

    [ "${#RLCH_DISCOVERED_MODULES[@]}" -eq 0 ]
}

@test "discover_modules succeeds when the namespace directory is absent" {
    rm -rf "${RLCH_MODULE_ROOT}/${RLCH_MODULE_NAMESPACE}"

    discover_modules "*"

    [ "${#RLCH_DISCOVERED_MODULES[@]}" -eq 0 ]
}

@test "discover_modules fails when the namespace path is a file" {
    rm -rf "${RLCH_MODULE_ROOT}/${RLCH_MODULE_NAMESPACE}"
    touch "${RLCH_MODULE_ROOT}/${RLCH_MODULE_NAMESPACE}"

    run discover_modules "*"

    [ "${status}" -eq 1 ]
    [[ "${output}" == *"Module namespace path is not a directory"* ]]
}

@test "list_modules prints discovered module identifiers" {
    create_test_module \
        "${RLCH_MODULE_ROOT}/${RLCH_MODULE_NAMESPACE}" \
        "1.1.1" >/dev/null

    create_test_module \
        "${RLCH_MODULE_ROOT}/${RLCH_MODULE_NAMESPACE}" \
        "1.1.2" >/dev/null

    run list_modules "1.1.*"

    [ "${status}" -eq 0 ]
    [ "${lines[0]}" = "1.1.1" ]
    [ "${lines[1]}" = "1.1.2" ]
    [ "${#lines[@]}" -eq 2 ]
}

@test "list_modules reports when no module is discovered" {
    run list_modules "*"

    [ "${status}" -eq 0 ]
    [ "${output}" = "No modules discovered." ]
}