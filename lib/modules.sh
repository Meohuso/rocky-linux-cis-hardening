#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
#
# SPDX-License-Identifier: MIT
#

# Prevent multiple sourcing.
if [[ -n "${RLCH_MODULES_LOADED:-}" ]]; then
    return 0
fi
readonly RLCH_MODULES_LOADED=1

declare -ag RLCH_DISCOVERED_MODULES=()

##
# Return the configured namespace directory.
#
# Outputs:
#   Absolute module namespace directory path.
#
# Returns:
#   0 on success.
#   1 when the module configuration is incomplete.
##
module_namespace_directory() {
    if [[ -z "${RLCH_MODULE_ROOT:-}" ]] ||
        [[ -z "${RLCH_MODULE_NAMESPACE:-}" ]]; then
        return 1
    fi

    printf '%s/%s\n' \
        "${RLCH_MODULE_ROOT%/}" \
        "${RLCH_MODULE_NAMESPACE}"
}

##
# Convert a module directory path into a module identifier.
#
# Arguments:
#   $1 Absolute module directory path.
#
# Outputs:
#   Module identifier relative to the configured namespace.
#
# Returns:
#   0 on success.
#   1 when the path is outside the configured namespace.
##
module_identifier_from_path() {
    local module_path="${1:-}"
    local namespace_directory
    local relative_path

    if [[ -z "${module_path}" ]]; then
        return 1
    fi

    if ! namespace_directory="$(module_namespace_directory)"; then
        return 1
    fi

    namespace_directory="${namespace_directory%/}"
    module_path="${module_path%/}"

    case "${module_path}" in
        "${namespace_directory}/"*)
            relative_path="${module_path#"${namespace_directory}/"}"
            ;;
        *)
            return 1
            ;;
    esac

    if [[ -z "${relative_path}" ]]; then
        return 1
    fi

    printf '%s\n' "${relative_path//\//.}"
}

##
# Determine whether a module identifier matches a shell pattern.
#
# Arguments:
#   $1 Module identifier.
#   $2 Shell pattern.
#
# Returns:
#   0 when the identifier matches.
#   1 otherwise.
##
module_matches_filter() {
    local module_identifier="${1:-}"
    local module_filter="${2:-}"

    if [[ -z "${module_identifier}" ]] ||
        [[ -z "${module_filter}" ]]; then
        return 1
    fi

    [[ "${module_identifier}" == ${module_filter} ]]
}

##
# Determine whether a directory is a valid module directory.
#
# Arguments:
#   $1 Module directory path.
#
# Returns:
#   0 when the required module files exist and are readable.
#   1 otherwise.
##
is_valid_module_directory() {
    local module_directory="${1:-}"
    local metadata_file
    local implementation_file

    if [[ -z "${module_directory}" ]] ||
        [[ ! -d "${module_directory}" ]]; then
        return 1
    fi

    metadata_file="${module_directory}/${RLCH_MODULE_METADATA_FILENAME}"

    implementation_file="${module_directory}/${RLCH_MODULE_IMPLEMENTATION_FILENAME}"

    readable_file_exists "${metadata_file}" &&
        readable_file_exists "${implementation_file}"
}

##
# Discover valid framework modules.
#
# Arguments:
#   $1 Optional module identifier filter.
#
# Globals modified:
#   RLCH_DISCOVERED_MODULES
#
# Returns:
#   0 on success, including when no module is discovered.
#   1 when discovery cannot be performed.
##
discover_modules() {
    local module_filter="${1:-${RLCH_MODULE_DEFAULT_FILTER}}"
    local namespace_directory
    local metadata_file
    local module_directory
    local module_identifier

    RLCH_DISCOVERED_MODULES=()

    if ! is_true "${RLCH_MODULE_DISCOVERY_ENABLED}"; then
        log_debug "Module discovery is disabled."
        return 0
    fi

    if [[ -z "${module_filter}" ]]; then
        error_message "Module filter must not be empty."
        return 1
    fi

    if ! namespace_directory="$(module_namespace_directory)"; then
        error_message "Unable to determine the module namespace directory."
        return 1
    fi

    if [[ ! -e "${namespace_directory}" ]]; then
        log_debug \
            "Module namespace directory does not exist: ${namespace_directory}"
        return 0
    fi

    if [[ ! -d "${namespace_directory}" ]]; then
        error_message \
            "Module namespace path is not a directory: ${namespace_directory}"
        return 1
    fi

    if [[ ! -r "${namespace_directory}" ]]; then
        error_message \
            "Module namespace directory is not readable: ${namespace_directory}"
        return 1
    fi

    while IFS= read -r -d '' metadata_file; do
        module_directory="$(dirname "${metadata_file}")"

        if ! is_valid_module_directory "${module_directory}"; then
            log_debug \
                "Ignoring incomplete module directory: ${module_directory}"
            continue
        fi

        if ! module_identifier="$(
            module_identifier_from_path "${module_directory}"
        )"; then
            log_warn \
                "Unable to determine module identifier: ${module_directory}"
            continue
        fi

        if module_matches_filter \
            "${module_identifier}" \
            "${module_filter}"; then
            RLCH_DISCOVERED_MODULES+=("${module_directory}")
        fi
    done < <(
        find "${namespace_directory}" \
            -type f \
            -name "${RLCH_MODULE_METADATA_FILENAME}" \
            -print0 |
            sort -z
    )

    log_debug \
        "Discovered ${#RLCH_DISCOVERED_MODULES[@]} module(s)."

    return 0
}

##
# Print discovered module identifiers.
#
# Arguments:
#   $1 Optional module identifier filter.
#
# Returns:
#   0 on success.
#   1 when module discovery fails.
##
list_modules() {
    local module_filter="${1:-${RLCH_MODULE_DEFAULT_FILTER}}"
    local module_directory
    local module_identifier

    if ! discover_modules "${module_filter}"; then
        return 1
    fi

    if ((${#RLCH_DISCOVERED_MODULES[@]} == 0)); then
        printf 'No modules discovered.\n'
        return 0
    fi

    for module_directory in "${RLCH_DISCOVERED_MODULES[@]}"; do
        if ! module_identifier="$(
            module_identifier_from_path "${module_directory}"
        )"; then
            error_message \
                "Unable to identify module: ${module_directory}"
            return 1
        fi

        printf '%s\n' "${module_identifier}"
    done

    return 0
}