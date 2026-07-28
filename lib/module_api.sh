#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
#
# SPDX-License-Identifier: MIT
#

# Prevent multiple sourcing.
if [[ -n "${RLCH_MODULE_API_LOADED:-}" ]]; then
    return 0
fi
readonly RLCH_MODULE_API_LOADED=1

readonly RLCH_MODULE_STATUS_COMPLIANT="compliant"
readonly RLCH_MODULE_STATUS_NON_COMPLIANT="non_compliant"
readonly RLCH_MODULE_STATUS_CHANGED="changed"
readonly RLCH_MODULE_STATUS_NOT_APPLICABLE="not_applicable"
readonly RLCH_MODULE_STATUS_ERROR="error"

readonly RLCH_MODULE_RESULT_SUCCESS=0
readonly RLCH_MODULE_RESULT_NON_COMPLIANT=1
readonly RLCH_MODULE_RESULT_ERROR=2
readonly RLCH_MODULE_RESULT_NOT_APPLICABLE=3
readonly RLCH_MODULE_RESULT_CHANGED=4

declare -ag RLCH_MODULE_REQUIRED_FUNCTIONS=(
    "check"
    "apply"
    "validate"
    "rollback"
)

RLCH_CURRENT_MODULE_DIRECTORY=""
RLCH_CURRENT_MODULE_ID=""
RLCH_CURRENT_MODULE_TITLE=""
RLCH_CURRENT_MODULE_DESCRIPTION=""
RLCH_CURRENT_MODULE_RATIONALE=""
RLCH_CURRENT_MODULE_LEVEL=""
RLCH_CURRENT_MODULE_ENABLED=""
RLCH_CURRENT_MODULE_REQUIRES_REBOOT=""
RLCH_CURRENT_MODULE_OPENSCAP_RULE=""
RLCH_CURRENT_MODULE_METADATA_FILE=""
RLCH_CURRENT_MODULE_IMPLEMENTATION_FILE=""

##
# Remove module implementation functions from the current shell.
#
# Globals:
#   RLCH_MODULE_REQUIRED_FUNCTIONS
#
# Returns:
#   0 on success.
##
clear_module_functions() {
    local function_name

    for function_name in "${RLCH_MODULE_REQUIRED_FUNCTIONS[@]}"; do
        if declare -F "${function_name}" >/dev/null 2>&1; then
            unset -f "${function_name}"
        fi
    done

    if declare -F metadata >/dev/null 2>&1; then
        unset -f metadata
    fi

    return 0
}

##
# Reset the currently loaded module context.
#
# Returns:
#   0 on success.
##
reset_module_context() {
    clear_module_functions

    RLCH_CURRENT_MODULE_DIRECTORY=""
    RLCH_CURRENT_MODULE_ID=""
    RLCH_CURRENT_MODULE_TITLE=""
    RLCH_CURRENT_MODULE_DESCRIPTION=""
    RLCH_CURRENT_MODULE_RATIONALE=""
    RLCH_CURRENT_MODULE_LEVEL=""
    RLCH_CURRENT_MODULE_ENABLED=""
    RLCH_CURRENT_MODULE_REQUIRES_REBOOT=""
    RLCH_CURRENT_MODULE_OPENSCAP_RULE=""
    RLCH_CURRENT_MODULE_METADATA_FILE=""
    RLCH_CURRENT_MODULE_IMPLEMENTATION_FILE=""

    return 0
}

##
# Determine whether a module result code is supported.
#
# Arguments:
#   $1 Module result code.
#
# Returns:
#   0 when the result code is supported.
#   1 otherwise.
##
is_valid_module_result() {
    local result_code="${1:-}"

    case "${result_code}" in
        "${RLCH_MODULE_RESULT_SUCCESS}"|"${RLCH_MODULE_RESULT_NON_COMPLIANT}"|"${RLCH_MODULE_RESULT_ERROR}"|"${RLCH_MODULE_RESULT_NOT_APPLICABLE}"|"${RLCH_MODULE_RESULT_CHANGED}")
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

##
# Convert a module result code to a status name.
#
# Arguments:
#   $1 Module result code.
#
# Outputs:
#   Canonical module status.
#
# Returns:
#   0 when the result code is supported.
#   1 otherwise.
##
module_status_from_result() {
    local result_code="${1:-}"

    case "${result_code}" in
        "${RLCH_MODULE_RESULT_SUCCESS}")
            printf '%s\n' "${RLCH_MODULE_STATUS_COMPLIANT}"
            ;;
        "${RLCH_MODULE_RESULT_NON_COMPLIANT}")
            printf '%s\n' "${RLCH_MODULE_STATUS_NON_COMPLIANT}"
            ;;
        "${RLCH_MODULE_RESULT_ERROR}")
            printf '%s\n' "${RLCH_MODULE_STATUS_ERROR}"
            ;;
        "${RLCH_MODULE_RESULT_NOT_APPLICABLE}")
            printf '%s\n' "${RLCH_MODULE_STATUS_NOT_APPLICABLE}"
            ;;
        "${RLCH_MODULE_RESULT_CHANGED}")
            printf '%s\n' "${RLCH_MODULE_STATUS_CHANGED}"
            ;;
        *)
            return 1
            ;;
    esac
}

##
# Validate a module identifier.
#
# Arguments:
#   $1 Module identifier.
#
# Returns:
#   0 when the identifier is valid.
#   1 otherwise.
##
is_valid_module_identifier() {
    local module_identifier="${1:-}"

    [[ "${module_identifier}" =~ ^[0-9]+(\.[0-9]+)+$ ]]
}

##
# Validate a CIS profile level.
#
# Arguments:
#   $1 Profile level.
#
# Returns:
#   0 when the level is supported.
#   1 otherwise.
##
is_valid_module_level() {
    local module_level="${1:-}"

    case "${module_level}" in
        "1"|"2")
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

##
# Validate the metadata currently loaded for a module.
#
# Arguments:
#   $1 Expected module identifier derived from its directory.
#
# Returns:
#   0 when the metadata is valid.
#   1 otherwise.
##
validate_loaded_module_metadata() {
    local expected_identifier="${1:-}"

    if [[ -z "${expected_identifier}" ]]; then
        error_message "Expected module identifier must not be empty."
        return 1
    fi

    if [[ -z "${RLCH_MODULE_ID:-}" ]]; then
        error_message "RLCH_MODULE_ID must not be empty."
        return 1
    fi

    if ! is_valid_module_identifier "${RLCH_MODULE_ID}"; then
        error_message "Invalid module identifier: ${RLCH_MODULE_ID}"
        return 1
    fi

    if [[ "${RLCH_MODULE_ID}" != "${expected_identifier}" ]]; then
        error_message "Module identifier ${RLCH_MODULE_ID} does not match its directory identifier ${expected_identifier}."
        return 1
    fi

    if [[ -z "${RLCH_MODULE_TITLE:-}" ]]; then
        error_message "RLCH_MODULE_TITLE must not be empty for module ${RLCH_MODULE_ID}."
        return 1
    fi

    if [[ -z "${RLCH_MODULE_DESCRIPTION:-}" ]]; then
        error_message "RLCH_MODULE_DESCRIPTION must not be empty for module ${RLCH_MODULE_ID}."
        return 1
    fi

    if [[ -z "${RLCH_MODULE_RATIONALE:-}" ]]; then
        error_message "RLCH_MODULE_RATIONALE must not be empty for module ${RLCH_MODULE_ID}."
        return 1
    fi

    if ! is_valid_module_level "${RLCH_MODULE_LEVEL:-}"; then
        error_message "RLCH_MODULE_LEVEL must be 1 or 2 for module ${RLCH_MODULE_ID}."
        return 1
    fi

    if ! is_boolean "${RLCH_MODULE_ENABLED:-}"; then
        error_message "RLCH_MODULE_ENABLED must be a boolean value for module ${RLCH_MODULE_ID}."
        return 1
    fi

    if ! is_boolean "${RLCH_MODULE_REQUIRES_REBOOT:-}"; then
        error_message "RLCH_MODULE_REQUIRES_REBOOT must be a boolean value for module ${RLCH_MODULE_ID}."
        return 1
    fi

    if [[ -z "${RLCH_MODULE_OPENSCAP_RULE:-}" ]]; then
        error_message "RLCH_MODULE_OPENSCAP_RULE must not be empty for module ${RLCH_MODULE_ID}."
        return 1
    fi

    return 0
}

##
# Validate the implementation functions loaded for a module.
#
# Returns:
#   0 when all required functions are available.
#   1 otherwise.
##
validate_loaded_module_functions() {
    local function_name

    for function_name in "${RLCH_MODULE_REQUIRED_FUNCTIONS[@]}"; do
        if ! declare -F "${function_name}" >/dev/null 2>&1; then
            error_message "Module ${RLCH_MODULE_ID:-unknown} does not implement required function: ${function_name}"
            return 1
        fi
    done

    return 0
}

##
# Clear temporary metadata variables loaded from metadata.conf.
#
# Returns:
#   0 on success.
##
clear_module_metadata_variables() {
    unset RLCH_MODULE_ID
    unset RLCH_MODULE_TITLE
    unset RLCH_MODULE_DESCRIPTION
    unset RLCH_MODULE_RATIONALE
    unset RLCH_MODULE_LEVEL
    unset RLCH_MODULE_ENABLED
    unset RLCH_MODULE_REQUIRES_REBOOT
    unset RLCH_MODULE_OPENSCAP_RULE

    return 0
}

##
# Copy temporary metadata variables into the current module context.
#
# Returns:
#   0 on success.
##
store_loaded_module_metadata() {
    RLCH_CURRENT_MODULE_ID="${RLCH_MODULE_ID}"
    RLCH_CURRENT_MODULE_TITLE="${RLCH_MODULE_TITLE}"

    # Public module context consumed by other sourced framework libraries.
    # shellcheck disable=SC2034
    RLCH_CURRENT_MODULE_DESCRIPTION="${RLCH_MODULE_DESCRIPTION}"

    # shellcheck disable=SC2034
    RLCH_CURRENT_MODULE_RATIONALE="${RLCH_MODULE_RATIONALE}"

    # shellcheck disable=SC2034
    RLCH_CURRENT_MODULE_LEVEL="${RLCH_MODULE_LEVEL}"

    RLCH_CURRENT_MODULE_ENABLED="${RLCH_MODULE_ENABLED}"
    RLCH_CURRENT_MODULE_REQUIRES_REBOOT="${RLCH_MODULE_REQUIRES_REBOOT}"

    # shellcheck disable=SC2034
    RLCH_CURRENT_MODULE_OPENSCAP_RULE="${RLCH_MODULE_OPENSCAP_RULE}"

    return 0
}

##
# Load and validate a framework module.
#
# Arguments:
#   $1 Module directory.
#
# Returns:
#   0 when the module is loaded and valid.
#   1 otherwise.
##
load_module() {
    local module_directory="${1:-}"
    local module_identifier
    local metadata_file
    local implementation_file

    reset_module_context
    clear_module_metadata_variables

    if [[ -z "${module_directory}" ]]; then
        error_message "Module directory must not be empty."
        return 1
    fi

    if ! is_valid_module_directory "${module_directory}"; then
        error_message "Invalid or incomplete module directory: ${module_directory}"
        return 1
    fi

    if ! module_identifier="$(module_identifier_from_path "${module_directory}")"; then
        error_message "Unable to determine module identifier: ${module_directory}"
        return 1
    fi

    metadata_file="${module_directory}/${RLCH_MODULE_METADATA_FILENAME}"
    implementation_file="${module_directory}/${RLCH_MODULE_IMPLEMENTATION_FILENAME}"

    # shellcheck source=/dev/null
    if ! source "${metadata_file}"; then
        error_message "Unable to load module metadata: ${metadata_file}"
        clear_module_metadata_variables
        return 1
    fi

    if ! validate_loaded_module_metadata "${module_identifier}"; then
        clear_module_metadata_variables
        return 1
    fi

    # shellcheck source=/dev/null
    if ! source "${implementation_file}"; then
        error_message "Unable to load module implementation: ${implementation_file}"
        clear_module_functions
        clear_module_metadata_variables
        return 1
    fi

    if ! validate_loaded_module_functions; then
        clear_module_functions
        clear_module_metadata_variables
        return 1
    fi

    # Public module path context consumed by other sourced framework libraries.
    # shellcheck disable=SC2034
    RLCH_CURRENT_MODULE_DIRECTORY="${module_directory}"

    # shellcheck disable=SC2034
    RLCH_CURRENT_MODULE_METADATA_FILE="${metadata_file}"

    # shellcheck disable=SC2034
    RLCH_CURRENT_MODULE_IMPLEMENTATION_FILE="${implementation_file}"

    store_loaded_module_metadata
    clear_module_metadata_variables

    log_debug "Loaded module ${RLCH_CURRENT_MODULE_ID}: ${RLCH_CURRENT_MODULE_TITLE}"

    return 0
}

##
# Determine whether the currently loaded module is enabled.
#
# Returns:
#   0 when the module is loaded and enabled.
#   1 otherwise.
##
current_module_is_enabled() {
    if [[ -z "${RLCH_CURRENT_MODULE_ID}" ]]; then
        return 1
    fi

    is_true "${RLCH_CURRENT_MODULE_ENABLED}"
}

##
# Determine whether the currently loaded module requires a reboot.
#
# Returns:
#   0 when the module requires a reboot.
#   1 otherwise.
##
current_module_requires_reboot() {
    if [[ -z "${RLCH_CURRENT_MODULE_ID}" ]]; then
        return 1
    fi

    is_true "${RLCH_CURRENT_MODULE_REQUIRES_REBOOT}"
}