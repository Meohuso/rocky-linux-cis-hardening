#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
#
# Module execution engine.
#
# SPDX-License-Identifier: MIT
#

# Prevent multiple sourcing.
if [[ -n "${RLCH_EXECUTION_LOADED:-}" ]]; then
    return 0
fi
readonly RLCH_EXECUTION_LOADED=1

readonly RLCH_MODULE_ACTION_CHECK="check"
readonly RLCH_MODULE_ACTION_APPLY="apply"
readonly RLCH_MODULE_ACTION_VALIDATE="validate"
readonly RLCH_MODULE_ACTION_ROLLBACK="rollback"

RLCH_EXECUTION_MODULE_ID=""
RLCH_EXECUTION_ACTION=""
RLCH_EXECUTION_RESULT=""
RLCH_EXECUTION_STATUS=""

##
# Reset the latest execution result.
#
# Globals modified:
#   RLCH_EXECUTION_MODULE_ID
#   RLCH_EXECUTION_ACTION
#   RLCH_EXECUTION_RESULT
#   RLCH_EXECUTION_STATUS
#
# Returns:
#   0 on success.
##
reset_execution_context() {
    RLCH_EXECUTION_MODULE_ID=""
    RLCH_EXECUTION_ACTION=""
    RLCH_EXECUTION_RESULT=""
    RLCH_EXECUTION_STATUS=""

    return 0
}

##
# Determine whether a module action is supported.
#
# Arguments:
#   $1 Module action.
#
# Returns:
#   0 when the action is supported.
#   1 otherwise.
##
is_valid_module_action() {
    local action="${1:-}"

    case "${action}" in
        "${RLCH_MODULE_ACTION_CHECK}" | \
        "${RLCH_MODULE_ACTION_APPLY}" | \
        "${RLCH_MODULE_ACTION_VALIDATE}" | \
        "${RLCH_MODULE_ACTION_ROLLBACK}")
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

##
# Determine whether a module must be enabled for an action.
#
# Arguments:
#   $1 Module action.
#
# Returns:
#   0 when the action requires an enabled module.
#   1 otherwise.
##
module_action_requires_enabled_module() {
    local action="${1:-}"

    case "${action}" in
        "${RLCH_MODULE_ACTION_APPLY}" | \
        "${RLCH_MODULE_ACTION_ROLLBACK}")
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

##
# Determine whether the requested module action is implemented.
#
# Arguments:
#   $1 Module action.
#
# Returns:
#   0 when the implementation function exists.
#   1 otherwise.
##
module_action_is_implemented() {
    local action="${1:-}"

    if ! is_valid_module_action "${action}"; then
        return 1
    fi

    declare -F "${action}" >/dev/null 2>&1
}

##
# Store a module execution result.
#
# Arguments:
#   $1 Module identifier.
#   $2 Module action.
#   $3 Module result code.
#
# Globals modified:
#   RLCH_EXECUTION_MODULE_ID
#   RLCH_EXECUTION_ACTION
#   RLCH_EXECUTION_RESULT
#   RLCH_EXECUTION_STATUS
#
# Returns:
#   0 when the result is valid and stored.
#   1 otherwise.
##
store_execution_result() {
    local module_identifier="${1:-}"
    local action="${2:-}"
    local result_code="${3:-}"
    local execution_status

    if [[ -z "${module_identifier}" ]]; then
        error_message "Execution module identifier must not be empty."
        return 1
    fi

    if ! is_valid_module_action "${action}"; then
        error_message "Unsupported module action: ${action:-empty}"
        return 1
    fi

    if ! is_valid_module_result "${result_code}"; then
        error_message \
            "Module ${module_identifier} returned unsupported result code: ${result_code:-empty}"
        return 1
    fi

    if ! execution_status="$(module_status_from_result "${result_code}")"; then
        error_message \
            "Unable to determine execution status for module ${module_identifier}."
        return 1
    fi

    # These values form the public execution context consumed by callers
    # after this library has been sourced.
    # shellcheck disable=SC2034
    RLCH_EXECUTION_MODULE_ID="${module_identifier}"
    # shellcheck disable=SC2034
    RLCH_EXECUTION_ACTION="${action}"
    # shellcheck disable=SC2034
    RLCH_EXECUTION_RESULT="${result_code}"

    RLCH_EXECUTION_STATUS="${execution_status}"

    return 0
}

##
# Execute an action for the currently loaded module.
#
# Arguments:
#   $1 Module action.
#
# Globals:
#   RLCH_CURRENT_MODULE_ID
#   RLCH_CURRENT_MODULE_ENABLED
#
# Globals modified:
#   RLCH_EXECUTION_MODULE_ID
#   RLCH_EXECUTION_ACTION
#   RLCH_EXECUTION_RESULT
#   RLCH_EXECUTION_STATUS
#
# Returns:
#   The module result code.
#   RLCH_MODULE_RESULT_ERROR when execution cannot be performed.
##
execute_current_module_action() {
    local action="${1:-}"
    local result_code

    reset_execution_context

    if [[ -z "${RLCH_CURRENT_MODULE_ID:-}" ]]; then
        error_message "No module is currently loaded."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! is_valid_module_action "${action}"; then
        error_message "Unsupported module action: ${action:-empty}"
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! module_action_is_implemented "${action}"; then
        error_message \
            "Module ${RLCH_CURRENT_MODULE_ID} does not implement action: ${action}"
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if module_action_requires_enabled_module "${action}" &&
        ! current_module_is_enabled; then

        echo "DEBUG: disabled branch reached"
        
        log_info \
            "Skipping ${action} for disabled module ${RLCH_CURRENT_MODULE_ID}."

        store_execution_result \
            "${RLCH_CURRENT_MODULE_ID}" \
            "${action}" \
            "${RLCH_MODULE_RESULT_NOT_APPLICABLE}"

        return "${RLCH_MODULE_RESULT_NOT_APPLICABLE}"
    fi

    log_info \
        "Executing ${action} for module ${RLCH_CURRENT_MODULE_ID}."

    set +e
    "${action}"
    result_code=$?
    set -e

    if ! is_valid_module_result "${result_code}"; then
        error_message \
            "Module ${RLCH_CURRENT_MODULE_ID} returned unsupported result code ${result_code} during ${action}."

        store_execution_result \
            "${RLCH_CURRENT_MODULE_ID}" \
            "${action}" \
            "${RLCH_MODULE_RESULT_ERROR}"

        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! store_execution_result \
        "${RLCH_CURRENT_MODULE_ID}" \
        "${action}" \
        "${result_code}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    log_info \
        "Module ${RLCH_CURRENT_MODULE_ID} completed ${action} with status ${RLCH_EXECUTION_STATUS}."

    return "${result_code}"
}

##
# Load a module and execute an action.
#
# Arguments:
#   $1 Module directory.
#   $2 Module action.
#
# Returns:
#   The module result code.
#   RLCH_MODULE_RESULT_ERROR when loading or execution fails.
##
execute_module_action() {
    local module_directory="${1:-}"
    local action="${2:-}"

    reset_execution_context

    if [[ -z "${module_directory}" ]]; then
        error_message "Module directory must not be empty."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! is_valid_module_action "${action}"; then
        error_message "Unsupported module action: ${action:-empty}"
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! load_module "${module_directory}"; then
        error_message \
            "Unable to load module from directory: ${module_directory}"
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    execute_current_module_action "${action}"
}

##
# Execute the check action for a module.
#
# Arguments:
#   $1 Module directory.
#
# Returns:
#   The module result code.
##
check_module() {
    execute_module_action \
        "${1:-}" \
        "${RLCH_MODULE_ACTION_CHECK}"
}

##
# Execute the apply action for a module.
#
# Arguments:
#   $1 Module directory.
#
# Returns:
#   The module result code.
##
apply_module() {
    execute_module_action \
        "${1:-}" \
        "${RLCH_MODULE_ACTION_APPLY}"
}

##
# Execute the validate action for a module.
#
# Arguments:
#   $1 Module directory.
#
# Returns:
#   The module result code.
##
validate_module() {
    execute_module_action \
        "${1:-}" \
        "${RLCH_MODULE_ACTION_VALIDATE}"
}

##
# Execute the rollback action for a module.
#
# Arguments:
#   $1 Module directory.
#
# Returns:
#   The module result code.
##
rollback_module() {
    execute_module_action \
        "${1:-}" \
        "${RLCH_MODULE_ACTION_ROLLBACK}"
}