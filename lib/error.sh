#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
#
# SPDX-License-Identifier: MIT
#

# Prevent multiple sourcing.
if [[ -n "${RLCH_ERROR_LOADED:-}" ]]; then
    return 0
fi
readonly RLCH_ERROR_LOADED=1

readonly RLCH_EXIT_SUCCESS=0
readonly RLCH_EXIT_GENERAL_ERROR=1
readonly RLCH_EXIT_INVALID_ARGUMENT=2
readonly RLCH_EXIT_PERMISSION_ERROR=3
readonly RLCH_EXIT_CONFIGURATION_ERROR=4
readonly RLCH_EXIT_ENVIRONMENT_ERROR=5
readonly RLCH_EXIT_EXECUTION_ERROR=6
readonly RLCH_EXIT_VALIDATION_ERROR=7

##
# Print an error message using the logging subsystem when available.
#
# Arguments:
#   $1 Error message.
#
# Returns:
#   0 when the message was emitted.
##
error_message() {
    local message="${1:-Unknown error.}"

    if declare -F log_error >/dev/null 2>&1; then
        log_error "${message}" || printf 'ERROR: %s\n' "${message}" >&2
    else
        printf 'ERROR: %s\n' "${message}" >&2
    fi

    return 0
}

##
# Terminate the current process with an error.
#
# Arguments:
#   $1 Error message.
#   $2 Optional exit status. Defaults to RLCH_EXIT_GENERAL_ERROR.
##
die() {
    local message="${1:-Unknown fatal error.}"
    local exit_status="${2:-${RLCH_EXIT_GENERAL_ERROR}}"

    if [[ ! "${exit_status}" =~ ^[0-9]+$ ]] ||
        ((exit_status < 1 || exit_status > 255)); then
        exit_status="${RLCH_EXIT_GENERAL_ERROR}"
    fi

    error_message "${message}"
    exit "${exit_status}"
}

##
# Terminate execution because of an invalid argument.
#
# Arguments:
#   $1 Error message.
##
die_invalid_argument() {
    die "${1:-Invalid argument.}" "${RLCH_EXIT_INVALID_ARGUMENT}"
}

##
# Terminate execution because of insufficient permissions.
#
# Arguments:
#   $1 Error message.
##
die_permission() {
    die "${1:-Insufficient permissions.}" "${RLCH_EXIT_PERMISSION_ERROR}"
}

##
# Terminate execution because of an invalid configuration.
#
# Arguments:
#   $1 Error message.
##
die_configuration() {
    die "${1:-Invalid configuration.}" "${RLCH_EXIT_CONFIGURATION_ERROR}"
}

##
# Terminate execution because of an unsupported environment.
#
# Arguments:
#   $1 Error message.
##
die_environment() {
    die "${1:-Unsupported environment.}" "${RLCH_EXIT_ENVIRONMENT_ERROR}"
}

##
# Terminate execution because an operation failed.
#
# Arguments:
#   $1 Error message.
##
die_execution() {
    die "${1:-Execution failed.}" "${RLCH_EXIT_EXECUTION_ERROR}"
}

##
# Terminate execution because validation failed.
#
# Arguments:
#   $1 Error message.
##
die_validation() {
    die "${1:-Validation failed.}" "${RLCH_EXIT_VALIDATION_ERROR}"
}