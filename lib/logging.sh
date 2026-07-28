#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
#
# SPDX-License-Identifier: MIT
#

# Prevent multiple sourcing.
if [[ -n "${RLCH_LOGGING_LOADED:-}" ]]; then
    return 0
fi
readonly RLCH_LOGGING_LOADED=1

readonly RLCH_LOG_LEVEL_DEBUG="DEBUG"
readonly RLCH_LOG_LEVEL_INFO="INFO"
readonly RLCH_LOG_LEVEL_WARN="WARN"
readonly RLCH_LOG_LEVEL_ERROR="ERROR"
readonly RLCH_LOG_LEVEL_FATAL="FATAL"

RLCH_LOG_LEVEL="${RLCH_LOG_LEVEL:-INFO}"
RLCH_LOG_TO_CONSOLE="${RLCH_LOG_TO_CONSOLE:-true}"
RLCH_LOG_TO_FILE="${RLCH_LOG_TO_FILE:-true}"
RLCH_LOG_FILENAME="${RLCH_LOG_FILENAME:-framework.log}"
RLCH_LOG_DATE_FORMAT="${RLCH_LOG_DATE_FORMAT:-%Y-%m-%d %H:%M:%S}"
RLCH_LOG_FILE="${RLCH_LOG_FILE:-}"

##
# Print a logging subsystem error without using the logging subsystem.
#
# Arguments:
#   $1 Error message.
#
# Returns:
#   0 on success.
##
_logging_print_error() {
    local message="${1:-Unknown logging error.}"

    printf 'RLCH logging error: %s\n' "${message}" >&2
}

##
# Return the numeric priority associated with a log level.
#
# Arguments:
#   $1 Log level.
#
# Outputs:
#   Numeric log priority.
#
# Returns:
#   0 when the level is valid.
#   1 when the level is invalid.
##
_logging_level_priority() {
    local level="${1:-}"

    case "${level}" in
        "${RLCH_LOG_LEVEL_DEBUG}")
            printf '%s\n' "10"
            ;;
        "${RLCH_LOG_LEVEL_INFO}")
            printf '%s\n' "20"
            ;;
        "${RLCH_LOG_LEVEL_WARN}")
            printf '%s\n' "30"
            ;;
        "${RLCH_LOG_LEVEL_ERROR}")
            printf '%s\n' "40"
            ;;
        "${RLCH_LOG_LEVEL_FATAL}")
            printf '%s\n' "50"
            ;;
        *)
            return 1
            ;;
    esac
}

##
# Determine whether a log message must be emitted.
#
# Arguments:
#   $1 Message log level.
#
# Returns:
#   0 when the message must be emitted.
#   1 when the message must be ignored.
##
_logging_should_emit() {
    local message_level="${1:-}"
    local configured_priority
    local message_priority

    if ! configured_priority="$(
        _logging_level_priority "${RLCH_LOG_LEVEL}"
    )"; then
        _logging_print_error \
            "Invalid configured log level: ${RLCH_LOG_LEVEL}"
        return 1
    fi

    if ! message_priority="$(
        _logging_level_priority "${message_level}"
    )"; then
        _logging_print_error \
            "Invalid message log level: ${message_level}"
        return 1
    fi

    ((message_priority >= configured_priority))
}

##
# Validate the logging configuration.
#
# Returns:
#   0 when the configuration is valid.
#   1 when the configuration is invalid.
##
validate_logging_configuration() {
    if ! _logging_level_priority "${RLCH_LOG_LEVEL}" >/dev/null; then
        _logging_print_error \
            "RLCH_LOG_LEVEL must be DEBUG, INFO, WARN, ERROR, or FATAL."
        return 1
    fi

    case "${RLCH_LOG_TO_CONSOLE}" in
        true | false) ;;
        *)
            _logging_print_error \
                "RLCH_LOG_TO_CONSOLE must be true or false."
            return 1
            ;;
    esac

    case "${RLCH_LOG_TO_FILE}" in
        true | false) ;;
        *)
            _logging_print_error \
                "RLCH_LOG_TO_FILE must be true or false."
            return 1
            ;;
    esac

    if [[ -z "${RLCH_LOG_FILENAME}" ]]; then
        _logging_print_error \
            "RLCH_LOG_FILENAME must not be empty."
        return 1
    fi

    if [[ "${RLCH_LOG_FILENAME}" == */* ]]; then
        _logging_print_error \
            "RLCH_LOG_FILENAME must contain a filename only."
        return 1
    fi

    if [[ -z "${RLCH_LOG_DATE_FORMAT}" ]]; then
        _logging_print_error \
            "RLCH_LOG_DATE_FORMAT must not be empty."
        return 1
    fi

    if [[ \
        "${RLCH_LOG_TO_CONSOLE}" == "false" &&
        "${RLCH_LOG_TO_FILE}" == "false"
    ]]; then
        _logging_print_error \
            "At least one logging destination must be enabled."
        return 1
    fi

    return 0
}

##
# Initialize the logging subsystem.
#
# Globals:
#   RLCH_LOG_DIR
#   RLCH_LOG_FILE
#   RLCH_LOG_FILENAME
#   RLCH_LOG_TO_FILE
#
# Returns:
#   0 on success.
#   1 on failure.
##
initialize_logging() {
    if ! validate_logging_configuration; then
        return 1
    fi

    if [[ "${RLCH_LOG_TO_FILE}" == "true" ]]; then
        if [[ -z "${RLCH_LOG_DIR:-}" ]]; then
            _logging_print_error \
                "RLCH_LOG_DIR is not initialized."
            return 1
        fi

        if ! mkdir -p -- "${RLCH_LOG_DIR}"; then
            _logging_print_error \
                "Unable to create log directory: ${RLCH_LOG_DIR}"
            return 1
        fi

        RLCH_LOG_FILE="${RLCH_LOG_DIR}/${RLCH_LOG_FILENAME}"

        if ! touch -- "${RLCH_LOG_FILE}"; then
            _logging_print_error \
                "Unable to create log file: ${RLCH_LOG_FILE}"
            return 1
        fi

        if ! chmod 0600 -- "${RLCH_LOG_FILE}"; then
            _logging_print_error \
                "Unable to set permissions on log file: ${RLCH_LOG_FILE}"
            return 1
        fi
    else
        RLCH_LOG_FILE=""
    fi

    log_info "Logging initialized."
}

##
# Write a message to configured logging destinations.
#
# Arguments:
#   $1 Log level.
#   $2 Message.
#
# Returns:
#   0 on success.
#   1 on failure.
##
log_message() {
    local level="${1:-}"
    local message="${2:-}"
    local timestamp
    local formatted_message

    if [[ -z "${level}" ]]; then
        _logging_print_error "A log level is required."
        return 1
    fi

    if [[ -z "${message}" ]]; then
        _logging_print_error "A log message is required."
        return 1
    fi

    if ! _logging_should_emit "${level}"; then
        return 0
    fi

    if ! timestamp="$(date "+${RLCH_LOG_DATE_FORMAT}")"; then
        _logging_print_error "Unable to generate log timestamp."
        return 1
    fi

    formatted_message="${timestamp} [${level}] ${message}"

    if [[ "${RLCH_LOG_TO_FILE}" == "true" ]]; then
        if [[ -z "${RLCH_LOG_FILE}" ]]; then
            _logging_print_error \
                "Logging is not initialized."
            return 1
        fi

        if ! printf '%s\n' "${formatted_message}" >>"${RLCH_LOG_FILE}"; then
            _logging_print_error \
                "Unable to write to log file: ${RLCH_LOG_FILE}"
            return 1
        fi
    fi

    if [[ "${RLCH_LOG_TO_CONSOLE}" == "true" ]]; then
        if [[ \
            "${level}" == "${RLCH_LOG_LEVEL_ERROR}" ||
            "${level}" == "${RLCH_LOG_LEVEL_FATAL}"
        ]]; then
            printf '[%s] %s\n' "${level}" "${message}" >&2
        else
            printf '[%s] %s\n' "${level}" "${message}"
        fi
    fi

    return 0
}

##
# Log a DEBUG message.
#
# Arguments:
#   $1 Message.
#
# Returns:
#   0 on success.
#   1 on failure.
##
log_debug() {
    log_message "${RLCH_LOG_LEVEL_DEBUG}" "${1:-}"
}

##
# Log an INFO message.
#
# Arguments:
#   $1 Message.
#
# Returns:
#   0 on success.
#   1 on failure.
##
log_info() {
    log_message "${RLCH_LOG_LEVEL_INFO}" "${1:-}"
}

##
# Log a WARN message.
#
# Arguments:
#   $1 Message.
#
# Returns:
#   0 on success.
#   1 on failure.
##
log_warn() {
    log_message "${RLCH_LOG_LEVEL_WARN}" "${1:-}"
}

##
# Log an ERROR message.
#
# Arguments:
#   $1 Message.
#
# Returns:
#   0 on success.
#   1 on failure.
##
log_error() {
    log_message "${RLCH_LOG_LEVEL_ERROR}" "${1:-}"
}

##
# Log a fatal error and terminate the current process.
#
# Arguments:
#   $1 Message.
#   $2 Optional exit status. Defaults to 1.
##
log_fatal() {
    local message="${1:-Unknown fatal error.}"
    local exit_status="${2:-1}"

    if [[ ! "${exit_status}" =~ ^[0-9]+$ ]] ||
        ((exit_status < 1 || exit_status > 255)); then
        exit_status=1
    fi

    log_message "${RLCH_LOG_LEVEL_FATAL}" "${message}" || true
    exit "${exit_status}"
}