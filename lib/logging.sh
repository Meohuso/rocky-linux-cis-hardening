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

##
# Log levels.
##
readonly RLCH_LOG_LEVEL_DEBUG="DEBUG"
readonly RLCH_LOG_LEVEL_INFO="INFO"
readonly RLCH_LOG_LEVEL_WARN="WARN"
readonly RLCH_LOG_LEVEL_ERROR="ERROR"

##
# Logging globals.
##
RLCH_LOG_FILE=""
RLCH_LOG_TO_CONSOLE="true"

##
# Initialize the logging subsystem.
#
# Returns:
#   0 on success.
##
initialize_logging() {

    mkdir -p "${RLCH_LOG_DIR}"

    RLCH_LOG_FILE="${RLCH_LOG_DIR}/framework.log"

    touch "${RLCH_LOG_FILE}"

    log_info "Logging initialized."
}

##
# Log a DEBUG message.
#
# Arguments:
#   $1 Message.
##
log_debug() {
    log_message "${RLCH_LOG_LEVEL_DEBUG}" "$1"
}

##
# Log an INFO message.
#
# Arguments:
#   $1 Message.
##
log_info() {
    log_message "${RLCH_LOG_LEVEL_INFO}" "$1"
}

##
# Log a WARN message.
#
# Arguments:
#   $1 Message.
##
log_warn() {
    log_message "${RLCH_LOG_LEVEL_WARN}" "$1"
}

##
# Log an ERROR message.
#
# Arguments:
#   $1 Message.
##
log_error() {
    log_message "${RLCH_LOG_LEVEL_ERROR}" "$1"
}

##
# Write a message to the log.
#
# Arguments:
#   $1 Log level.
#   $2 Message.
##
log_message() {

    local level="$1"
    local message="$2"
    local timestamp

    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"

    printf '%s [%s] %s\n' \
        "${timestamp}" \
        "${level}" \
        "${message}" \
        >> "${RLCH_LOG_FILE}"

    if [[ "${RLCH_LOG_TO_CONSOLE}" == "true" ]]; then
        printf '[%s] %s\n' \
            "${level}" \
            "${message}"
    fi
}