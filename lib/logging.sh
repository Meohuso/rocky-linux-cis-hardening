#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
#
# Logging library
#

[[ "${BASH_SOURCE[0]}" != "${0}" ]] || {
    echo "This file must be sourced."
    exit 1
}

#------------------------------------------------------------------------------
# Internal logging function
#------------------------------------------------------------------------------

_log() {
    local level="$1"
    local message="$2"
    local timestamp

    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"

    printf "[%s] [%5s] %s\n" \
        "${timestamp}" \
        "${level}" \
        "${message}" | tee -a "${LOG_FILE}"
}

#------------------------------------------------------------------------------
# Public API
#------------------------------------------------------------------------------

log_debug() {
    [[ "${LOG_LEVEL}" == "DEBUG" ]] || return 0
    _log "DEBUG" "$1"
}

log_info() {
    _log "INFO" "$1"
}

log_warn() {
    _log "WARN" "$1"
}

log_error() {
    _log "ERROR" "$1"
}

log_success() {
    _log "SUCCESS" "$1"
}

log_fatal() {
    _log "FATAL" "$1"
    exit "${EXIT_ERROR}"
}