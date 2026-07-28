#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
#
# SPDX-License-Identifier: MIT
#

# Prevent multiple sourcing.
if [[ -n "${RLCH_CONSTANTS_LOADED:-}" ]]; then
    return 0
fi
readonly RLCH_CONSTANTS_LOADED=1

##
# Load framework constants.
#
# Globals initialized:
#   RLCH_PROJECT_NAME
#   RLCH_ROOT_DIR
#   RLCH_LIB_DIR
#   RLCH_CONFIG_DIR
#   RLCH_AUDIT_DIR
#   RLCH_REPORT_DIR
#   RLCH_RUNTIME_DIR
#   RLCH_STATE_DIR
#   RLCH_TEMPLATE_DIR
#   RLCH_TEST_DIR
#   RLCH_LOG_DIR
#   RLCH_VERSION_FILE
#   RLCH_VERSION
#
# Returns:
#   0 on success.
##
load_constants() {

    if [[ -n "${RLCH_CONSTANTS_INITIALIZED:-}" ]]; then
        return 0
    fi

    readonly RLCH_PROJECT_NAME="Rocky Linux CIS Hardening Framework"

    readonly RLCH_ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

    readonly RLCH_LIB_DIR="${RLCH_ROOT_DIR}/lib"
    readonly RLCH_CONFIG_DIR="${RLCH_ROOT_DIR}/config"
    readonly RLCH_AUDIT_DIR="${RLCH_ROOT_DIR}/audit"
    readonly RLCH_REPORT_DIR="${RLCH_ROOT_DIR}/reports"
    readonly RLCH_RUNTIME_DIR="${RLCH_ROOT_DIR}/runtime"
    readonly RLCH_STATE_DIR="${RLCH_ROOT_DIR}/state"
    readonly RLCH_TEMPLATE_DIR="${RLCH_ROOT_DIR}/templates"
    readonly RLCH_TEST_DIR="${RLCH_ROOT_DIR}/tests"
    readonly RLCH_LOG_DIR="${RLCH_ROOT_DIR}/logs"

    readonly RLCH_VERSION_FILE="${RLCH_ROOT_DIR}/VERSION"

    if [[ -r "${RLCH_VERSION_FILE}" ]]; then
        readonly RLCH_VERSION="$(
            head -n 1 "${RLCH_VERSION_FILE}" | tr -d '[:space:]'
        )"
    else
        readonly RLCH_VERSION="0.0.0-dev"
    fi

    readonly RLCH_CONSTANTS_INITIALIZED=1
}