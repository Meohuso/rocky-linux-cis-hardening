#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
#
# Global constants
#

#------------------------------------------------------------------------------
# Project information
#------------------------------------------------------------------------------

readonly PROJECT_NAME="rocky-linux-cis-hardening"
readonly PROJECT_VERSION="$(< VERSION)"

#------------------------------------------------------------------------------
# Directories
#------------------------------------------------------------------------------

readonly PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

readonly LIB_DIR="${PROJECT_ROOT}/lib"
readonly SCRIPT_DIR="${PROJECT_ROOT}/scripts"
readonly TEMPLATE_DIR="${PROJECT_ROOT}/templates"
readonly STATE_DIR="${PROJECT_ROOT}/state"
readonly REPORT_DIR="${PROJECT_ROOT}/reports"
readonly LOG_DIR="${PROJECT_ROOT}/logs"
readonly AUDIT_DIR="${PROJECT_ROOT}/audit"
readonly TEST_DIR="${PROJECT_ROOT}/tests"

#------------------------------------------------------------------------------
# Runtime
#------------------------------------------------------------------------------

readonly LOG_FILE="${LOG_DIR}/framework.log"

readonly REPORT_HTML="${REPORT_DIR}/report.html"
readonly REPORT_XML="${REPORT_DIR}/report.xml"

#------------------------------------------------------------------------------
# Exit codes
#------------------------------------------------------------------------------

readonly EXIT_SUCCESS=0
readonly EXIT_ERROR=1
readonly EXIT_CONFIGURATION_ERROR=2
readonly EXIT_PREREQUISITE_ERROR=3
readonly EXIT_VALIDATION_ERROR=4

#------------------------------------------------------------------------------
# Colors
#------------------------------------------------------------------------------

readonly COLOR_RED="\033[31m"
readonly COLOR_GREEN="\033[32m"
readonly COLOR_YELLOW="\033[33m"
readonly COLOR_BLUE="\033[34m"
readonly COLOR_RESET="\033[0m"