#!/usr/bin/env bash
# CIS 5.3.1.2 - Verify latest authselect version in enabled repositories.
# SPDX-License-Identifier: MIT

RLCH_CIS_5_3_1_2_RPM="${RLCH_CIS_5_3_1_2_RPM:-rpm}"
RLCH_CIS_5_3_1_2_DNF="${RLCH_CIS_5_3_1_2_DNF:-dnf5}"

check() {
    local result=0 available
    "${RLCH_CIS_5_3_1_2_RPM}" -q authselect >/dev/null 2>&1 ||
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"

    # Force metadata refresh and reject unavailable enabled repositories. A
    # cached or empty repository view cannot prove "latest version".
    available="$("${RLCH_CIS_5_3_1_2_DNF}" --refresh \
        --setopt=skip_if_unavailable=False repoquery --available \
        --queryformat='%{name}' authselect 2>/dev/null)" || return "${RLCH_MODULE_RESULT_ERROR}"
    [[ "${available}" =~ (^|[[:space:]])authselect($|[[:space:]]) ]] || return "${RLCH_MODULE_RESULT_ERROR}"
    "${RLCH_CIS_5_3_1_2_DNF}" --refresh --setopt=skip_if_unavailable=False \
        check-upgrade authselect >/dev/null 2>&1 || result=$?
    case "${result}" in
        0) return "${RLCH_MODULE_RESULT_SUCCESS}" ;;
        100) return "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ;;
        *) return "${RLCH_MODULE_RESULT_ERROR}" ;;
    esac
}

apply() {
    local result=0
    check || result=$?
    [[ "${result}" -ne "${RLCH_MODULE_RESULT_SUCCESS}" ]] || return "${RLCH_MODULE_RESULT_SUCCESS}"
    [[ "${result}" -ne "${RLCH_MODULE_RESULT_ERROR}" ]] || return "${RLCH_MODULE_RESULT_ERROR}"
    # authselect is a core authentication package. Downgrading system packages through
    # DNF history is unsupported on RHEL 10, and an old RPM may be unavailable.
    # Do not start a transaction that this framework cannot safely undo.
    error_message "CIS 5.3.1.2 requires a planned authselect installation or upgrade with a system snapshot and recovery path."
    return "${RLCH_MODULE_RESULT_ERROR}"
}

validate() { check; }

rollback() {
    # This control never changes packages automatically.
    return "${RLCH_MODULE_RESULT_SUCCESS}"
}
