#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
#
# CIS 1.4.2 - Ensure access to bootloader config is configured.
#
# SPDX-License-Identifier: MIT
#

RLCH_CIS_1_4_2_GRUB_CONFIG="${RLCH_CIS_1_4_2_GRUB_CONFIG:-${RLCH_GRUB_CONFIG:-/boot/grub2/grub.cfg}}"
RLCH_CIS_1_4_2_USER_CONFIG="${RLCH_CIS_1_4_2_USER_CONFIG:-${RLCH_GRUB_USER_CONFIG:-/boot/grub2/user.cfg}}"

check() {
    if ! grub_file_access_is_configured "${RLCH_CIS_1_4_2_GRUB_CONFIG}"; then
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi

    if ! grub_file_access_is_configured "${RLCH_CIS_1_4_2_USER_CONFIG}"; then
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi

    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

apply() {
    local file
    local result
    local changed="false"

    for file in \
        "${RLCH_CIS_1_4_2_GRUB_CONFIG}" \
        "${RLCH_CIS_1_4_2_USER_CONFIG}"; do
        grub_set_file_access "${file}"
        result=$?

        if [[ "${result}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]]; then
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi

        if [[ "${result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]]; then
            changed="true"
        fi
    done

    if [[ "${changed}" == "true" ]]; then
        return "${RLCH_MODULE_RESULT_CHANGED}"
    fi

    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

validate() {
    check
}

rollback() {
    local file
    local result
    local changed="false"

    for file in \
        "${RLCH_CIS_1_4_2_GRUB_CONFIG}" \
        "${RLCH_CIS_1_4_2_USER_CONFIG}"; do
        grub_rollback_file_access "${file}"
        result=$?

        if [[ "${result}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]]; then
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi

        if [[ "${result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]]; then
            changed="true"
        fi
    done

    if [[ "${changed}" == "true" ]]; then
        return "${RLCH_MODULE_RESULT_CHANGED}"
    fi

    return "${RLCH_MODULE_RESULT_SUCCESS}"
}
