#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
#
# Reusable GRUB2 helpers.
#
# SPDX-License-Identifier: MIT
#

if [[ -n "${RLCH_GRUB_LOADED:-}" ]]; then
    return 0
fi
readonly RLCH_GRUB_LOADED=1

RLCH_GRUB_USER_CONFIG="${RLCH_GRUB_USER_CONFIG:-/boot/grub2/user.cfg}"

grub_password_is_configured() {
    local user_config="${1:-${RLCH_GRUB_USER_CONFIG}}"

    if [[ ! -s "${user_config}" ]]; then
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi

    if awk '
        /^[[:space:]]*GRUB2_PASSWORD=grub\.pbkdf2\.sha512\.[^[:space:]]+[[:space:]]*$/ {
            found = 1
        }

        END {
            exit(found ? 0 : 1)
        }
    ' "${user_config}"; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
}
