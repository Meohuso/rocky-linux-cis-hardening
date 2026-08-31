#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
#
# Reusable RPM package and signing-key helpers.
#
# SPDX-License-Identifier: MIT
#

RLCH_RPM_COMMAND="${RLCH_RPM_COMMAND:-rpm}"

rpm_list_gpg_keys() {
    "${RLCH_RPM_COMMAND}" -q gpg-pubkey 2>/dev/null
}

rpm_has_gpg_keys() {
    local output

    if ! output="$(rpm_list_gpg_keys)"; then
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi

    if [[ -z "${output}" ]]; then
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi

    return "${RLCH_MODULE_RESULT_COMPLIANT}"
}
