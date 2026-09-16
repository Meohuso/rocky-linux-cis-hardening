#!/usr/bin/env bash
# Test helper for CIS 2.1.22.
# SPDX-License-Identifier: MIT

network_listener_inventory_helper_setup() {
    export RLCH_TEST_NETWORK_LISTENER_ROOT="${BATS_TEST_TMPDIR}/cis-2.1.22"
    export RLCH_TEST_NETWORK_LISTENER_ARGUMENT_FILE="${RLCH_TEST_NETWORK_LISTENER_ROOT}/ss-argument"
    export RLCH_CIS_2_1_22_SS_COMMAND="rlch_test_network_listener_ss"
    export RLCH_TEST_NETWORK_LISTENER_OUTPUT=""
    export RLCH_TEST_NETWORK_LISTENER_SS_FAIL="false"

    mkdir -p "${RLCH_TEST_NETWORK_LISTENER_ROOT}"
}

rlch_test_network_listener_ss() {
    printf '%s\n' "${1:-}" > "${RLCH_TEST_NETWORK_LISTENER_ARGUMENT_FILE}"
    [[ "${RLCH_TEST_NETWORK_LISTENER_SS_FAIL}" != "true" ]] || return 1
    printf '%s' "${RLCH_TEST_NETWORK_LISTENER_OUTPUT}"
}
