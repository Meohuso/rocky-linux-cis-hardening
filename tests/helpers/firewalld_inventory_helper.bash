#!/usr/bin/env bash
# Test helper for CIS 4.2.1.
# SPDX-License-Identifier: MIT

firewalld_inventory_helper_setup() {
    export RLCH_TEST_FIREWALLD_INVENTORY_ROOT="${BATS_TEST_TMPDIR}/cis-4.2.1"
    export RLCH_TEST_FIREWALLD_INVENTORY_ARGUMENT_FILE="${RLCH_TEST_FIREWALLD_INVENTORY_ROOT}/arguments"
    export RLCH_CIS_4_2_1_FIREWALL_CMD="rlch_test_firewalld_inventory"
    export RLCH_TEST_FIREWALLD_INVENTORY_OUTPUT=$'public (active)\n  services: cockpit ssh\n  ports: 6443/tcp'
    export RLCH_TEST_FIREWALLD_INVENTORY_FAIL="false"

    mkdir -p "${RLCH_TEST_FIREWALLD_INVENTORY_ROOT}"
}

rlch_test_firewalld_inventory() {
    printf '%s\n' "$*" > "${RLCH_TEST_FIREWALLD_INVENTORY_ARGUMENT_FILE}"
    [[ "${RLCH_TEST_FIREWALLD_INVENTORY_FAIL}" != "true" ]] || return 1
    printf '%s\n' "${RLCH_TEST_FIREWALLD_INVENTORY_OUTPUT}"
}
