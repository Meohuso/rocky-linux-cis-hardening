#!/usr/bin/env bash
#
# Test helper for CIS 2.3.2.
# SPDX-License-Identifier: MIT
#

chrony_config_helper_setup() {
    export RLCH_CIS_2_3_2_TEST_ROOT="${BATS_TEST_TMPDIR}/cis-2.3.2"
    export RLCH_CIS_2_3_2_CONFIG="${RLCH_CIS_2_3_2_TEST_ROOT}/chrony.conf"
    export RLCH_CIS_2_3_2_STATE_DIR="${RLCH_CIS_2_3_2_TEST_ROOT}/state"
    export RLCH_CIS_2_3_2_STATE_FILE="${RLCH_CIS_2_3_2_STATE_DIR}/original-state"
    export RLCH_CIS_2_3_2_BACKUP_FILE="${RLCH_CIS_2_3_2_STATE_DIR}/chrony.conf"
    export RLCH_CIS_2_3_2_ID_COMMAND="rlch_test_chrony_config_id"
    export RLCH_CIS_2_3_2_SERVERS="0.rhel.pool.ntp.org,1.rhel.pool.ntp.org,2.rhel.pool.ntp.org,3.rhel.pool.ntp.org"
    export RLCH_TEST_CHRONY_CONFIG_EFFECTIVE_UID="0"
    export RLCH_TEST_CHRONY_CONFIG_ID_FAIL="false"

    mkdir -p "${RLCH_CIS_2_3_2_TEST_ROOT}"
}

rlch_test_chrony_config_id() {
    [[ "${1:-}" == "-u" ]] || return 1
    [[ "${RLCH_TEST_CHRONY_CONFIG_ID_FAIL}" != "true" ]] || return 1
    printf '%s\n' "${RLCH_TEST_CHRONY_CONFIG_EFFECTIVE_UID}"
}
