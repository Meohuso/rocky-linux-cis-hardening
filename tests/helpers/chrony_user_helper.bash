#!/usr/bin/env bash
#
# Test helper for CIS 2.3.3.
# SPDX-License-Identifier: MIT
#

chrony_user_helper_setup() {
    export RLCH_CIS_2_3_3_TEST_ROOT="${BATS_TEST_TMPDIR}/cis-2.3.3"
    export RLCH_CIS_2_3_3_CONFIG="${RLCH_CIS_2_3_3_TEST_ROOT}/chronyd"
    export RLCH_CIS_2_3_3_STATE_DIR="${RLCH_CIS_2_3_3_TEST_ROOT}/state"
    export RLCH_CIS_2_3_3_STATE_FILE="${RLCH_CIS_2_3_3_STATE_DIR}/original-state"
    export RLCH_CIS_2_3_3_BACKUP_FILE="${RLCH_CIS_2_3_3_STATE_DIR}/chronyd"
    export RLCH_CIS_2_3_3_ID_COMMAND="rlch_test_chrony_user_id"
    export RLCH_TEST_CHRONY_USER_EFFECTIVE_UID="0"
    export RLCH_TEST_CHRONY_USER_ID_FAIL="false"

    mkdir -p "${RLCH_CIS_2_3_3_TEST_ROOT}"
}

rlch_test_chrony_user_id() {
    [[ "${1:-}" == "-u" ]] || return 1
    [[ "${RLCH_TEST_CHRONY_USER_ID_FAIL}" != "true" ]] || return 1
    printf '%s\n' "${RLCH_TEST_CHRONY_USER_EFFECTIVE_UID}"
}
