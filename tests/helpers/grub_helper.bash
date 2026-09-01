#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
#
# Bats helper for GRUB2-related tests.
#
# SPDX-License-Identifier: MIT
#

setup_grub_test_environment() {
    RLCH_TEST_GRUB_DIR="${BATS_TEST_TMPDIR}/grub-test"
    RLCH_TEST_GRUB_USER_CONFIG="${RLCH_TEST_GRUB_DIR}/user.cfg"

    mkdir -p "${RLCH_TEST_GRUB_DIR}"

    RLCH_GRUB_USER_CONFIG="${RLCH_TEST_GRUB_USER_CONFIG}"
}

teardown_grub_test_environment() {
    rm -rf "${RLCH_TEST_GRUB_DIR}"
}

write_grub_test_user_config() {
    cat > "${RLCH_TEST_GRUB_USER_CONFIG}"
}
