#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
#
# Bats helper for RPM-related tests.
#
# SPDX-License-Identifier: MIT
#

setup_rpm_test_environment() {
    RLCH_TEST_RPM_DIR="${BATS_TEST_TMPDIR}/rpm-test"
    RLCH_TEST_RPM_BIN="${RLCH_TEST_RPM_DIR}/bin"
    RLCH_TEST_RPM_KEYS="${RLCH_TEST_RPM_DIR}/gpg-keys"
    RLCH_TEST_RPM_EXIT_STATUS="${RLCH_TEST_RPM_DIR}/exit-status"

    mkdir -p "${RLCH_TEST_RPM_BIN}"
    : > "${RLCH_TEST_RPM_KEYS}"
    printf '0\n' > "${RLCH_TEST_RPM_EXIT_STATUS}"

    cat > "${RLCH_TEST_RPM_BIN}/rpm" <<'EOF'
#!/usr/bin/env bash

if [[ "${1:-}" != "-q" || "${2:-}" != "gpg-pubkey" ]]; then
    exit 2
fi

status="$(cat "${RLCH_TEST_RPM_EXIT_STATUS}")"

if [[ "${status}" -ne 0 ]]; then
    exit "${status}"
fi

cat "${RLCH_TEST_RPM_KEYS}"
EOF

    chmod +x "${RLCH_TEST_RPM_BIN}/rpm"

    export RLCH_TEST_RPM_KEYS
    export RLCH_TEST_RPM_EXIT_STATUS
    RLCH_RPM_COMMAND="${RLCH_TEST_RPM_BIN}/rpm"
}

teardown_rpm_test_environment() {
    rm -rf "${RLCH_TEST_RPM_DIR}"
}

add_rpm_test_gpg_key() {
    local package_name="${1:?GPG key package name is required}"

    printf '%s\n' "${package_name}" >> "${RLCH_TEST_RPM_KEYS}"
}

set_rpm_test_exit_status() {
    local status="${1:?Exit status is required}"

    printf '%s\n' "${status}" > "${RLCH_TEST_RPM_EXIT_STATUS}"
}
