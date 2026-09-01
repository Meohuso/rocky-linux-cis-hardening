#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
#
# Bats helper for systemd-coredump tests.
#
# SPDX-License-Identifier: MIT
#

setup_coredump_test_environment() {
    RLCH_TEST_COREDUMP_DIR="${BATS_TEST_TMPDIR}/coredump-test"
    RLCH_TEST_COREDUMP_BIN="${RLCH_TEST_COREDUMP_DIR}/bin"
    RLCH_TEST_COREDUMP_CONFIG_DIR="${RLCH_TEST_COREDUMP_DIR}/coredump.conf.d"
    RLCH_TEST_COREDUMP_CONFIG="${RLCH_TEST_COREDUMP_CONFIG_DIR}/60-rlch-coredump.conf"

    mkdir -p "${RLCH_TEST_COREDUMP_BIN}" "${RLCH_TEST_COREDUMP_CONFIG_DIR}"

    cat > "${RLCH_TEST_COREDUMP_BIN}/id" <<'EOF'
#!/usr/bin/env bash

if [[ "${1:-}" == "-u" ]]; then
    printf '%s\n' "${RLCH_TEST_COREDUMP_EFFECTIVE_UID:-0}"
    exit 0
fi

exec /usr/bin/id "$@"
EOF

    cat > "${RLCH_TEST_COREDUMP_BIN}/chown" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF

    chmod +x "${RLCH_TEST_COREDUMP_BIN}/id" "${RLCH_TEST_COREDUMP_BIN}/chown"

    export RLCH_TEST_COREDUMP_EFFECTIVE_UID=0

    PATH="${RLCH_TEST_COREDUMP_BIN}:${PATH}"
    export PATH

    RLCH_COREDUMP_CONFIG_DIR="${RLCH_TEST_COREDUMP_CONFIG_DIR}"
    RLCH_COREDUMP_BACKUP_SUFFIX=".rlch.bak"
}

teardown_coredump_test_environment() {
    rm -rf "${RLCH_TEST_COREDUMP_DIR}"
}

set_coredump_test_effective_uid() {
    local uid="${1:?Effective UID is required}"

    export RLCH_TEST_COREDUMP_EFFECTIVE_UID="${uid}"
}

write_coredump_test_config() {
    cat > "${RLCH_TEST_COREDUMP_CONFIG}"
}
