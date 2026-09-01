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
    RLCH_TEST_GRUB_BIN="${RLCH_TEST_GRUB_DIR}/bin"
    RLCH_TEST_GRUB_CONFIG="${RLCH_TEST_GRUB_DIR}/grub.cfg"
    RLCH_TEST_GRUB_USER_CONFIG="${RLCH_TEST_GRUB_DIR}/user.cfg"

    mkdir -p "${RLCH_TEST_GRUB_BIN}"

    cat > "${RLCH_TEST_GRUB_BIN}/id" <<'EOF'
#!/usr/bin/env bash

if [[ "${1:-}" == "-u" ]]; then
    printf '%s\n' "${RLCH_TEST_GRUB_EFFECTIVE_UID:-0}"
    exit 0
fi

exec /usr/bin/id "$@"
EOF

    chmod +x "${RLCH_TEST_GRUB_BIN}/id"

    export RLCH_TEST_GRUB_EFFECTIVE_UID=0

    PATH="${RLCH_TEST_GRUB_BIN}:${PATH}"
    export PATH

    RLCH_GRUB_CONFIG="${RLCH_TEST_GRUB_CONFIG}"
    RLCH_GRUB_USER_CONFIG="${RLCH_TEST_GRUB_USER_CONFIG}"
    RLCH_GRUB_BACKUP_SUFFIX=".rlch.bak"
}

teardown_grub_test_environment() {
    rm -rf "${RLCH_TEST_GRUB_DIR}"
}

set_grub_test_effective_uid() {
    local uid="${1:?Effective UID is required}"

    export RLCH_TEST_GRUB_EFFECTIVE_UID="${uid}"
}

write_grub_test_config() {
    cat > "${RLCH_TEST_GRUB_CONFIG}"
}

write_grub_test_user_config() {
    cat > "${RLCH_TEST_GRUB_USER_CONFIG}"
}
