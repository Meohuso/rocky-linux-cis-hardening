#!/usr/bin/env bash
# SPDX-License-Identifier: MIT

setup_aide_test_environment() {
    RLCH_TEST_AIDE_DIR="${BATS_TEST_TMPDIR}/aide-test"
    RLCH_TEST_AIDE_BIN="${RLCH_TEST_AIDE_DIR}/bin"
    RLCH_TEST_AIDE_CONFIG="${RLCH_TEST_AIDE_DIR}/aide.conf"
    mkdir -p "${RLCH_TEST_AIDE_BIN}"
    : > "${RLCH_TEST_AIDE_CONFIG}"

    cat > "${RLCH_TEST_AIDE_BIN}/id" <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" == "-u" ]]; then
    printf '%s\n' "${RLCH_TEST_EFFECTIVE_UID:-0}"
    exit 0
fi
exec /usr/bin/id "$@"
EOF
    chmod +x "${RLCH_TEST_AIDE_BIN}/id"

    export RLCH_TEST_EFFECTIVE_UID=0
    PATH="${RLCH_TEST_AIDE_BIN}:${PATH}"
    export PATH
    RLCH_AIDE_CONFIG="${RLCH_TEST_AIDE_CONFIG}"
    RLCH_AIDE_CONFIG_BACKUP_SUFFIX=".rlch.bak"
}

teardown_aide_test_environment() { rm -rf "${RLCH_TEST_AIDE_DIR}"; }

set_aide_test_effective_uid() {
    export RLCH_TEST_EFFECTIVE_UID="${1:?Effective UID is required}"
}

write_aide_test_config() { cat > "${RLCH_TEST_AIDE_CONFIG}"; }

create_aide_test_backup() {
    cp -p -- "${RLCH_TEST_AIDE_CONFIG}" "${RLCH_TEST_AIDE_CONFIG}${RLCH_AIDE_CONFIG_BACKUP_SUFFIX}"
}
