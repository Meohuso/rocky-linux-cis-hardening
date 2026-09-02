#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
#
# Bats helper for system-wide cryptographic policy tests.
#
# SPDX-License-Identifier: MIT
#

setup_crypto_policy_test_environment() {
    RLCH_TEST_CRYPTO_POLICY_DIR="${BATS_TEST_TMPDIR}/crypto-policy-test"
    RLCH_TEST_CRYPTO_POLICY_BIN="${RLCH_TEST_CRYPTO_POLICY_DIR}/bin"
    RLCH_TEST_CRYPTO_POLICY_STATE_DIR="${RLCH_TEST_CRYPTO_POLICY_DIR}/state"
    RLCH_TEST_CRYPTO_POLICY_RUNTIME_STATE="${RLCH_TEST_CRYPTO_POLICY_DIR}/current-policy"

    mkdir -p "${RLCH_TEST_CRYPTO_POLICY_BIN}" "${RLCH_TEST_CRYPTO_POLICY_STATE_DIR}"

    cat > "${RLCH_TEST_CRYPTO_POLICY_BIN}/id" <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" == "-u" ]]; then
    printf '%s\n' "${RLCH_TEST_CRYPTO_POLICY_EFFECTIVE_UID:-0}"
    exit 0
fi
exec /usr/bin/id "$@"
EOF

    cat > "${RLCH_TEST_CRYPTO_POLICY_BIN}/update-crypto-policies" <<'EOF'
#!/usr/bin/env bash
case "${1:-}" in
    --show)
        cat "${RLCH_TEST_CRYPTO_POLICY_RUNTIME_STATE}"
        ;;
    --set)
        [[ -n "${2:-}" ]] || exit 1
        printf '%s\n' "${2}" > "${RLCH_TEST_CRYPTO_POLICY_RUNTIME_STATE}"
        ;;
    *)
        exit 1
        ;;
esac
EOF

    chmod +x "${RLCH_TEST_CRYPTO_POLICY_BIN}/id" "${RLCH_TEST_CRYPTO_POLICY_BIN}/update-crypto-policies"

    export RLCH_TEST_CRYPTO_POLICY_EFFECTIVE_UID=0
    export RLCH_TEST_CRYPTO_POLICY_RUNTIME_STATE

    PATH="${RLCH_TEST_CRYPTO_POLICY_BIN}:${PATH}"
    export PATH

    RLCH_CRYPTO_POLICY_STATE_DIR="${RLCH_TEST_CRYPTO_POLICY_STATE_DIR}"
    RLCH_CRYPTO_POLICY_BACKUP_FILE="${RLCH_TEST_CRYPTO_POLICY_STATE_DIR}/crypto-policy.backup"
}

teardown_crypto_policy_test_environment() {
    rm -rf "${RLCH_TEST_CRYPTO_POLICY_DIR}"
}

set_crypto_policy_test_effective_uid() {
    export RLCH_TEST_CRYPTO_POLICY_EFFECTIVE_UID="${1:?Effective UID is required}"
}

set_crypto_policy_test_current() {
    printf '%s\n' "${1:?Policy is required}" > "${RLCH_TEST_CRYPTO_POLICY_RUNTIME_STATE}"
}
