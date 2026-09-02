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
    RLCH_TEST_CRYPTO_POLICY_MODULE_DIR="${RLCH_TEST_CRYPTO_POLICY_DIR}/modules"
    RLCH_TEST_CRYPTO_POLICY_RUNTIME_STATE="${RLCH_TEST_CRYPTO_POLICY_DIR}/current-policy"
    RLCH_TEST_CRYPTO_POLICY_CURRENT_FILE="${RLCH_TEST_CRYPTO_POLICY_DIR}/CURRENT.pol"

    mkdir -p "${RLCH_TEST_CRYPTO_POLICY_BIN}" "${RLCH_TEST_CRYPTO_POLICY_STATE_DIR}" "${RLCH_TEST_CRYPTO_POLICY_MODULE_DIR}"

    cat > "${RLCH_TEST_CRYPTO_POLICY_BIN}/id" <<'SCRIPT'
#!/usr/bin/env bash
if [[ "${1:-}" == "-u" ]]; then
    printf '%s\n' "${RLCH_TEST_CRYPTO_POLICY_EFFECTIVE_UID:-0}"
    exit 0
fi
exec /usr/bin/id "$@"
SCRIPT

    cat > "${RLCH_TEST_CRYPTO_POLICY_BIN}/chown" <<'SCRIPT'
#!/usr/bin/env bash
exit 0
SCRIPT

    cat > "${RLCH_TEST_CRYPTO_POLICY_BIN}/update-crypto-policies" <<'SCRIPT'
#!/usr/bin/env bash
case "${1:-}" in
    --show)
        cat "${RLCH_TEST_CRYPTO_POLICY_RUNTIME_STATE}"
        ;;
    --set)
        [[ -n "${2:-}" ]] || exit 1
        printf '%s\n' "${2}" > "${RLCH_TEST_CRYPTO_POLICY_RUNTIME_STATE}"
        if [[ ":${2}:" == *":NO-SHA1:"* ]]; then
            printf '%s\n' 'hash = SHA2-256 SHA2-384 SHA2-512' 'sign = RSA-SHA2-256 RSA-SHA2-384 RSA-SHA2-512' 'sha1_in_certs = 0' > "${RLCH_TEST_CRYPTO_POLICY_CURRENT_FILE}"
        else
            printf '%s\n' 'hash = SHA1 SHA2-256 SHA2-384 SHA2-512' 'sign = RSA-SHA1 RSA-SHA2-256 RSA-SHA2-384 RSA-SHA2-512' 'sha1_in_certs = 1' > "${RLCH_TEST_CRYPTO_POLICY_CURRENT_FILE}"
        fi
        ;;
    *) exit 1 ;;
esac
SCRIPT

    chmod +x "${RLCH_TEST_CRYPTO_POLICY_BIN}/id" "${RLCH_TEST_CRYPTO_POLICY_BIN}/chown" "${RLCH_TEST_CRYPTO_POLICY_BIN}/update-crypto-policies"
    export RLCH_TEST_CRYPTO_POLICY_EFFECTIVE_UID=0 RLCH_TEST_CRYPTO_POLICY_RUNTIME_STATE RLCH_TEST_CRYPTO_POLICY_CURRENT_FILE
    PATH="${RLCH_TEST_CRYPTO_POLICY_BIN}:${PATH}"
    export PATH

    RLCH_CRYPTO_POLICY_STATE_DIR="${RLCH_TEST_CRYPTO_POLICY_STATE_DIR}"
    RLCH_CRYPTO_POLICY_BACKUP_FILE="${RLCH_TEST_CRYPTO_POLICY_STATE_DIR}/crypto-policy.backup"
    RLCH_CRYPTO_POLICY_MODULE_DIR="${RLCH_TEST_CRYPTO_POLICY_MODULE_DIR}"
    RLCH_CRYPTO_POLICY_CURRENT_FILE="${RLCH_TEST_CRYPTO_POLICY_CURRENT_FILE}"
    RLCH_CRYPTO_POLICY_BACKUP_SUFFIX=".rlch.bak"
}

teardown_crypto_policy_test_environment() { rm -rf "${RLCH_TEST_CRYPTO_POLICY_DIR}"; }
set_crypto_policy_test_effective_uid() { export RLCH_TEST_CRYPTO_POLICY_EFFECTIVE_UID="${1:?Effective UID is required}"; }
set_crypto_policy_test_current() { printf '%s\n' "${1:?Policy is required}" > "${RLCH_TEST_CRYPTO_POLICY_RUNTIME_STATE}"; }
write_crypto_policy_test_current_file() { cat > "${RLCH_TEST_CRYPTO_POLICY_CURRENT_FILE}"; }
