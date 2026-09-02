#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
#
# Bats helper for warning banner tests.
#
# SPDX-License-Identifier: MIT
#

setup_banner_test_environment() {
    RLCH_TEST_BANNER_DIR="${BATS_TEST_TMPDIR}/banner-test"
    RLCH_TEST_BANNER_BIN="${RLCH_TEST_BANNER_DIR}/bin"
    RLCH_TEST_BANNER_ETC="${RLCH_TEST_BANNER_DIR}/etc"

    mkdir -p "${RLCH_TEST_BANNER_BIN}" "${RLCH_TEST_BANNER_ETC}"

    cat > "${RLCH_TEST_BANNER_BIN}/id" <<'SCRIPT'
#!/usr/bin/env bash
if [[ "${1:-}" == "-u" ]]; then
    printf '%s\n' "${RLCH_TEST_BANNER_EFFECTIVE_UID:-0}"
    exit 0
fi
exec /usr/bin/id "$@"
SCRIPT

    cat > "${RLCH_TEST_BANNER_BIN}/chown" <<'SCRIPT'
#!/usr/bin/env bash
exit 0
SCRIPT

    chmod +x "${RLCH_TEST_BANNER_BIN}/id" "${RLCH_TEST_BANNER_BIN}/chown"

    export RLCH_TEST_BANNER_EFFECTIVE_UID=0
    PATH="${RLCH_TEST_BANNER_BIN}:${PATH}"
    export PATH

    RLCH_BANNER_BACKUP_SUFFIX=".rlch.bak"
}

teardown_banner_test_environment() {
    rm -rf "${RLCH_TEST_BANNER_DIR}"
}

set_banner_test_effective_uid() {
    export RLCH_TEST_BANNER_EFFECTIVE_UID="${1:?Effective UID is required}"
}

write_banner_test_os_release() {
    cat > "${RLCH_TEST_BANNER_ETC}/os-release"
}
