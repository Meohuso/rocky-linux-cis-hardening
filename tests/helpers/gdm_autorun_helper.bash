#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
#
# Bats helper for CIS 1.8.8.
#
# SPDX-License-Identifier: MIT
#

setup_gdm_autorun_test_environment() {
    RLCH_TEST_GDM_AUTORUN_DIR="${BATS_TEST_TMPDIR}/gdm-autorun-test"
    RLCH_TEST_GDM_AUTORUN_BIN="${RLCH_TEST_GDM_AUTORUN_DIR}/bin"
    RLCH_TEST_GDM_AUTORUN_ETC="${RLCH_TEST_GDM_AUTORUN_DIR}/etc"
    RLCH_TEST_GDM_AUTORUN_STATE="${RLCH_TEST_GDM_AUTORUN_DIR}/state"

    mkdir -p \
        "${RLCH_TEST_GDM_AUTORUN_BIN}" \
        "${RLCH_TEST_GDM_AUTORUN_ETC}" \
        "${RLCH_TEST_GDM_AUTORUN_STATE}"

    cat > "${RLCH_TEST_GDM_AUTORUN_BIN}/rpm" <<'SCRIPT'
#!/usr/bin/env bash
if [[ "${1:-}" == "-q" &&
      "${2:-}" == "gdm" &&
      "${RLCH_TEST_GDM_AUTORUN_INSTALLED:-false}" == "true" ]]; then
    exit 0
fi
exit 1
SCRIPT

    cat > "${RLCH_TEST_GDM_AUTORUN_BIN}/dconf" <<'SCRIPT'
#!/usr/bin/env bash
if [[ "${1:-}" == "update" ]]; then
    exit 0
fi
exit 1
SCRIPT

    cat > "${RLCH_TEST_GDM_AUTORUN_BIN}/chown" <<'SCRIPT'
#!/usr/bin/env bash
exit 0
SCRIPT

    chmod +x \
        "${RLCH_TEST_GDM_AUTORUN_BIN}/rpm" \
        "${RLCH_TEST_GDM_AUTORUN_BIN}/dconf" \
        "${RLCH_TEST_GDM_AUTORUN_BIN}/chown"

    export RLCH_TEST_GDM_AUTORUN_INSTALLED=false

    PATH="${RLCH_TEST_GDM_AUTORUN_BIN}:${PATH}"
    export PATH
}

teardown_gdm_autorun_test_environment() {
    rm -rf "${RLCH_TEST_GDM_AUTORUN_DIR}"
}

set_gdm_autorun_test_installed() {
    export RLCH_TEST_GDM_AUTORUN_INSTALLED="${1:?Installed state is required}"
}
