#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
#
# Bats helper for CIS 1.8.10.
#
# SPDX-License-Identifier: MIT
#

setup_gdm_xdmcp_test_environment() {
    RLCH_TEST_GDM_XDMCP_DIR="${BATS_TEST_TMPDIR}/gdm-xdmcp-test"
    RLCH_TEST_GDM_XDMCP_BIN="${RLCH_TEST_GDM_XDMCP_DIR}/bin"
    RLCH_TEST_GDM_XDMCP_ETC="${RLCH_TEST_GDM_XDMCP_DIR}/etc"
    RLCH_TEST_GDM_XDMCP_STATE="${RLCH_TEST_GDM_XDMCP_DIR}/state"

    mkdir -p \
        "${RLCH_TEST_GDM_XDMCP_BIN}" \
        "${RLCH_TEST_GDM_XDMCP_ETC}" \
        "${RLCH_TEST_GDM_XDMCP_STATE}"

    cat > "${RLCH_TEST_GDM_XDMCP_BIN}/rpm" <<'SCRIPT'
#!/usr/bin/env bash
if [[ "${1:-}" == "-q" &&
      "${2:-}" == "gdm" &&
      "${RLCH_TEST_GDM_XDMCP_INSTALLED:-false}" == "true" ]]; then
    exit 0
fi
exit 1
SCRIPT

    cat > "${RLCH_TEST_GDM_XDMCP_BIN}/chown" <<'SCRIPT'
#!/usr/bin/env bash
exit 0
SCRIPT

    chmod +x \
        "${RLCH_TEST_GDM_XDMCP_BIN}/rpm" \
        "${RLCH_TEST_GDM_XDMCP_BIN}/chown"

    export RLCH_TEST_GDM_XDMCP_INSTALLED=false

    PATH="${RLCH_TEST_GDM_XDMCP_BIN}:${PATH}"
    export PATH
}

teardown_gdm_xdmcp_test_environment() {
    rm -rf "${RLCH_TEST_GDM_XDMCP_DIR}"
}

set_gdm_xdmcp_test_installed() {
    export RLCH_TEST_GDM_XDMCP_INSTALLED="${1:?Installed state is required}"
}
