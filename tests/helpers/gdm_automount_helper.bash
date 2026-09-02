#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
# Bats helper for CIS 1.8.6.
# SPDX-License-Identifier: MIT
#
setup_gdm_automount_test_environment() {
    RLCH_TEST_GDM_AUTOMOUNT_DIR="${BATS_TEST_TMPDIR}/gdm-automount-test"
    RLCH_TEST_GDM_AUTOMOUNT_BIN="${RLCH_TEST_GDM_AUTOMOUNT_DIR}/bin"
    RLCH_TEST_GDM_AUTOMOUNT_ETC="${RLCH_TEST_GDM_AUTOMOUNT_DIR}/etc"
    RLCH_TEST_GDM_AUTOMOUNT_STATE="${RLCH_TEST_GDM_AUTOMOUNT_DIR}/state"
    mkdir -p "${RLCH_TEST_GDM_AUTOMOUNT_BIN}" "${RLCH_TEST_GDM_AUTOMOUNT_ETC}" "${RLCH_TEST_GDM_AUTOMOUNT_STATE}"
    cat > "${RLCH_TEST_GDM_AUTOMOUNT_BIN}/rpm" <<'SCRIPT'
#!/usr/bin/env bash
if [[ "${1:-}" == "-q" && "${2:-}" == "gdm" &&
      "${RLCH_TEST_GDM_AUTOMOUNT_INSTALLED:-false}" == "true" ]]; then
    exit 0
fi
exit 1
SCRIPT
    cat > "${RLCH_TEST_GDM_AUTOMOUNT_BIN}/dconf" <<'SCRIPT'
#!/usr/bin/env bash
[[ "${1:-}" == "update" ]]
SCRIPT
    cat > "${RLCH_TEST_GDM_AUTOMOUNT_BIN}/chown" <<'SCRIPT'
#!/usr/bin/env bash
exit 0
SCRIPT
    chmod +x "${RLCH_TEST_GDM_AUTOMOUNT_BIN}/rpm" "${RLCH_TEST_GDM_AUTOMOUNT_BIN}/dconf" "${RLCH_TEST_GDM_AUTOMOUNT_BIN}/chown"
    export RLCH_TEST_GDM_AUTOMOUNT_INSTALLED=false
    PATH="${RLCH_TEST_GDM_AUTOMOUNT_BIN}:${PATH}"
    export PATH
}
teardown_gdm_automount_test_environment() { rm -rf "${RLCH_TEST_GDM_AUTOMOUNT_DIR}"; }
set_gdm_automount_test_installed() { export RLCH_TEST_GDM_AUTOMOUNT_INSTALLED="${1:?Installed state required}"; }
