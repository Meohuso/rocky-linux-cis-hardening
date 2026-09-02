#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
#
# Bats helper for CIS 1.8.3 GDM user list tests.
#
# SPDX-License-Identifier: MIT
#

setup_gdm_user_list_test_environment() {
    RLCH_TEST_GDM_USER_LIST_DIR="${BATS_TEST_TMPDIR}/gdm-user-list-test"
    RLCH_TEST_GDM_USER_LIST_BIN="${RLCH_TEST_GDM_USER_LIST_DIR}/bin"
    RLCH_TEST_GDM_USER_LIST_ETC="${RLCH_TEST_GDM_USER_LIST_DIR}/etc"
    RLCH_TEST_GDM_USER_LIST_STATE="${RLCH_TEST_GDM_USER_LIST_DIR}/state"

    mkdir -p \
        "${RLCH_TEST_GDM_USER_LIST_BIN}" \
        "${RLCH_TEST_GDM_USER_LIST_ETC}" \
        "${RLCH_TEST_GDM_USER_LIST_STATE}"

    cat > "${RLCH_TEST_GDM_USER_LIST_BIN}/rpm" <<'SCRIPT'
#!/usr/bin/env bash
if [[ "${1:-}" == "-q" &&
      "${2:-}" == "gdm" &&
      "${RLCH_TEST_GDM_USER_LIST_INSTALLED:-false}" == "true" ]]; then
    exit 0
fi
exit 1
SCRIPT

    cat > "${RLCH_TEST_GDM_USER_LIST_BIN}/dconf" <<'SCRIPT'
#!/usr/bin/env bash
if [[ "${1:-}" == "update" ]]; then
    exit 0
fi
exit 1
SCRIPT

    cat > "${RLCH_TEST_GDM_USER_LIST_BIN}/chown" <<'SCRIPT'
#!/usr/bin/env bash
exit 0
SCRIPT

    chmod +x \
        "${RLCH_TEST_GDM_USER_LIST_BIN}/rpm" \
        "${RLCH_TEST_GDM_USER_LIST_BIN}/dconf" \
        "${RLCH_TEST_GDM_USER_LIST_BIN}/chown"

    export RLCH_TEST_GDM_USER_LIST_INSTALLED=false

    PATH="${RLCH_TEST_GDM_USER_LIST_BIN}:${PATH}"
    export PATH
}

teardown_gdm_user_list_test_environment() {
    rm -rf "${RLCH_TEST_GDM_USER_LIST_DIR}"
}

set_gdm_user_list_test_installed() {
    export RLCH_TEST_GDM_USER_LIST_INSTALLED="${1:?Installed state is required}"
}
