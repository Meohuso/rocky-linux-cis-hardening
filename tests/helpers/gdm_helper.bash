#!/usr/bin/env bash
setup_gdm_test_environment() {
    RLCH_TEST_GDM_DIR="${BATS_TEST_TMPDIR}/gdm-test"
    RLCH_TEST_GDM_BIN="${RLCH_TEST_GDM_DIR}/bin"
    RLCH_TEST_GDM_ETC="${RLCH_TEST_GDM_DIR}/etc"
    RLCH_TEST_GDM_STATE="${RLCH_TEST_GDM_DIR}/state"
    mkdir -p "${RLCH_TEST_GDM_BIN}" "${RLCH_TEST_GDM_ETC}" "${RLCH_TEST_GDM_STATE}"
    cat > "${RLCH_TEST_GDM_BIN}/rpm" <<'EOF'
#!/usr/bin/env bash
[[ "${1:-}" == "-q" && "${2:-}" == "gdm" && "${RLCH_TEST_GDM_INSTALLED:-false}" == "true" ]]
EOF
    cat > "${RLCH_TEST_GDM_BIN}/dconf" <<'EOF'
#!/usr/bin/env bash
[[ "${1:-}" == "update" ]]
EOF
    cat > "${RLCH_TEST_GDM_BIN}/chown" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
    chmod +x "${RLCH_TEST_GDM_BIN}/rpm" "${RLCH_TEST_GDM_BIN}/dconf" "${RLCH_TEST_GDM_BIN}/chown"
    export RLCH_TEST_GDM_INSTALLED=false
    PATH="${RLCH_TEST_GDM_BIN}:${PATH}"; export PATH
}
teardown_gdm_test_environment() { rm -rf "${RLCH_TEST_GDM_DIR}"; }
set_gdm_test_installed() { export RLCH_TEST_GDM_INSTALLED="$1"; }
