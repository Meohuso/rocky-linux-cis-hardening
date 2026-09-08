#!/usr/bin/env bash
setup_rpcbind_server_test_environment() {
    RLCH_TEST_RPCBIND_DIR="${BATS_TEST_TMPDIR}/rpcbind-test"
    RLCH_TEST_RPCBIND_BIN="${RLCH_TEST_RPCBIND_DIR}/bin"
    RLCH_TEST_RPCBIND_PACKAGES="${RLCH_TEST_RPCBIND_DIR}/packages"
    RLCH_TEST_RPCBIND_UNITS="${RLCH_TEST_RPCBIND_DIR}/units"
    RLCH_TEST_RPCBIND_STATE="${RLCH_TEST_RPCBIND_DIR}/state"
    mkdir -p "${RLCH_TEST_RPCBIND_BIN}" "${RLCH_TEST_RPCBIND_UNITS}" "${RLCH_TEST_RPCBIND_STATE}"
    : > "${RLCH_TEST_RPCBIND_PACKAGES}"
    cat > "${RLCH_TEST_RPCBIND_BIN}/rpm" <<'EOF'
#!/usr/bin/env bash
[[ "${1:-}" == "-q" ]] || exit 2
grep -Fxq -- "${2:-}" "${RLCH_TEST_RPCBIND_PACKAGES:?}"
EOF
    cat > "${RLCH_TEST_RPCBIND_BIN}/systemctl" <<'EOF'
#!/usr/bin/env bash
dir="${RLCH_TEST_RPCBIND_UNITS:?}"
cmd="${1:-}"
if [[ "${cmd}" == "is-active" ]]; then unit="${3:-}"; else unit="${2:-}"; fi
name="${unit//./_}"
ef="${dir}/${name}.enabled"; af="${dir}/${name}.active"
case "${cmd}" in
 is-active) [[ "$(cat -- "${af}")" == "active" ]] ;;
 is-enabled) s="$(cat -- "${ef}")"; printf '%s\n' "${s}"; [[ "${s}" == "enabled" ]] ;;
 stop) printf '%s\n' inactive > "${af}" ;;
 start) printf '%s\n' active > "${af}" ;;
 disable) printf '%s\n' disabled > "${ef}" ;;
 enable) printf '%s\n' enabled > "${ef}" ;;
 mask) printf '%s\n' masked > "${ef}" ;;
 unmask) printf '%s\n' disabled > "${ef}" ;;
 *) exit 2 ;;
esac
EOF
    chmod +x "${RLCH_TEST_RPCBIND_BIN}/rpm" "${RLCH_TEST_RPCBIND_BIN}/systemctl"
    export RLCH_TEST_RPCBIND_PACKAGES RLCH_TEST_RPCBIND_UNITS
    RLCH_CIS_2_1_12_RPM_COMMAND="${RLCH_TEST_RPCBIND_BIN}/rpm"
    RLCH_CIS_2_1_12_SYSTEMCTL_COMMAND="${RLCH_TEST_RPCBIND_BIN}/systemctl"
    set_rpcbind_unit_state rpcbind.service disabled inactive
    set_rpcbind_unit_state rpcbind.socket disabled inactive
}
teardown_rpcbind_server_test_environment() { rm -rf "${RLCH_TEST_RPCBIND_DIR}"; }
add_rpcbind_package() { printf '%s\n' rpcbind > "${RLCH_TEST_RPCBIND_PACKAGES}"; }
set_rpcbind_unit_state() {
    local n="${1//./_}"
    printf '%s\n' "${2}" > "${RLCH_TEST_RPCBIND_UNITS}/${n}.enabled"
    printf '%s\n' "${3}" > "${RLCH_TEST_RPCBIND_UNITS}/${n}.active"
}
get_rpcbind_enabled() { local n="${1//./_}"; cat "${RLCH_TEST_RPCBIND_UNITS}/${n}.enabled"; }
get_rpcbind_active() { local n="${1//./_}"; cat "${RLCH_TEST_RPCBIND_UNITS}/${n}.active"; }
