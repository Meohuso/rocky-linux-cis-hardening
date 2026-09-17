#!/usr/bin/env bash

bluetooth_service_helper_setup() {
    export RLCH_TEST_BLUETOOTH_ROOT="${BATS_TEST_TMPDIR}/cis-3.1.3"
    export RLCH_TEST_BLUETOOTH_BIN="${RLCH_TEST_BLUETOOTH_ROOT}/bin"
    export RLCH_TEST_BLUETOOTH_INSTALLED="${RLCH_TEST_BLUETOOTH_ROOT}/installed"
    export RLCH_TEST_BLUETOOTH_ACTIVE="${RLCH_TEST_BLUETOOTH_ROOT}/active"
    export RLCH_TEST_BLUETOOTH_ENABLED="${RLCH_TEST_BLUETOOTH_ROOT}/enabled"
    export RLCH_TEST_BLUETOOTH_LOG="${RLCH_TEST_BLUETOOTH_ROOT}/systemctl.log"
    export RLCH_TEST_BLUETOOTH_UID=0
    export RLCH_TEST_BLUETOOTH_FAIL_ACTION=""

    mkdir -p "${RLCH_TEST_BLUETOOTH_BIN}"
    printf '%s\n' true > "${RLCH_TEST_BLUETOOTH_INSTALLED}"
    printf '%s\n' active > "${RLCH_TEST_BLUETOOTH_ACTIVE}"
    printf '%s\n' enabled > "${RLCH_TEST_BLUETOOTH_ENABLED}"
    : > "${RLCH_TEST_BLUETOOTH_LOG}"

    export RLCH_CIS_3_1_3_RPM_COMMAND="${RLCH_TEST_BLUETOOTH_BIN}/rpm"
    export RLCH_CIS_3_1_3_SYSTEMCTL_COMMAND="${RLCH_TEST_BLUETOOTH_BIN}/systemctl"
    export RLCH_CIS_3_1_3_ID_COMMAND="${RLCH_TEST_BLUETOOTH_BIN}/id"
    export RLCH_CIS_3_1_3_STATE_DIR="${RLCH_TEST_BLUETOOTH_ROOT}/state"
    export RLCH_CIS_3_1_3_STATE_FILE="${RLCH_CIS_3_1_3_STATE_DIR}/service.state"

    bluetooth_service_helper_write_commands
}

bluetooth_service_helper_write_commands() {
    cat > "${RLCH_TEST_BLUETOOTH_BIN}/id" <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" == -u ]]; then
    printf '%s\n' "${RLCH_TEST_BLUETOOTH_UID}"
    exit 0
fi
exit 1
EOF

    cat > "${RLCH_TEST_BLUETOOTH_BIN}/rpm" <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" == -q && "${2:-}" == bluez && "$(cat "${RLCH_TEST_BLUETOOTH_INSTALLED}")" == true ]]; then
    exit 0
fi
exit 1
EOF

    cat > "${RLCH_TEST_BLUETOOTH_BIN}/systemctl" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "${RLCH_TEST_BLUETOOTH_LOG}"
if [[ -n "${RLCH_TEST_BLUETOOTH_FAIL_ACTION}" && "$*" == "${RLCH_TEST_BLUETOOTH_FAIL_ACTION}" ]]; then
    exit 1
fi

command="${1:-}"
shift || true
runtime=false
if [[ "${1:-}" == --runtime ]]; then
    runtime=true
    shift
fi
[[ "${1:-}" == bluetooth.service ]] || exit 1

case "${command}" in
    is-active)
        state="$(cat "${RLCH_TEST_BLUETOOTH_ACTIVE}")"
        printf '%s\n' "${state}"
        [[ "${state}" == active ]]
        ;;
    is-enabled)
        state="$(cat "${RLCH_TEST_BLUETOOTH_ENABLED}")"
        printf '%s\n' "${state}"
        [[ "${state}" == enabled || "${state}" == enabled-runtime ]]
        ;;
    stop)
        printf '%s\n' inactive > "${RLCH_TEST_BLUETOOTH_ACTIVE}"
        ;;
    start)
        current_enabled="$(cat "${RLCH_TEST_BLUETOOTH_ENABLED}")"
        [[ "${current_enabled}" != masked && "${current_enabled}" != masked-runtime ]] || exit 1
        printf '%s\n' active > "${RLCH_TEST_BLUETOOTH_ACTIVE}"
        ;;
    disable)
        printf '%s\n' disabled > "${RLCH_TEST_BLUETOOTH_ENABLED}"
        ;;
    enable)
        if [[ "${runtime}" == true ]]; then
            printf '%s\n' enabled-runtime > "${RLCH_TEST_BLUETOOTH_ENABLED}"
        else
            printf '%s\n' enabled > "${RLCH_TEST_BLUETOOTH_ENABLED}"
        fi
        ;;
    mask)
        if [[ "${runtime}" == true ]]; then
            printf '%s\n' masked-runtime > "${RLCH_TEST_BLUETOOTH_ENABLED}"
        else
            printf '%s\n' masked > "${RLCH_TEST_BLUETOOTH_ENABLED}"
        fi
        ;;
    unmask)
        printf '%s\n' disabled > "${RLCH_TEST_BLUETOOTH_ENABLED}"
        ;;
    *)
        exit 1
        ;;
esac
EOF
    chmod +x "${RLCH_TEST_BLUETOOTH_BIN}/id" "${RLCH_TEST_BLUETOOTH_BIN}/rpm" "${RLCH_TEST_BLUETOOTH_BIN}/systemctl"
}
