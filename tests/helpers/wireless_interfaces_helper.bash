#!/usr/bin/env bash

wireless_interfaces_helper_setup() {
    export RLCH_TEST_WIRELESS_ROOT="${BATS_TEST_TMPDIR}/cis-3.1.2"
    export RLCH_TEST_WIRELESS_SYS_CLASS_NET="${RLCH_TEST_WIRELESS_ROOT}/sys/class/net"
    export RLCH_TEST_WIRELESS_BIN="${RLCH_TEST_WIRELESS_ROOT}/bin"
    export RLCH_TEST_WIRELESS_WIFI_STATE="${RLCH_TEST_WIRELESS_ROOT}/wifi.state"
    export RLCH_TEST_WIRELESS_WWAN_STATE="${RLCH_TEST_WIRELESS_ROOT}/wwan.state"
    export RLCH_TEST_WIRELESS_NMCLI_LOG="${RLCH_TEST_WIRELESS_ROOT}/nmcli.log"
    export RLCH_TEST_WIRELESS_FLAGS="${RLCH_TEST_WIRELESS_SYS_CLASS_NET}/wlan0/flags"
    export RLCH_TEST_WIRELESS_UID=0
    export RLCH_TEST_WIRELESS_NMCLI_FAIL=""
    export RLCH_TEST_WIRELESS_NMCLI_FAIL_ACTION=""

    mkdir -p "${RLCH_TEST_WIRELESS_SYS_CLASS_NET}/wlan0/wireless" "${RLCH_TEST_WIRELESS_BIN}"
    printf '%s\n' 0x1 > "${RLCH_TEST_WIRELESS_FLAGS}"
    printf '%s\n' enabled > "${RLCH_TEST_WIRELESS_WIFI_STATE}"
    printf '%s\n' disabled > "${RLCH_TEST_WIRELESS_WWAN_STATE}"
    : > "${RLCH_TEST_WIRELESS_NMCLI_LOG}"

    export RLCH_CIS_3_1_2_SYS_CLASS_NET="${RLCH_TEST_WIRELESS_SYS_CLASS_NET}"
    export RLCH_CIS_3_1_2_NMCLI_COMMAND="${RLCH_TEST_WIRELESS_BIN}/nmcli"
    export RLCH_CIS_3_1_2_ID_COMMAND="${RLCH_TEST_WIRELESS_BIN}/id"
    export RLCH_CIS_3_1_2_STATE_DIR="${RLCH_TEST_WIRELESS_ROOT}/state"
    export RLCH_CIS_3_1_2_STATE_FILE="${RLCH_CIS_3_1_2_STATE_DIR}/radio.state"

    wireless_interfaces_helper_write_commands
}

wireless_interfaces_helper_write_commands() {
    cat > "${RLCH_TEST_WIRELESS_BIN}/id" <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" == -u ]]; then
    printf '%s\n' "${RLCH_TEST_WIRELESS_UID}"
    exit 0
fi
exit 1
EOF

    cat > "${RLCH_TEST_WIRELESS_BIN}/nmcli" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "${RLCH_TEST_WIRELESS_NMCLI_LOG}"
if [[ -n "${RLCH_TEST_WIRELESS_NMCLI_FAIL}" ||
      ( -n "${RLCH_TEST_WIRELESS_NMCLI_FAIL_ACTION}" && "$*" == "${RLCH_TEST_WIRELESS_NMCLI_FAIL_ACTION}" ) ]]; then
    exit 1
fi
if [[ "${1:-}" != radio ]]; then
    exit 1
fi
case "${2:-}:${3:-}" in
    wifi:)
        cat "${RLCH_TEST_WIRELESS_WIFI_STATE}"
        ;;
    wwan:)
        cat "${RLCH_TEST_WIRELESS_WWAN_STATE}"
        ;;
    all:off)
        printf '%s\n' disabled > "${RLCH_TEST_WIRELESS_WIFI_STATE}"
        printf '%s\n' disabled > "${RLCH_TEST_WIRELESS_WWAN_STATE}"
        printf '%s\n' 0x0 > "${RLCH_TEST_WIRELESS_FLAGS}"
        ;;
    wifi:on)
        printf '%s\n' enabled > "${RLCH_TEST_WIRELESS_WIFI_STATE}"
        printf '%s\n' 0x1 > "${RLCH_TEST_WIRELESS_FLAGS}"
        ;;
    wifi:off)
        printf '%s\n' disabled > "${RLCH_TEST_WIRELESS_WIFI_STATE}"
        printf '%s\n' 0x0 > "${RLCH_TEST_WIRELESS_FLAGS}"
        ;;
    wwan:on)
        printf '%s\n' enabled > "${RLCH_TEST_WIRELESS_WWAN_STATE}"
        ;;
    wwan:off)
        printf '%s\n' disabled > "${RLCH_TEST_WIRELESS_WWAN_STATE}"
        ;;
    *)
        exit 1
        ;;
esac
EOF
    chmod +x "${RLCH_TEST_WIRELESS_BIN}/id" "${RLCH_TEST_WIRELESS_BIN}/nmcli"
}
