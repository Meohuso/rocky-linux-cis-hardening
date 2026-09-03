#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
#
# Bats helper for CIS 2.1.2.
#
# SPDX-License-Identifier: MIT
#

setup_avahi_test_environment() {
    RLCH_TEST_AVAHI_DIR="${BATS_TEST_TMPDIR}/avahi-test"
    RLCH_TEST_AVAHI_BIN="${RLCH_TEST_AVAHI_DIR}/bin"
    RLCH_TEST_AVAHI_STATE="${RLCH_TEST_AVAHI_DIR}/state"
    RLCH_TEST_AVAHI_SYSTEMCTL_STATE="${RLCH_TEST_AVAHI_DIR}/systemctl"

    mkdir -p \
        "${RLCH_TEST_AVAHI_BIN}" \
        "${RLCH_TEST_AVAHI_STATE}" \
        "${RLCH_TEST_AVAHI_SYSTEMCTL_STATE}"

    printf '%s\n' "false" > "${RLCH_TEST_AVAHI_SYSTEMCTL_STATE}/installed"

    for label in service socket; do
        printf '%s\n' "inactive" > "${RLCH_TEST_AVAHI_SYSTEMCTL_STATE}/${label}.active"
        printf '%s\n' "disabled" > "${RLCH_TEST_AVAHI_SYSTEMCTL_STATE}/${label}.enabled"
    done

    cat > "${RLCH_TEST_AVAHI_BIN}/rpm" <<'SCRIPT'
#!/usr/bin/env bash
state_dir="${RLCH_TEST_AVAHI_SYSTEMCTL_STATE:?}"

if [[ "${1:-}" == "-q" &&
      "${2:-}" == "avahi" &&
      "$(cat "${state_dir}/installed")" == "true" ]]; then
    exit 0
fi

exit 1
SCRIPT

    cat > "${RLCH_TEST_AVAHI_BIN}/systemctl" <<'SCRIPT'
#!/usr/bin/env bash
state_dir="${RLCH_TEST_AVAHI_SYSTEMCTL_STATE:?}"
command="${1:-}"

get_label() {
    case "${1:-}" in
        avahi-daemon.service)
            printf '%s\n' "service"
            ;;
        avahi-daemon.socket)
            printf '%s\n' "socket"
            ;;
        *)
            exit 1
            ;;
    esac
}

case "${command}" in
    is-active)
        if [[ "${2:-}" == "--quiet" ]]; then
            unit="${3:-}"
        else
            unit="${2:-}"
        fi
        label="$(get_label "${unit}")"
        state="$(cat "${state_dir}/${label}.active")"
        printf '%s\n' "${state}"
        [[ "${state}" == "active" ]]
        ;;
    is-enabled)
        if [[ "${2:-}" == "--quiet" ]]; then
            unit="${3:-}"
        else
            unit="${2:-}"
        fi
        label="$(get_label "${unit}")"
        state="$(cat "${state_dir}/${label}.enabled")"
        printf '%s\n' "${state}"
        [[ "${state}" == "enabled" ]]
        ;;
    stop|start|disable|enable|mask|unmask)
        unit="${2:-}"
        label="$(get_label "${unit}")"
        case "${command}" in
            stop) printf '%s\n' "inactive" > "${state_dir}/${label}.active" ;;
            start) printf '%s\n' "active" > "${state_dir}/${label}.active" ;;
            disable) printf '%s\n' "disabled" > "${state_dir}/${label}.enabled" ;;
            enable) printf '%s\n' "enabled" > "${state_dir}/${label}.enabled" ;;
            mask) printf '%s\n' "masked" > "${state_dir}/${label}.enabled" ;;
            unmask) printf '%s\n' "disabled" > "${state_dir}/${label}.enabled" ;;
        esac
        ;;
    *)
        exit 1
        ;;
esac
SCRIPT

    chmod +x \
        "${RLCH_TEST_AVAHI_BIN}/rpm" \
        "${RLCH_TEST_AVAHI_BIN}/systemctl"

    export RLCH_TEST_AVAHI_SYSTEMCTL_STATE

    PATH="${RLCH_TEST_AVAHI_BIN}:${PATH}"
    export PATH
}

teardown_avahi_test_environment() {
    rm -rf "${RLCH_TEST_AVAHI_DIR}"
}

set_avahi_test_installed() {
    printf '%s\n' "${1:?Installed state is required}" \
        > "${RLCH_TEST_AVAHI_SYSTEMCTL_STATE}/installed"
}

set_avahi_test_unit_state() {
    local label="${1:?Unit label is required}"
    local active="${2:?Active state is required}"
    local enabled="${3:?Enabled state is required}"

    printf '%s\n' "${active}" > "${RLCH_TEST_AVAHI_SYSTEMCTL_STATE}/${label}.active"
    printf '%s\n' "${enabled}" > "${RLCH_TEST_AVAHI_SYSTEMCTL_STATE}/${label}.enabled"
}
