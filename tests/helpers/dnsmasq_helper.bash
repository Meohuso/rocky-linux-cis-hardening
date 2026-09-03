#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
#
# Bats helper for CIS 2.1.5.
#
# SPDX-License-Identifier: MIT
#

setup_dnsmasq_test_environment() {
    RLCH_TEST_DNSMASQ_DIR="${BATS_TEST_TMPDIR}/dnsmasq-test"
    RLCH_TEST_DNSMASQ_BIN="${RLCH_TEST_DNSMASQ_DIR}/bin"
    RLCH_TEST_DNSMASQ_STATE="${RLCH_TEST_DNSMASQ_DIR}/state"
    RLCH_TEST_DNSMASQ_SYSTEMCTL_STATE="${RLCH_TEST_DNSMASQ_DIR}/systemctl"

    mkdir -p \
        "${RLCH_TEST_DNSMASQ_BIN}" \
        "${RLCH_TEST_DNSMASQ_STATE}" \
        "${RLCH_TEST_DNSMASQ_SYSTEMCTL_STATE}"

    printf '%s\n' "false" > "${RLCH_TEST_DNSMASQ_SYSTEMCTL_STATE}/installed"
    printf '%s\n' "inactive" > "${RLCH_TEST_DNSMASQ_SYSTEMCTL_STATE}/active"
    printf '%s\n' "disabled" > "${RLCH_TEST_DNSMASQ_SYSTEMCTL_STATE}/enabled"

    cat > "${RLCH_TEST_DNSMASQ_BIN}/rpm" <<'SCRIPT'
#!/usr/bin/env bash
state_dir="${RLCH_TEST_DNSMASQ_SYSTEMCTL_STATE:?}"

if [[ "${1:-}" == "-q" &&
      "${2:-}" == "dnsmasq" &&
      "$(cat "${state_dir}/installed")" == "true" ]]; then
    exit 0
fi

exit 1
SCRIPT

    cat > "${RLCH_TEST_DNSMASQ_BIN}/systemctl" <<'SCRIPT'
#!/usr/bin/env bash
state_dir="${RLCH_TEST_DNSMASQ_SYSTEMCTL_STATE:?}"
command="${1:-}"

case "${command}" in
    is-active)
        state="$(cat "${state_dir}/active")"
        if [[ "${2:-}" == "--quiet" ]]; then
            unit="${3:-}"
        else
            unit="${2:-}"
        fi
        [[ "${unit}" == "dnsmasq.service" ]] || exit 1
        printf '%s\n' "${state}"
        [[ "${state}" == "active" ]]
        ;;
    is-enabled)
        state="$(cat "${state_dir}/enabled")"
        if [[ "${2:-}" == "--quiet" ]]; then
            unit="${3:-}"
        else
            unit="${2:-}"
        fi
        [[ "${unit}" == "dnsmasq.service" ]] || exit 1
        printf '%s\n' "${state}"
        [[ "${state}" == "enabled" ]]
        ;;
    stop)
        [[ "${2:-}" == "dnsmasq.service" ]] || exit 1
        printf '%s\n' "inactive" > "${state_dir}/active"
        ;;
    start)
        [[ "${2:-}" == "dnsmasq.service" ]] || exit 1
        printf '%s\n' "active" > "${state_dir}/active"
        ;;
    disable)
        [[ "${2:-}" == "dnsmasq.service" ]] || exit 1
        printf '%s\n' "disabled" > "${state_dir}/enabled"
        ;;
    enable)
        [[ "${2:-}" == "dnsmasq.service" ]] || exit 1
        printf '%s\n' "enabled" > "${state_dir}/enabled"
        ;;
    mask)
        [[ "${2:-}" == "dnsmasq.service" ]] || exit 1
        printf '%s\n' "masked" > "${state_dir}/enabled"
        ;;
    unmask)
        [[ "${2:-}" == "dnsmasq.service" ]] || exit 1
        printf '%s\n' "disabled" > "${state_dir}/enabled"
        ;;
    *)
        exit 1
        ;;
esac
SCRIPT

    chmod +x \
        "${RLCH_TEST_DNSMASQ_BIN}/rpm" \
        "${RLCH_TEST_DNSMASQ_BIN}/systemctl"

    export RLCH_TEST_DNSMASQ_SYSTEMCTL_STATE

    PATH="${RLCH_TEST_DNSMASQ_BIN}:${PATH}"
    export PATH
}

teardown_dnsmasq_test_environment() {
    rm -rf "${RLCH_TEST_DNSMASQ_DIR}"
}

set_dnsmasq_test_installed() {
    printf '%s\n' "${1:?Installed state is required}" \
        > "${RLCH_TEST_DNSMASQ_SYSTEMCTL_STATE}/installed"
}

set_dnsmasq_test_state() {
    local active="${1:?Active state is required}"
    local enabled="${2:?Enabled state is required}"

    printf '%s\n' "${active}" > "${RLCH_TEST_DNSMASQ_SYSTEMCTL_STATE}/active"
    printf '%s\n' "${enabled}" > "${RLCH_TEST_DNSMASQ_SYSTEMCTL_STATE}/enabled"
}
