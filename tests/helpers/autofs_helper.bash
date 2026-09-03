#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
#
# Bats helper for CIS 2.1.1.
#
# SPDX-License-Identifier: MIT
#

setup_autofs_test_environment() {
    RLCH_TEST_AUTOFS_DIR="${BATS_TEST_TMPDIR}/autofs-test"
    RLCH_TEST_AUTOFS_BIN="${RLCH_TEST_AUTOFS_DIR}/bin"
    RLCH_TEST_AUTOFS_STATE="${RLCH_TEST_AUTOFS_DIR}/state"
    RLCH_TEST_AUTOFS_SYSTEMCTL_STATE="${RLCH_TEST_AUTOFS_DIR}/systemctl"

    mkdir -p \
        "${RLCH_TEST_AUTOFS_BIN}" \
        "${RLCH_TEST_AUTOFS_STATE}" \
        "${RLCH_TEST_AUTOFS_SYSTEMCTL_STATE}"

    printf '%s\n' "false" > "${RLCH_TEST_AUTOFS_SYSTEMCTL_STATE}/installed"
    printf '%s\n' "inactive" > "${RLCH_TEST_AUTOFS_SYSTEMCTL_STATE}/active"
    printf '%s\n' "disabled" > "${RLCH_TEST_AUTOFS_SYSTEMCTL_STATE}/enabled"

    cat > "${RLCH_TEST_AUTOFS_BIN}/rpm" <<'SCRIPT'
#!/usr/bin/env bash
state_dir="${RLCH_TEST_AUTOFS_SYSTEMCTL_STATE:?}"

if [[ "${1:-}" == "-q" &&
      "${2:-}" == "autofs" &&
      "$(cat "${state_dir}/installed")" == "true" ]]; then
    exit 0
fi

exit 1
SCRIPT

    cat > "${RLCH_TEST_AUTOFS_BIN}/systemctl" <<'SCRIPT'
#!/usr/bin/env bash
state_dir="${RLCH_TEST_AUTOFS_SYSTEMCTL_STATE:?}"
command="${1:-}"

case "${command}" in
    is-active)
        state="$(cat "${state_dir}/active")"
        if [[ "${2:-}" == "--quiet" ]]; then
            service="${3:-}"
        else
            service="${2:-}"
        fi
        : "${service:?}"
        printf '%s\n' "${state}"
        [[ "${state}" == "active" ]]
        ;;
    is-enabled)
        state="$(cat "${state_dir}/enabled")"
        if [[ "${2:-}" == "--quiet" ]]; then
            service="${3:-}"
        else
            service="${2:-}"
        fi
        : "${service:?}"
        printf '%s\n' "${state}"
        [[ "${state}" == "enabled" ]]
        ;;
    stop)
        printf '%s\n' "inactive" > "${state_dir}/active"
        ;;
    start)
        printf '%s\n' "active" > "${state_dir}/active"
        ;;
    disable)
        printf '%s\n' "disabled" > "${state_dir}/enabled"
        ;;
    enable)
        printf '%s\n' "enabled" > "${state_dir}/enabled"
        ;;
    mask)
        printf '%s\n' "masked" > "${state_dir}/enabled"
        ;;
    unmask)
        printf '%s\n' "disabled" > "${state_dir}/enabled"
        ;;
    *)
        exit 1
        ;;
esac
SCRIPT

    chmod +x \
        "${RLCH_TEST_AUTOFS_BIN}/rpm" \
        "${RLCH_TEST_AUTOFS_BIN}/systemctl"

    export RLCH_TEST_AUTOFS_SYSTEMCTL_STATE

    PATH="${RLCH_TEST_AUTOFS_BIN}:${PATH}"
    export PATH
}

teardown_autofs_test_environment() {
    rm -rf "${RLCH_TEST_AUTOFS_DIR}"
}

set_autofs_test_installed() {
    printf '%s\n' "${1:?Installed state is required}" \
        > "${RLCH_TEST_AUTOFS_SYSTEMCTL_STATE}/installed"
}

set_autofs_test_active_state() {
    printf '%s\n' "${1:?Active state is required}" \
        > "${RLCH_TEST_AUTOFS_SYSTEMCTL_STATE}/active"
}

set_autofs_test_enabled_state() {
    printf '%s\n' "${1:?Enabled state is required}" \
        > "${RLCH_TEST_AUTOFS_SYSTEMCTL_STATE}/enabled"
}
