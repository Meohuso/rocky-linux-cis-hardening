#!/usr/bin/env bash

setup_cups_server_test_environment() {
    RLCH_TEST_CUPS_DIR="${BATS_TEST_TMPDIR}/cups-server-test"
    RLCH_TEST_CUPS_BIN="${RLCH_TEST_CUPS_DIR}/bin"
    RLCH_TEST_CUPS_PACKAGES="${RLCH_TEST_CUPS_DIR}/installed-packages"
    RLCH_TEST_CUPS_ENABLED="${RLCH_TEST_CUPS_DIR}/enabled-state"
    RLCH_TEST_CUPS_ACTIVE="${RLCH_TEST_CUPS_DIR}/active-state"
    RLCH_TEST_CUPS_STATE="${RLCH_TEST_CUPS_DIR}/state"

    mkdir -p "${RLCH_TEST_CUPS_BIN}" "${RLCH_TEST_CUPS_STATE}"
    : > "${RLCH_TEST_CUPS_PACKAGES}"
    printf '%s\n' "disabled" > "${RLCH_TEST_CUPS_ENABLED}"
    printf '%s\n' "inactive" > "${RLCH_TEST_CUPS_ACTIVE}"

    cat > "${RLCH_TEST_CUPS_BIN}/rpm" <<'SCRIPT'
#!/usr/bin/env bash
packages="${RLCH_TEST_CUPS_PACKAGES:?}"
if [[ "${1:-}" != "-q" || -z "${2:-}" ]]; then
    exit 2
fi
grep -Fxq -- "${2}" "${packages}"
SCRIPT

    cat > "${RLCH_TEST_CUPS_BIN}/systemctl" <<'SCRIPT'
#!/usr/bin/env bash
enabled_file="${RLCH_TEST_CUPS_ENABLED:?}"
active_file="${RLCH_TEST_CUPS_ACTIVE:?}"

case "${1:-}" in
    is-active)
        state="$(cat -- "${active_file}")"
        [[ "${state}" == "active" ]]
        ;;
    is-enabled)
        state="$(cat -- "${enabled_file}")"
        printf '%s\n' "${state}"
        [[ "${state}" == "enabled" ]]
        ;;
    stop)
        printf '%s\n' "inactive" > "${active_file}"
        ;;
    start)
        printf '%s\n' "active" > "${active_file}"
        ;;
    disable)
        printf '%s\n' "disabled" > "${enabled_file}"
        ;;
    enable)
        printf '%s\n' "enabled" > "${enabled_file}"
        ;;
    mask)
        printf '%s\n' "masked" > "${enabled_file}"
        ;;
    unmask)
        if [[ "$(cat -- "${enabled_file}")" == "masked" ]]; then
            printf '%s\n' "disabled" > "${enabled_file}"
        fi
        ;;
    *)
        exit 2
        ;;
esac
SCRIPT

    chmod +x "${RLCH_TEST_CUPS_BIN}/rpm" "${RLCH_TEST_CUPS_BIN}/systemctl"

    export RLCH_TEST_CUPS_PACKAGES
    export RLCH_TEST_CUPS_ENABLED
    export RLCH_TEST_CUPS_ACTIVE

    RLCH_CIS_2_1_11_RPM_COMMAND="${RLCH_TEST_CUPS_BIN}/rpm"
    RLCH_CIS_2_1_11_SYSTEMCTL_COMMAND="${RLCH_TEST_CUPS_BIN}/systemctl"
}

teardown_cups_server_test_environment() {
    rm -rf "${RLCH_TEST_CUPS_DIR}"
}

add_cups_server_test_package() {
    local package_name="${1:?Package name is required}"
    if ! grep -Fxq -- "${package_name}" "${RLCH_TEST_CUPS_PACKAGES}"; then
        printf '%s\n' "${package_name}" >> "${RLCH_TEST_CUPS_PACKAGES}"
    fi
}

set_cups_server_test_state() {
    local enabled_state="${1:?Enabled state is required}"
    local active_state="${2:?Active state is required}"
    printf '%s\n' "${enabled_state}" > "${RLCH_TEST_CUPS_ENABLED}"
    printf '%s\n' "${active_state}" > "${RLCH_TEST_CUPS_ACTIVE}"
}
