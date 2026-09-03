#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
#
# Bats helper for CIS 2.1.9.
#
# SPDX-License-Identifier: MIT
#

setup_nfs_server_test_environment() {
    RLCH_TEST_NFS_DIR="${BATS_TEST_TMPDIR}/nfs-server-test"
    RLCH_TEST_NFS_BIN="${RLCH_TEST_NFS_DIR}/bin"
    RLCH_TEST_NFS_PACKAGES="${RLCH_TEST_NFS_DIR}/installed-packages"
    RLCH_TEST_NFS_ENABLED="${RLCH_TEST_NFS_DIR}/enabled-state"
    RLCH_TEST_NFS_ACTIVE="${RLCH_TEST_NFS_DIR}/active-state"
    RLCH_TEST_NFS_SYSTEMCTL_STATUS="${RLCH_TEST_NFS_DIR}/systemctl-status"
    RLCH_TEST_NFS_STATE="${RLCH_TEST_NFS_DIR}/state"

    mkdir -p "${RLCH_TEST_NFS_BIN}" "${RLCH_TEST_NFS_STATE}"

    : > "${RLCH_TEST_NFS_PACKAGES}"
    printf '%s\n' "disabled" > "${RLCH_TEST_NFS_ENABLED}"
    printf '%s\n' "inactive" > "${RLCH_TEST_NFS_ACTIVE}"
    printf '%s\n' "0" > "${RLCH_TEST_NFS_SYSTEMCTL_STATUS}"

    cat > "${RLCH_TEST_NFS_BIN}/rpm" <<'SCRIPT'
#!/usr/bin/env bash

packages="${RLCH_TEST_NFS_PACKAGES:?}"

if [[ "${1:-}" != "-q" || -z "${2:-}" ]]; then
    exit 2
fi

grep -Fxq -- "${2}" "${packages}"
SCRIPT

    cat > "${RLCH_TEST_NFS_BIN}/systemctl" <<'SCRIPT'
#!/usr/bin/env bash

enabled_file="${RLCH_TEST_NFS_ENABLED:?}"
active_file="${RLCH_TEST_NFS_ACTIVE:?}"
status_file="${RLCH_TEST_NFS_SYSTEMCTL_STATUS:?}"

status="$(cat -- "${status_file}")"
if [[ "${status}" -ne 0 ]] &&
    [[ "${1:-}" != "is-enabled" ]] &&
    [[ "${1:-}" != "is-active" ]]; then
    exit "${status}"
fi

case "${1:-}" in
    is-active)
        state="$(cat -- "${active_file}")"
        if [[ "${2:-}" == "--quiet" ]]; then
            [[ "${state}" == "active" ]]
            exit
        fi
        printf '%s\n' "${state}"
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

    chmod +x "${RLCH_TEST_NFS_BIN}/rpm" "${RLCH_TEST_NFS_BIN}/systemctl"

    export RLCH_TEST_NFS_PACKAGES
    export RLCH_TEST_NFS_ENABLED
    export RLCH_TEST_NFS_ACTIVE
    export RLCH_TEST_NFS_SYSTEMCTL_STATUS

    RLCH_CIS_2_1_9_RPM_COMMAND="${RLCH_TEST_NFS_BIN}/rpm"
    RLCH_CIS_2_1_9_SYSTEMCTL_COMMAND="${RLCH_TEST_NFS_BIN}/systemctl"
}

teardown_nfs_server_test_environment() {
    rm -rf "${RLCH_TEST_NFS_DIR}"
}

add_nfs_server_test_package() {
    local package_name="${1:?Package name is required}"

    if ! grep -Fxq -- "${package_name}" "${RLCH_TEST_NFS_PACKAGES}"; then
        printf '%s\n' "${package_name}" >> "${RLCH_TEST_NFS_PACKAGES}"
    fi
}

set_nfs_server_test_state() {
    local enabled_state="${1:?Enabled state is required}"
    local active_state="${2:?Active state is required}"

    printf '%s\n' "${enabled_state}" > "${RLCH_TEST_NFS_ENABLED}"
    printf '%s\n' "${active_state}" > "${RLCH_TEST_NFS_ACTIVE}"
}
