#!/usr/bin/env bash

setup_nis_server_test_environment() {
    RLCH_TEST_NIS_SERVER_DIR="${BATS_TEST_TMPDIR}/nis-server-test"
    RLCH_TEST_NIS_SERVER_BIN="${RLCH_TEST_NIS_SERVER_DIR}/bin"
    RLCH_TEST_NIS_SERVER_PACKAGES="${RLCH_TEST_NIS_SERVER_DIR}/installed-packages"
    RLCH_TEST_NIS_SERVER_STATE="${RLCH_TEST_NIS_SERVER_DIR}/state"
    RLCH_TEST_NIS_SERVER_DNF_STATUS="${RLCH_TEST_NIS_SERVER_DIR}/dnf-status"
    mkdir -p "${RLCH_TEST_NIS_SERVER_BIN}" "${RLCH_TEST_NIS_SERVER_STATE}"
    : > "${RLCH_TEST_NIS_SERVER_PACKAGES}"
    printf '%s\n' "0" > "${RLCH_TEST_NIS_SERVER_DNF_STATUS}"

    cat > "${RLCH_TEST_NIS_SERVER_BIN}/rpm" <<'SCRIPT'
#!/usr/bin/env bash
packages="${RLCH_TEST_NIS_SERVER_PACKAGES:?}"
if [[ "${1:-}" != "-q" || -z "${2:-}" ]]; then exit 2; fi
if grep -Fxq -- "${2}" "${packages}"; then
    printf '%s\n' "${2}-1.0-1.test"
    exit 0
fi
exit 1
SCRIPT

    cat > "${RLCH_TEST_NIS_SERVER_BIN}/dnf" <<'SCRIPT'
#!/usr/bin/env bash
packages="${RLCH_TEST_NIS_SERVER_PACKAGES:?}"
status_file="${RLCH_TEST_NIS_SERVER_DNF_STATUS:?}"
status="$(cat -- "${status_file}")"
if [[ "${status}" -ne 0 ]]; then exit "${status}"; fi
if [[ "${1:-}" != "-y" || -z "${2:-}" || -z "${3:-}" ]]; then exit 2; fi
package="${3}"
case "${2}" in
    remove)
        tmp="${packages}.tmp"
        grep -Fvx -- "${package}" "${packages}" > "${tmp}" || true
        mv -f -- "${tmp}" "${packages}"
        ;;
    install)
        if ! grep -Fxq -- "${package}" "${packages}"; then
            printf '%s\n' "${package}" >> "${packages}"
        fi
        ;;
    *) exit 2 ;;
esac
SCRIPT
    chmod +x "${RLCH_TEST_NIS_SERVER_BIN}/rpm" "${RLCH_TEST_NIS_SERVER_BIN}/dnf"
    export RLCH_TEST_NIS_SERVER_PACKAGES RLCH_TEST_NIS_SERVER_DNF_STATUS
    RLCH_CIS_2_1_10_RPM_COMMAND="${RLCH_TEST_NIS_SERVER_BIN}/rpm"
    RLCH_CIS_2_1_10_DNF_COMMAND="${RLCH_TEST_NIS_SERVER_BIN}/dnf"
}

teardown_nis_server_test_environment() { rm -rf "${RLCH_TEST_NIS_SERVER_DIR}"; }

add_nis_server_test_package() {
    local package_name="${1:?Package name is required}"
    if ! grep -Fxq -- "${package_name}" "${RLCH_TEST_NIS_SERVER_PACKAGES}"; then
        printf '%s\n' "${package_name}" >> "${RLCH_TEST_NIS_SERVER_PACKAGES}"
    fi
}

set_nis_server_test_dnf_status() {
    printf '%s\n' "${1:?Status is required}" > "${RLCH_TEST_NIS_SERVER_DNF_STATUS}"
}
