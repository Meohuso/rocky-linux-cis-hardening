#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
# Bats helper for cron access controls.
# SPDX-License-Identifier: MIT
#

setup_cron_access_test_environment() {
    RLCH_TEST_CRON_ACCESS_DIR="${BATS_TEST_TMPDIR}/cron-access-test"
    RLCH_TEST_CRON_ACCESS_BIN="${RLCH_TEST_CRON_ACCESS_DIR}/bin"
    RLCH_TEST_CRON_ACCESS_ETC="${RLCH_TEST_CRON_ACCESS_DIR}/etc"
    RLCH_TEST_CRON_ACCESS_STATE="${RLCH_TEST_CRON_ACCESS_DIR}/state"
    RLCH_TEST_CRON_ACCESS_METADATA="${RLCH_TEST_CRON_ACCESS_DIR}/metadata"

    mkdir -p "${RLCH_TEST_CRON_ACCESS_BIN}" "${RLCH_TEST_CRON_ACCESS_ETC}" "${RLCH_TEST_CRON_ACCESS_STATE}"

    cat > "${RLCH_TEST_CRON_ACCESS_BIN}/stat" <<'SCRIPT'
#!/usr/bin/env bash
format=""
while [[ "$#" -gt 0 ]]; do
    case "$1" in
        -c) format="${2:-}"; shift 2 ;;
        --) shift; file="${1:-}"; shift || true ;;
        *) file="$1"; shift ;;
    esac
done
[[ -n "${file:-}" && -e "${file}" ]] || exit 1
case "${format}" in
    "%u")
        if [[ -f "${RLCH_TEST_CRON_ACCESS_METADATA}.owner" ]]; then
            cat "${RLCH_TEST_CRON_ACCESS_METADATA}.owner"
        else
            printf '%s\n' "${RLCH_TEST_CRON_ACCESS_OWNER:-0}"
        fi
        ;;
    "%g")
        if [[ -f "${RLCH_TEST_CRON_ACCESS_METADATA}.group" ]]; then
            cat "${RLCH_TEST_CRON_ACCESS_METADATA}.group"
        else
            printf '%s\n' "${RLCH_TEST_CRON_ACCESS_GROUP:-0}"
        fi
        ;;
    "%a")
        if [[ -f "${RLCH_TEST_CRON_ACCESS_METADATA}.mode" ]]; then
            cat "${RLCH_TEST_CRON_ACCESS_METADATA}.mode"
        else
            printf '%s\n' "${RLCH_TEST_CRON_ACCESS_MODE:-600}"
        fi
        ;;
    *) exit 1 ;;
esac
SCRIPT

    cat > "${RLCH_TEST_CRON_ACCESS_BIN}/chown" <<'SCRIPT'
#!/usr/bin/env bash
ownership="${1:-}"
[[ -n "${ownership}" ]] || exit 1
printf '%s\n' "${ownership%%:*}" > "${RLCH_TEST_CRON_ACCESS_METADATA}.owner"
printf '%s\n' "${ownership#*:}" > "${RLCH_TEST_CRON_ACCESS_METADATA}.group"
SCRIPT

    cat > "${RLCH_TEST_CRON_ACCESS_BIN}/chmod" <<'SCRIPT'
#!/usr/bin/env bash
mode="${1:-}"
[[ -n "${mode}" ]] || exit 1
printf '%s\n' "${mode#0}" > "${RLCH_TEST_CRON_ACCESS_METADATA}.mode"
SCRIPT

    chmod +x "${RLCH_TEST_CRON_ACCESS_BIN}/stat" "${RLCH_TEST_CRON_ACCESS_BIN}/chown" "${RLCH_TEST_CRON_ACCESS_BIN}/chmod"
    export RLCH_TEST_CRON_ACCESS_METADATA
    set_cron_access_test_metadata 0 0 600
    PATH="${RLCH_TEST_CRON_ACCESS_BIN}:${PATH}"
    export PATH
}

teardown_cron_access_test_environment() {
    rm -rf "${RLCH_TEST_CRON_ACCESS_DIR}"
}

set_cron_access_test_metadata() {
    export RLCH_TEST_CRON_ACCESS_OWNER="${1:?Owner is required}"
    export RLCH_TEST_CRON_ACCESS_GROUP="${2:?Group is required}"
    export RLCH_TEST_CRON_ACCESS_MODE="${3:?Mode is required}"
}

sync_cron_access_test_metadata() {
    local field
    for field in owner group mode; do
        if [[ -f "${RLCH_TEST_CRON_ACCESS_METADATA}.${field}" ]]; then
            case "${field}" in
                owner) RLCH_TEST_CRON_ACCESS_OWNER="$(cat "${RLCH_TEST_CRON_ACCESS_METADATA}.${field}")" ;;
                group) RLCH_TEST_CRON_ACCESS_GROUP="$(cat "${RLCH_TEST_CRON_ACCESS_METADATA}.${field}")" ;;
                mode) RLCH_TEST_CRON_ACCESS_MODE="$(cat "${RLCH_TEST_CRON_ACCESS_METADATA}.${field}")" ;;
            esac
        fi
    done

    export RLCH_TEST_CRON_ACCESS_OWNER RLCH_TEST_CRON_ACCESS_GROUP RLCH_TEST_CRON_ACCESS_MODE
}
