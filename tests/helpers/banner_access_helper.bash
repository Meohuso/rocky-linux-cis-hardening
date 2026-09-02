#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
#
# Bats helper for CIS 1.7.4 access tests.
#
# SPDX-License-Identifier: MIT
#

setup_banner_access_test_environment() {
    RLCH_TEST_BANNER_ACCESS_DIR="${BATS_TEST_TMPDIR}/banner-access-test"
    RLCH_TEST_BANNER_ACCESS_BIN="${RLCH_TEST_BANNER_ACCESS_DIR}/bin"
    RLCH_TEST_BANNER_ACCESS_ETC="${RLCH_TEST_BANNER_ACCESS_DIR}/etc"
    RLCH_TEST_BANNER_ACCESS_STATE="${RLCH_TEST_BANNER_ACCESS_DIR}/state"
    RLCH_TEST_BANNER_ACCESS_METADATA="${RLCH_TEST_BANNER_ACCESS_DIR}/metadata"

    mkdir -p \
        "${RLCH_TEST_BANNER_ACCESS_BIN}" \
        "${RLCH_TEST_BANNER_ACCESS_ETC}" \
        "${RLCH_TEST_BANNER_ACCESS_STATE}"

    cat > "${RLCH_TEST_BANNER_ACCESS_BIN}/stat" <<'SCRIPT'
#!/usr/bin/env bash
format=""
file=""

while [[ "$#" -gt 0 ]]; do
    case "$1" in
        -c)
            format="${2:-}"
            shift 2
            ;;
        --)
            shift
            file="${1:-}"
            shift || true
            ;;
        *)
            file="$1"
            shift
            ;;
    esac
done

if [[ -z "${file}" || ! -e "${file}" ]]; then
    exit 1
fi

case "${format}" in
    "%U")
        printf '%s\n' "${RLCH_TEST_BANNER_ACCESS_OWNER:-root}"
        ;;
    "%G")
        printf '%s\n' "${RLCH_TEST_BANNER_ACCESS_GROUP:-root}"
        ;;
    "%a")
        printf '%s\n' "${RLCH_TEST_BANNER_ACCESS_MODE:-644}"
        ;;
    *)
        exit 1
        ;;
esac
SCRIPT

    cat > "${RLCH_TEST_BANNER_ACCESS_BIN}/chown" <<'SCRIPT'
#!/usr/bin/env bash
ownership="${1:-}"
if [[ -z "${ownership}" ]]; then
    exit 1
fi

printf '%s\n' "${ownership%%:*}" > "${RLCH_TEST_BANNER_ACCESS_METADATA}.owner"
printf '%s\n' "${ownership#*:}" > "${RLCH_TEST_BANNER_ACCESS_METADATA}.group"
exit 0
SCRIPT

    cat > "${RLCH_TEST_BANNER_ACCESS_BIN}/chmod" <<'SCRIPT'
#!/usr/bin/env bash
mode="${1:-}"
if [[ -z "${mode}" ]]; then
    exit 1
fi

mode="${mode#0}"
printf '%s\n' "${mode}" > "${RLCH_TEST_BANNER_ACCESS_METADATA}.mode"
exit 0
SCRIPT

    chmod +x \
        "${RLCH_TEST_BANNER_ACCESS_BIN}/stat" \
        "${RLCH_TEST_BANNER_ACCESS_BIN}/chown" \
        "${RLCH_TEST_BANNER_ACCESS_BIN}/chmod"

    export RLCH_TEST_BANNER_ACCESS_METADATA
    export RLCH_TEST_BANNER_ACCESS_OWNER="root"
    export RLCH_TEST_BANNER_ACCESS_GROUP="root"
    export RLCH_TEST_BANNER_ACCESS_MODE="644"

    PATH="${RLCH_TEST_BANNER_ACCESS_BIN}:${PATH}"
    export PATH
}

teardown_banner_access_test_environment() {
    rm -rf "${RLCH_TEST_BANNER_ACCESS_DIR}"
}

set_banner_access_test_metadata() {
    export RLCH_TEST_BANNER_ACCESS_OWNER="${1:?Owner is required}"
    export RLCH_TEST_BANNER_ACCESS_GROUP="${2:?Group is required}"
    export RLCH_TEST_BANNER_ACCESS_MODE="${3:?Mode is required}"
}

sync_banner_access_test_metadata() {
    if [[ -f "${RLCH_TEST_BANNER_ACCESS_METADATA}.owner" ]]; then
        export RLCH_TEST_BANNER_ACCESS_OWNER
        RLCH_TEST_BANNER_ACCESS_OWNER="$(cat "${RLCH_TEST_BANNER_ACCESS_METADATA}.owner")"
    fi

    if [[ -f "${RLCH_TEST_BANNER_ACCESS_METADATA}.group" ]]; then
        export RLCH_TEST_BANNER_ACCESS_GROUP
        RLCH_TEST_BANNER_ACCESS_GROUP="$(cat "${RLCH_TEST_BANNER_ACCESS_METADATA}.group")"
    fi

    if [[ -f "${RLCH_TEST_BANNER_ACCESS_METADATA}.mode" ]]; then
        export RLCH_TEST_BANNER_ACCESS_MODE
        RLCH_TEST_BANNER_ACCESS_MODE="$(cat "${RLCH_TEST_BANNER_ACCESS_METADATA}.mode")"
    fi
}
