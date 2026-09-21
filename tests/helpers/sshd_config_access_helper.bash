#!/usr/bin/env bash
# Test helper for CIS 5.1.1.
# SPDX-License-Identifier: MIT

sshd_config_access_helper_setup() {
    export RLCH_TEST_SSHD_ACCESS_ROOT="${BATS_TEST_TMPDIR}/cis-5.1.1"
    export RLCH_TEST_SSHD_ACCESS_BIN="${RLCH_TEST_SSHD_ACCESS_ROOT}/bin"
    export RLCH_TEST_SSHD_ACCESS_METADATA="${RLCH_TEST_SSHD_ACCESS_ROOT}/metadata"
    export RLCH_TEST_SSHD_ACCESS_LOG="${RLCH_TEST_SSHD_ACCESS_ROOT}/commands"
    export RLCH_CIS_5_1_1_PATH="${RLCH_TEST_SSHD_ACCESS_ROOT}/sshd_config"
    export RLCH_CIS_5_1_1_STATE_DIR="${RLCH_TEST_SSHD_ACCESS_ROOT}/state"
    export RLCH_CIS_5_1_1_STATE_FILE="${RLCH_CIS_5_1_1_STATE_DIR}/access"
    export RLCH_CIS_5_1_1_ID_COMMAND="rlch_test_sshd_access_id"
    export RLCH_TEST_SSHD_ACCESS_UID="0"
    export RLCH_TEST_SSHD_ACCESS_ID_FAIL="false"
    export RLCH_TEST_SSHD_ACCESS_FAIL=""

    mkdir -p "${RLCH_TEST_SSHD_ACCESS_BIN}"
    : > "${RLCH_CIS_5_1_1_PATH}"
    sshd_config_access_helper_set 0 0 600

    cat > "${RLCH_TEST_SSHD_ACCESS_BIN}/stat" <<'SCRIPT'
#!/usr/bin/env bash
format=""
while [[ "$#" -gt 0 ]]; do
    case "$1" in
        -c) format="${2:-}"; shift 2 ;;
        --) shift; file="${1:-}"; shift || true ;;
        *) file="$1"; shift ;;
    esac
done
printf 'stat %s %s\n' "${format}" "${file:-}" >> "${RLCH_TEST_SSHD_ACCESS_LOG}"
[[ "${RLCH_TEST_SSHD_ACCESS_FAIL}" != "stat" && -f "${file:-}" ]] || exit 2
case "${format}" in
    %u) cat "${RLCH_TEST_SSHD_ACCESS_METADATA}.owner" ;;
    %g) cat "${RLCH_TEST_SSHD_ACCESS_METADATA}.group" ;;
    %a) cat "${RLCH_TEST_SSHD_ACCESS_METADATA}.mode" ;;
    *) exit 2 ;;
esac
SCRIPT

    cat > "${RLCH_TEST_SSHD_ACCESS_BIN}/chown" <<'SCRIPT'
#!/usr/bin/env bash
printf 'chown %s\n' "$*" >> "${RLCH_TEST_SSHD_ACCESS_LOG}"
[[ "${RLCH_TEST_SSHD_ACCESS_FAIL}" != "chown" ]] || exit 2
ownership="${1:-}"
printf '%s\n' "${ownership%%:*}" > "${RLCH_TEST_SSHD_ACCESS_METADATA}.owner"
printf '%s\n' "${ownership#*:}" > "${RLCH_TEST_SSHD_ACCESS_METADATA}.group"
SCRIPT

    cat > "${RLCH_TEST_SSHD_ACCESS_BIN}/chmod" <<'SCRIPT'
#!/usr/bin/env bash
printf 'chmod %s\n' "$*" >> "${RLCH_TEST_SSHD_ACCESS_LOG}"
[[ "${RLCH_TEST_SSHD_ACCESS_FAIL}" != "chmod" ]] || exit 2
printf '%s\n' "${1#0}" > "${RLCH_TEST_SSHD_ACCESS_METADATA}.mode"
SCRIPT

    chmod +x "${RLCH_TEST_SSHD_ACCESS_BIN}/stat" "${RLCH_TEST_SSHD_ACCESS_BIN}/chown" "${RLCH_TEST_SSHD_ACCESS_BIN}/chmod"
    PATH="${RLCH_TEST_SSHD_ACCESS_BIN}:${PATH}"
    export PATH
}

sshd_config_access_helper_set() {
    printf '%s\n' "${1:?Owner required}" > "${RLCH_TEST_SSHD_ACCESS_METADATA}.owner"
    printf '%s\n' "${2:?Group required}" > "${RLCH_TEST_SSHD_ACCESS_METADATA}.group"
    printf '%s\n' "${3:?Mode required}" > "${RLCH_TEST_SSHD_ACCESS_METADATA}.mode"
}

rlch_test_sshd_access_id() {
    [[ "${1:-}" == "-u" && "${RLCH_TEST_SSHD_ACCESS_ID_FAIL}" != "true" ]] || return 2
    printf '%s\n' "${RLCH_TEST_SSHD_ACCESS_UID}"
}
