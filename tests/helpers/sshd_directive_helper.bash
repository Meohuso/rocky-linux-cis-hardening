#!/usr/bin/env bash
# Test helper for sshd directive controls.
# SPDX-License-Identifier: MIT

sshd_directive_helper_setup() {
    export RLCH_TEST_SSHD_ROOT="${BATS_TEST_TMPDIR}/sshd-directive"
    export RLCH_TEST_SSHD_BIN="${RLCH_TEST_SSHD_ROOT}/bin"
    export RLCH_TEST_SSHD_EFFECTIVE="${RLCH_TEST_SSHD_ROOT}/effective"
    export RLCH_TEST_SSHD_UID=0 RLCH_TEST_SSHD_FAIL=""
    mkdir -p "${RLCH_TEST_SSHD_BIN}" "${RLCH_TEST_SSHD_ROOT}/etc/ssh/sshd_config.d"
    cat > "${RLCH_TEST_SSHD_BIN}/sshd" <<'SCRIPT'
#!/usr/bin/env bash
if [[ "$1" == -t ]]; then [[ "${RLCH_TEST_SSHD_FAIL}" != validate ]] || exit 1; exit 0; fi
[[ "$1" == -T && "${RLCH_TEST_SSHD_FAIL}" != query ]] || exit 1
if [[ -s "${RLCH_TEST_SSHD_EFFECTIVE}" ]]; then cat "${RLCH_TEST_SSHD_EFFECTIVE}"; exit 0; fi
for file in "${RLCH_TEST_SSHD_ROOT}/etc/ssh/sshd_config.d/"*.conf; do
    [[ -f "$file" ]] || continue
    awk 'NF && $1 !~ /^#/ { print tolower($1), $2 }' "$file"
done
SCRIPT
    cat > "${RLCH_TEST_SSHD_BIN}/id" <<'SCRIPT'
#!/usr/bin/env bash
[[ "$1" == -u ]] || exit 1
printf '%s\n' "${RLCH_TEST_SSHD_UID}"
SCRIPT
    cat > "${RLCH_TEST_SSHD_BIN}/chown" <<'SCRIPT'
#!/usr/bin/env bash
exit 0
SCRIPT
    chmod +x "${RLCH_TEST_SSHD_BIN}/sshd" "${RLCH_TEST_SSHD_BIN}/id" "${RLCH_TEST_SSHD_BIN}/chown"
    export RLCH_SSHD_COMMAND="${RLCH_TEST_SSHD_BIN}/sshd"
    export RLCH_SSHD_ID_COMMAND="${RLCH_TEST_SSHD_BIN}/id"
    PATH="${RLCH_TEST_SSHD_BIN}:${PATH}"; export PATH
}

sshd_directive_effective() { printf '%s %s\n' "${1,,}" "$2" > "${RLCH_TEST_SSHD_EFFECTIVE}"; }
