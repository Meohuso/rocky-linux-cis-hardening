#!/usr/bin/env bash
# Test helper for CIS 5.1.2.
# SPDX-License-Identifier: MIT

sshd_private_key_access_helper_setup() {
    export RLCH_TEST_PRIVATE_KEY_ROOT="${BATS_TEST_TMPDIR}/cis-5.1.2"
    export RLCH_TEST_PRIVATE_KEY_BIN="${RLCH_TEST_PRIVATE_KEY_ROOT}/bin"
    export RLCH_TEST_PRIVATE_KEY_META="${RLCH_TEST_PRIVATE_KEY_ROOT}/meta"
    export RLCH_TEST_PRIVATE_KEY_LOG="${RLCH_TEST_PRIVATE_KEY_ROOT}/commands"
    export RLCH_CIS_5_1_2_KEY_DIR="${RLCH_TEST_PRIVATE_KEY_ROOT}/ssh"
    export RLCH_CIS_5_1_2_STATE_DIR="${RLCH_TEST_PRIVATE_KEY_ROOT}/state"
    export RLCH_CIS_5_1_2_STATE_FILE="${RLCH_CIS_5_1_2_STATE_DIR}/access"
    export RLCH_CIS_5_1_2_ID_COMMAND="rlch_test_private_key_id"
    export RLCH_CIS_5_1_2_GETENT_COMMAND="rlch_test_private_key_getent"
    export RLCH_TEST_PRIVATE_KEY_UID="0"
    export RLCH_TEST_PRIVATE_KEY_GID="997"
    export RLCH_TEST_PRIVATE_KEY_FAIL=""
    mkdir -p "${RLCH_TEST_PRIVATE_KEY_BIN}" "${RLCH_CIS_5_1_2_KEY_DIR}" "${RLCH_TEST_PRIVATE_KEY_META}"

    cat > "${RLCH_TEST_PRIVATE_KEY_BIN}/stat" <<'SCRIPT'
#!/usr/bin/env bash
format=""; file=""
while [[ "$#" -gt 0 ]]; do case "$1" in -c) format="$2"; shift 2;; --) shift; file="$1"; shift;; *) file="$1"; shift;; esac; done
name="$(basename -- "${file}")"; [[ -f "${file}" && "${RLCH_TEST_PRIVATE_KEY_FAIL}" != "stat:${name}" ]] || exit 2
case "${format}" in %u) cat "${RLCH_TEST_PRIVATE_KEY_META}/${name}.owner";; %g) cat "${RLCH_TEST_PRIVATE_KEY_META}/${name}.group";; %a) cat "${RLCH_TEST_PRIVATE_KEY_META}/${name}.mode";; *) exit 2;; esac
SCRIPT
    cat > "${RLCH_TEST_PRIVATE_KEY_BIN}/chown" <<'SCRIPT'
#!/usr/bin/env bash
ownership="$1"; shift; [[ "$1" == "--" ]] && shift; file="$1"; name="$(basename -- "${file}")"
printf 'chown %s %s\n' "${ownership}" "${file}" >> "${RLCH_TEST_PRIVATE_KEY_LOG}"
[[ "${RLCH_TEST_PRIVATE_KEY_FAIL}" != "chown:${name}" ]] || exit 2
printf '%s\n' "${ownership%%:*}" > "${RLCH_TEST_PRIVATE_KEY_META}/${name}.owner"; printf '%s\n' "${ownership#*:}" > "${RLCH_TEST_PRIVATE_KEY_META}/${name}.group"
SCRIPT
    cat > "${RLCH_TEST_PRIVATE_KEY_BIN}/chmod" <<'SCRIPT'
#!/usr/bin/env bash
mode="$1"; shift; [[ "$1" == "--" ]] && shift; file="$1"; name="$(basename -- "${file}")"
if [[ "${file}" == "${RLCH_CIS_5_1_2_STATE_FILE}.tmp."* ]]; then /bin/chmod "${mode}" "${file}"; exit; fi
printf 'chmod %s %s\n' "${mode}" "${file}" >> "${RLCH_TEST_PRIVATE_KEY_LOG}"
[[ "${RLCH_TEST_PRIVATE_KEY_FAIL}" != "chmod:${name}" ]] || exit 2
printf '%s\n' "${mode#0}" > "${RLCH_TEST_PRIVATE_KEY_META}/${name}.mode"
SCRIPT
    chmod +x "${RLCH_TEST_PRIVATE_KEY_BIN}/stat" "${RLCH_TEST_PRIVATE_KEY_BIN}/chown" "${RLCH_TEST_PRIVATE_KEY_BIN}/chmod"
    PATH="${RLCH_TEST_PRIVATE_KEY_BIN}:${PATH}"; export PATH
}

sshd_private_key_add() { local name="$1"; : > "${RLCH_CIS_5_1_2_KEY_DIR}/${name}"; printf '%s\n' "$2" > "${RLCH_TEST_PRIVATE_KEY_META}/${name}.owner"; printf '%s\n' "$3" > "${RLCH_TEST_PRIVATE_KEY_META}/${name}.group"; printf '%s\n' "$4" > "${RLCH_TEST_PRIVATE_KEY_META}/${name}.mode"; }
sshd_private_key_value() { cat "${RLCH_TEST_PRIVATE_KEY_META}/$1.$2"; }
rlch_test_private_key_id() { [[ "$1" == -u && "${RLCH_TEST_PRIVATE_KEY_FAIL}" != id ]] || return 2; printf '%s\n' "${RLCH_TEST_PRIVATE_KEY_UID}"; }
rlch_test_private_key_getent() { [[ "$1" == group && "$2" == ssh_keys && "${RLCH_TEST_PRIVATE_KEY_FAIL}" != getent ]] || return 2; printf 'ssh_keys:x:%s:\n' "${RLCH_TEST_PRIVATE_KEY_GID}"; }
