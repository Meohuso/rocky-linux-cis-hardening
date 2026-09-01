#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
#
# Bats helper for GRUB2-related tests.
#
# SPDX-License-Identifier: MIT
#

setup_grub_test_environment() {
    RLCH_TEST_GRUB_DIR="${BATS_TEST_TMPDIR}/grub-test"
    RLCH_TEST_GRUB_BIN="${RLCH_TEST_GRUB_DIR}/bin"
    RLCH_TEST_GRUB_CONFIG="${RLCH_TEST_GRUB_DIR}/grub.cfg"
    RLCH_TEST_GRUB_USER_CONFIG="${RLCH_TEST_GRUB_DIR}/user.cfg"
    RLCH_TEST_GRUB_OWNERSHIP_STATE="${RLCH_TEST_GRUB_DIR}/ownership.state"

    mkdir -p "${RLCH_TEST_GRUB_BIN}"

    cat > "${RLCH_TEST_GRUB_BIN}/id" <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" == "-u" ]]; then
    printf '%s\n' "${RLCH_TEST_GRUB_EFFECTIVE_UID:-0}"
    exit 0
fi
exec /usr/bin/id "$@"
EOF

    cat > "${RLCH_TEST_GRUB_BIN}/stat" <<'EOF'
#!/usr/bin/env bash
format=""
file=""
while [[ "$#" -gt 0 ]]; do
    case "${1}" in
        -L) shift ;;
        -c|-Lc) format="${2:-}"; shift 2 ;;
        --) shift; file="${1:-}"; shift ;;
        *) [[ -z "${file}" ]] && file="${1}"; shift ;;
    esac
done

case "${format}" in
    "%u")
        if [[ -f "${RLCH_TEST_GRUB_OWNERSHIP_STATE}" ]] &&
           grep -Fqx "${file}|0|0" "${RLCH_TEST_GRUB_OWNERSHIP_STATE}"; then
            printf '%s\n' "0"
        else
            printf '%s\n' "${RLCH_TEST_GRUB_DEFAULT_UID:-0}"
        fi
        ;;
    "%g")
        if [[ -f "${RLCH_TEST_GRUB_OWNERSHIP_STATE}" ]] &&
           grep -Fqx "${file}|0|0" "${RLCH_TEST_GRUB_OWNERSHIP_STATE}"; then
            printf '%s\n' "0"
        else
            printf '%s\n' "${RLCH_TEST_GRUB_DEFAULT_GID:-0}"
        fi
        ;;
    *)
        exec /usr/bin/stat -Lc "${format}" -- "${file}"
        ;;
esac
EOF

    cat > "${RLCH_TEST_GRUB_BIN}/chown" <<'EOF'
#!/usr/bin/env bash
ownership="${1:-}"
shift || true
[[ "${1:-}" == "--" ]] && shift
file="${1:-}"

[[ "${ownership}" == "0:0" && -n "${file}" ]] || exit 1

tmp_file="${RLCH_TEST_GRUB_OWNERSHIP_STATE}.tmp"
if [[ -f "${RLCH_TEST_GRUB_OWNERSHIP_STATE}" ]]; then
    grep -Fv "${file}|" "${RLCH_TEST_GRUB_OWNERSHIP_STATE}" > "${tmp_file}" || true
else
    : > "${tmp_file}"
fi
printf '%s|0|0\n' "${file}" >> "${tmp_file}"
mv -- "${tmp_file}" "${RLCH_TEST_GRUB_OWNERSHIP_STATE}"
EOF

    chmod +x "${RLCH_TEST_GRUB_BIN}/id" "${RLCH_TEST_GRUB_BIN}/stat" "${RLCH_TEST_GRUB_BIN}/chown"

    export RLCH_TEST_GRUB_EFFECTIVE_UID=0
    export RLCH_TEST_GRUB_DEFAULT_UID=0
    export RLCH_TEST_GRUB_DEFAULT_GID=0
    export RLCH_TEST_GRUB_OWNERSHIP_STATE

    PATH="${RLCH_TEST_GRUB_BIN}:${PATH}"
    export PATH

    RLCH_GRUB_CONFIG="${RLCH_TEST_GRUB_CONFIG}"
    RLCH_GRUB_USER_CONFIG="${RLCH_TEST_GRUB_USER_CONFIG}"
    RLCH_GRUB_BACKUP_SUFFIX=".rlch.bak"
}

teardown_grub_test_environment() {
    rm -rf "${RLCH_TEST_GRUB_DIR}"
}

set_grub_test_effective_uid() {
    local uid="${1:?Effective UID is required}"
    export RLCH_TEST_GRUB_EFFECTIVE_UID="${uid}"
}

set_grub_test_default_ownership() {
    local uid="${1:?UID is required}"
    local gid="${2:?GID is required}"
    export RLCH_TEST_GRUB_DEFAULT_UID="${uid}"
    export RLCH_TEST_GRUB_DEFAULT_GID="${gid}"
}

write_grub_test_config() {
    cat > "${RLCH_TEST_GRUB_CONFIG}"
}

write_grub_test_user_config() {
    cat > "${RLCH_TEST_GRUB_USER_CONFIG}"
}
