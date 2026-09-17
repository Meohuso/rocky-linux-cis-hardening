#!/usr/bin/env bash

sysctl_control_helper_setup() {
    export RLCH_TEST_SYSCTL_CONTROL_ROOT="${BATS_TEST_TMPDIR}/sysctl-control"
    export RLCH_TEST_SYSCTL_CONTROL_BIN="${RLCH_TEST_SYSCTL_CONTROL_ROOT}/bin"
    export RLCH_TEST_SYSCTL_CONTROL_CONFIG_DIR="${RLCH_TEST_SYSCTL_CONTROL_ROOT}/sysctl.d"
    export RLCH_TEST_SYSCTL_CONTROL_RUNTIME="${RLCH_TEST_SYSCTL_CONTROL_ROOT}/runtime.state"
    export RLCH_TEST_SYSCTL_CONTROL_UID=0
    export RLCH_TEST_SYSCTL_CONTROL_FAIL_WRITE=""

    mkdir -p "${RLCH_TEST_SYSCTL_CONTROL_BIN}" "${RLCH_TEST_SYSCTL_CONTROL_CONFIG_DIR}"
    : > "${RLCH_TEST_SYSCTL_CONTROL_RUNTIME}"
    export RLCH_SYSCTL_CONTROL_SYSCTL_COMMAND="${RLCH_TEST_SYSCTL_CONTROL_BIN}/sysctl"
    export RLCH_SYSCTL_CONTROL_ID_COMMAND="${RLCH_TEST_SYSCTL_CONTROL_BIN}/id"
    export RLCH_SYSCTL_CONTROL_CHOWN_COMMAND="${RLCH_TEST_SYSCTL_CONTROL_BIN}/chown"
    sysctl_control_helper_write_commands
}

sysctl_control_helper_write_commands() {
    cat > "${RLCH_TEST_SYSCTL_CONTROL_BIN}/id" <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" == -u ]]; then
    printf '%s\n' "${RLCH_TEST_SYSCTL_CONTROL_UID}"
    exit 0
fi
exit 1
EOF

    cat > "${RLCH_TEST_SYSCTL_CONTROL_BIN}/sysctl" <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" == -n ]]; then
    parameter="${2:-}"
    awk -F= -v parameter="${parameter}" '$1 == parameter { print substr($0, length($1) + 2); found = 1 } END { exit(found ? 0 : 1) }' "${RLCH_TEST_SYSCTL_CONTROL_RUNTIME}"
    exit $?
fi
if [[ "${1:-}" == -w ]]; then
    assignment="${2:-}"
    parameter="${assignment%%=*}"
    value="${assignment#*=}"
    [[ "${RLCH_TEST_SYSCTL_CONTROL_FAIL_WRITE}" != "${parameter}" ]] || exit 1
    temporary="${RLCH_TEST_SYSCTL_CONTROL_RUNTIME}.tmp"
    awk -F= -v parameter="${parameter}" '$1 != parameter { print }' "${RLCH_TEST_SYSCTL_CONTROL_RUNTIME}" > "${temporary}"
    printf '%s=%s\n' "${parameter}" "${value}" >> "${temporary}"
    mv -- "${temporary}" "${RLCH_TEST_SYSCTL_CONTROL_RUNTIME}"
    printf '%s = %s\n' "${parameter}" "${value}"
    exit 0
fi
exit 1
EOF

    cat > "${RLCH_TEST_SYSCTL_CONTROL_BIN}/chown" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
    chmod +x "${RLCH_TEST_SYSCTL_CONTROL_BIN}/id" "${RLCH_TEST_SYSCTL_CONTROL_BIN}/sysctl" "${RLCH_TEST_SYSCTL_CONTROL_BIN}/chown"
}

sysctl_control_helper_set_runtime() {
    local parameter="${1:?Parameter is required}"
    local value="${2:?Value is required}"
    local temporary="${RLCH_TEST_SYSCTL_CONTROL_RUNTIME}.tmp"

    awk -F= -v parameter="${parameter}" '$1 != parameter { print }' "${RLCH_TEST_SYSCTL_CONTROL_RUNTIME}" > "${temporary}"
    printf '%s=%s\n' "${parameter}" "${value}" >> "${temporary}"
    mv -- "${temporary}" "${RLCH_TEST_SYSCTL_CONTROL_RUNTIME}"
}

sysctl_control_helper_runtime_value() {
    "${RLCH_SYSCTL_CONTROL_SYSCTL_COMMAND}" -n "${1:?Parameter is required}"
}

sysctl_control_helper_write_config() {
    local config_file="${1:?Configuration file is required}"
    mkdir -p "$(dirname -- "${config_file}")"
    while IFS= read -r line; do
        printf '%s\n' "${line}"
    done > "${config_file}"
}
