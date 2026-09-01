#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
#
# Bats helper for sysctl-related tests.
#
# SPDX-License-Identifier: MIT
#

setup_sysctl_test_environment() {
    RLCH_TEST_SYSCTL_DIR="${BATS_TEST_TMPDIR}/sysctl-test"
    RLCH_TEST_SYSCTL_BIN="${RLCH_TEST_SYSCTL_DIR}/bin"
    RLCH_TEST_SYSCTL_CONFIG_DIR="${RLCH_TEST_SYSCTL_DIR}/sysctl.d"
    RLCH_TEST_SYSCTL_CONFIG="${RLCH_TEST_SYSCTL_CONFIG_DIR}/60-rlch-aslr.conf"
    RLCH_TEST_SYSCTL_STATE="${RLCH_TEST_SYSCTL_DIR}/runtime.state"

    mkdir -p "${RLCH_TEST_SYSCTL_BIN}" "${RLCH_TEST_SYSCTL_CONFIG_DIR}"

    cat > "${RLCH_TEST_SYSCTL_BIN}/id" <<'EOF'
#!/usr/bin/env bash

if [[ "${1:-}" == "-u" ]]; then
    printf '%s\n' "${RLCH_TEST_SYSCTL_EFFECTIVE_UID:-0}"
    exit 0
fi

exec /usr/bin/id "$@"
EOF

    cat > "${RLCH_TEST_SYSCTL_BIN}/sysctl" <<'EOF'
#!/usr/bin/env bash

if [[ "${1:-}" == "-n" ]]; then
    parameter="${2:-}"
    awk -F= -v parameter="${parameter}" '
        $1 == parameter {
            print $2
            found = 1
        }
        END {
            exit(found ? 0 : 1)
        }
    ' "${RLCH_TEST_SYSCTL_STATE}"
    exit $?
fi

if [[ "${1:-}" == "-w" ]]; then
    assignment="${2:-}"
    parameter="${assignment%%=*}"
    value="${assignment#*=}"
    temporary="${RLCH_TEST_SYSCTL_STATE}.tmp"

    awk -F= -v parameter="${parameter}" '
        $1 != parameter {
            print
        }
    ' "${RLCH_TEST_SYSCTL_STATE}" > "${temporary}"

    printf '%s=%s\n' "${parameter}" "${value}" >> "${temporary}"
    mv -- "${temporary}" "${RLCH_TEST_SYSCTL_STATE}"
    printf '%s = %s\n' "${parameter}" "${value}"
    exit 0
fi

exit 1
EOF

    cat > "${RLCH_TEST_SYSCTL_BIN}/chown" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF

    chmod +x \
        "${RLCH_TEST_SYSCTL_BIN}/id" \
        "${RLCH_TEST_SYSCTL_BIN}/sysctl" \
        "${RLCH_TEST_SYSCTL_BIN}/chown"

    : > "${RLCH_TEST_SYSCTL_STATE}"

    export RLCH_TEST_SYSCTL_EFFECTIVE_UID=0
    export RLCH_TEST_SYSCTL_STATE

    PATH="${RLCH_TEST_SYSCTL_BIN}:${PATH}"
    export PATH

    RLCH_SYSCTL_CONFIG_DIR="${RLCH_TEST_SYSCTL_CONFIG_DIR}"
    RLCH_SYSCTL_BACKUP_SUFFIX=".rlch.bak"
}

teardown_sysctl_test_environment() {
    rm -rf "${RLCH_TEST_SYSCTL_DIR}"
}

set_sysctl_test_effective_uid() {
    local uid="${1:?Effective UID is required}"

    export RLCH_TEST_SYSCTL_EFFECTIVE_UID="${uid}"
}

set_sysctl_test_runtime_value() {
    local parameter="${1:?Parameter is required}"
    local value="${2:?Value is required}"

    printf '%s=%s\n' "${parameter}" "${value}" > "${RLCH_TEST_SYSCTL_STATE}"
}

write_sysctl_test_config() {
    cat > "${RLCH_TEST_SYSCTL_CONFIG}"
}
