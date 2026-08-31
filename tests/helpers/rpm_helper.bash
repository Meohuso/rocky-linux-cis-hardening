#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
#
# Bats helper for RPM and DNF-related tests.
#
# SPDX-License-Identifier: MIT
#

setup_rpm_test_environment() {
    RLCH_TEST_RPM_DIR="${BATS_TEST_TMPDIR}/rpm-test"
    RLCH_TEST_RPM_BIN="${RLCH_TEST_RPM_DIR}/bin"
    RLCH_TEST_RPM_KEYS="${RLCH_TEST_RPM_DIR}/gpg-keys"
    RLCH_TEST_RPM_EXIT_STATUS="${RLCH_TEST_RPM_DIR}/exit-status"
    RLCH_TEST_DNF_REPOSITORIES="${RLCH_TEST_RPM_DIR}/dnf-repositories"
    RLCH_TEST_DNF_EXIT_STATUS="${RLCH_TEST_RPM_DIR}/dnf-exit-status"
    RLCH_TEST_DNF_CONFIG="${RLCH_TEST_RPM_DIR}/dnf.conf"

    mkdir -p "${RLCH_TEST_RPM_BIN}"
    : > "${RLCH_TEST_RPM_KEYS}"
    : > "${RLCH_TEST_DNF_REPOSITORIES}"
    printf '0\n' > "${RLCH_TEST_RPM_EXIT_STATUS}"
    printf '0\n' > "${RLCH_TEST_DNF_EXIT_STATUS}"
    printf '[main]\n' > "${RLCH_TEST_DNF_CONFIG}"

    cat > "${RLCH_TEST_RPM_BIN}/rpm" <<'EOF'
#!/usr/bin/env bash

if [[ "${1:-}" != "-q" || "${2:-}" != "gpg-pubkey" ]]; then
    exit 2
fi

status="$(cat "${RLCH_TEST_RPM_EXIT_STATUS}")"

if [[ "${status}" -ne 0 ]]; then
    exit "${status}"
fi

cat "${RLCH_TEST_RPM_KEYS}"
EOF

    cat > "${RLCH_TEST_RPM_BIN}/dnf" <<'EOF'
#!/usr/bin/env bash

if [[ "${1:-}" != "-q" || "${2:-}" != "repolist" || "${3:-}" != "--enabled" ]]; then
    exit 2
fi

status="$(cat "${RLCH_TEST_DNF_EXIT_STATUS}")"

if [[ "${status}" -ne 0 ]]; then
    exit "${status}"
fi

if [[ -s "${RLCH_TEST_DNF_REPOSITORIES}" ]]; then
    printf '%-24s %s\n' "repo id" "repo name"
    cat "${RLCH_TEST_DNF_REPOSITORIES}"
fi
EOF

    cat > "${RLCH_TEST_RPM_BIN}/id" <<'EOF'
#!/usr/bin/env bash

if [[ "${1:-}" == "-u" ]]; then
    printf '%s\n' "${RLCH_TEST_EFFECTIVE_UID:-0}"
    exit 0
fi

exec /usr/bin/id "$@"
EOF

    chmod +x "${RLCH_TEST_RPM_BIN}/rpm"
    chmod +x "${RLCH_TEST_RPM_BIN}/dnf"
    chmod +x "${RLCH_TEST_RPM_BIN}/id"

    export RLCH_TEST_RPM_KEYS
    export RLCH_TEST_RPM_EXIT_STATUS
    export RLCH_TEST_DNF_REPOSITORIES
    export RLCH_TEST_DNF_EXIT_STATUS
    export RLCH_TEST_EFFECTIVE_UID=0

    PATH="${RLCH_TEST_RPM_BIN}:${PATH}"
    export PATH

    RLCH_RPM_COMMAND="${RLCH_TEST_RPM_BIN}/rpm"
    RLCH_DNF_COMMAND="${RLCH_TEST_RPM_BIN}/dnf"
    RLCH_DNF_CONFIG="${RLCH_TEST_DNF_CONFIG}"
    RLCH_DNF_CONFIG_BACKUP_SUFFIX=".rlch.bak"
}

teardown_rpm_test_environment() {
    rm -rf "${RLCH_TEST_RPM_DIR}"
}

add_rpm_test_gpg_key() {
    local package_name="${1:?GPG key package name is required}"

    printf '%s\n' "${package_name}" >> "${RLCH_TEST_RPM_KEYS}"
}

set_rpm_test_exit_status() {
    local status="${1:?Exit status is required}"

    printf '%s\n' "${status}" > "${RLCH_TEST_RPM_EXIT_STATUS}"
}

set_rpm_test_effective_uid() {
    local uid="${1:?Effective UID is required}"

    export RLCH_TEST_EFFECTIVE_UID="${uid}"
}

write_dnf_test_config() {
    cat > "${RLCH_TEST_DNF_CONFIG}"
}

create_dnf_test_config_backup() {
    cp -p -- \
        "${RLCH_TEST_DNF_CONFIG}" \
        "${RLCH_TEST_DNF_CONFIG}${RLCH_DNF_CONFIG_BACKUP_SUFFIX}"
}

add_dnf_test_repository() {
    local repository_id="${1:?Repository identifier is required}"
    local repository_name="${2:?Repository name is required}"

    printf '%-24s %s\n' \
        "${repository_id}" \
        "${repository_name}" >> "${RLCH_TEST_DNF_REPOSITORIES}"
}

set_dnf_test_exit_status() {
    local status="${1:?Exit status is required}"

    printf '%s\n' "${status}" > "${RLCH_TEST_DNF_EXIT_STATUS}"
}
