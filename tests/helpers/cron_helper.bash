#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
#
# Bats helper for cron-related tests.
#
# SPDX-License-Identifier: MIT
#

setup_cron_test_environment() {
    RLCH_TEST_CRON_DIR="${BATS_TEST_TMPDIR}/cron-test"
    RLCH_TEST_CRON_BIN="${RLCH_TEST_CRON_DIR}/bin"
    RLCH_TEST_CRONTAB="${RLCH_TEST_CRON_DIR}/crontab"

    mkdir -p "${RLCH_TEST_CRON_BIN}"

    cat > "${RLCH_TEST_CRONTAB}" <<'EOF'
SHELL=/bin/bash
PATH=/sbin:/bin:/usr/sbin:/usr/bin
MAILTO=root
EOF

    cat > "${RLCH_TEST_CRON_BIN}/id" <<'EOF'
#!/usr/bin/env bash

if [[ "${1:-}" == "-u" ]]; then
    printf '%s\n' "${RLCH_TEST_EFFECTIVE_UID:-0}"
    exit 0
fi

exec /usr/bin/id "$@"
EOF

    chmod +x "${RLCH_TEST_CRON_BIN}/id"

    export RLCH_TEST_EFFECTIVE_UID=0

    PATH="${RLCH_TEST_CRON_BIN}:${PATH}"
    export PATH

    RLCH_CRON_BACKUP_SUFFIX=".rlch.bak"
}

teardown_cron_test_environment() {
    rm -rf "${RLCH_TEST_CRON_DIR}"
}

set_cron_test_effective_uid() {
    local uid="${1:?Effective UID is required}"

    export RLCH_TEST_EFFECTIVE_UID="${uid}"
}

write_cron_test_crontab() {
    cat > "${RLCH_TEST_CRONTAB}"
}

create_cron_test_backup() {
    cp -p -- \
        "${RLCH_TEST_CRONTAB}" \
        "${RLCH_TEST_CRONTAB}${RLCH_CRON_BACKUP_SUFFIX}"
}
