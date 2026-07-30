#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
#
# Shared Bats helpers for mount library tests.
#
# SPDX-License-Identifier: MIT
#

setup_mount_test_environment() {
    RLCH_TEST_MOUNT_ROOT="$(mktemp -d)"
    RLCH_TEST_MOUNT_BIN="${RLCH_TEST_MOUNT_ROOT}/bin"
    RLCH_TEST_MOUNT_STATE="${RLCH_TEST_MOUNT_ROOT}/state"
    RLCH_TEST_MOUNT_FSTAB="${RLCH_TEST_MOUNT_ROOT}/fstab"
    RLCH_TEST_MOUNT_BACKUP="${RLCH_TEST_MOUNT_ROOT}/backup/fstab"
    RLCH_TEST_MOUNT_LOG="${RLCH_TEST_MOUNT_ROOT}/mount.log"

    mkdir -p "${RLCH_TEST_MOUNT_BIN}" "${RLCH_TEST_MOUNT_STATE}"
    : >"${RLCH_TEST_MOUNT_LOG}"

    export RLCH_TEST_MOUNT_ROOT
    export RLCH_TEST_MOUNT_STATE
    export RLCH_TEST_MOUNT_LOG
    export PATH="${RLCH_TEST_MOUNT_BIN}:${PATH}"

    create_fake_findmnt
    create_fake_mount
    set_mount_runtime_state "/tmp" "rw,relatime"
    set_mount_fstab_entry "/tmp" "defaults"
}

teardown_mount_test_environment() {
    rm -rf "${RLCH_TEST_MOUNT_ROOT:-}"
}

create_fake_findmnt() {
    cat >"${RLCH_TEST_MOUNT_BIN}/findmnt" <<'EOF_FINDMNT'
#!/usr/bin/env bash
set -u

output=""
target=""
while (($# > 0)); do
    case "$1" in
        --output)
            output="${2:-}"
            shift 2
            ;;
        --target)
            target="${2:-}"
            shift 2
            ;;
        *)
            shift
            ;;
    esac
done

[[ -f "${RLCH_TEST_MOUNT_STATE}/target" ]] || exit 1
runtime_target="$(cat "${RLCH_TEST_MOUNT_STATE}/target")"
runtime_options="$(cat "${RLCH_TEST_MOUNT_STATE}/options")"

case "${output}" in
    TARGET)
        printf '%s\n' "${runtime_target}"
        ;;
    OPTIONS)
        printf '%s\n' "${runtime_options}"
        ;;
    *)
        exit 1
        ;;
esac
EOF_FINDMNT
    chmod 0755 "${RLCH_TEST_MOUNT_BIN}/findmnt"
}

create_fake_mount() {
    cat >"${RLCH_TEST_MOUNT_BIN}/mount" <<'EOF_MOUNT'
#!/usr/bin/env bash
set -u

printf '%s\n' "$*" >>"${RLCH_TEST_MOUNT_LOG}"

if [[ -f "${RLCH_TEST_MOUNT_STATE}/mount_fail" ]]; then
    exit 1
fi

if [[ "${1:-}" == "-o" && "${2:-}" == remount,* ]]; then
    option="${2#remount,}"
    options="$(cat "${RLCH_TEST_MOUNT_STATE}/options")"
    case ",${options}," in
        *",${option},"*) ;;
        *) printf '%s,%s\n' "${options}" "${option}" >"${RLCH_TEST_MOUNT_STATE}/options" ;;
    esac
fi
EOF_MOUNT
    chmod 0755 "${RLCH_TEST_MOUNT_BIN}/mount"
}

set_mount_runtime_state() {
    local target="${1:?Target is required.}"
    local options="${2:?Options are required.}"

    printf '%s\n' "${target}" >"${RLCH_TEST_MOUNT_STATE}/target"
    printf '%s\n' "${options}" >"${RLCH_TEST_MOUNT_STATE}/options"
}

set_mount_fstab_entry() {
    local mount_point="${1:?Mount point is required.}"
    local options="${2:?Options are required.}"

    cat >"${RLCH_TEST_MOUNT_FSTAB}" <<EOF_FSTAB
# test fstab
/dev/mapper/rl-root / xfs defaults 0 0
/dev/mapper/rl-tmp ${mount_point} xfs ${options} 0 0
EOF_FSTAB
}

remove_mount_fstab_entry() {
    cat >"${RLCH_TEST_MOUNT_FSTAB}" <<'EOF_FSTAB'
/dev/mapper/rl-root / xfs defaults 0 0
EOF_FSTAB
}
