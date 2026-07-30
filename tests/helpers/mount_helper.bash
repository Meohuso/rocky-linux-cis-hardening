#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
#
# Shared mount Bats test helpers.
#
# SPDX-License-Identifier: MIT
#

if [[ -n "${RLCH_MOUNT_TEST_HELPER_LOADED:-}" ]]; then
    return 0
fi

readonly RLCH_MOUNT_TEST_HELPER_LOADED="true"

##
# Initialize an isolated mount test environment.
#
# Globals set:
#   RLCH_TEST_TEMPORARY_DIRECTORY
#   RLCH_TEST_BIN_DIRECTORY
#   RLCH_TEST_FSTAB
#   RLCH_TEST_RUNTIME_MOUNTS
#   RLCH_TEST_MOUNT_LOG
#   RLCH_TEST_EFFECTIVE_UID
#   RLCH_MOUNT_FSTAB
#   RLCH_MOUNT_FINDMNT_COMMAND
#   RLCH_MOUNT_COMMAND
#
# Returns:
#   0 on success.
##
setup_mount_test_environment() {
    RLCH_TEST_TEMPORARY_DIRECTORY="$(
        mktemp -d "${BATS_TEST_TMPDIR}/rlch-mount.XXXXXX"
    )"
    RLCH_TEST_BIN_DIRECTORY="${RLCH_TEST_TEMPORARY_DIRECTORY}/bin"
    RLCH_TEST_FSTAB="${RLCH_TEST_TEMPORARY_DIRECTORY}/fstab"
    RLCH_TEST_RUNTIME_MOUNTS="${RLCH_TEST_TEMPORARY_DIRECTORY}/runtime-mounts"
    RLCH_TEST_MOUNT_LOG="${RLCH_TEST_TEMPORARY_DIRECTORY}/mount.log"
    RLCH_TEST_EFFECTIVE_UID="0"

    mkdir -p "${RLCH_TEST_BIN_DIRECTORY}"
    : > "${RLCH_TEST_FSTAB}"
    : > "${RLCH_TEST_RUNTIME_MOUNTS}"
    : > "${RLCH_TEST_MOUNT_LOG}"

    create_mount_test_id_command
    create_mount_test_findmnt_command
    create_mount_test_mount_command

    export PATH="${RLCH_TEST_BIN_DIRECTORY}:${PATH}"
    export RLCH_TEST_EFFECTIVE_UID
    export RLCH_TEST_RUNTIME_MOUNTS
    export RLCH_TEST_MOUNT_LOG

    RLCH_MOUNT_FSTAB="${RLCH_TEST_FSTAB}"
    RLCH_MOUNT_FINDMNT_COMMAND="${RLCH_TEST_BIN_DIRECTORY}/findmnt"
    RLCH_MOUNT_COMMAND="${RLCH_TEST_BIN_DIRECTORY}/mount"
}

##
# Remove the isolated mount test environment.
##
teardown_mount_test_environment() {
    if [[ -n "${RLCH_TEST_TEMPORARY_DIRECTORY:-}" ]]; then
        rm -rf -- "${RLCH_TEST_TEMPORARY_DIRECTORY}"
    fi
}

##
# Create the fake id command used by the mount library.
##
create_mount_test_id_command() {
    cat > "${RLCH_TEST_BIN_DIRECTORY}/id" <<'EOF'
#!/usr/bin/env bash

if [[ "${1:-}" == "-u" ]]; then
    printf '%s\n' "${RLCH_TEST_EFFECTIVE_UID:-0}"
    exit 0
fi

exec /usr/bin/id "$@"
EOF

    chmod 0755 "${RLCH_TEST_BIN_DIRECTORY}/id"
}

##
# Create the fake findmnt command used by the mount library.
##
create_mount_test_findmnt_command() {
    cat > "${RLCH_TEST_BIN_DIRECTORY}/findmnt" <<'EOF'
#!/usr/bin/env bash

target=""
previous=""

for argument in "$@"; do
    if [[ "${previous}" == "--target" ]]; then
        target="${argument}"
        break
    fi
    previous="${argument}"
done

[[ -n "${target}" ]] || exit 1
[[ -r "${RLCH_TEST_RUNTIME_MOUNTS}" ]] || exit 1

while IFS=$'\t' read -r source mount_target filesystem options; do
    [[ -n "${mount_target}" ]] || continue

    if [[ "${mount_target}" == "${target}" ]]; then
        printf '%s %s %s %s\n' \
            "${source}" \
            "${mount_target}" \
            "${filesystem}" \
            "${options}"
        exit 0
    fi
done < "${RLCH_TEST_RUNTIME_MOUNTS}"

exit 1
EOF

    chmod 0755 "${RLCH_TEST_BIN_DIRECTORY}/findmnt"
}

##
# Create the fake mount command used by rollback tests.
##
create_mount_test_mount_command() {
    cat > "${RLCH_TEST_BIN_DIRECTORY}/mount" <<'EOF'
#!/usr/bin/env bash

printf '%s\n' "$*" >> "${RLCH_TEST_MOUNT_LOG}"
exit 0
EOF

    chmod 0755 "${RLCH_TEST_BIN_DIRECTORY}/mount"
}

##
# Set the effective UID returned by the fake id command.
#
# Arguments:
#   $1 Numeric effective UID.
##
set_mount_test_effective_uid() {
    RLCH_TEST_EFFECTIVE_UID="${1:?Effective UID is required.}"
    export RLCH_TEST_EFFECTIVE_UID
}

##
# Add a persistent fstab entry.
#
# Arguments:
#   $1 Mount target.
#   $2 Optional source.
#   $3 Optional filesystem type.
#   $4 Optional mount options.
##
add_mount_test_fstab_entry() {
    local target="${1:?Mount target is required.}"
    local source="${2:-/dev/mapper/rlch-test}"
    local filesystem="${3:-xfs}"
    local options="${4:-defaults}"

    printf '%s\t%s\t%s\t%s\t0\t0\n' \
        "${source}" \
        "${target}" \
        "${filesystem}" \
        "${options}" >> "${RLCH_TEST_FSTAB}"
}

##
# Add a runtime mount entry.
#
# Arguments:
#   $1 Mount target.
#   $2 Optional source.
#   $3 Optional filesystem type.
#   $4 Optional mount options.
##
add_mount_test_runtime_entry() {
    local target="${1:?Mount target is required.}"
    local source="${2:-/dev/mapper/rlch-test}"
    local filesystem="${3:-xfs}"
    local options="${4:-rw,relatime}"

    printf '%s\t%s\t%s\t%s\n' \
        "${source}" \
        "${target}" \
        "${filesystem}" \
        "${options}" >> "${RLCH_TEST_RUNTIME_MOUNTS}"
}

##
# Create the backup path expected by the mount library.
#
# Arguments:
#   $1 Backup content.
##
create_mount_test_fstab_backup() {
    local content="${1:-}"

    printf '%s' "${content}" > "${RLCH_TEST_FSTAB}${RLCH_MOUNT_BACKUP_SUFFIX}"
}
