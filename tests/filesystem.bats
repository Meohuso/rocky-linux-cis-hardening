#!/usr/bin/env bats

setup() {
    TEST_ROOT_DIR="$(
        cd "${BATS_TEST_DIRNAME}/.." && pwd
    )"

    TEST_TEMP_DIR="$(
        mktemp -d "${BATS_TEST_TMPDIR}/rlch-filesystem.XXXXXX"
    )"

    # shellcheck source=../lib/common.sh
    source "${TEST_ROOT_DIR}/lib/common.sh"

    # shellcheck source=../lib/error.sh
    source "${TEST_ROOT_DIR}/lib/error.sh"

    # shellcheck source=../lib/filesystem.sh
    source "${TEST_ROOT_DIR}/lib/filesystem.sh"
}

teardown() {
    rm -rf "${TEST_TEMP_DIR}"
}

@test "filesystem library prevents multiple sourcing" {
    run bash -c "
        source '${TEST_ROOT_DIR}/lib/common.sh'
        source '${TEST_ROOT_DIR}/lib/error.sh'
        source '${TEST_ROOT_DIR}/lib/filesystem.sh'
        source '${TEST_ROOT_DIR}/lib/filesystem.sh'
        printf '%s' \"\${RLCH_FILESYSTEM_LOADED}\"
    "

    [ "${status}" -eq 0 ]
    [ "${output}" = "1" ]
}

@test "filesystem_exists detects a regular file" {
    touch "${TEST_TEMP_DIR}/file"

    run filesystem_exists "${TEST_TEMP_DIR}/file"

    [ "${status}" -eq 0 ]
}

@test "filesystem_exists detects a broken symbolic link" {
    ln -s "${TEST_TEMP_DIR}/missing" "${TEST_TEMP_DIR}/link"

    run filesystem_exists "${TEST_TEMP_DIR}/link"

    [ "${status}" -eq 0 ]
}

@test "filesystem_exists rejects a missing path" {
    run filesystem_exists "${TEST_TEMP_DIR}/missing"

    [ "${status}" -eq 1 ]
}

@test "filesystem_file_exists detects a regular file" {
    touch "${TEST_TEMP_DIR}/file"

    run filesystem_file_exists "${TEST_TEMP_DIR}/file"

    [ "${status}" -eq 0 ]
}

@test "filesystem_file_exists rejects a directory" {
    mkdir "${TEST_TEMP_DIR}/directory"

    run filesystem_file_exists "${TEST_TEMP_DIR}/directory"

    [ "${status}" -eq 1 ]
}

@test "filesystem_directory_exists detects a directory" {
    mkdir "${TEST_TEMP_DIR}/directory"

    run filesystem_directory_exists "${TEST_TEMP_DIR}/directory"

    [ "${status}" -eq 0 ]
}

@test "filesystem_symlink_exists detects a symbolic link" {
    ln -s "${TEST_TEMP_DIR}/target" "${TEST_TEMP_DIR}/link"

    run filesystem_symlink_exists "${TEST_TEMP_DIR}/link"

    [ "${status}" -eq 0 ]
}

@test "filesystem_is_readable detects a readable file" {
    touch "${TEST_TEMP_DIR}/file"
    chmod 0644 "${TEST_TEMP_DIR}/file"

    run filesystem_is_readable "${TEST_TEMP_DIR}/file"

    [ "${status}" -eq 0 ]
}

@test "filesystem_is_executable detects an executable file" {
    touch "${TEST_TEMP_DIR}/file"
    chmod 0755 "${TEST_TEMP_DIR}/file"

    run filesystem_is_executable "${TEST_TEMP_DIR}/file"

    [ "${status}" -eq 0 ]
}

@test "filesystem_create_directory creates parent directories" {
    run filesystem_create_directory \
        "${TEST_TEMP_DIR}/parent/child" \
        "0750"

    [ "${status}" -eq 0 ]
    [ -d "${TEST_TEMP_DIR}/parent/child" ]
    [ "$(stat -c '%a' "${TEST_TEMP_DIR}/parent/child")" = "750" ]
}

@test "filesystem_create_directory is idempotent" {
    mkdir "${TEST_TEMP_DIR}/directory"

    run filesystem_create_directory \
        "${TEST_TEMP_DIR}/directory" \
        "0700"

    [ "${status}" -eq 0 ]
    [ "$(stat -c '%a' "${TEST_TEMP_DIR}/directory")" = "700" ]
}

@test "filesystem_create_directory rejects an invalid mode" {
    run filesystem_create_directory \
        "${TEST_TEMP_DIR}/directory" \
        "999"

    [ "${status}" -eq 1 ]
    [ ! -e "${TEST_TEMP_DIR}/directory" ]
}

@test "filesystem_remove_file removes a file" {
    touch "${TEST_TEMP_DIR}/file"

    run filesystem_remove_file "${TEST_TEMP_DIR}/file"

    [ "${status}" -eq 0 ]
    [ ! -e "${TEST_TEMP_DIR}/file" ]
}

@test "filesystem_remove_file is idempotent" {
    run filesystem_remove_file "${TEST_TEMP_DIR}/missing"

    [ "${status}" -eq 0 ]
}

@test "filesystem_remove_file rejects a directory" {
    mkdir "${TEST_TEMP_DIR}/directory"

    run filesystem_remove_file "${TEST_TEMP_DIR}/directory"

    [ "${status}" -eq 1 ]
    [ -d "${TEST_TEMP_DIR}/directory" ]
}

@test "filesystem_remove_directory removes an empty directory" {
    mkdir "${TEST_TEMP_DIR}/directory"

    run filesystem_remove_directory "${TEST_TEMP_DIR}/directory"

    [ "${status}" -eq 0 ]
    [ ! -e "${TEST_TEMP_DIR}/directory" ]
}

@test "filesystem_remove_directory rejects a non-empty directory by default" {
    mkdir "${TEST_TEMP_DIR}/directory"
    touch "${TEST_TEMP_DIR}/directory/file"

    run filesystem_remove_directory "${TEST_TEMP_DIR}/directory"

    [ "${status}" -eq 1 ]
    [ -d "${TEST_TEMP_DIR}/directory" ]
}

@test "filesystem_remove_directory recursively removes a directory" {
    mkdir -p "${TEST_TEMP_DIR}/directory/child"
    touch "${TEST_TEMP_DIR}/directory/child/file"

    run filesystem_remove_directory \
        "${TEST_TEMP_DIR}/directory" \
        "true"

    [ "${status}" -eq 0 ]
    [ ! -e "${TEST_TEMP_DIR}/directory" ]
}

@test "filesystem_copy copies a regular file" {
    printf 'content' >"${TEST_TEMP_DIR}/source"

    run filesystem_copy \
        "${TEST_TEMP_DIR}/source" \
        "${TEST_TEMP_DIR}/destination"

    [ "${status}" -eq 0 ]
    [ "$(cat "${TEST_TEMP_DIR}/destination")" = "content" ]
}

@test "filesystem_copy rejects an existing destination by default" {
    printf 'source' >"${TEST_TEMP_DIR}/source"
    printf 'destination' >"${TEST_TEMP_DIR}/destination"

    run filesystem_copy \
        "${TEST_TEMP_DIR}/source" \
        "${TEST_TEMP_DIR}/destination"

    [ "${status}" -eq 1 ]
    [ "$(cat "${TEST_TEMP_DIR}/destination")" = "destination" ]
}

@test "filesystem_copy overwrites an existing destination when enabled" {
    printf 'source' >"${TEST_TEMP_DIR}/source"
    printf 'destination' >"${TEST_TEMP_DIR}/destination"

    run filesystem_copy \
        "${TEST_TEMP_DIR}/source" \
        "${TEST_TEMP_DIR}/destination" \
        "true"

    [ "${status}" -eq 0 ]
    [ "$(cat "${TEST_TEMP_DIR}/destination")" = "source" ]
}

@test "filesystem_move moves a regular file" {
    printf 'content' >"${TEST_TEMP_DIR}/source"

    run filesystem_move \
        "${TEST_TEMP_DIR}/source" \
        "${TEST_TEMP_DIR}/destination"

    [ "${status}" -eq 0 ]
    [ ! -e "${TEST_TEMP_DIR}/source" ]
    [ "$(cat "${TEST_TEMP_DIR}/destination")" = "content" ]
}

@test "filesystem_read_file prints file content" {
    printf 'content' >"${TEST_TEMP_DIR}/file"

    run filesystem_read_file "${TEST_TEMP_DIR}/file"

    [ "${status}" -eq 0 ]
    [ "${output}" = "content" ]
}

@test "filesystem_write_file creates a file" {
    run filesystem_write_file \
        "${TEST_TEMP_DIR}/file" \
        "content" \
        "0600"

    [ "${status}" -eq 0 ]
    [ "$(cat "${TEST_TEMP_DIR}/file")" = "content" ]
    [ "$(stat -c '%a' "${TEST_TEMP_DIR}/file")" = "600" ]
}

@test "filesystem_write_file replaces file content" {
    printf 'old' >"${TEST_TEMP_DIR}/file"
    chmod 0640 "${TEST_TEMP_DIR}/file"

    run filesystem_write_file \
        "${TEST_TEMP_DIR}/file" \
        "new"

    [ "${status}" -eq 0 ]
    [ "$(cat "${TEST_TEMP_DIR}/file")" = "new" ]
    [ "$(stat -c '%a' "${TEST_TEMP_DIR}/file")" = "640" ]
}

@test "filesystem_append_file creates a file" {
    run filesystem_append_file \
        "${TEST_TEMP_DIR}/file" \
        "content" \
        "0600"

    [ "${status}" -eq 0 ]
    [ "$(cat "${TEST_TEMP_DIR}/file")" = "content" ]
    [ "$(stat -c '%a' "${TEST_TEMP_DIR}/file")" = "600" ]
}

@test "filesystem_append_file appends content" {
    printf 'first' >"${TEST_TEMP_DIR}/file"

    run filesystem_append_file \
        "${TEST_TEMP_DIR}/file" \
        "second"

    [ "${status}" -eq 0 ]
    [ "$(cat "${TEST_TEMP_DIR}/file")" = "firstsecond" ]
}

@test "filesystem_replace_line replaces matching lines" {
    cat >"${TEST_TEMP_DIR}/file" <<'EOF'
first
PermitRootLogin yes
middle
PermitRootLogin prohibit-password
last
EOF

    run filesystem_replace_line \
        "${TEST_TEMP_DIR}/file" \
        '^[[:space:]]*PermitRootLogin[[:space:]]+' \
        'PermitRootLogin no'

    [ "${status}" -eq 0 ]

    run cat "${TEST_TEMP_DIR}/file"

    [ "${status}" -eq 0 ]
    [ "${output}" = $'first\nPermitRootLogin no\nmiddle\nlast' ]
}

@test "filesystem_replace_line appends when no line matches" {
    printf 'first\nsecond\n' >"${TEST_TEMP_DIR}/file"

    run filesystem_replace_line \
        "${TEST_TEMP_DIR}/file" \
        '^PermitRootLogin' \
        'PermitRootLogin no'

    [ "${status}" -eq 0 ]

    run cat "${TEST_TEMP_DIR}/file"

    [ "${output}" = $'first\nsecond\nPermitRootLogin no' ]
}

@test "filesystem_replace_line is idempotent" {
    printf 'PermitRootLogin no\n' >"${TEST_TEMP_DIR}/file"

    filesystem_replace_line \
        "${TEST_TEMP_DIR}/file" \
        '^PermitRootLogin' \
        'PermitRootLogin no'

    run filesystem_replace_line \
        "${TEST_TEMP_DIR}/file" \
        '^PermitRootLogin' \
        'PermitRootLogin no'

    [ "${status}" -eq 0 ]
    [ "$(grep -c '^PermitRootLogin no$' "${TEST_TEMP_DIR}/file")" -eq 1 ]
}

@test "filesystem_remove_matching_lines removes all matching lines" {
    cat >"${TEST_TEMP_DIR}/file" <<'EOF'
keep
remove this
keep too
remove that
EOF

    run filesystem_remove_matching_lines \
        "${TEST_TEMP_DIR}/file" \
        '^remove'

    [ "${status}" -eq 0 ]

    run cat "${TEST_TEMP_DIR}/file"

    [ "${output}" = $'keep\nkeep too' ]
}

@test "filesystem_backup creates the default backup" {
    printf 'content' >"${TEST_TEMP_DIR}/file"

    run filesystem_backup "${TEST_TEMP_DIR}/file"

    [ "${status}" -eq 0 ]
    [ "${output}" = "${TEST_TEMP_DIR}/file.rlch.bak" ]
    [ "$(cat "${TEST_TEMP_DIR}/file.rlch.bak")" = "content" ]
}

@test "filesystem_backup preserves an existing backup by default" {
    printf 'new' >"${TEST_TEMP_DIR}/file"
    printf 'old' >"${TEST_TEMP_DIR}/file.rlch.bak"

    run filesystem_backup "${TEST_TEMP_DIR}/file"

    [ "${status}" -eq 0 ]
    [ "$(cat "${TEST_TEMP_DIR}/file.rlch.bak")" = "old" ]
}

@test "filesystem_backup overwrites an existing backup when enabled" {
    printf 'new' >"${TEST_TEMP_DIR}/file"
    printf 'old' >"${TEST_TEMP_DIR}/file.rlch.bak"

    run filesystem_backup \
        "${TEST_TEMP_DIR}/file" \
        "${TEST_TEMP_DIR}/file.rlch.bak" \
        "true"

    [ "${status}" -eq 0 ]
    [ "$(cat "${TEST_TEMP_DIR}/file.rlch.bak")" = "new" ]
}

@test "filesystem_restore restores a backup" {
    printf 'backup' >"${TEST_TEMP_DIR}/backup"
    printf 'current' >"${TEST_TEMP_DIR}/destination"

    run filesystem_restore \
        "${TEST_TEMP_DIR}/backup" \
        "${TEST_TEMP_DIR}/destination"

    [ "${status}" -eq 0 ]
    [ "$(cat "${TEST_TEMP_DIR}/destination")" = "backup" ]
}

@test "filesystem_sha256 returns the expected checksum" {
    printf 'content' >"${TEST_TEMP_DIR}/file"

    run filesystem_sha256 "${TEST_TEMP_DIR}/file"

    [ "${status}" -eq 0 ]
    [ "${output}" = "$(sha256sum "${TEST_TEMP_DIR}/file" | cut -d' ' -f1)" ]
}

@test "filesystem_owner returns the numeric owner identifier" {
    touch "${TEST_TEMP_DIR}/file"

    run filesystem_owner "${TEST_TEMP_DIR}/file"

    [ "${status}" -eq 0 ]
    [ "${output}" = "$(id -u)" ]
}

@test "filesystem_group returns the numeric group identifier" {
    touch "${TEST_TEMP_DIR}/file"

    run filesystem_group "${TEST_TEMP_DIR}/file"

    [ "${status}" -eq 0 ]
    [ "${output}" = "$(id -g)" ]
}

@test "filesystem_mode returns the numeric mode" {
    touch "${TEST_TEMP_DIR}/file"
    chmod 0640 "${TEST_TEMP_DIR}/file"

    run filesystem_mode "${TEST_TEMP_DIR}/file"

    [ "${status}" -eq 0 ]
    [ "${output}" = "640" ]
}

@test "filesystem_set_owner sets the owner" {
    touch "${TEST_TEMP_DIR}/file"

    run filesystem_set_owner \
        "${TEST_TEMP_DIR}/file" \
        "$(id -u)"

    [ "${status}" -eq 0 ]
    [ "$(stat -c '%u' "${TEST_TEMP_DIR}/file")" = "$(id -u)" ]
}

@test "filesystem_set_group sets the group" {
    touch "${TEST_TEMP_DIR}/file"

    run filesystem_set_group \
        "${TEST_TEMP_DIR}/file" \
        "$(id -g)"

    [ "${status}" -eq 0 ]
    [ "$(stat -c '%g' "${TEST_TEMP_DIR}/file")" = "$(id -g)" ]
}

@test "filesystem_set_mode sets the mode" {
    touch "${TEST_TEMP_DIR}/file"

    run filesystem_set_mode \
        "${TEST_TEMP_DIR}/file" \
        "0600"

    [ "${status}" -eq 0 ]
    [ "$(stat -c '%a' "${TEST_TEMP_DIR}/file")" = "600" ]
}

@test "filesystem_set_mode rejects an invalid mode" {
    touch "${TEST_TEMP_DIR}/file"

    run filesystem_set_mode \
        "${TEST_TEMP_DIR}/file" \
        "999"

    [ "${status}" -eq 1 ]
}