#!/usr/bin/env bats

setup() {
    TEST_ROOT_DIR="$(
        cd "${BATS_TEST_DIRNAME}/.." && pwd
    )"

    TEST_TEMP_DIR="$(
        mktemp -d "${BATS_TEST_TMPDIR}/rlch-system.XXXXXX"
    )"

    # shellcheck source=../lib/common.sh
    source "${TEST_ROOT_DIR}/lib/common.sh"

    # shellcheck source=../lib/error.sh
    source "${TEST_ROOT_DIR}/lib/error.sh"

    # shellcheck source=../lib/system.sh
    source "${TEST_ROOT_DIR}/lib/system.sh"
}

teardown() {
    rm -rf "${TEST_TEMP_DIR}"
}

create_os_release_file() {
    local content="${1:-}"

    printf '%s\n' "${content}" >"${TEST_TEMP_DIR}/os-release"
}

create_mock_command() {
    local command_name="${1:-}"
    local command_body="${2:-}"

    mkdir -p "${TEST_TEMP_DIR}/bin"

    cat >"${TEST_TEMP_DIR}/bin/${command_name}" <<EOF
#!/usr/bin/env bash
${command_body}
EOF

    chmod +x "${TEST_TEMP_DIR}/bin/${command_name}"
}

@test "system library prevents multiple sourcing" {
    run bash -c "
        source '${TEST_ROOT_DIR}/lib/common.sh'
        source '${TEST_ROOT_DIR}/lib/error.sh'
        source '${TEST_ROOT_DIR}/lib/system.sh'
        source '${TEST_ROOT_DIR}/lib/system.sh'
        printf '%s' \"\${RLCH_SYSTEM_LOADED}\"
    "

    [ "${status}" -eq 0 ]
    [ "${output}" = "1" ]
}

@test "system_command_exists succeeds for an available command" {
    run system_command_exists "bash"

    [ "${status}" -eq 0 ]
}

@test "system_command_exists fails for an unavailable command" {
    run system_command_exists "rlch-command-that-does-not-exist"

    [ "${status}" -eq 1 ]
}

@test "system_command_exists fails for an empty command name" {
    run system_command_exists ""

    [ "${status}" -eq 1 ]
}

@test "system_require_command succeeds for an available command" {
    run system_require_command "bash"

    [ "${status}" -eq 0 ]
    [ -z "${output}" ]
}

@test "system_require_command rejects an empty command name" {
    run system_require_command ""

    [ "${status}" -eq 1 ]
    [[ "${output}" == *"A command name is required."* ]]
}

@test "system_require_command reports an unavailable command" {
    run system_require_command "rlch-command-that-does-not-exist"

    [ "${status}" -eq 1 ]
    [[ "${output}" == *"Required system command is unavailable"* ]]
}

@test "system_os_release_value reads an unquoted value" {
    create_os_release_file \
        $'ID=rocky\nNAME="Rocky Linux"\nVERSION_ID="10.2"'

    run system_os_release_value \
        "ID" \
        "${TEST_TEMP_DIR}/os-release"

    [ "${status}" -eq 0 ]
    [ "${output}" = "rocky" ]
}

@test "system_os_release_value removes double quotes" {
    create_os_release_file \
        $'ID=rocky\nNAME="Rocky Linux"\nVERSION_ID="10.2"'

    run system_os_release_value \
        "NAME" \
        "${TEST_TEMP_DIR}/os-release"

    [ "${status}" -eq 0 ]
    [ "${output}" = "Rocky Linux" ]
}

@test "system_os_release_value removes single quotes" {
    create_os_release_file \
        $'ID=rocky\nNAME=\'Rocky Linux\'\nVERSION_ID=\'10.2\''

    run system_os_release_value \
        "VERSION_ID" \
        "${TEST_TEMP_DIR}/os-release"

    [ "${status}" -eq 0 ]
    [ "${output}" = "10.2" ]
}

@test "system_os_release_value returns the first matching key" {
    create_os_release_file \
        $'ID=rocky\nID=other'

    run system_os_release_value \
        "ID" \
        "${TEST_TEMP_DIR}/os-release"

    [ "${status}" -eq 0 ]
    [ "${output}" = "rocky" ]
}

@test "system_os_release_value rejects an invalid key" {
    create_os_release_file \
        "ID=rocky"

    run system_os_release_value \
        "invalid-key" \
        "${TEST_TEMP_DIR}/os-release"

    [ "${status}" -eq 1 ]
}

@test "system_os_release_value fails when the file is missing" {
    run system_os_release_value \
        "ID" \
        "${TEST_TEMP_DIR}/missing-os-release"

    [ "${status}" -eq 1 ]
}

@test "system_os_release_value fails when the key is missing" {
    create_os_release_file \
        "ID=rocky"

    run system_os_release_value \
        "VERSION_ID" \
        "${TEST_TEMP_DIR}/os-release"

    [ "${status}" -eq 1 ]
}

@test "system_operating_system_id returns the operating system identifier" {
    create_os_release_file \
        $'ID=rocky\nVERSION_ID="10.2"'

    run system_operating_system_id \
        "${TEST_TEMP_DIR}/os-release"

    [ "${status}" -eq 0 ]
    [ "${output}" = "rocky" ]
}

@test "system_operating_system_name returns the operating system name" {
    create_os_release_file \
        $'ID=rocky\nNAME="Rocky Linux"'

    run system_operating_system_name \
        "${TEST_TEMP_DIR}/os-release"

    [ "${status}" -eq 0 ]
    [ "${output}" = "Rocky Linux" ]
}

@test "system_operating_system_version_id returns the version identifier" {
    create_os_release_file \
        $'ID=rocky\nVERSION_ID="10.2"'

    run system_operating_system_version_id \
        "${TEST_TEMP_DIR}/os-release"

    [ "${status}" -eq 0 ]
    [ "${output}" = "10.2" ]
}

@test "system_operating_system_major_version returns the numeric major version" {
    create_os_release_file \
        $'ID=rocky\nVERSION_ID="10.2"'

    run system_operating_system_major_version \
        "${TEST_TEMP_DIR}/os-release"

    [ "${status}" -eq 0 ]
    [ "${output}" = "10" ]
}

@test "system_operating_system_major_version accepts a version without minor component" {
    create_os_release_file \
        $'ID=rocky\nVERSION_ID="10"'

    run system_operating_system_major_version \
        "${TEST_TEMP_DIR}/os-release"

    [ "${status}" -eq 0 ]
    [ "${output}" = "10" ]
}

@test "system_operating_system_major_version rejects a nonnumeric version" {
    create_os_release_file \
        $'ID=rocky\nVERSION_ID="rolling"'

    run system_operating_system_major_version \
        "${TEST_TEMP_DIR}/os-release"

    [ "${status}" -eq 1 ]
}

@test "system_is_rocky_linux succeeds for Rocky Linux" {
    create_os_release_file \
        $'ID=rocky\nVERSION_ID="10.2"'

    run system_is_rocky_linux \
        "${TEST_TEMP_DIR}/os-release"

    [ "${status}" -eq 0 ]
}

@test "system_is_rocky_linux comparison is case insensitive" {
    create_os_release_file \
        $'ID=ROCKY\nVERSION_ID="10.2"'

    run system_is_rocky_linux \
        "${TEST_TEMP_DIR}/os-release"

    [ "${status}" -eq 0 ]
}

@test "system_is_rocky_linux fails for another distribution" {
    create_os_release_file \
        $'ID=rhel\nVERSION_ID="10.2"'

    run system_is_rocky_linux \
        "${TEST_TEMP_DIR}/os-release"

    [ "${status}" -eq 1 ]
}

@test "system_is_rocky_linux_10 succeeds for Rocky Linux 10" {
    create_os_release_file \
        $'ID=rocky\nVERSION_ID="10.2"'

    run system_is_rocky_linux_10 \
        "${TEST_TEMP_DIR}/os-release"

    [ "${status}" -eq 0 ]
}

@test "system_is_rocky_linux_10 fails for Rocky Linux 9" {
    create_os_release_file \
        $'ID=rocky\nVERSION_ID="9.6"'

    run system_is_rocky_linux_10 \
        "${TEST_TEMP_DIR}/os-release"

    [ "${status}" -eq 1 ]
}

@test "system_is_rocky_linux_10 fails for another distribution version 10" {
    create_os_release_file \
        $'ID=rhel\nVERSION_ID="10.0"'

    run system_is_rocky_linux_10 \
        "${TEST_TEMP_DIR}/os-release"

    [ "${status}" -eq 1 ]
}

@test "system_kernel_release returns uname kernel release" {
    run system_kernel_release

    [ "${status}" -eq 0 ]
    [ -n "${output}" ]
}

@test "system_architecture returns uname architecture" {
    run system_architecture

    [ "${status}" -eq 0 ]
    [ -n "${output}" ]
}

@test "system_hostname prefers hostnamectl when it succeeds" {
    create_mock_command \
        "hostnamectl" \
        'printf "%s\n" "rocky-hostnamectl"'

    create_mock_command \
        "hostname" \
        'printf "%s\n" "rocky-hostname"'

    PATH="${TEST_TEMP_DIR}/bin:${PATH}" run system_hostname

    [ "${status}" -eq 0 ]
    [ "${output}" = "rocky-hostnamectl" ]
}

@test "system_hostname falls back to hostname when hostnamectl fails" {
    create_mock_command \
        "hostnamectl" \
        'exit 1'

    create_mock_command \
        "hostname" \
        'printf "%s\n" "rocky-hostname"'

    PATH="${TEST_TEMP_DIR}/bin:${PATH}" run system_hostname

    [ "${status}" -eq 0 ]
    [ "${output}" = "rocky-hostname" ]
}

@test "system_hostname falls back when hostnamectl returns an empty value" {
    create_mock_command \
        "hostnamectl" \
        'exit 0'

    create_mock_command \
        "hostname" \
        'printf "%s\n" "rocky-hostname"'

    PATH="${TEST_TEMP_DIR}/bin:${PATH}" run system_hostname

    [ "${status}" -eq 0 ]
    [ "${output}" = "rocky-hostname" ]
}

@test "system_boot_id returns a trimmed boot identifier" {
    printf '  test-boot-id  \n' >"${TEST_TEMP_DIR}/boot-id"

    run system_boot_id "${TEST_TEMP_DIR}/boot-id"

    [ "${status}" -eq 0 ]
    [ "${output}" = "test-boot-id" ]
}

@test "system_boot_id fails for an empty boot identifier" {
    printf '   \n' >"${TEST_TEMP_DIR}/boot-id"

    run system_boot_id "${TEST_TEMP_DIR}/boot-id"

    [ "${status}" -eq 1 ]
}

@test "system_boot_id fails when the file is missing" {
    run system_boot_id "${TEST_TEMP_DIR}/missing-boot-id"

    [ "${status}" -eq 1 ]
}

@test "system_uptime_seconds returns whole seconds" {
    printf '12345.67 23456.78\n' >"${TEST_TEMP_DIR}/uptime"

    run system_uptime_seconds "${TEST_TEMP_DIR}/uptime"

    [ "${status}" -eq 0 ]
    [ "${output}" = "12345" ]
}

@test "system_uptime_seconds accepts an integer uptime" {
    printf '12345 23456\n' >"${TEST_TEMP_DIR}/uptime"

    run system_uptime_seconds "${TEST_TEMP_DIR}/uptime"

    [ "${status}" -eq 0 ]
    [ "${output}" = "12345" ]
}

@test "system_uptime_seconds rejects an invalid uptime" {
    printf 'invalid 23456.78\n' >"${TEST_TEMP_DIR}/uptime"

    run system_uptime_seconds "${TEST_TEMP_DIR}/uptime"

    [ "${status}" -eq 1 ]
}

@test "system_uptime_seconds fails when the file is missing" {
    run system_uptime_seconds "${TEST_TEMP_DIR}/missing-uptime"

    [ "${status}" -eq 1 ]
}

@test "bootstrap loads the system library" {
    run bash -c "
        source '${TEST_ROOT_DIR}/lib/bootstrap.sh'
        _bootstrap_load_core_libraries
        declare -F system_is_rocky_linux >/dev/null
    "

    [ "${status}" -eq 0 ]
}