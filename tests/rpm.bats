#!/usr/bin/env bats
#
# Rocky Linux CIS Hardening Framework
#
# RPM and DNF library tests.
#
# SPDX-License-Identifier: MIT
#

setup() {
    source "${BATS_TEST_DIRNAME}/test_helper.bash"
    source "${BATS_TEST_DIRNAME}/helpers/rpm_helper.bash"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/common.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/modules.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/module_api.sh"

    setup_rpm_test_environment
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/rpm.sh"
}

teardown() {
    teardown_rpm_test_environment
}

@test "rpm_list_gpg_keys lists installed RPM GPG public keys" {
    add_rpm_test_gpg_key "gpg-pubkey-350d275d-6279464b"
    add_rpm_test_gpg_key "gpg-pubkey-702d426d-6382fa7c"

    run rpm_list_gpg_keys

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
    [[ "${output}" == *"gpg-pubkey-350d275d-6279464b"* ]]
    [[ "${output}" == *"gpg-pubkey-702d426d-6382fa7c"* ]]
}

@test "rpm_has_gpg_keys succeeds when at least one GPG key is installed" {
    add_rpm_test_gpg_key "gpg-pubkey-350d275d-6279464b"

    run rpm_has_gpg_keys

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "rpm_has_gpg_keys is non-compliant when no GPG key is installed" {
    run rpm_has_gpg_keys

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "rpm_has_gpg_keys is non-compliant when rpm query fails" {
    set_rpm_test_exit_status "1"

    run rpm_has_gpg_keys

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "rpm_package_is_installed succeeds for an installed package" {
    add_rpm_test_package "aide"

    run rpm_package_is_installed "aide"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "rpm_package_is_installed reports non-compliance for a missing package" {
    run rpm_package_is_installed "aide"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "rpm_package_is_installed rejects an empty package name" {
    run rpm_package_is_installed ""

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
}

@test "dnf_install_package installs a missing package" {
    run dnf_install_package "aide"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    grep -Fxq "aide" "${RLCH_TEST_RPM_PACKAGES}"
}

@test "dnf_install_package is idempotent for an installed package" {
    add_rpm_test_package "aide"

    run dnf_install_package "aide"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "dnf_install_package requires root for a missing package" {
    set_rpm_test_effective_uid "1000"

    run dnf_install_package "aide"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
}

@test "dnf_install_package reports an error when dnf fails" {
    set_dnf_test_exit_status "1"

    run dnf_install_package "aide"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
}

@test "dnf_remove_package removes an installed package" {
    add_rpm_test_package "aide"

    run dnf_remove_package "aide"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    ! grep -Fxq "aide" "${RLCH_TEST_RPM_PACKAGES}"
}

@test "dnf_remove_package is idempotent for a missing package" {
    run dnf_remove_package "aide"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "dnf_remove_package requires root for an installed package" {
    add_rpm_test_package "aide"
    set_rpm_test_effective_uid "1000"

    run dnf_remove_package "aide"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
}

@test "dnf_main_option_value reads gpgcheck from the main section" {
    write_dnf_test_config <<'EOF'
[main]
gpgcheck=1
EOF

    run dnf_main_option_value "gpgcheck" "${RLCH_TEST_DNF_CONFIG}"

    [ "${status}" -eq 0 ]
    [ "${output}" = "1" ]
}

@test "dnf_main_option_value ignores repository sections" {
    write_dnf_test_config <<'EOF'
[main]
best=True

[example]
gpgcheck=1
EOF

    run dnf_main_option_value "gpgcheck" "${RLCH_TEST_DNF_CONFIG}"

    [ "${status}" -ne 0 ]
}

@test "dnf_main_option_is_enabled succeeds when gpgcheck equals one" {
    write_dnf_test_config <<'EOF'
[main]
gpgcheck = 1
EOF

    run dnf_main_option_is_enabled "gpgcheck" "${RLCH_TEST_DNF_CONFIG}"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "dnf_main_option_is_enabled reports non-compliance when gpgcheck is zero" {
    write_dnf_test_config <<'EOF'
[main]
gpgcheck=0
EOF

    run dnf_main_option_is_enabled "gpgcheck" "${RLCH_TEST_DNF_CONFIG}"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "dnf_main_option_is_enabled reports non-compliance when gpgcheck is absent" {
    run dnf_main_option_is_enabled "gpgcheck" "${RLCH_TEST_DNF_CONFIG}"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "dnf_set_main_option enables gpgcheck and creates a backup" {
    write_dnf_test_config <<'EOF'
[main]
gpgcheck=0
best=True
EOF

    run dnf_set_main_option "gpgcheck" "1" "${RLCH_TEST_DNF_CONFIG}"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    grep -Fxq "gpgcheck=1" "${RLCH_TEST_DNF_CONFIG}"
    grep -Fxq "gpgcheck=0" "${RLCH_TEST_DNF_CONFIG}${RLCH_DNF_CONFIG_BACKUP_SUFFIX}"
}

@test "dnf_set_main_option is idempotent when gpgcheck is already enabled" {
    write_dnf_test_config <<'EOF'
[main]
gpgcheck=1
EOF

    run dnf_set_main_option "gpgcheck" "1" "${RLCH_TEST_DNF_CONFIG}"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
    [ ! -e "${RLCH_TEST_DNF_CONFIG}${RLCH_DNF_CONFIG_BACKUP_SUFFIX}" ]
}

@test "dnf_set_main_option removes duplicate active gpgcheck entries" {
    write_dnf_test_config <<'EOF'
[main]
gpgcheck=0
gpgcheck = 0
best=True
EOF

    run dnf_set_main_option "gpgcheck" "1" "${RLCH_TEST_DNF_CONFIG}"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "$(grep -Ec '^[[:space:]]*gpgcheck[[:space:]]*=' "${RLCH_TEST_DNF_CONFIG}")" -eq 1 ]
    grep -Fxq "gpgcheck=1" "${RLCH_TEST_DNF_CONFIG}"
}

@test "dnf_set_main_option adds gpgcheck to an existing main section" {
    write_dnf_test_config <<'EOF'
[main]
best=True

[example]
enabled=1
EOF

    run dnf_set_main_option "gpgcheck" "1" "${RLCH_TEST_DNF_CONFIG}"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    grep -Fxq "gpgcheck=1" "${RLCH_TEST_DNF_CONFIG}"
}

@test "dnf_set_main_option requires root privileges" {
    set_rpm_test_effective_uid "1000"

    run dnf_set_main_option "gpgcheck" "1" "${RLCH_TEST_DNF_CONFIG}"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
}

@test "dnf_rollback_config restores the backup" {
    write_dnf_test_config <<'EOF'
[main]
gpgcheck=0
EOF
    create_dnf_test_config_backup

    printf '[main]\ngpgcheck=1\n' > "${RLCH_TEST_DNF_CONFIG}"

    run dnf_rollback_config "${RLCH_TEST_DNF_CONFIG}"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    grep -Fxq "gpgcheck=0" "${RLCH_TEST_DNF_CONFIG}"
}

@test "dnf_rollback_config is idempotent when no backup exists" {
    run dnf_rollback_config "${RLCH_TEST_DNF_CONFIG}"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "dnf_rollback_config requires root privileges" {
    create_dnf_test_config_backup
    set_rpm_test_effective_uid "1000"

    run dnf_rollback_config "${RLCH_TEST_DNF_CONFIG}"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
}

@test "dnf_list_enabled_repositories lists enabled repositories" {
    add_dnf_test_repository "baseos" "Rocky Linux BaseOS"
    add_dnf_test_repository "appstream" "Rocky Linux AppStream"

    run dnf_list_enabled_repositories

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
    [[ "${output}" == *"baseos"* ]]
    [[ "${output}" == *"appstream"* ]]
}

@test "dnf_has_enabled_repositories succeeds when repositories are enabled" {
    add_dnf_test_repository "baseos" "Rocky Linux BaseOS"

    run dnf_has_enabled_repositories

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "dnf_has_enabled_repositories reports non-compliance when no repository is enabled" {
    run dnf_has_enabled_repositories

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "dnf_has_enabled_repositories reports non-compliance when dnf fails" {
    set_dnf_test_exit_status "1"

    run dnf_has_enabled_repositories

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}
