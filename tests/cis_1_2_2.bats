#!/usr/bin/env bats
#
# Rocky Linux CIS Hardening Framework
#
# CIS 1.2.2 tests.
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

    RLCH_CIS_1_2_2_DNF_CONFIG="${RLCH_TEST_DNF_CONFIG}"
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/1/2/2/module.sh"
}

teardown() {
    teardown_rpm_test_environment
}

@test "check succeeds when gpgcheck is globally enabled" {
    write_dnf_test_config <<'EOF'
[main]
gpgcheck=1
EOF

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check reports non-compliance when gpgcheck is disabled" {
    write_dnf_test_config <<'EOF'
[main]
gpgcheck=0
EOF

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check reports non-compliance when gpgcheck is missing" {
    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "apply enables gpgcheck globally" {
    write_dnf_test_config <<'EOF'
[main]
gpgcheck=0
EOF

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    grep -Fxq "gpgcheck=1" "${RLCH_TEST_DNF_CONFIG}"
}

@test "apply is idempotent when gpgcheck is already enabled" {
    write_dnf_test_config <<'EOF'
[main]
gpgcheck=1
EOF

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "apply fails without root privileges" {
    set_rpm_test_effective_uid "1000"

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
}

@test "validate delegates to the compliance check" {
    write_dnf_test_config <<'EOF'
[main]
gpgcheck=1
EOF

    run validate

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "rollback restores the original DNF configuration" {
    write_dnf_test_config <<'EOF'
[main]
gpgcheck=0
EOF

    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]

    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    grep -Fxq "gpgcheck=0" "${RLCH_TEST_DNF_CONFIG}"
}

@test "rollback is idempotent when no backup exists" {
    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "rollback fails without root privileges" {
    create_dnf_test_config_backup
    set_rpm_test_effective_uid "1000"

    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
}

@test "metadata declares the expected CIS control" {
    local metadata_file

    metadata_file="${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/1/2/2/metadata.conf"

    clear_module_metadata_variables
    source "${metadata_file}"

    [ "${RLCH_MODULE_ID}" = "1.2.2" ]
    [ "${RLCH_MODULE_LEVEL}" = "1" ]
    [ "${RLCH_MODULE_ENABLED}" = "true" ]
    [ "${RLCH_MODULE_REQUIRES_REBOOT}" = "false" ]
    [ "${RLCH_MODULE_OPENSCAP_RULE}" = "xccdf_org.ssgproject.content_rule_ensure_gpgcheck_globally_activated" ]
}
