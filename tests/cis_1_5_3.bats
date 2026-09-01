#!/usr/bin/env bats
#
# Rocky Linux CIS Hardening Framework
#
# CIS 1.5.3 tests.
#
# SPDX-License-Identifier: MIT
#

setup() {
    source "${BATS_TEST_DIRNAME}/test_helper.bash"
    source "${BATS_TEST_DIRNAME}/helpers/coredump_helper.bash"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/common.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/modules.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/module_api.sh"

    setup_coredump_test_environment
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/coredump.sh"

    RLCH_CIS_1_5_3_CONFIG="${RLCH_TEST_COREDUMP_CONFIG}"
    RLCH_CIS_1_5_3_OPTION="ProcessSizeMax"
    RLCH_CIS_1_5_3_VALUE="0"

    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/1/5/3/module.sh"
}

teardown() {
    teardown_coredump_test_environment
}

create_compliant_coredump_configuration() {
    write_coredump_test_config <<'EOF'
[Coredump]
ProcessSizeMax=0
EOF
}

@test "check succeeds when core dump backtraces are disabled" {
    create_compliant_coredump_configuration

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check reports non-compliance when ProcessSizeMax is missing" {
    write_coredump_test_config <<'EOF'
[Coredump]
Storage=none
EOF

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check reports non-compliance when ProcessSizeMax is not zero" {
    write_coredump_test_config <<'EOF'
[Coredump]
ProcessSizeMax=2G
EOF

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "apply disables core dump backtraces" {
    write_coredump_test_config <<'EOF'
[Coredump]
ProcessSizeMax=2G
EOF

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    grep -Fqx "ProcessSizeMax=0" "${RLCH_TEST_COREDUMP_CONFIG}"
}

@test "apply is idempotent when core dump backtraces are disabled" {
    create_compliant_coredump_configuration

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "apply requires root privileges when remediation is needed" {
    set_coredump_test_effective_uid "1000"

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
}

@test "validate delegates to the compliance check" {
    create_compliant_coredump_configuration

    run validate

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "rollback restores the previous coredump configuration" {
    write_coredump_test_config <<'EOF'
[Coredump]
ProcessSizeMax=2G
EOF

    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]

    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    grep -Fqx "ProcessSizeMax=2G" "${RLCH_TEST_COREDUMP_CONFIG}"
}

@test "rollback is idempotent when no managed state exists" {
    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "metadata declares the expected CIS control" {
    clear_module_metadata_variables
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/1/5/3/metadata.conf"

    [ "${RLCH_MODULE_ID}" = "1.5.3" ]
    [ "${RLCH_MODULE_LEVEL}" = "1" ]
    [ "${RLCH_MODULE_ENABLED}" = "true" ]
    [ "${RLCH_MODULE_REQUIRES_REBOOT}" = "false" ]
    [ "${RLCH_MODULE_OPENSCAP_RULE}" = "xccdf_org.ssgproject.content_rule_coredump_disable_backtraces" ]
}
