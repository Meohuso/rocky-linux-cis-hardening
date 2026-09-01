#!/usr/bin/env bats
#
# Rocky Linux CIS Hardening Framework
#
# CIS 1.5.4 tests.
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

    RLCH_CIS_1_5_4_CONFIG="${RLCH_TEST_COREDUMP_CONFIG_DIR}/60-rlch-coredump-storage.conf"
    RLCH_CIS_1_5_4_OPTION="Storage"
    RLCH_CIS_1_5_4_VALUE="none"

    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/1/5/4/module.sh"
}

teardown() {
    teardown_coredump_test_environment
}

create_compliant_coredump_storage_configuration() {
    cat > "${RLCH_CIS_1_5_4_CONFIG}" <<'EOF'
[Coredump]
Storage=none
EOF
}

@test "check succeeds when core dump storage is disabled" {
    create_compliant_coredump_storage_configuration

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check reports non-compliance when Storage is missing" {
    cat > "${RLCH_CIS_1_5_4_CONFIG}" <<'EOF'
[Coredump]
ProcessSizeMax=0
EOF

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check reports non-compliance when core dumps are stored externally" {
    cat > "${RLCH_CIS_1_5_4_CONFIG}" <<'EOF'
[Coredump]
Storage=external
EOF

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check reports non-compliance when core dumps are stored in the journal" {
    cat > "${RLCH_CIS_1_5_4_CONFIG}" <<'EOF'
[Coredump]
Storage=journal
EOF

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "apply disables core dump storage" {
    cat > "${RLCH_CIS_1_5_4_CONFIG}" <<'EOF'
[Coredump]
Storage=external
EOF

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    grep -Fqx "Storage=none" "${RLCH_CIS_1_5_4_CONFIG}"
    [ -e "${RLCH_CIS_1_5_4_CONFIG}.rlch.bak" ]
}

@test "apply creates a compliant configuration when the file is absent" {
    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    grep -Fqx "[Coredump]" "${RLCH_CIS_1_5_4_CONFIG}"
    grep -Fqx "Storage=none" "${RLCH_CIS_1_5_4_CONFIG}"
}

@test "apply is idempotent when core dump storage is disabled" {
    create_compliant_coredump_storage_configuration

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
    [ ! -e "${RLCH_CIS_1_5_4_CONFIG}.rlch.bak" ]
}

@test "apply requires root privileges when remediation is needed" {
    set_coredump_test_effective_uid "1000"

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
}

@test "validate delegates to the compliance check" {
    create_compliant_coredump_storage_configuration

    run validate

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "rollback restores the previous core dump storage configuration" {
    cat > "${RLCH_CIS_1_5_4_CONFIG}" <<'EOF'
[Coredump]
Storage=external
EOF

    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]

    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    grep -Fqx "Storage=external" "${RLCH_CIS_1_5_4_CONFIG}"
}

@test "rollback removes a configuration created by the framework" {
    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]

    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ ! -e "${RLCH_CIS_1_5_4_CONFIG}" ]
}

@test "rollback is idempotent when no managed state exists" {
    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "metadata declares the expected CIS control" {
    clear_module_metadata_variables
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/1/5/4/metadata.conf"

    [ "${RLCH_MODULE_ID}" = "1.5.4" ]
    [ "${RLCH_MODULE_LEVEL}" = "1" ]
    [ "${RLCH_MODULE_ENABLED}" = "true" ]
    [ "${RLCH_MODULE_REQUIRES_REBOOT}" = "false" ]
    [ "${RLCH_MODULE_OPENSCAP_RULE}" = "xccdf_org.ssgproject.content_rule_coredump_disable_storage" ]
}
