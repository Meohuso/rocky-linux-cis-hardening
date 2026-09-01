#!/usr/bin/env bats
#
# Rocky Linux CIS Hardening Framework
#
# systemd-coredump library tests.
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
}

teardown() {
    teardown_coredump_test_environment
}

@test "coredump_option_is_configured succeeds for ProcessSizeMax zero" {
    write_coredump_test_config <<'EOF'
[Coredump]
ProcessSizeMax=0
EOF

    run coredump_option_is_configured \
        "${RLCH_TEST_COREDUMP_CONFIG}" \
        "ProcessSizeMax" \
        "0"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "coredump_option_is_configured accepts surrounding whitespace" {
    write_coredump_test_config <<'EOF'
[ Coredump ]
ProcessSizeMax = 0
EOF

    run coredump_option_is_configured \
        "${RLCH_TEST_COREDUMP_CONFIG}" \
        "ProcessSizeMax" \
        "0"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "coredump_option_is_configured ignores commented settings" {
    write_coredump_test_config <<'EOF'
[Coredump]
# ProcessSizeMax=0
EOF

    run coredump_option_is_configured \
        "${RLCH_TEST_COREDUMP_CONFIG}" \
        "ProcessSizeMax" \
        "0"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "coredump_option_is_configured reports non-compliance for another value" {
    write_coredump_test_config <<'EOF'
[Coredump]
ProcessSizeMax=2G
EOF

    run coredump_option_is_configured \
        "${RLCH_TEST_COREDUMP_CONFIG}" \
        "ProcessSizeMax" \
        "0"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "coredump_option_is_configured ignores options outside Coredump section" {
    write_coredump_test_config <<'EOF'
[Other]
ProcessSizeMax=0
EOF

    run coredump_option_is_configured \
        "${RLCH_TEST_COREDUMP_CONFIG}" \
        "ProcessSizeMax" \
        "0"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "coredump_set_option creates a managed configuration" {
    run coredump_set_option \
        "${RLCH_TEST_COREDUMP_CONFIG}" \
        "ProcessSizeMax" \
        "0"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    grep -Fqx "[Coredump]" "${RLCH_TEST_COREDUMP_CONFIG}"
    grep -Fqx "ProcessSizeMax=0" "${RLCH_TEST_COREDUMP_CONFIG}"
}

@test "coredump_set_option replaces an existing active setting" {
    write_coredump_test_config <<'EOF'
[Coredump]
ProcessSizeMax=2G
EOF

    run coredump_set_option \
        "${RLCH_TEST_COREDUMP_CONFIG}" \
        "ProcessSizeMax" \
        "0"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "$(grep -c '^ProcessSizeMax=' "${RLCH_TEST_COREDUMP_CONFIG}")" -eq 1 ]
    grep -Fqx "ProcessSizeMax=0" "${RLCH_TEST_COREDUMP_CONFIG}"
    [ -e "${RLCH_TEST_COREDUMP_CONFIG}.rlch.bak" ]
}

@test "coredump_set_option is idempotent" {
    write_coredump_test_config <<'EOF'
[Coredump]
ProcessSizeMax=0
EOF

    run coredump_set_option \
        "${RLCH_TEST_COREDUMP_CONFIG}" \
        "ProcessSizeMax" \
        "0"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
    [ ! -e "${RLCH_TEST_COREDUMP_CONFIG}.rlch.bak" ]
}

@test "coredump_set_option requires root privileges" {
    set_coredump_test_effective_uid "1000"

    run coredump_set_option \
        "${RLCH_TEST_COREDUMP_CONFIG}" \
        "ProcessSizeMax" \
        "0"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
}

@test "coredump_rollback_config restores the original configuration" {
    write_coredump_test_config <<'EOF'
[Coredump]
ProcessSizeMax=2G
EOF

    run coredump_set_option \
        "${RLCH_TEST_COREDUMP_CONFIG}" \
        "ProcessSizeMax" \
        "0"
    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]

    run coredump_rollback_config "${RLCH_TEST_COREDUMP_CONFIG}"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    grep -Fqx "ProcessSizeMax=2G" "${RLCH_TEST_COREDUMP_CONFIG}"
}

@test "coredump_rollback_config removes a file created by the framework" {
    run coredump_set_option \
        "${RLCH_TEST_COREDUMP_CONFIG}" \
        "ProcessSizeMax" \
        "0"
    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]

    run coredump_rollback_config "${RLCH_TEST_COREDUMP_CONFIG}"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ ! -e "${RLCH_TEST_COREDUMP_CONFIG}" ]
}

@test "coredump_rollback_config is idempotent without managed state" {
    run coredump_rollback_config "${RLCH_TEST_COREDUMP_CONFIG}"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}
