#!/usr/bin/env bats
#
# Rocky Linux CIS Hardening Framework
#
# CIS 1.1.2.1 tests.
#
# SPDX-License-Identifier: MIT
#

setup() {
    # shellcheck source=tests/test_helper.bash
    source "${BATS_TEST_DIRNAME}/test_helper.bash"

    # shellcheck source=lib/common.sh
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/common.sh"

    # shellcheck source=lib/modules.sh
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/modules.sh"

    # shellcheck source=lib/module_api.sh
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/module_api.sh"

    RLCH_CIS_1_1_2_1_FSTAB="${BATS_TEST_TMPDIR}/fstab"

    # shellcheck source=modules/cis/1/1/2/1/module.sh
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/1/1/2/1/module.sh"
}

@test "check delegates partition validation for /tmp to the mount library" {
    mount_check_partition() {
        printf '%s|%s\n' "${1}" "${2}"
        return "${RLCH_MODULE_RESULT_COMPLIANT}"
    }

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_COMPLIANT}" ]
    [ "${output}" = "/tmp|${RLCH_CIS_1_1_2_1_FSTAB}" ]
}

@test "check returns compliant when /tmp is a separate persistent and runtime mount" {
    mount_check_partition() {
        return "${RLCH_MODULE_RESULT_COMPLIANT}"
    }

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_COMPLIANT}" ]
}

@test "check reports non-compliance when /tmp is not a separate mount" {
    mount_check_partition() {
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    }

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check propagates a mount library error" {
    mount_check_partition() {
        return "${RLCH_MODULE_RESULT_ERROR}"
    }

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
}

@test "apply delegates to the unsupported partition provisioning policy" {
    mount_apply_partition() {
        printf 'partition provisioning refused\n'
        return "${RLCH_MODULE_RESULT_ERROR}"
    }

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [ "${output}" = "partition provisioning refused" ]
}

@test "validate delegates to check" {
    mount_check_partition() {
        printf '%s|%s\n' "${1}" "${2}"
        return "${RLCH_MODULE_RESULT_COMPLIANT}"
    }

    run validate

    [ "${status}" -eq "${RLCH_MODULE_RESULT_COMPLIANT}" ]
    [ "${output}" = "/tmp|${RLCH_CIS_1_1_2_1_FSTAB}" ]
}

@test "validate reports non-compliance when check fails" {
    mount_check_partition() {
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    }

    run validate

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "rollback delegates restoration for /tmp to the mount library" {
    mount_rollback() {
        printf '%s|%s\n' "${1}" "${2}"
        return "${RLCH_MODULE_RESULT_CHANGED}"
    }

    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "${output}" = "/tmp|${RLCH_CIS_1_1_2_1_FSTAB}" ]
}

@test "rollback is compliant when no framework-managed backup exists" {
    mount_rollback() {
        return "${RLCH_MODULE_RESULT_COMPLIANT}"
    }

    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_COMPLIANT}" ]
}

@test "rollback propagates a mount library error" {
    mount_rollback() {
        return "${RLCH_MODULE_RESULT_ERROR}"
    }

    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
}