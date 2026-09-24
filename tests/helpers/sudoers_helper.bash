#!/usr/bin/env bash
# Test helper for sudoers controls.
# SPDX-License-Identifier: MIT

sudoers_helper_setup() {
    export RLCH_TEST_SUDOERS_ROOT="${BATS_TEST_TMPDIR}/sudoers"
    export RLCH_SUDOERS_MAIN_FILE="${RLCH_TEST_SUDOERS_ROOT}/etc/sudoers"
    export RLCH_SUDOERS_INCLUDE_DIR="${RLCH_TEST_SUDOERS_ROOT}/etc/sudoers.d"
    export RLCH_SUDOERS_VISUDO_COMMAND=rlch_test_visudo RLCH_SUDOERS_ID_COMMAND=rlch_test_sudoers_id
    export RLCH_TEST_SUDOERS_UID=0 RLCH_TEST_SUDOERS_FAIL="" RLCH_TEST_SUDOERS_VALIDATE_CALLS=0
    mkdir -p -- "${RLCH_SUDOERS_INCLUDE_DIR}" "${RLCH_TEST_SUDOERS_ROOT}/bin"
    printf '@includedir %s\n' "${RLCH_SUDOERS_INCLUDE_DIR}" > "${RLCH_SUDOERS_MAIN_FILE}"
    cat > "${RLCH_TEST_SUDOERS_ROOT}/bin/chown" <<'SCRIPT'
#!/usr/bin/env bash
exit 0
SCRIPT
    chmod +x "${RLCH_TEST_SUDOERS_ROOT}/bin/chown"
    PATH="${RLCH_TEST_SUDOERS_ROOT}/bin:${PATH}"; export PATH
}

rlch_test_visudo() {
    [[ "${1:-}" == -c ]] || return 1
    RLCH_TEST_SUDOERS_VALIDATE_CALLS=$((RLCH_TEST_SUDOERS_VALIDATE_CALLS + 1))
    [[ "${RLCH_TEST_SUDOERS_FAIL}" != validate ]] || return 1
    [[ "${RLCH_TEST_SUDOERS_FAIL}" != post_write || "${RLCH_TEST_SUDOERS_VALIDATE_CALLS}" -lt 3 ]]
}
rlch_test_sudoers_id() { [[ "${1:-}" == -u ]] || return 1; printf '%s\n' "${RLCH_TEST_SUDOERS_UID}"; }
