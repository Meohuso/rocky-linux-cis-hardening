#!/usr/bin/env bats
setup() {
    source "${BATS_TEST_DIRNAME}/test_helper.bash"
    source "${BATS_TEST_DIRNAME}/../lib/module_api.sh"
    export RLCH_CIS_5_3_2_2_AUTHSELECT="${BATS_TEST_TMPDIR}/authselect"
    export RLCH_CIS_5_3_2_2_PAM_DIR="${BATS_TEST_TMPDIR}/pam.d"
    export RLCH_TEST_AUTHSELECT_LOG="${BATS_TEST_TMPDIR}/authselect.log"
    mkdir -p "$RLCH_CIS_5_3_2_2_PAM_DIR"
    cat > "$RLCH_CIS_5_3_2_2_AUTHSELECT" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$RLCH_TEST_AUTHSELECT_LOG"
exit "${RLCH_TEST_AUTHSELECT_EXIT:-0}"
EOF
    chmod +x "$RLCH_CIS_5_3_2_2_AUTHSELECT"
    for file in system-auth password-auth; do
        cat > "$RLCH_CIS_5_3_2_2_PAM_DIR/$file" <<'EOF'
# keep administrator comment
auth required pam_faillock.so preauth silent
auth sufficient pam_unix.so nullok
auth required pam_faillock.so authfail
account required pam_faillock.so
account required pam_unix.so
EOF
    done
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/3/2/2/module.sh"
}

@test "complete authselect-managed stacks are compliant" {
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    [ "$(cat "$RLCH_TEST_AUTHSELECT_LOG")" = check ]
}

@test "equivalent PAM control flags in brackets are accepted" {
    for file in system-auth password-auth; do
        sed -i 's/auth required pam_faillock.so preauth/auth [success=ok new_authtok_reqd=ok ignore=ignore default=bad] pam_faillock.so preauth/; s/auth sufficient pam_unix.so/auth [success=done new_authtok_reqd=done default=ignore] pam_unix.so/; s/account required pam_faillock.so/account [success=ok new_authtok_reqd=ok ignore=ignore default=bad] pam_faillock.so/' "$RLCH_CIS_5_3_2_2_PAM_DIR/$file"
    done
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
}

@test "a missing preauth in password-auth is noncompliant" {
    sed -i '/preauth/d' "$RLCH_CIS_5_3_2_2_PAM_DIR/password-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
}

@test "a missing authfail in system-auth is noncompliant" {
    sed -i '/authfail/d' "$RLCH_CIS_5_3_2_2_PAM_DIR/system-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
}

@test "account hook is required in both stacks" {
    sed -i '/account required pam_faillock.so/d' "$RLCH_CIS_5_3_2_2_PAM_DIR/password-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
}

@test "preauth after pam_unix is noncompliant" {
    sed -i '2,3{N;s/auth required pam_faillock.so preauth silent\nauth sufficient pam_unix.so nullok/auth sufficient pam_unix.so nullok\nauth required pam_faillock.so preauth silent/;}' "$RLCH_CIS_5_3_2_2_PAM_DIR/system-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
}

@test "authfail before pam_unix is noncompliant" {
    sed -i '3,4{N;s/auth sufficient pam_unix.so nullok\nauth required pam_faillock.so authfail/auth required pam_faillock.so authfail\nauth sufficient pam_unix.so nullok/;}' "$RLCH_CIS_5_3_2_2_PAM_DIR/system-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
}

@test "duplicated pam_unix auth is noncompliant" {
    printf 'auth sufficient pam_unix.so\n' >> "$RLCH_CIS_5_3_2_2_PAM_DIR/system-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
}

@test "commented faillock cannot satisfy the control" {
    sed -i 's/^auth required pam_faillock.so preauth/# auth required pam_faillock.so preauth/' "$RLCH_CIS_5_3_2_2_PAM_DIR/system-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
}

@test "authselect inconsistency is an error" {
    export RLCH_TEST_AUTHSELECT_EXIT=1
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
}

@test "missing generated stack is noncompliant" {
    rm "$RLCH_CIS_5_3_2_2_PAM_DIR/password-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
}

@test "apply on compliant stacks is idempotent" {
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
}

@test "apply preserves custom PAM lines when remediation is unsafe" {
    printf '# organization policy\n' >> "$RLCH_CIS_5_3_2_2_PAM_DIR/system-auth"
    sed -i '/authfail/d' "$RLCH_CIS_5_3_2_2_PAM_DIR/system-auth"
    local before
    before="$(cat "$RLCH_CIS_5_3_2_2_PAM_DIR/system-auth")"
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    [ "$(cat "$RLCH_CIS_5_3_2_2_PAM_DIR/system-auth")" = "$before" ]
}

@test "validate checks and rollback is a no-op" {
    run validate; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
}

@test "metadata uses manual mapping for the two independent rules" {
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/3/2/2/metadata.conf"
    [ "$RLCH_MODULE_ID" = 5.3.2.2 ]
    [ "$RLCH_MODULE_OPENSCAP_RULE" = manual ]
}
