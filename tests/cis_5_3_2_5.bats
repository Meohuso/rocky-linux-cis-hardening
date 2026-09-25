#!/usr/bin/env bats
setup() {
    source "${BATS_TEST_DIRNAME}/test_helper.bash"
    source "${BATS_TEST_DIRNAME}/../lib/module_api.sh"
    export RLCH_CIS_5_3_2_5_AUTHSELECT="${BATS_TEST_TMPDIR}/authselect"
    export RLCH_CIS_5_3_2_5_PAM_DIR="${BATS_TEST_TMPDIR}/pam.d"
    mkdir -p "$RLCH_CIS_5_3_2_5_PAM_DIR"
    cat > "$RLCH_CIS_5_3_2_5_AUTHSELECT" <<'EOF'
#!/usr/bin/env bash
exit "${RLCH_TEST_AUTHSELECT_EXIT:-0}"
EOF
    chmod +x "$RLCH_CIS_5_3_2_5_AUTHSELECT"
    for file in system-auth password-auth; do
        printf '# keep\nauth sufficient pam_unix.so nullok\naccount required pam_unix.so\npassword sufficient pam_unix.so sha512\n' > "$RLCH_CIS_5_3_2_5_PAM_DIR/$file"
    done
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/3/2/5/module.sh"
}

@test "auth and password hooks in both generated stacks are compliant" {
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
}

@test "bracket control flags are recognized" {
    sed -i 's/auth sufficient pam_unix.so/auth [success=done default=ignore] pam_unix.so/' "$RLCH_CIS_5_3_2_5_PAM_DIR/system-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
}

@test "a missing auth hook is noncompliant" {
    sed -i '/^auth sufficient pam_unix.so/d' "$RLCH_CIS_5_3_2_5_PAM_DIR/password-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
}

@test "a missing password hook is noncompliant even when account hook exists" {
    sed -i '/^password sufficient pam_unix.so/d' "$RLCH_CIS_5_3_2_5_PAM_DIR/system-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
}

@test "commented and duplicate hooks are rejected" {
    sed -i 's/^auth sufficient pam_unix.so/# auth sufficient pam_unix.so/' "$RLCH_CIS_5_3_2_5_PAM_DIR/system-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
    sed -i 's/^# auth sufficient pam_unix.so/auth sufficient pam_unix.so/' "$RLCH_CIS_5_3_2_5_PAM_DIR/system-auth"
    printf 'auth required pam_unix.so\n' >> "$RLCH_CIS_5_3_2_5_PAM_DIR/system-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
}

@test "authselect failure is an error and missing generated files are noncompliant" {
    export RLCH_TEST_AUTHSELECT_EXIT=1
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    export RLCH_TEST_AUTHSELECT_EXIT=0
    rm "$RLCH_CIS_5_3_2_5_PAM_DIR/password-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
}

@test "compliant apply is idempotent" {
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
}

@test "noncompliant apply refuses to alter PAM files" {
    sed -i '/^auth sufficient pam_unix.so/d' "$RLCH_CIS_5_3_2_5_PAM_DIR/system-auth"
    local before
    before="$(cat "$RLCH_CIS_5_3_2_5_PAM_DIR/system-auth")"
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    [ "$(cat "$RLCH_CIS_5_3_2_5_PAM_DIR/system-auth")" = "$before" ]
}

@test "validate checks while rollback has no changes" {
    run validate; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
}

@test "metadata records partial mapping honestly" {
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/3/2/5/metadata.conf"
    [ "$RLCH_MODULE_ID" = 5.3.2.5 ]
    [ "$RLCH_MODULE_OPENSCAP_RULE" = manual ]
}
