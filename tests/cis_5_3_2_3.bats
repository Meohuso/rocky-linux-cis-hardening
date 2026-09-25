#!/usr/bin/env bats
setup() {
    source "${BATS_TEST_DIRNAME}/test_helper.bash"
    source "${BATS_TEST_DIRNAME}/../lib/module_api.sh"
    export RLCH_CIS_5_3_2_3_AUTHSELECT="${BATS_TEST_TMPDIR}/authselect"
    export RLCH_CIS_5_3_2_3_PAM_DIR="${BATS_TEST_TMPDIR}/pam.d"
    export RLCH_TEST_AUTHSELECT_LOG="${BATS_TEST_TMPDIR}/authselect.log"
    mkdir -p "$RLCH_CIS_5_3_2_3_PAM_DIR"
    cat > "$RLCH_CIS_5_3_2_3_AUTHSELECT" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$RLCH_TEST_AUTHSELECT_LOG"
exit "${RLCH_TEST_AUTHSELECT_EXIT:-0}"
EOF
    chmod +x "$RLCH_CIS_5_3_2_3_AUTHSELECT"
    for file in system-auth password-auth; do
        printf '# keep\npassword requisite pam_pwquality.so retry=3\npassword sufficient pam_unix.so\n' > "$RLCH_CIS_5_3_2_3_PAM_DIR/$file"
    done
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/3/2/3/module.sh"
}

@test "both generated stacks with pwquality are compliant" {
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    [ "$(cat "$RLCH_TEST_AUTHSELECT_LOG")" = check ]
}

@test "a different valid PAM control flag is accepted" {
    sed -i 's/password requisite pam_pwquality.so/password [success=ok default=bad] pam_pwquality.so/' "$RLCH_CIS_5_3_2_3_PAM_DIR/system-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
}

@test "a missing pwquality password hook is noncompliant" {
    sed -i '/pam_pwquality.so/d' "$RLCH_CIS_5_3_2_3_PAM_DIR/password-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
}

@test "a comment or an auth hook does not satisfy the password requirement" {
    sed -i 's/^password requisite pam_pwquality.so/# password requisite pam_pwquality.so/' "$RLCH_CIS_5_3_2_3_PAM_DIR/system-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
    sed -i 's/^# password requisite pam_pwquality.so/auth requisite pam_pwquality.so/' "$RLCH_CIS_5_3_2_3_PAM_DIR/system-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
}

@test "duplicate pwquality hooks are noncompliant" {
    printf 'password required pam_pwquality.so\n' >> "$RLCH_CIS_5_3_2_3_PAM_DIR/system-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
}

@test "broken authselect and missing files are handled separately" {
    export RLCH_TEST_AUTHSELECT_EXIT=1
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    export RLCH_TEST_AUTHSELECT_EXIT=0
    rm "$RLCH_CIS_5_3_2_3_PAM_DIR/password-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
}

@test "compliant apply is idempotent" {
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
}

@test "noncompliant apply preserves organization PAM policy" {
    sed -i '/pam_pwquality.so/d' "$RLCH_CIS_5_3_2_3_PAM_DIR/system-auth"
    local before
    before="$(cat "$RLCH_CIS_5_3_2_3_PAM_DIR/system-auth")"
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    [ "$(cat "$RLCH_CIS_5_3_2_3_PAM_DIR/system-auth")" = "$before" ]
}

@test "validate checks and rollback is a no-op" {
    run validate; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
}

@test "metadata does not mislabel a related package rule as exact" {
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/3/2/3/metadata.conf"
    [ "$RLCH_MODULE_ID" = 5.3.2.3 ]
    [ "$RLCH_MODULE_OPENSCAP_RULE" = manual ]
}
