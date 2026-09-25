#!/usr/bin/env bats
setup() {
    source "${BATS_TEST_DIRNAME}/test_helper.bash"
    source "${BATS_TEST_DIRNAME}/../lib/module_api.sh"
    export RLCH_CIS_5_3_2_1_CONFIG="${BATS_TEST_TMPDIR}/authselect.conf"
    export RLCH_CIS_5_3_2_1_CUSTOM_DIR="${BATS_TEST_TMPDIR}/custom"
    export RLCH_CIS_5_3_2_1_DEFAULT_DIR="${BATS_TEST_TMPDIR}/default"
    export RLCH_CIS_5_3_2_1_AUTHSELECT="${BATS_TEST_TMPDIR}/authselect"
    export RLCH_TEST_AUTHSELECT_LOG="${BATS_TEST_TMPDIR}/authselect.log"
    mkdir -p "$RLCH_CIS_5_3_2_1_CUSTOM_DIR/org" "$RLCH_CIS_5_3_2_1_DEFAULT_DIR/local"
    printf 'custom/org\nwith-faillock\n' > "$RLCH_CIS_5_3_2_1_CONFIG"
    cat > "$RLCH_CIS_5_3_2_1_AUTHSELECT" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$RLCH_TEST_AUTHSELECT_LOG"
exit "${RLCH_TEST_AUTHSELECT_EXIT:-0}"
EOF
    chmod +x "$RLCH_CIS_5_3_2_1_AUTHSELECT"
    for file in system-auth password-auth; do
        cat > "$RLCH_CIS_5_3_2_1_CUSTOM_DIR/org/$file" <<'EOF'
# original comment
password requisite pam_pwquality.so retry=3
password required pam_pwhistory.so use_authtok
auth required pam_faillock.so preauth
password sufficient pam_unix.so sha512
EOF
        cp "$RLCH_CIS_5_3_2_1_CUSTOM_DIR/org/$file" "$RLCH_CIS_5_3_2_1_DEFAULT_DIR/local/$file"
    done
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/3/2/1/module.sh"
}

@test "checks the two sources of the active custom profile" {
    run check
    [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    [ "$(cat "$RLCH_TEST_AUTHSELECT_LOG")" = check ]
}

@test "checks standard profile sources in the system default directory" {
    printf 'local\n' > "$RLCH_CIS_5_3_2_1_CONFIG"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
}

@test "a missing module in either source is noncompliant" {
    sed -i '/pam_pwhistory.so/d' "$RLCH_CIS_5_3_2_1_CUSTOM_DIR/org/password-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
}

@test "commented modules are not counted" {
    sed -i 's/^auth required pam_faillock.so/# auth required pam_faillock.so/' "$RLCH_CIS_5_3_2_1_CUSTOM_DIR/org/system-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
}

@test "duplicate module entries do not hide a missing different module" {
    sed -i '/pam_unix.so/d' "$RLCH_CIS_5_3_2_1_CUSTOM_DIR/org/system-auth"
    printf 'password requisite pam_pwquality.so\n' >> "$RLCH_CIS_5_3_2_1_CUSTOM_DIR/org/system-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
}

@test "a broken authselect configuration is an error" {
    export RLCH_TEST_AUTHSELECT_EXIT=1
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
}

@test "a missing profile source is noncompliant" {
    rm "$RLCH_CIS_5_3_2_1_CUSTOM_DIR/org/password-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
}

@test "missing or malformed profile selection is an error" {
    rm "$RLCH_CIS_5_3_2_1_CONFIG"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    printf 'custom/../../unsafe\n' > "$RLCH_CIS_5_3_2_1_CONFIG"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
}

@test "apply is idempotent for a compliant profile" {
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
}

@test "apply refuses to guess PAM stack order and preserves profile sources" {
    local before
    sed -i '/pam_pwquality.so/d' "$RLCH_CIS_5_3_2_1_CUSTOM_DIR/org/system-auth"
    before="$(cat "$RLCH_CIS_5_3_2_1_CUSTOM_DIR/org/system-auth")"
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    [ "$(cat "$RLCH_CIS_5_3_2_1_CUSTOM_DIR/org/system-auth")" = "$before" ]
}

@test "validate checks profile and rollback never changes it" {
    run validate; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    [ "$(cat "$RLCH_TEST_AUTHSELECT_LOG")" = check ]
}

@test "metadata records exact primary rule" {
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/3/2/1/metadata.conf"
    [ "$RLCH_MODULE_ID" = 5.3.2.1 ]
    [ "$RLCH_MODULE_OPENSCAP_RULE" = xccdf_org.ssgproject.content_rule_accounts_password_pam_modules_in_authselect_profile ]
}
