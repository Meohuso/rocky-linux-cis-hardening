#!/usr/bin/env bats
setup() {
    source "${BATS_TEST_DIRNAME}/test_helper.bash"
    source "${BATS_TEST_DIRNAME}/../lib/module_api.sh"
    export RLCH_CIS_5_3_3_1_1_CONF="${BATS_TEST_TMPDIR}/faillock.conf"
    export RLCH_CIS_5_3_3_1_1_PAM_DIR="${BATS_TEST_TMPDIR}/pam.d"
    export RLCH_CIS_5_3_3_1_1_STATE="${BATS_TEST_TMPDIR}/state"
    export RLCH_CIS_5_3_3_1_1_AUTHSELECT="${BATS_TEST_TMPDIR}/authselect"
    mkdir -p "$RLCH_CIS_5_3_3_1_1_PAM_DIR"
    printf '#!/bin/sh\nexit "${RLCH_TEST_AUTHSELECT_EXIT:-0}"\n' > "$RLCH_CIS_5_3_3_1_1_AUTHSELECT"
    chmod +x "$RLCH_CIS_5_3_3_1_1_AUTHSELECT"
    for file in system-auth password-auth; do
        printf 'auth required pam_faillock.so preauth silent\nauth required pam_faillock.so authfail\n' > "$RLCH_CIS_5_3_3_1_1_PAM_DIR/$file"
    done
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/3/3/1/1/module.sh"
}

@test "metadata maps the exact rule" {
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/3/3/1/1/metadata.conf"
    [ "$RLCH_MODULE_ID" = 5.3.3.1.1 ]
    [ "$RLCH_MODULE_OPENSCAP_RULE" = xccdf_org.ssgproject.content_rule_accounts_passwords_pam_faillock_deny ]
}

@test "thresholds 1 3 and 5 are compliant and apply does not weaken them" {
    for value in 1 3 5; do
        printf 'deny = %s\n' "$value" > "$RLCH_CIS_5_3_3_1_1_CONF"
        run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
        run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
        [ "$(cat "$RLCH_CIS_5_3_3_1_1_CONF")" = "deny = $value" ]
    done
}

@test "zero, six, and absence are noncompliant" {
    for value in 0 6; do
        printf 'deny = %s\n' "$value" > "$RLCH_CIS_5_3_3_1_1_CONF"
        run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
    done
    rm "$RLCH_CIS_5_3_3_1_1_CONF"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
}

@test "comments are ignored and valid spaces are accepted" {
    printf '# deny = 5\n  deny  =  3  # administrator\n' > "$RLCH_CIS_5_3_3_1_1_CONF"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    printf '# deny = 5\n' > "$RLCH_CIS_5_3_3_1_1_CONF"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
}

@test "non-numeric and duplicated settings are errors" {
    printf 'deny = five\n' > "$RLCH_CIS_5_3_3_1_1_CONF"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    printf 'deny = 5\ndeny = 0\n' > "$RLCH_CIS_5_3_3_1_1_CONF"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
}

@test "compliant inline options override absent configuration" {
    for file in system-auth password-auth; do
        sed -i 's/preauth silent/preauth silent deny=3/; s/authfail$/authfail deny=3/' "$RLCH_CIS_5_3_3_1_1_PAM_DIR/$file"
    done
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    [ ! -e "$RLCH_CIS_5_3_3_1_1_CONF" ]
}

@test "invalid inline option is noncompliant despite compliant configuration" {
    printf 'deny = 5\n' > "$RLCH_CIS_5_3_3_1_1_CONF"
    sed -i 's/authfail$/authfail deny=6/' "$RLCH_CIS_5_3_3_1_1_PAM_DIR/system-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    [ "$(cat "$RLCH_CIS_5_3_3_1_1_CONF")" = 'deny = 5' ]
    [ ! -e "$RLCH_CIS_5_3_3_1_1_STATE" ]
}

@test "mixed inline and config requires both values to comply" {
    printf 'deny = 6\n' > "$RLCH_CIS_5_3_3_1_1_CONF"
    sed -i 's/authfail$/authfail deny=3/' "$RLCH_CIS_5_3_3_1_1_PAM_DIR/system-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
}

@test "malformed and repeated inline options are errors" {
    sed -i 's/authfail$/authfail deny=bad/' "$RLCH_CIS_5_3_3_1_1_PAM_DIR/system-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    sed -i 's/deny=bad/deny=5 deny=0/' "$RLCH_CIS_5_3_3_1_1_PAM_DIR/system-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
}

@test "apply creates setting and second apply is idempotent" {
    result=0; apply || result=$?
    [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    [ "$(grep -c '^deny' "$RLCH_CIS_5_3_3_1_1_CONF")" -eq 1 ]
}

@test "apply retains comments other settings ownership and mode" {
    printf '# administrator\nunlock_time = 900\ndeny = 6 # old\n' > "$RLCH_CIS_5_3_3_1_1_CONF"
    chmod 0600 "$RLCH_CIS_5_3_3_1_1_CONF"
    before="$(stat -c '%u:%g:%a' "$RLCH_CIS_5_3_3_1_1_CONF")"
    result=0; apply || result=$?
    [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    [ "$(stat -c '%u:%g:%a' "$RLCH_CIS_5_3_3_1_1_CONF")" = "$before" ]
    [ "$(sed -n '1,2p' "$RLCH_CIS_5_3_3_1_1_CONF")" = "$(printf '# administrator\nunlock_time = 900')" ]
}

@test "rollback restores the original deny line but preserves later unlock_time" {
    printf '# keep\ndeny = 6 # old\n' > "$RLCH_CIS_5_3_3_1_1_CONF"
    result=0; apply || result=$?
    [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    printf 'unlock_time = 900\n' >> "$RLCH_CIS_5_3_3_1_1_CONF"
    result=0; rollback || result=$?
    [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    [ "$(cat "$RLCH_CIS_5_3_3_1_1_CONF")" = "$(printf '# keep\ndeny = 6 # old\nunlock_time = 900')" ]
}

@test "rollback removes only owned deny line and keeps other settings" {
    printf '# keep\nunlock_time = 900\n' > "$RLCH_CIS_5_3_3_1_1_CONF"
    result=0; apply || result=$?
    [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    result=0; rollback || result=$?
    [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    [ "$(cat "$RLCH_CIS_5_3_3_1_1_CONF")" = "$(printf '# keep\nunlock_time = 900')" ]
}

@test "rollback removes created file only when it remains empty" {
    result=0; apply || result=$?
    [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    result=0; rollback || result=$?
    [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    [ ! -e "$RLCH_CIS_5_3_3_1_1_CONF" ]
    result=0; apply || result=$?
    printf 'unlock_time = 900\n' >> "$RLCH_CIS_5_3_3_1_1_CONF"
    result=0; rollback || result=$?
    [ -f "$RLCH_CIS_5_3_3_1_1_CONF" ]
    [ "$(cat "$RLCH_CIS_5_3_3_1_1_CONF")" = 'unlock_time = 900' ]
}

@test "rollback refuses an administrator deny edit without losing state" {
    result=0; apply || result=$?
    printf 'deny = 3 # administrator\n' >> "$RLCH_CIS_5_3_3_1_1_CONF"
    run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    [ -f "$RLCH_CIS_5_3_3_1_1_STATE/file" ]
    [ "$(grep -c 'administrator' "$RLCH_CIS_5_3_3_1_1_CONF")" -eq 1 ]
}

@test "authselect inconsistency blocks check and apply" {
    cat > "$RLCH_CIS_5_3_3_1_1_AUTHSELECT" <<'EOF'
#!/bin/sh
exit 1
EOF
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    [ ! -e "$RLCH_CIS_5_3_3_1_1_CONF" ]
}
