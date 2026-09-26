#!/usr/bin/env bats
setup() {
    source "${BATS_TEST_DIRNAME}/test_helper.bash"
    source "${BATS_TEST_DIRNAME}/../lib/module_api.sh"
    export RLCH_CIS_5_3_3_1_2_CONF="${BATS_TEST_TMPDIR}/faillock.conf"
    export RLCH_CIS_5_3_3_1_2_PAM_DIR="${BATS_TEST_TMPDIR}/pam.d"
    export RLCH_CIS_5_3_3_1_2_STATE="${BATS_TEST_TMPDIR}/state"
    export RLCH_CIS_5_3_3_1_2_AUTHSELECT="${BATS_TEST_TMPDIR}/authselect"
    mkdir -p "$RLCH_CIS_5_3_3_1_2_PAM_DIR"
    printf '#!/bin/sh\nexit "${RLCH_TEST_AUTHSELECT_EXIT:-0}"\n' > "$RLCH_CIS_5_3_3_1_2_AUTHSELECT"
    chmod +x "$RLCH_CIS_5_3_3_1_2_AUTHSELECT"
    for file in system-auth password-auth; do
        printf 'auth required pam_faillock.so preauth silent\nauth required pam_faillock.so authfail\n' > "$RLCH_CIS_5_3_3_1_2_PAM_DIR/$file"
    done
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/3/3/1/2/module.sh"
}

@test "metadata maps the exact rule" {
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/3/3/1/2/metadata.conf"
    [ "$RLCH_MODULE_ID" = 5.3.3.1.2 ]
    [ "$RLCH_MODULE_OPENSCAP_RULE" = xccdf_org.ssgproject.content_rule_accounts_passwords_pam_faillock_unlock_time ]
}

@test "zero, 900, 1200 and 1800 are compliant and apply preserves them" {
    for value in 0 900 1200 1800; do
        printf 'unlock_time = %s\n' "$value" > "$RLCH_CIS_5_3_3_1_2_CONF"
        run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
        run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
        [ "$(cat "$RLCH_CIS_5_3_3_1_2_CONF")" = "unlock_time = $value" ]
    done
}

@test "one, 600, 899, and absence are noncompliant" {
    for value in 1 600 899; do
        printf 'unlock_time = %s\n' "$value" > "$RLCH_CIS_5_3_3_1_2_CONF"
        run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
    done
    rm "$RLCH_CIS_5_3_3_1_2_CONF"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
}

@test "comments are ignored and valid spaces are accepted" {
    printf '# unlock_time = 900\n  unlock_time  =  1800  # administrator\n' > "$RLCH_CIS_5_3_3_1_2_CONF"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    printf '# unlock_time = 900\n' > "$RLCH_CIS_5_3_3_1_2_CONF"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
}

@test "non-numeric and duplicated settings are errors" {
    printf 'unlock_time = five\n' > "$RLCH_CIS_5_3_3_1_2_CONF"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    printf 'unlock_time = 900\nunlock_time = 0\n' > "$RLCH_CIS_5_3_3_1_2_CONF"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
}

@test "inline zero, 900 and 1800 override absent configuration" {
    for value in 0 900 1800; do
        for file in system-auth password-auth; do
            printf 'auth required pam_faillock.so preauth unlock_time=%s\nauth required pam_faillock.so authfail unlock_time=%s\n' "$value" "$value" > "$RLCH_CIS_5_3_3_1_2_PAM_DIR/$file"
        done
        run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
        run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
        [ ! -e "$RLCH_CIS_5_3_3_1_2_CONF" ]
    done
}

@test "invalid inline option is noncompliant despite compliant configuration" {
    printf 'unlock_time = 900\n' > "$RLCH_CIS_5_3_3_1_2_CONF"
    sed -i 's/authfail$/authfail unlock_time=600/' "$RLCH_CIS_5_3_3_1_2_PAM_DIR/system-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    [ "$(cat "$RLCH_CIS_5_3_3_1_2_CONF")" = 'unlock_time = 900' ]
    [ ! -e "$RLCH_CIS_5_3_3_1_2_STATE" ]
}

@test "mixed inline and config requires both values to comply" {
    printf 'unlock_time = 600\n' > "$RLCH_CIS_5_3_3_1_2_CONF"
    sed -i 's/authfail$/authfail unlock_time=1800/' "$RLCH_CIS_5_3_3_1_2_PAM_DIR/system-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
}

@test "malformed and repeated inline options are errors" {
    sed -i 's/authfail$/authfail unlock_time=bad/' "$RLCH_CIS_5_3_3_1_2_PAM_DIR/system-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    sed -i 's/unlock_time=bad/unlock_time=900 unlock_time=0/' "$RLCH_CIS_5_3_3_1_2_PAM_DIR/system-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
}

@test "apply creates setting and second apply is idempotent" {
    result=0; apply || result=$?
    [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    [ "$(grep -c '^unlock_time' "$RLCH_CIS_5_3_3_1_2_CONF")" -eq 1 ]
}

@test "apply retains comments other settings ownership and mode" {
    printf '# administrator\ndeny = 5 # rlch-cis-5.3.3.1.1\nunlock_time = 600 # old\n' > "$RLCH_CIS_5_3_3_1_2_CONF"
    chmod 0600 "$RLCH_CIS_5_3_3_1_2_CONF"
    before="$(stat -c '%u:%g:%a' "$RLCH_CIS_5_3_3_1_2_CONF")"
    result=0; apply || result=$?
    [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    [ "$(stat -c '%u:%g:%a' "$RLCH_CIS_5_3_3_1_2_CONF")" = "$before" ]
    [ "$(sed -n '1,2p' "$RLCH_CIS_5_3_3_1_2_CONF")" = "$(printf '# administrator\ndeny = 5 # rlch-cis-5.3.3.1.1')" ]
    [ "$(tail -1 "$RLCH_CIS_5_3_3_1_2_CONF")" = 'unlock_time = 900 # rlch-cis-5.3.3.1.2' ]
}

@test "rollback restores original unlock time while preserving deny and later settings" {
    printf '# keep\ndeny = 5 # rlch-cis-5.3.3.1.1\nunlock_time = 600 # old\n' > "$RLCH_CIS_5_3_3_1_2_CONF"
    result=0; apply || result=$?
    [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    printf 'fail_interval = 900\n' >> "$RLCH_CIS_5_3_3_1_2_CONF"
    result=0; rollback || result=$?
    [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    [ "$(cat "$RLCH_CIS_5_3_3_1_2_CONF")" = "$(printf '# keep\ndeny = 5 # rlch-cis-5.3.3.1.1\nunlock_time = 600 # old\nfail_interval = 900')" ]
}

@test "rollback removes only owned unlock time and keeps deny" {
    printf '# keep\ndeny = 5 # rlch-cis-5.3.3.1.1\n' > "$RLCH_CIS_5_3_3_1_2_CONF"
    result=0; apply || result=$?
    [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    result=0; rollback || result=$?
    [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    [ "$(cat "$RLCH_CIS_5_3_3_1_2_CONF")" = "$(printf '# keep\ndeny = 5 # rlch-cis-5.3.3.1.1')" ]
}

@test "both controls retain each other's settings during independent rollback" {
    export RLCH_CIS_5_3_3_1_1_CONF="$RLCH_CIS_5_3_3_1_2_CONF"
    export RLCH_CIS_5_3_3_1_1_PAM_DIR="$RLCH_CIS_5_3_3_1_2_PAM_DIR"
    export RLCH_CIS_5_3_3_1_1_AUTHSELECT="$RLCH_CIS_5_3_3_1_2_AUTHSELECT"
    export RLCH_CIS_5_3_3_1_1_STATE="${BATS_TEST_TMPDIR}/deny-state"
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/3/3/1/1/module.sh"
    result=0; apply || result=$?
    [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/3/3/1/2/module.sh"
    result=0; apply || result=$?
    [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/3/3/1/1/module.sh"
    result=0; rollback || result=$?
    [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    [ "$(cat "$RLCH_CIS_5_3_3_1_2_CONF")" = 'unlock_time = 900 # rlch-cis-5.3.3.1.2' ]
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/3/3/1/2/module.sh"
    result=0; rollback || result=$?
    [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    [ -f "$RLCH_CIS_5_3_3_1_2_CONF" ]
    [ ! -s "$RLCH_CIS_5_3_3_1_2_CONF" ]
}

@test "rollback removes created file only when it remains empty" {
    result=0; apply || result=$?
    [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    result=0; rollback || result=$?
    [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    [ ! -e "$RLCH_CIS_5_3_3_1_2_CONF" ]
    result=0; apply || result=$?
    printf 'deny = 5 # rlch-cis-5.3.3.1.1\n' >> "$RLCH_CIS_5_3_3_1_2_CONF"
    result=0; rollback || result=$?
    [ -f "$RLCH_CIS_5_3_3_1_2_CONF" ]
    [ "$(cat "$RLCH_CIS_5_3_3_1_2_CONF")" = 'deny = 5 # rlch-cis-5.3.3.1.1' ]
}

@test "rollback refuses an administrator unlock_time edit without losing state" {
    result=0; apply || result=$?
    printf 'unlock_time = 1800 # administrator\n' >> "$RLCH_CIS_5_3_3_1_2_CONF"
    run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    [ -f "$RLCH_CIS_5_3_3_1_2_STATE/file" ]
    [ "$(grep -c 'administrator' "$RLCH_CIS_5_3_3_1_2_CONF")" -eq 1 ]
}

@test "authselect inconsistency blocks check and apply" {
    cat > "$RLCH_CIS_5_3_3_1_2_AUTHSELECT" <<'EOF'
#!/bin/sh
exit 1
EOF
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    [ ! -e "$RLCH_CIS_5_3_3_1_2_CONF" ]
}
