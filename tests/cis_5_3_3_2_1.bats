#!/usr/bin/env bats
setup() {
    source "${BATS_TEST_DIRNAME}/test_helper.bash"
    source "${BATS_TEST_DIRNAME}/../lib/module_api.sh"
    export RLCH_CIS_5_3_3_2_1_CONF="${BATS_TEST_TMPDIR}/etc/pwquality.conf"
    export RLCH_CIS_5_3_3_2_1_BASE="${BATS_TEST_TMPDIR}/usr/pwquality.conf"
    export RLCH_CIS_5_3_3_2_1_PAM_DIR="${BATS_TEST_TMPDIR}/pam.d"
    export RLCH_CIS_5_3_3_2_1_AUTHSELECT="${BATS_TEST_TMPDIR}/authselect"
    export RLCH_CIS_5_3_3_2_1_STATE="${BATS_TEST_TMPDIR}/state"
    mkdir -p "${BATS_TEST_TMPDIR}/etc" "${BATS_TEST_TMPDIR}/usr" "$RLCH_CIS_5_3_3_2_1_PAM_DIR"
    printf '#!/bin/sh\nexit "${RLCH_TEST_AUTHSELECT_EXIT:-0}"\n' > "$RLCH_CIS_5_3_3_2_1_AUTHSELECT"
    chmod +x "$RLCH_CIS_5_3_3_2_1_AUTHSELECT"
    for file in system-auth password-auth; do
        printf 'password requisite pam_pwquality.so retry=3\n' > "$RLCH_CIS_5_3_3_2_1_PAM_DIR/$file"
    done
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/3/3/2/1/module.sh"
}

@test "metadata has exact rule and Level 1" {
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/3/3/2/1/metadata.conf"
    [ "$RLCH_MODULE_ID" = 5.3.3.2.1 ]
    [ "$RLCH_MODULE_LEVEL" = 1 ]
    [ "$RLCH_MODULE_OPENSCAP_RULE" = xccdf_org.ssgproject.content_rule_accounts_password_pam_difok ]
}

@test "effective compliant values remain unchanged" {
    for value in 2 3 10; do
        printf 'difok = %s\n' "$value" > "$RLCH_CIS_5_3_3_2_1_CONF"
        run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
        run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
        [ "$(cat "$RLCH_CIS_5_3_3_2_1_CONF")" = "difok = $value" ]
    done
}

@test "absent and weak settings remediate, validate, and are idempotent" {
    for value in absent 0 1; do
        rm -f "$RLCH_CIS_5_3_3_2_1_CONF"
        rm -rf "$RLCH_CIS_5_3_3_2_1_STATE"
        [ "$value" = absent ] || printf 'difok = %s\n' "$value" > "$RLCH_CIS_5_3_3_2_1_CONF"
        run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
        result=0; apply || result=$?
        [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
        run validate; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
        run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
        result=0; rollback || result=$?
        [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
        if [ "$value" = absent ]; then [ ! -e "$RLCH_CIS_5_3_3_2_1_CONF" ]; else [ "$(cat "$RLCH_CIS_5_3_3_2_1_CONF")" = "difok = $value" ]; fi
    done
}

@test "vendor and administrator drop-ins merge by filename and main file wins" {
    mkdir -p "$RLCH_CIS_5_3_3_2_1_BASE.d" "$RLCH_CIS_5_3_3_2_1_CONF.d"
    printf 'difok = 1\n' > "$RLCH_CIS_5_3_3_2_1_BASE.d/10-base.conf"
    printf 'difok = 3\n' > "$RLCH_CIS_5_3_3_2_1_CONF.d/20-local.conf"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    printf 'difok = 0\n' > "$RLCH_CIS_5_3_3_2_1_BASE.d/20-local.conf"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    printf 'difok = 1\n' > "$RLCH_CIS_5_3_3_2_1_CONF"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
    printf 'difok = 2\n' > "$RLCH_CIS_5_3_3_2_1_CONF"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
}

@test "vendor main fallback and administrator main override" {
    printf 'difok = 3\n' > "$RLCH_CIS_5_3_3_2_1_BASE"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    printf '# local\n' > "$RLCH_CIS_5_3_3_2_1_CONF"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
}

@test "duplicate valid definitions use last value but unsafe replacement is refused" {
    printf 'difok = 3\ndifok = 1\n' > "$RLCH_CIS_5_3_3_2_1_CONF"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    [ ! -e "$RLCH_CIS_5_3_3_2_1_STATE" ]
    printf 'difok = 1\ndifok = 3\n' > "$RLCH_CIS_5_3_3_2_1_CONF"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
}

@test "malformed and unreadable path are errors" {
    printf 'difok = invalid\n' > "$RLCH_CIS_5_3_3_2_1_CONF"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    rm "$RLCH_CIS_5_3_3_2_1_CONF"
    ln -s "$RLCH_CIS_5_3_3_2_1_BASE" "$RLCH_CIS_5_3_3_2_1_CONF"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
}

@test "inline PAM overrides configuration and unsafe changes are refused" {
    printf 'difok = 1\n' > "$RLCH_CIS_5_3_3_2_1_CONF"
    for file in system-auth password-auth; do
        printf 'password requisite pam_pwquality.so difok=4\n' > "$RLCH_CIS_5_3_3_2_1_PAM_DIR/$file"
    done
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    sed -i 's/difok=4/difok=1/' "$RLCH_CIS_5_3_3_2_1_PAM_DIR/system-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    [ "$(cat "$RLCH_CIS_5_3_3_2_1_CONF")" = 'difok = 1' ]
}

@test "custom conf and duplicate inline options are errors" {
    sed -i 's/retry=3/retry=3 conf=\/other/' "$RLCH_CIS_5_3_3_2_1_PAM_DIR/system-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    sed -i 's@conf=/other@difok=2 difok=1@' "$RLCH_CIS_5_3_3_2_1_PAM_DIR/system-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
}

@test "rollback preserves unrelated settings and file metadata" {
    printf '# keep\nminlen = 14\ndifok = 1 # old\n' > "$RLCH_CIS_5_3_3_2_1_CONF"
    chmod 0600 "$RLCH_CIS_5_3_3_2_1_CONF"
    before="$(stat -c '%u:%g:%a' "$RLCH_CIS_5_3_3_2_1_CONF")"
    result=0; apply || result=$?
    [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    [ "$(stat -c '%u:%g:%a' "$RLCH_CIS_5_3_3_2_1_CONF")" = "$before" ]
    printf 'maxrepeat = 3\n' >> "$RLCH_CIS_5_3_3_2_1_CONF"
    result=0; rollback || result=$?
    [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    [ "$(cat "$RLCH_CIS_5_3_3_2_1_CONF")" = "$(printf '# keep\nminlen = 14\ndifok = 1 # old\nmaxrepeat = 3')" ]
}

@test "rollback refuses administrator edit and keeps state" {
    result=0; apply || result=$?
    printf 'difok = 5\n' >> "$RLCH_CIS_5_3_3_2_1_CONF"
    run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    [ -f "$RLCH_CIS_5_3_3_2_1_STATE/original" ]
}

@test "rollback of a created file preserves later administrator settings" {
    result=0; apply || result=$?
    [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    printf 'minlen = 14\n' >> "$RLCH_CIS_5_3_3_2_1_CONF"
    result=0; rollback || result=$?
    [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    [ "$(cat "$RLCH_CIS_5_3_3_2_1_CONF")" = 'minlen = 14' ]
}

@test "failed post-write validation immediately restores prior state" {
    printf 'difok = 1\nminlen = 14\n' > "$RLCH_CIS_5_3_3_2_1_CONF"
    cat > "$RLCH_CIS_5_3_3_2_1_AUTHSELECT" <<'EOF'
#!/bin/sh
count_file="${RLCH_CIS_5_3_3_2_1_STATE}.calls"
count=0
if [ -f "$count_file" ]; then count="$(cat "$count_file")"; fi
count=$((count + 1))
printf '%s\n' "$count" > "$count_file"
[ "$count" -lt 2 ]
EOF
    result=0; apply || result=$?
    [ "$result" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    [ "$(cat "$RLCH_CIS_5_3_3_2_1_CONF")" = "$(printf 'difok = 1\nminlen = 14')" ]
    [ ! -e "$RLCH_CIS_5_3_3_2_1_STATE" ]
}

@test "authselect failure blocks all changes" {
    printf '#!/bin/sh\nexit 1\n' > "$RLCH_CIS_5_3_3_2_1_AUTHSELECT"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    [ ! -e "$RLCH_CIS_5_3_3_2_1_CONF" ]
}
