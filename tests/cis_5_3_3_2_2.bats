#!/usr/bin/env bats
setup() {
    source "${BATS_TEST_DIRNAME}/test_helper.bash"
    source "${BATS_TEST_DIRNAME}/../lib/module_api.sh"
    export RLCH_CIS_5_3_3_2_2_CONF="${BATS_TEST_TMPDIR}/etc/pwquality.conf"
    export RLCH_CIS_5_3_3_2_2_BASE="${BATS_TEST_TMPDIR}/usr/pwquality.conf"
    export RLCH_CIS_5_3_3_2_2_PAM_DIR="${BATS_TEST_TMPDIR}/pam.d"
    export RLCH_CIS_5_3_3_2_2_AUTHSELECT="${BATS_TEST_TMPDIR}/authselect"
    export RLCH_CIS_5_3_3_2_2_STATE="${BATS_TEST_TMPDIR}/state"
    mkdir -p "${BATS_TEST_TMPDIR}/etc" "${BATS_TEST_TMPDIR}/usr" "$RLCH_CIS_5_3_3_2_2_PAM_DIR"
    printf '#!/bin/sh\nexit "${RLCH_TEST_AUTHSELECT_EXIT:-0}"\n' > "$RLCH_CIS_5_3_3_2_2_AUTHSELECT"
    chmod +x "$RLCH_CIS_5_3_3_2_2_AUTHSELECT"
    for file in system-auth password-auth; do
        printf 'password requisite pam_pwquality.so retry=3\n' > "$RLCH_CIS_5_3_3_2_2_PAM_DIR/$file"
    done
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/3/3/2/2/module.sh"
}

@test "metadata has exact rule and Level 1" {
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/3/3/2/2/metadata.conf"
    [ "$RLCH_MODULE_ID" = 5.3.3.2.2 ]
    [ "$RLCH_MODULE_LEVEL" = 1 ]
    [ "$RLCH_MODULE_OPENSCAP_RULE" = xccdf_org.ssgproject.content_rule_accounts_password_pam_minlen ]
}

@test "effective compliant values remain unchanged" {
    for value in 14 15 20; do
        printf 'minlen = %s\n' "$value" > "$RLCH_CIS_5_3_3_2_2_CONF"
        run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
        run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
        [ "$(cat "$RLCH_CIS_5_3_3_2_2_CONF")" = "minlen = $value" ]
    done
}

@test "absent and weak settings remediate, validate, and are idempotent" {
    for value in absent 0 8 13; do
        rm -f "$RLCH_CIS_5_3_3_2_2_CONF"
        rm -rf "$RLCH_CIS_5_3_3_2_2_STATE"
        [ "$value" = absent ] || printf 'minlen = %s\n' "$value" > "$RLCH_CIS_5_3_3_2_2_CONF"
        run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
        result=0; apply || result=$?
        [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
        run validate; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
        run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
        result=0; rollback || result=$?
        [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
        if [ "$value" = absent ]; then [ ! -e "$RLCH_CIS_5_3_3_2_2_CONF" ]; else [ "$(cat "$RLCH_CIS_5_3_3_2_2_CONF")" = "minlen = $value" ]; fi
    done
}

@test "vendor and administrator drop-ins merge by filename and main file wins" {
    mkdir -p "$RLCH_CIS_5_3_3_2_2_BASE.d" "$RLCH_CIS_5_3_3_2_2_CONF.d"
    printf 'minlen = 8\n' > "$RLCH_CIS_5_3_3_2_2_BASE.d/10-base.conf"
    printf 'minlen = 20\n' > "$RLCH_CIS_5_3_3_2_2_CONF.d/20-local.conf"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    printf 'minlen = 0\n' > "$RLCH_CIS_5_3_3_2_2_BASE.d/20-local.conf"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    printf 'minlen = 8\n' > "$RLCH_CIS_5_3_3_2_2_CONF"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
    printf 'minlen = 14\n' > "$RLCH_CIS_5_3_3_2_2_CONF"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
}

@test "vendor main fallback and administrator main override" {
    printf 'minlen = 20\n' > "$RLCH_CIS_5_3_3_2_2_BASE"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    printf '# local\n' > "$RLCH_CIS_5_3_3_2_2_CONF"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
}

@test "duplicate valid definitions use last value but unsafe replacement is refused" {
    printf 'minlen = 20\nminlen = 8\n' > "$RLCH_CIS_5_3_3_2_2_CONF"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    [ ! -e "$RLCH_CIS_5_3_3_2_2_STATE" ]
    printf 'minlen = 8\nminlen = 20\n' > "$RLCH_CIS_5_3_3_2_2_CONF"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
}

@test "malformed and unreadable path are errors" {
    printf 'minlen = invalid\n' > "$RLCH_CIS_5_3_3_2_2_CONF"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    rm "$RLCH_CIS_5_3_3_2_2_CONF"
    ln -s "$RLCH_CIS_5_3_3_2_2_BASE" "$RLCH_CIS_5_3_3_2_2_CONF"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
}

@test "inline PAM overrides configuration and unsafe changes are refused" {
    printf 'minlen = 8\n' > "$RLCH_CIS_5_3_3_2_2_CONF"
    for file in system-auth password-auth; do
        printf 'password requisite pam_pwquality.so minlen=16\n' > "$RLCH_CIS_5_3_3_2_2_PAM_DIR/$file"
    done
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    sed -i 's/minlen=16/minlen=8/' "$RLCH_CIS_5_3_3_2_2_PAM_DIR/system-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    [ "$(cat "$RLCH_CIS_5_3_3_2_2_CONF")" = 'minlen = 8' ]
}

@test "custom conf and duplicate inline options are errors" {
    sed -i 's/retry=3/retry=3 conf=\/other/' "$RLCH_CIS_5_3_3_2_2_PAM_DIR/system-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    sed -i 's@conf=/other@minlen=14 minlen=8@' "$RLCH_CIS_5_3_3_2_2_PAM_DIR/system-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    sed -i 's/minlen=14 minlen=8/minlen=bad/' "$RLCH_CIS_5_3_3_2_2_PAM_DIR/system-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
}

@test "comments and spaces are parsed; inconsistent stacks are errors" {
    printf '# minlen = 8\n minlen  =  15 # administrator\n' > "$RLCH_CIS_5_3_3_2_2_CONF"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    printf '# missing hook\n' > "$RLCH_CIS_5_3_3_2_2_PAM_DIR/system-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
}

@test "rollback preserves unrelated settings and file metadata" {
    printf '# keep\ndifok = 2\nminlen = 8 # old\n' > "$RLCH_CIS_5_3_3_2_2_CONF"
    chmod 0600 "$RLCH_CIS_5_3_3_2_2_CONF"
    before="$(stat -c '%u:%g:%a' "$RLCH_CIS_5_3_3_2_2_CONF")"
    result=0; apply || result=$?
    [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    [ "$(stat -c '%u:%g:%a' "$RLCH_CIS_5_3_3_2_2_CONF")" = "$before" ]
    printf 'maxrepeat = 3\n' >> "$RLCH_CIS_5_3_3_2_2_CONF"
    result=0; rollback || result=$?
    [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    [ "$(cat "$RLCH_CIS_5_3_3_2_2_CONF")" = "$(printf '# keep\ndifok = 2\nminlen = 8 # old\nmaxrepeat = 3')" ]
}

@test "rollback refuses administrator edit and keeps state" {
    result=0; apply || result=$?
    printf 'minlen = 20\n' >> "$RLCH_CIS_5_3_3_2_2_CONF"
    run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    [ -f "$RLCH_CIS_5_3_3_2_2_STATE/original" ]
}

@test "rollback of a created file preserves later administrator settings" {
    result=0; apply || result=$?
    [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    printf 'difok = 2\n' >> "$RLCH_CIS_5_3_3_2_2_CONF"
    result=0; rollback || result=$?
    [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    [ "$(cat "$RLCH_CIS_5_3_3_2_2_CONF")" = 'difok = 2' ]
}

@test "failed post-write validation immediately restores prior state" {
    printf 'minlen = 8\ndifok = 2\n' > "$RLCH_CIS_5_3_3_2_2_CONF"
    cat > "$RLCH_CIS_5_3_3_2_2_AUTHSELECT" <<'EOF'
#!/bin/sh
count_file="${RLCH_CIS_5_3_3_2_2_STATE}.calls"
count=0
if [ -f "$count_file" ]; then count="$(cat "$count_file")"; fi
count=$((count + 1))
printf '%s\n' "$count" > "$count_file"
[ "$count" -lt 2 ]
EOF
    result=0; apply || result=$?
    [ "$result" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    [ "$(cat "$RLCH_CIS_5_3_3_2_2_CONF")" = "$(printf 'minlen = 8\ndifok = 2')" ]
    [ ! -e "$RLCH_CIS_5_3_3_2_2_STATE" ]
}

@test "authselect failure blocks all changes" {
    printf '#!/bin/sh\nexit 1\n' > "$RLCH_CIS_5_3_3_2_2_AUTHSELECT"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    [ ! -e "$RLCH_CIS_5_3_3_2_2_CONF" ]
}

@test "difok and minlen apply and rollback independently in both orders" {
    export RLCH_CIS_5_3_3_2_1_CONF="$RLCH_CIS_5_3_3_2_2_CONF"
    export RLCH_CIS_5_3_3_2_1_BASE="$RLCH_CIS_5_3_3_2_2_BASE"
    export RLCH_CIS_5_3_3_2_1_PAM_DIR="$RLCH_CIS_5_3_3_2_2_PAM_DIR"
    export RLCH_CIS_5_3_3_2_1_AUTHSELECT="$RLCH_CIS_5_3_3_2_2_AUTHSELECT"
    export RLCH_CIS_5_3_3_2_1_STATE="${BATS_TEST_TMPDIR}/difok-state"
    printf 'difok = 1\nminlen = 8\n' > "$RLCH_CIS_5_3_3_2_2_CONF"
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/3/3/2/1/module.sh"
    result=0; apply || result=$?
    [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/3/3/2/2/module.sh"
    result=0; apply || result=$?
    [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/3/3/2/1/module.sh"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    result=0; rollback || result=$?
    [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/3/3/2/2/module.sh"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    [ "$(grep -c '^minlen = 14' "$RLCH_CIS_5_3_3_2_2_CONF")" -eq 1 ]
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/3/3/2/1/module.sh"
    result=0; apply || result=$?
    [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/3/3/2/2/module.sh"
    result=0; rollback || result=$?
    [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/3/3/2/1/module.sh"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    [ "$(grep -c '^difok = 2' "$RLCH_CIS_5_3_3_2_2_CONF")" -eq 1 ]
}
