#!/usr/bin/env bats
setup() {
    source "${BATS_TEST_DIRNAME}/test_helper.bash"
    source "${BATS_TEST_DIRNAME}/../lib/module_api.sh"
    export RLCH_CIS_5_3_3_2_4_CONF="${BATS_TEST_TMPDIR}/etc/pwquality.conf"
    export RLCH_CIS_5_3_3_2_4_BASE="${BATS_TEST_TMPDIR}/usr/pwquality.conf"
    export RLCH_CIS_5_3_3_2_4_PAM_DIR="${BATS_TEST_TMPDIR}/pam.d"
    export RLCH_CIS_5_3_3_2_4_AUTHSELECT="${BATS_TEST_TMPDIR}/authselect"
    export RLCH_CIS_5_3_3_2_4_STATE="${BATS_TEST_TMPDIR}/state"
    mkdir -p "${BATS_TEST_TMPDIR}/etc" "${BATS_TEST_TMPDIR}/usr" "$RLCH_CIS_5_3_3_2_4_PAM_DIR"
    printf '#!/bin/sh\nexit "${RLCH_TEST_AUTHSELECT_EXIT:-0}"\n' > "$RLCH_CIS_5_3_3_2_4_AUTHSELECT"
    chmod +x "$RLCH_CIS_5_3_3_2_4_AUTHSELECT"
    for file in system-auth password-auth; do
        printf 'password requisite pam_pwquality.so retry=3\n' > "$RLCH_CIS_5_3_3_2_4_PAM_DIR/$file"
    done
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/3/3/2/4/module.sh"
}

@test "metadata has exact rule and Level 1" {
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/3/3/2/4/metadata.conf"
    [ "$RLCH_MODULE_ID" = 5.3.3.2.4 ]
    [ "$RLCH_MODULE_LEVEL" = 1 ]
    [ "$RLCH_MODULE_OPENSCAP_RULE" = xccdf_org.ssgproject.content_rule_accounts_password_pam_maxrepeat ]
}

@test "effective compliant values remain unchanged" {
    for value in 1 2 3; do
        printf 'maxrepeat = %s\n' "$value" > "$RLCH_CIS_5_3_3_2_4_CONF"
        run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
        run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
        [ "$(cat "$RLCH_CIS_5_3_3_2_4_CONF")" = "maxrepeat = $value" ]
    done
}

@test "absent and weak settings remediate, validate, and are idempotent" {
    for value in absent 0 4 20; do
        rm -f "$RLCH_CIS_5_3_3_2_4_CONF"
        rm -rf "$RLCH_CIS_5_3_3_2_4_STATE"
        [ "$value" = absent ] || printf 'maxrepeat = %s\n' "$value" > "$RLCH_CIS_5_3_3_2_4_CONF"
        run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
        result=0; apply || result=$?
        [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
        run validate; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
        run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
        result=0; rollback || result=$?
        [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
        if [ "$value" = absent ]; then [ ! -e "$RLCH_CIS_5_3_3_2_4_CONF" ]; else [ "$(cat "$RLCH_CIS_5_3_3_2_4_CONF")" = "maxrepeat = $value" ]; fi
    done
}

@test "vendor and administrator drop-ins merge by filename and main file wins" {
    mkdir -p "$RLCH_CIS_5_3_3_2_4_BASE.d" "$RLCH_CIS_5_3_3_2_4_CONF.d"
    printf 'maxrepeat = 4\n' > "$RLCH_CIS_5_3_3_2_4_BASE.d/10-base.conf"
    printf 'maxrepeat = 2\n' > "$RLCH_CIS_5_3_3_2_4_CONF.d/20-local.conf"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    printf 'maxrepeat = 0\n' > "$RLCH_CIS_5_3_3_2_4_BASE.d/20-local.conf"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    printf 'maxrepeat = 4\n' > "$RLCH_CIS_5_3_3_2_4_CONF"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
    printf 'maxrepeat = 3\n' > "$RLCH_CIS_5_3_3_2_4_CONF"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
}

@test "vendor main fallback and administrator main override" {
    printf 'maxrepeat = 2\n' > "$RLCH_CIS_5_3_3_2_4_BASE"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    printf '# local\n' > "$RLCH_CIS_5_3_3_2_4_CONF"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
}

@test "duplicate valid definitions use last value but unsafe replacement is refused" {
    printf 'maxrepeat = 2\nmaxrepeat = 4\n' > "$RLCH_CIS_5_3_3_2_4_CONF"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    [ ! -e "$RLCH_CIS_5_3_3_2_4_STATE" ]
    printf 'maxrepeat = 4\nmaxrepeat = 2\n' > "$RLCH_CIS_5_3_3_2_4_CONF"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
}

@test "malformed and unreadable path are errors" {
    printf 'maxrepeat = invalid\n' > "$RLCH_CIS_5_3_3_2_4_CONF"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    rm "$RLCH_CIS_5_3_3_2_4_CONF"
    ln -s "$RLCH_CIS_5_3_3_2_4_BASE" "$RLCH_CIS_5_3_3_2_4_CONF"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
}

@test "negative maxrepeat is outside the supported policy domain" {
    printf 'maxrepeat = -1\n' > "$RLCH_CIS_5_3_3_2_4_CONF"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    sed -i 's/retry=3/retry=3 maxrepeat=-1/' "$RLCH_CIS_5_3_3_2_4_PAM_DIR/system-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
}

@test "inline PAM overrides configuration and unsafe changes are refused" {
    printf 'maxrepeat = 4\n' > "$RLCH_CIS_5_3_3_2_4_CONF"
    for file in system-auth password-auth; do
        printf 'password requisite pam_pwquality.so maxrepeat=2\n' > "$RLCH_CIS_5_3_3_2_4_PAM_DIR/$file"
    done
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    sed -i 's/maxrepeat=2/maxrepeat=4/' "$RLCH_CIS_5_3_3_2_4_PAM_DIR/system-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    [ "$(cat "$RLCH_CIS_5_3_3_2_4_CONF")" = 'maxrepeat = 4' ]
    sed -i 's/maxrepeat=4/maxrepeat=0/' "$RLCH_CIS_5_3_3_2_4_PAM_DIR/system-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
}

@test "custom conf and duplicate inline options are errors" {
    sed -i 's/retry=3/retry=3 conf=\/other/' "$RLCH_CIS_5_3_3_2_4_PAM_DIR/system-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    sed -i 's@conf=/other@maxrepeat=3 maxrepeat=4@' "$RLCH_CIS_5_3_3_2_4_PAM_DIR/system-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    sed -i 's/maxrepeat=3 maxrepeat=4/maxrepeat=bad/' "$RLCH_CIS_5_3_3_2_4_PAM_DIR/system-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
}

@test "comments and spaces are parsed; inconsistent stacks are errors" {
    printf '# maxrepeat = 4\n maxrepeat  =  2 # administrator\n' > "$RLCH_CIS_5_3_3_2_4_CONF"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    printf '# missing hook\n' > "$RLCH_CIS_5_3_3_2_4_PAM_DIR/system-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
}

@test "rollback preserves unrelated settings and file metadata" {
    printf '# keep\ndifok = 2\nmaxrepeat = 4 # old\n' > "$RLCH_CIS_5_3_3_2_4_CONF"
    chmod 0600 "$RLCH_CIS_5_3_3_2_4_CONF"
    before="$(stat -c '%u:%g:%a' "$RLCH_CIS_5_3_3_2_4_CONF")"
    result=0; apply || result=$?
    [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    [ "$(stat -c '%u:%g:%a' "$RLCH_CIS_5_3_3_2_4_CONF")" = "$before" ]
    printf 'minlen = 14\n' >> "$RLCH_CIS_5_3_3_2_4_CONF"
    result=0; rollback || result=$?
    [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    [ "$(cat "$RLCH_CIS_5_3_3_2_4_CONF")" = "$(printf '# keep\ndifok = 2\nmaxrepeat = 4 # old\nminlen = 14')" ]
}

@test "rollback refuses administrator edit and keeps state" {
    result=0; apply || result=$?
    printf 'maxrepeat = 4\n' >> "$RLCH_CIS_5_3_3_2_4_CONF"
    run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    [ -f "$RLCH_CIS_5_3_3_2_4_STATE/original" ]
}

@test "rollback of a created file preserves later administrator settings" {
    result=0; apply || result=$?
    [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    printf 'difok = 2\n' >> "$RLCH_CIS_5_3_3_2_4_CONF"
    result=0; rollback || result=$?
    [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    [ "$(cat "$RLCH_CIS_5_3_3_2_4_CONF")" = 'difok = 2' ]
}

@test "failed post-write validation immediately restores prior state" {
    printf 'maxrepeat = 4\ndifok = 2\n' > "$RLCH_CIS_5_3_3_2_4_CONF"
    cat > "$RLCH_CIS_5_3_3_2_4_AUTHSELECT" <<'EOF'
#!/bin/sh
count_file="${RLCH_CIS_5_3_3_2_4_STATE}.calls"
count=0
if [ -f "$count_file" ]; then count="$(cat "$count_file")"; fi
count=$((count + 1))
printf '%s\n' "$count" > "$count_file"
[ "$count" -lt 2 ]
EOF
    result=0; apply || result=$?
    [ "$result" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    [ "$(cat "$RLCH_CIS_5_3_3_2_4_CONF")" = "$(printf 'maxrepeat = 4\ndifok = 2')" ]
    [ ! -e "$RLCH_CIS_5_3_3_2_4_STATE" ]
}

@test "authselect failure blocks all changes" {
    printf '#!/bin/sh\nexit 1\n' > "$RLCH_CIS_5_3_3_2_4_AUTHSELECT"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    [ ! -e "$RLCH_CIS_5_3_3_2_4_CONF" ]
}

@test "four pwquality controls preserve independent rollback state" {
    local path="${BATS_TEST_DIRNAME}/../modules/cis/5/3/3/2"
    local control
    for control in 1 2 3; do
        local prefix="RLCH_CIS_5_3_3_2_${control}"
        printf -v "${prefix}_CONF" '%s' "$RLCH_CIS_5_3_3_2_4_CONF"
        printf -v "${prefix}_BASE" '%s' "$RLCH_CIS_5_3_3_2_4_BASE"
        printf -v "${prefix}_PAM_DIR" '%s' "$RLCH_CIS_5_3_3_2_4_PAM_DIR"
        printf -v "${prefix}_AUTHSELECT" '%s' "$RLCH_CIS_5_3_3_2_4_AUTHSELECT"
        printf -v "${prefix}_STATE" '%s' "${BATS_TEST_TMPDIR}/state-${control}"
    done
    printf 'difok = 1\nminlen = 8\nminclass = 2\nmaxrepeat = 0\n' > "$RLCH_CIS_5_3_3_2_4_CONF"
    for control in 1 2 3 4; do
        source "$path/$control/module.sh"
        result=0; apply || result=$?
        [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    done
    for control in 1 2 3 4; do
        source "$path/$control/module.sh"
        run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    done
    source "$path/4/module.sh"
    result=0; rollback || result=$?
    [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    for control in 1 2 3; do
        source "$path/$control/module.sh"
        run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    done
    source "$path/4/module.sh"
    result=0; apply || result=$?
    [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    source "$path/2/module.sh"
    result=0; rollback || result=$?
    [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    source "$path/4/module.sh"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    [ "$(grep -c '^maxrepeat = 3' "$RLCH_CIS_5_3_3_2_4_CONF")" -eq 1 ]
}
