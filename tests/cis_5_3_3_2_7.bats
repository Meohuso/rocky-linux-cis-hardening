#!/usr/bin/env bats
setup() {
    source "${BATS_TEST_DIRNAME}/test_helper.bash"
    source "${BATS_TEST_DIRNAME}/../lib/module_api.sh"
    export RLCH_CIS_5_3_3_2_7_CONF="${BATS_TEST_TMPDIR}/etc/pwquality.conf"
    export RLCH_CIS_5_3_3_2_7_BASE="${BATS_TEST_TMPDIR}/usr/pwquality.conf"
    export RLCH_CIS_5_3_3_2_7_PAM_DIR="${BATS_TEST_TMPDIR}/pam.d"
    export RLCH_CIS_5_3_3_2_7_AUTHSELECT="${BATS_TEST_TMPDIR}/authselect"
    export RLCH_CIS_5_3_3_2_7_STATE="${BATS_TEST_TMPDIR}/state"
    mkdir -p "${BATS_TEST_TMPDIR}/etc" "${BATS_TEST_TMPDIR}/usr" "$RLCH_CIS_5_3_3_2_7_PAM_DIR"
    printf '#!/bin/sh\nexit "${RLCH_TEST_AUTHSELECT_EXIT:-0}"\n' > "$RLCH_CIS_5_3_3_2_7_AUTHSELECT"
    chmod +x "$RLCH_CIS_5_3_3_2_7_AUTHSELECT"
    for file in system-auth password-auth; do
        printf 'password requisite pam_pwquality.so retry=3\n' > "$RLCH_CIS_5_3_3_2_7_PAM_DIR/$file"
    done
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/3/3/2/7/module.sh"
}

@test "metadata has exact Level 1 rule" {
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/3/3/2/7/metadata.conf"
    [ "$RLCH_MODULE_ID" = 5.3.3.2.7 ]
    [ "$RLCH_MODULE_LEVEL" = 1 ]
    [ "$RLCH_MODULE_OPENSCAP_RULE" = xccdf_org.ssgproject.content_rule_accounts_password_pam_enforce_root ]
}

@test "missing and commented flags fail; canonical whitespace and duplicates pass" {
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
    printf '# enforce_for_root\n' > "$RLCH_CIS_5_3_3_2_7_CONF"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
    printf '  enforce_for_root  # existing\nenforce_for_root\n' > "$RLCH_CIS_5_3_3_2_7_CONF"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    [ ! -e "$RLCH_CIS_5_3_3_2_7_STATE" ]
}

@test "noncanonical equals values and malformed tails are errors" {
    for line in 'enforce_for_root=0' 'enforce_for_root = 1' 'enforce_for_root=anything' 'enforce_for_root junk'; do
        printf '%s\n' "$line" > "$RLCH_CIS_5_3_3_2_7_CONF"
        run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
        run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    done
}

@test "vendor-only flag is insufficient; administrator drop-in is an explicit witness" {
    mkdir -p "$RLCH_CIS_5_3_3_2_7_BASE.d" "$RLCH_CIS_5_3_3_2_7_CONF.d"
    printf 'enforce_for_root\n' > "$RLCH_CIS_5_3_3_2_7_BASE.d/10-base.conf"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
    printf 'enforce_for_root\n' > "$RLCH_CIS_5_3_3_2_7_CONF.d/20-admin.conf"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    printf '# override vendor\n' > "$RLCH_CIS_5_3_3_2_7_CONF.d/10-base.conf"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    rm "$RLCH_CIS_5_3_3_2_7_CONF.d/20-admin.conf"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
}

@test "vendor main fallback does not satisfy administrator requirement" {
    printf 'enforce_for_root\n' > "$RLCH_CIS_5_3_3_2_7_BASE"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
    printf 'enforce_for_root\n' > "$RLCH_CIS_5_3_3_2_7_CONF"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
}

@test "unsafe configuration paths fail closed" {
    ln -s "$RLCH_CIS_5_3_3_2_7_BASE" "$RLCH_CIS_5_3_3_2_7_CONF"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    rm "$RLCH_CIS_5_3_3_2_7_CONF"
    mkdir "$RLCH_CIS_5_3_3_2_7_CONF.d"
    ln -s "$RLCH_CIS_5_3_3_2_7_BASE" "$RLCH_CIS_5_3_3_2_7_CONF.d/20.conf"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
}

@test "unterminated administrator file is left unchanged" {
    printf 'difok = 2' > "$RLCH_CIS_5_3_3_2_7_CONF"
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    [ "$(cat "$RLCH_CIS_5_3_3_2_7_CONF")" = 'difok = 2' ]
    [ ! -e "$RLCH_CIS_5_3_3_2_7_STATE" ]
}

@test "PAM inline presence does not replace configuration; conf and ambiguous inline fail" {
    sed -i 's/retry=3/retry=3 enforce_for_root/' "$RLCH_CIS_5_3_3_2_7_PAM_DIR/system-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
    printf 'enforce_for_root\n' > "$RLCH_CIS_5_3_3_2_7_CONF"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    sed -i 's/enforce_for_root/enforce_for_root=0/' "$RLCH_CIS_5_3_3_2_7_PAM_DIR/system-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    sed -i 's/enforce_for_root=0/conf=\/custom/' "$RLCH_CIS_5_3_3_2_7_PAM_DIR/system-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
}

@test "invalid authselect refuses changes" {
    printf '#!/bin/sh\nexit 1\n' > "$RLCH_CIS_5_3_3_2_7_AUTHSELECT"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    [ ! -e "$RLCH_CIS_5_3_3_2_7_CONF" ]
}

@test "apply is idempotent and rollback preserves metadata and unrelated changes" {
    printf '# keep\ndifok = 2\n' > "$RLCH_CIS_5_3_3_2_7_CONF"
    chmod 0600 "$RLCH_CIS_5_3_3_2_7_CONF"
    before="$(stat -c '%u:%g:%a' "$RLCH_CIS_5_3_3_2_7_CONF")"
    result=0; apply || result=$?
    [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    [ "$(stat -c '%u:%g:%a' "$RLCH_CIS_5_3_3_2_7_CONF")" = "$before" ]
    printf 'minlen = 14\n' >> "$RLCH_CIS_5_3_3_2_7_CONF"
    result=0; rollback || result=$?
    [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    [ "$(cat "$RLCH_CIS_5_3_3_2_7_CONF")" = "$(printf '# keep\ndifok = 2\nminlen = 14')" ]
}

@test "rollback detects a concurrent edit of its directive and keeps state" {
    result=0; apply || result=$?
    sed -i 's/^enforce_for_root$/enforce_for_root=0/' "$RLCH_CIS_5_3_3_2_7_CONF"
    run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    [ -f "$RLCH_CIS_5_3_3_2_7_STATE/file" ]
}

@test "initially absent file is removed only when no other data was added" {
    result=0; apply || result=$?
    result=0; rollback || result=$?
    [ ! -e "$RLCH_CIS_5_3_3_2_7_CONF" ]
    result=0; apply || result=$?
    printf 'dictcheck = 1\n' >> "$RLCH_CIS_5_3_3_2_7_CONF"
    result=0; rollback || result=$?
    [ "$(cat "$RLCH_CIS_5_3_3_2_7_CONF")" = 'dictcheck = 1' ]
}

@test "post-write failure immediately restores the original file" {
    printf 'difok = 2\n' > "$RLCH_CIS_5_3_3_2_7_CONF"
    cat > "$RLCH_CIS_5_3_3_2_7_AUTHSELECT" <<'EOF'
#!/bin/sh
count_file="${RLCH_CIS_5_3_3_2_7_STATE}.calls"
count=0
if [ -f "$count_file" ]; then count="$(cat "$count_file")"; fi
count=$((count + 1))
printf '%s\n' "$count" > "$count_file"
[ "$count" -lt 2 ]
EOF
    result=0; apply || result=$?
    [ "$result" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    [ "$(cat "$RLCH_CIS_5_3_3_2_7_CONF")" = 'difok = 2' ]
    [ ! -e "$RLCH_CIS_5_3_3_2_7_STATE" ]
}

@test "seven controls coexist and independent rollbacks preserve each other's settings" {
    local path="${BATS_TEST_DIRNAME}/../modules/cis/5/3/3/2" control prefix
    for control in 1 2 3 4 5 6; do
        prefix="RLCH_CIS_5_3_3_2_${control}"
        printf -v "${prefix}_CONF" '%s' "$RLCH_CIS_5_3_3_2_7_CONF"
        printf -v "${prefix}_BASE" '%s' "$RLCH_CIS_5_3_3_2_7_BASE"
        printf -v "${prefix}_PAM_DIR" '%s' "$RLCH_CIS_5_3_3_2_7_PAM_DIR"
        printf -v "${prefix}_AUTHSELECT" '%s' "$RLCH_CIS_5_3_3_2_7_AUTHSELECT"
        printf -v "${prefix}_STATE" '%s' "${BATS_TEST_TMPDIR}/state-${control}"
    done
    printf 'difok = 1\nminlen = 8\nminclass = 2\nmaxrepeat = 0\nmaxsequence = 0\ndictcheck = 0\n' > "$RLCH_CIS_5_3_3_2_7_CONF"
    for control in 1 2 3 4 5 6 7; do
        source "$path/$control/module.sh"
        result=0; apply || result=$?
        [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    done
    for control in 1 2 3 4 5 6 7; do
        source "$path/$control/module.sh"
        run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    done
    source "$path/7/module.sh"
    result=0; rollback || result=$?
    [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    for control in 1 2 3 4 5 6; do
        source "$path/$control/module.sh"
        run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    done
    source "$path/7/module.sh"
    result=0; apply || result=$?
    [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    source "$path/4/module.sh"
    result=0; rollback || result=$?
    [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    source "$path/7/module.sh"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
}
