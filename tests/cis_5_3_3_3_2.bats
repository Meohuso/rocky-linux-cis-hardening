#!/usr/bin/env bats
setup() {
    source "${BATS_TEST_DIRNAME}/test_helper.bash"
    source "${BATS_TEST_DIRNAME}/../lib/module_api.sh"
    export RLCH_CIS_5_3_3_3_2_CONF="${BATS_TEST_TMPDIR}/security/pwhistory.conf"
    export RLCH_CIS_5_3_3_3_2_BASE="${BATS_TEST_TMPDIR}/vendor/pwhistory.conf"
    export RLCH_CIS_5_3_3_3_2_PAM_DIR="${BATS_TEST_TMPDIR}/pam.d"
    export RLCH_CIS_5_3_3_3_2_AUTHSELECT="${BATS_TEST_TMPDIR}/authselect"
    export RLCH_CIS_5_3_3_3_2_STATE="${BATS_TEST_TMPDIR}/state-2"
    mkdir -p "${BATS_TEST_TMPDIR}/security" "${BATS_TEST_TMPDIR}/vendor" "$RLCH_CIS_5_3_3_3_2_PAM_DIR"
    printf '#!/bin/sh\nexit "${RLCH_TEST_AUTHSELECT_EXIT:-0}"\n' > "$RLCH_CIS_5_3_3_3_2_AUTHSELECT"
    chmod +x "$RLCH_CIS_5_3_3_3_2_AUTHSELECT"
    for file in system-auth password-auth; do
        printf 'password requisite pam_pwhistory.so use_authtok\n' > "$RLCH_CIS_5_3_3_3_2_PAM_DIR/$file"
    done
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/3/3/3/2/module.sh"
}

@test "exact metadata identifies the Level 1 primary rule" {
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/3/3/3/2/metadata.conf"
    [ "$RLCH_MODULE_ID" = 5.3.3.3.2 ]
    [ "$RLCH_MODULE_LEVEL" = 1 ]
    [ "$RLCH_MODULE_OPENSCAP_RULE" = xccdf_org.ssgproject.content_rule_accounts_password_pam_pwhistory_enforce_for_root ]
}

@test "absent and commented are findings, canonical spaces and duplicates comply" {
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
    printf '# enforce_for_root\n' > "$RLCH_CIS_5_3_3_3_2_CONF"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
    printf '  enforce_for_root # existing\nenforce_for_root\n' > "$RLCH_CIS_5_3_3_3_2_CONF"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    [ ! -e "$RLCH_CIS_5_3_3_3_2_STATE" ]
}

@test "equals forms and extra tokens are unsafe even if runtime may set flag" {
    for line in 'enforce_for_root=0' 'enforce_for_root=1' 'enforce_for_root = 1' 'enforce_for_root extra'; do
        printf '%s\n' "$line" > "$RLCH_CIS_5_3_3_3_2_CONF"
        run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
        run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    done
}

@test "vendor fallback is runtime active but insufficient as CIS administrator witness" {
    printf 'enforce_for_root\n' > "$RLCH_CIS_5_3_3_3_2_BASE"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
    printf 'enforce_for_root\n' > "$RLCH_CIS_5_3_3_3_2_CONF"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
}

@test "inline PAM flag alone is insufficient, malformed inline and custom conf fail" {
    sed -i 's/use_authtok/enforce_for_root use_authtok/' "$RLCH_CIS_5_3_3_3_2_PAM_DIR/system-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
    printf 'enforce_for_root\n' > "$RLCH_CIS_5_3_3_3_2_CONF"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    sed -i 's/enforce_for_root /enforce_for_root=0 /' "$RLCH_CIS_5_3_3_3_2_PAM_DIR/system-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    sed -i 's/enforce_for_root=0/conf=\/custom/' "$RLCH_CIS_5_3_3_3_2_PAM_DIR/system-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
}

@test "invalid authselect or symlink blocks correction" {
    printf '#!/bin/sh\nexit 1\n' > "$RLCH_CIS_5_3_3_3_2_AUTHSELECT"
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    printf '#!/bin/sh\nexit 0\n' > "$RLCH_CIS_5_3_3_3_2_AUTHSELECT"
    ln -s "$RLCH_CIS_5_3_3_3_2_BASE" "$RLCH_CIS_5_3_3_3_2_CONF"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
}

@test "apply and rollback preserve remember and file metadata" {
    printf '# keep\nremember = 30\nretry = 3\nfile = /tmp/opasswd\n' > "$RLCH_CIS_5_3_3_3_2_CONF"
    chmod 0600 "$RLCH_CIS_5_3_3_3_2_CONF"
    before="$(stat -c '%u:%g:%a' "$RLCH_CIS_5_3_3_3_2_CONF")"
    result=0; apply || result=$?
    [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    [ "$(stat -c '%u:%g:%a' "$RLCH_CIS_5_3_3_3_2_CONF")" = "$before" ]
    printf 'remember = 35\n' >> "$RLCH_CIS_5_3_3_3_2_CONF"
    result=0; rollback || result=$?
    [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    [ "$(cat "$RLCH_CIS_5_3_3_3_2_CONF")" = "$(printf '# keep\nremember = 30\nretry = 3\nfile = /tmp/opasswd\nremember = 35')" ]
}

@test "concurrent edit to managed flag refuses rollback and retains state" {
    result=0; apply || result=$?
    sed -i 's/^enforce_for_root$/enforce_for_root=0/' "$RLCH_CIS_5_3_3_3_2_CONF"
    run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    [ -f "$RLCH_CIS_5_3_3_3_2_STATE/file" ]
}

@test "new file is removed only if no independent properties have been added" {
    result=0; apply || result=$?
    result=0; rollback || result=$?
    [ ! -e "$RLCH_CIS_5_3_3_3_2_CONF" ]
    result=0; apply || result=$?
    printf 'remember = 24\n' >> "$RLCH_CIS_5_3_3_3_2_CONF"
    result=0; rollback || result=$?
    [ "$(cat "$RLCH_CIS_5_3_3_3_2_CONF")" = 'remember = 24' ]
}

@test "post-write failure immediately restores original data" {
    printf 'remember = 24\n' > "$RLCH_CIS_5_3_3_3_2_CONF"
    cat > "$RLCH_CIS_5_3_3_3_2_AUTHSELECT" <<'EOF'
#!/bin/sh
file="${RLCH_CIS_5_3_3_3_2_STATE}.calls"
count=0
if [ -f "$file" ]; then count="$(cat "$file")"; fi
count=$((count + 1)); printf '%s\n' "$count" > "$file"
[ "$count" -lt 2 ]
EOF
    result=0; apply || result=$?
    [ "$result" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    [ "$(cat "$RLCH_CIS_5_3_3_3_2_CONF")" = 'remember = 24' ]
    [ ! -e "$RLCH_CIS_5_3_3_3_2_STATE" ]
}

@test "remember and root flag rollbacks are independent in both directions" {
    local path="${BATS_TEST_DIRNAME}/../modules/cis/5/3/3/3"
    RLCH_CIS_5_3_3_3_1_CONF="$RLCH_CIS_5_3_3_3_2_CONF"
    RLCH_CIS_5_3_3_3_1_PAM_DIR="$RLCH_CIS_5_3_3_3_2_PAM_DIR"
    RLCH_CIS_5_3_3_3_1_AUTHSELECT="$RLCH_CIS_5_3_3_3_2_AUTHSELECT"
    RLCH_CIS_5_3_3_3_1_STATE="${BATS_TEST_TMPDIR}/state-1"
    source "$path/1/module.sh"
    result=0; apply || result=$?
    [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    source "$path/2/module.sh"
    result=0; apply || result=$?
    [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    for control in 1 2; do
        source "$path/$control/module.sh"
        run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    done
    source "$path/2/module.sh"
    result=0; rollback || result=$?
    source "$path/1/module.sh"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    source "$path/2/module.sh"
    result=0; apply || result=$?
    source "$path/1/module.sh"
    result=0; rollback || result=$?
    source "$path/2/module.sh"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
}
