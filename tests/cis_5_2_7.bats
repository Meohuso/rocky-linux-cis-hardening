#!/usr/bin/env bats
setup() {
    source "${BATS_TEST_DIRNAME}/test_helper.bash"
    source "${BATS_TEST_DIRNAME}/../lib/module_api.sh"
    export RLCH_CIS_5_2_7_PAM_FILE="${BATS_TEST_TMPDIR}/su"
    export RLCH_CIS_5_2_7_STATE_DIR="${BATS_TEST_TMPDIR}/state"
    export RLCH_TEST_GROUP="${BATS_TEST_TMPDIR}/group"
    export RLCH_TEST_PASSWD="${BATS_TEST_TMPDIR}/passwd"
    export RLCH_TEST_LOG="${BATS_TEST_TMPDIR}/commands.log"
    mkdir -p "${BATS_TEST_TMPDIR}/bin"
    export RLCH_CIS_5_2_7_GETENT="${BATS_TEST_TMPDIR}/bin/getent"
    export RLCH_CIS_5_2_7_GROUPADD="${BATS_TEST_TMPDIR}/bin/groupadd"
    export RLCH_CIS_5_2_7_GROUPDEL="${BATS_TEST_TMPDIR}/bin/groupdel"
    export RLCH_CIS_5_2_7_ID="${BATS_TEST_TMPDIR}/bin/id"
    printf 'auth sufficient pam_rootok.so\nauth substack system-auth\naccount include system-auth\n' > "${RLCH_CIS_5_2_7_PAM_FILE}"
    : > "${RLCH_TEST_GROUP}"
    : > "${RLCH_TEST_PASSWD}"
    cat > "${RLCH_CIS_5_2_7_GETENT}" <<'EOF'
#!/usr/bin/env bash
if [[ "$1" == group ]]; then
    entry="$(grep -E "^$2:" "$RLCH_TEST_GROUP")"
    [[ -n "$entry" ]] || exit 2
    printf '%s\n' "$entry"
else
    cat "$RLCH_TEST_PASSWD"
fi
EOF
    cat > "${RLCH_CIS_5_2_7_GROUPADD}" <<'EOF'
#!/usr/bin/env bash
[[ "${RLCH_TEST_GROUPADD_FAIL:-}" != 1 ]] || exit 1
printf 'add %s\n' "$1" >> "$RLCH_TEST_LOG"
printf '%s:x:12345:\n' "$1" >> "$RLCH_TEST_GROUP"
EOF
    cat > "${RLCH_CIS_5_2_7_GROUPDEL}" <<'EOF'
#!/usr/bin/env bash
printf 'del %s\n' "$1" >> "$RLCH_TEST_LOG"
sed -i "/^$1:/d" "$RLCH_TEST_GROUP"
EOF
    cat > "${RLCH_CIS_5_2_7_ID}" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "${RLCH_TEST_UID:-0}"
EOF
    chmod +x "${BATS_TEST_TMPDIR}/bin/"*
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/2/7/module.sh"
}

@test "check requires an empty sugroup and active exact PAM rule" {
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
    printf 'sugroup:x:12345:\n' > "$RLCH_TEST_GROUP"
    printf 'auth required pam_wheel.so use_uid group=sugroup\n' >> "$RLCH_CIS_5_2_7_PAM_FILE"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
}

@test "check rejects supplementary and primary group members" {
    printf 'sugroup:x:12345:admin\n' > "$RLCH_TEST_GROUP"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
    printf 'sugroup:x:12345:\n' > "$RLCH_TEST_GROUP"
    printf 'admin:x:1000:12345::/home/admin:/bin/bash\n' > "$RLCH_TEST_PASSWD"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
}

@test "pre-existing populated group is never changed" {
    printf 'sugroup:x:12345:admin\n' > "$RLCH_TEST_GROUP"
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
    [ "$(cat "$RLCH_TEST_GROUP")" = 'sugroup:x:12345:admin' ]
    [ ! -s "$RLCH_TEST_LOG" ]
    [ ! -e "$RLCH_CIS_5_2_7_STATE_DIR" ]
}

@test "existing wheel membership is untouched" {
    printf 'sugroup:x:12345:\nwheel:x:10:admin\n' > "$RLCH_TEST_GROUP"
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    [ "$(tail -1 "$RLCH_TEST_GROUP")" = 'wheel:x:10:admin' ]
    [ ! -s "$RLCH_TEST_LOG" ]
}

@test "apply inserts rule before the existing auth stack preserving all lines" {
    local before result=0
    before="$(cat "$RLCH_CIS_5_2_7_PAM_FILE")"
    apply || result=$?
    [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    [ "$(sed -n '1p' "$RLCH_CIS_5_2_7_PAM_FILE")" = 'auth sufficient pam_rootok.so' ]
    [ "$(sed -n '2p' "$RLCH_CIS_5_2_7_PAM_FILE")" = 'auth required pam_wheel.so use_uid group=sugroup' ]
    [ "$(sed -n '3,$p' "$RLCH_CIS_5_2_7_PAM_FILE")" = "$(printf '%s\n' "$before" | sed -n '2,$p')" ]
    [ -f "$RLCH_CIS_5_2_7_STATE_DIR/created.gid" ]
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
}

@test "pre-existing empty group is preserved on rollback" {
    printf 'sugroup:x:12345:\n' > "$RLCH_TEST_GROUP"
    local original result=0
    original="$(cat "$RLCH_CIS_5_2_7_PAM_FILE")"
    apply || result=$?; [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    [ ! -e "$RLCH_CIS_5_2_7_STATE_DIR/created.gid" ]
    result=0; rollback || result=$?; [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    [ "$(cat "$RLCH_TEST_GROUP")" = 'sugroup:x:12345:' ]
    [ "$(cat "$RLCH_CIS_5_2_7_PAM_FILE")" = "$original" ]
    [ ! -s "$RLCH_TEST_LOG" ]
}

@test "rollback removes only a group created by this control" {
    local original result=0
    original="$(cat "$RLCH_CIS_5_2_7_PAM_FILE")"
    apply || result=$?; [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    result=0; rollback || result=$?; [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    [ ! -s "$RLCH_TEST_GROUP" ]
    [ "$(cat "$RLCH_CIS_5_2_7_PAM_FILE")" = "$original" ]
    [ "$(cat "$RLCH_TEST_LOG")" = $'add sugroup\ndel sugroup' ]
    run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
}

@test "rollback refuses to overwrite subsequent PAM edits" {
    local result=0
    apply || result=$?; [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    printf '# administrator change\n' >> "$RLCH_CIS_5_2_7_PAM_FILE"
    run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    [ -s "$RLCH_TEST_GROUP" ]
    [ -f "$RLCH_CIS_5_2_7_STATE_DIR/pam.original" ]
}

@test "rollback refuses to delete a created group that acquired members" {
    local result=0
    apply || result=$?; [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    printf 'sugroup:x:12345:admin\n' > "$RLCH_TEST_GROUP"
    run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    [ "$(cat "$RLCH_TEST_GROUP")" = 'sugroup:x:12345:admin' ]
}

@test "ambiguous active PAM rule is left untouched" {
    printf 'auth required pam_wheel.so use_uid group=wheel\n' >> "$RLCH_CIS_5_2_7_PAM_FILE"
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    [ ! -s "$RLCH_TEST_GROUP" ]
    [ ! -e "$RLCH_CIS_5_2_7_STATE_DIR" ]
}

@test "complex PAM control flag does not hide a competing wheel rule" {
    printf 'auth [success=1 default=ignore] pam_wheel.so use_uid group=wheel\n' >> "$RLCH_CIS_5_2_7_PAM_FILE"
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    [ ! -s "$RLCH_TEST_GROUP" ]
}

@test "the separate group named cis and its members are never modified" {
    printf 'cis:x:123:admin\n' > "$RLCH_TEST_GROUP"
    local result=0
    apply || result=$?; [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    [ "$(head -1 "$RLCH_TEST_GROUP")" = 'cis:x:123:admin' ]
    result=0; rollback || result=$?; [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    [ "$(cat "$RLCH_TEST_GROUP")" = 'cis:x:123:admin' ]
}

@test "rollback refuses to delete a replacement group with another gid" {
    local result=0
    apply || result=$?; [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    printf 'sugroup:x:99999:\n' > "$RLCH_TEST_GROUP"
    run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    [ "$(cat "$RLCH_TEST_GROUP")" = 'sugroup:x:99999:' ]
}

@test "failure to create the group preserves PAM" {
    export RLCH_TEST_GROUPADD_FAIL=1
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    [ ! -s "$RLCH_TEST_GROUP" ]
    [ ! -e "$RLCH_CIS_5_2_7_STATE_DIR" ]
}

@test "apply requires root; validate delegates to check" {
    export RLCH_TEST_UID=1000
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    run validate; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
}

@test "metadata records composite mapping as manual" {
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/2/7/metadata.conf"
    [ "$RLCH_MODULE_ID" = 5.2.7 ]
    [ "$RLCH_MODULE_OPENSCAP_RULE" = manual ]
}
