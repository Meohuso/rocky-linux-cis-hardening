#!/usr/bin/env bats
setup() {
    source "${BATS_TEST_DIRNAME}/test_helper.bash"
    source "${BATS_TEST_DIRNAME}/../lib/module_api.sh"
    export RLCH_CIS_5_4_1_4_LOGIN_DEFS="${BATS_TEST_TMPDIR}/login.defs"
    export RLCH_CIS_5_4_1_4_LIBUSER="${BATS_TEST_TMPDIR}/libuser.conf"
    export RLCH_CIS_5_4_1_4_RPM="${BATS_TEST_TMPDIR}/rpm"
    export RLCH_CIS_5_4_1_4_STATE="${BATS_TEST_TMPDIR}/state-hash"
    printf '# keep\nPASS_MAX_DAYS 365\nPASS_MIN_DAYS 1\nPASS_WARN_AGE 7\nENCRYPT_METHOD SHA512\n' > "$RLCH_CIS_5_4_1_4_LOGIN_DEFS"
    printf '# keep\n[defaults]\ncrypt_style = sha512\ncreate_modules = files\n[other]\ncrypt_style = md5\n' > "$RLCH_CIS_5_4_1_4_LIBUSER"
    printf '#!/bin/sh\n[ "$1" = -q ] && [ "$2" = --quiet ] && [ "$3" = libuser ] || exit 2\nexit "${RLCH_TEST_RPM_EXIT:-0}"\n' > "$RLCH_CIS_5_4_1_4_RPM"
    chmod +x "$RLCH_CIS_5_4_1_4_RPM"
    printf 'alice:$6$hash:20000:1:365:7:::\n' > "$BATS_TEST_TMPDIR/shadow"
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/4/1/4/module.sh"
}

id() { if [[ "${1:-}" == -u ]]; then printf '%s\n' "${RLCH_TEST_EUID:-0}"; else command id "$@"; fi; }

@test "metadata is manual for both Level 1 rules" {
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/4/1/4/metadata.conf"
    [ "$RLCH_MODULE_ID" = 5.4.1.4 ]
    [ "$RLCH_MODULE_LEVEL" = 1 ]
    [ "$RLCH_MODULE_OPENSCAP_RULE" = manual ]
}

@test "selected SHA512 and sha512 comply without mutation" {
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
}

@test "login.defs missing and alternative algorithms fail exact tailoring" {
    for value in sha512 SHA256 YESCRYPT MD5; do
        sed -i "s/^ENCRYPT_METHOD .*/ENCRYPT_METHOD $value/" "$RLCH_CIS_5_4_1_4_LOGIN_DEFS"
        run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
    done
    sed -i '/^ENCRYPT_METHOD/d' "$RLCH_CIS_5_4_1_4_LOGIN_DEFS"
    printf '# ENCRYPT_METHOD SHA512\n' >> "$RLCH_CIS_5_4_1_4_LOGIN_DEFS"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
}

@test "malformed and duplicate login defaults are errors" {
    printf 'ENCRYPT_METHOD\n' >> "$RLCH_CIS_5_4_1_4_LOGIN_DEFS"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    printf 'ENCRYPT_METHOD SHA512\nENCRYPT_METHOD SHA512\n' > "$RLCH_CIS_5_4_1_4_LOGIN_DEFS"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
}

@test "libuser package absent skips only libuser part" {
    export RLCH_TEST_RPM_EXIT=1
    rm "$RLCH_CIS_5_4_1_4_LIBUSER"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    sed -i 's/ENCRYPT_METHOD SHA512/ENCRYPT_METHOD YESCRYPT/' "$RLCH_CIS_5_4_1_4_LOGIN_DEFS"
    result=0; apply || result=$?
    [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    [ ! -e "$RLCH_CIS_5_4_1_4_LIBUSER" ]
    result=0; rollback || result=$?; [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
}

@test "rpm query failure is ERROR" {
    export RLCH_TEST_RPM_EXIT=2
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
}

@test "libuser wrong section, absent and weak property fail" {
    printf '[other]\ncrypt_style = sha512\n[defaults]\n' > "$RLCH_CIS_5_4_1_4_LIBUSER"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
    sed -i '$a crypt_style = md5' "$RLCH_CIS_5_4_1_4_LIBUSER"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
    sed -i 's/crypt_style = md5/crypt_style = sha512/' "$RLCH_CIS_5_4_1_4_LIBUSER"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
}

@test "libuser duplicates, malformed and wrong case are refused" {
    printf 'crypt_style = md5\n' >> "$RLCH_CIS_5_4_1_4_LIBUSER"
    # The second section is unrelated and may contain its own value.
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    sed -i '/\[other\]/i crypt_style = sha512' "$RLCH_CIS_5_4_1_4_LIBUSER"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    sed -i '/\[other\]/i crypt_style = broken=token' "$RLCH_CIS_5_4_1_4_LIBUSER"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    printf '[defaults]\ncrypt_style = SHA512\n' > "$RLCH_CIS_5_4_1_4_LIBUSER"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
    printf '[defaults]\ncrypt_style = sha512 # note\n' > "$RLCH_CIS_5_4_1_4_LIBUSER"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
}

@test "installed libuser missing file or section needs review and no partial login change" {
    sed -i 's/ENCRYPT_METHOD SHA512/ENCRYPT_METHOD MD5/' "$RLCH_CIS_5_4_1_4_LOGIN_DEFS"
    rm "$RLCH_CIS_5_4_1_4_LIBUSER"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    grep -q '^ENCRYPT_METHOD MD5$' "$RLCH_CIS_5_4_1_4_LOGIN_DEFS"
    printf '[other]\ncrypt_style = md5\n' > "$RLCH_CIS_5_4_1_4_LIBUSER"
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    [ ! -e "$RLCH_CIS_5_4_1_4_STATE" ]
}

@test "apply changes two properties while preserving file metadata and other sections" {
    sed -i 's/ENCRYPT_METHOD SHA512/ENCRYPT_METHOD YESCRYPT # old/' "$RLCH_CIS_5_4_1_4_LOGIN_DEFS"
    sed -i 's/^crypt_style = sha512$/crypt_style = md5 # old/' "$RLCH_CIS_5_4_1_4_LIBUSER"
    before_login="$(stat -c '%u:%g:%a' "$RLCH_CIS_5_4_1_4_LOGIN_DEFS")"
    before_lib="$(stat -c '%u:%g:%a' "$RLCH_CIS_5_4_1_4_LIBUSER")"
    result=0; apply || result=$?; [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    [ "$(stat -c '%u:%g:%a' "$RLCH_CIS_5_4_1_4_LOGIN_DEFS")" = "$before_login" ]
    [ "$(stat -c '%u:%g:%a' "$RLCH_CIS_5_4_1_4_LIBUSER")" = "$before_lib" ]
    printf 'UMASK 077\n' >> "$RLCH_CIS_5_4_1_4_LOGIN_DEFS"
    printf 'other = yes\n' >> "$RLCH_CIS_5_4_1_4_LIBUSER"
    result=0; rollback || result=$?; [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    grep -q '^ENCRYPT_METHOD YESCRYPT # old$' "$RLCH_CIS_5_4_1_4_LOGIN_DEFS"
    grep -q '^crypt_style = md5 # old$' "$RLCH_CIS_5_4_1_4_LIBUSER"
    grep -q '^UMASK 077$' "$RLCH_CIS_5_4_1_4_LOGIN_DEFS"
    grep -q '^other = yes$' "$RLCH_CIS_5_4_1_4_LIBUSER"
    [ "$(cat "$BATS_TEST_TMPDIR/shadow")" = 'alice:$6$hash:20000:1:365:7:::' ]
}

@test "missing crypt_style in existing defaults can be added then removed" {
    sed -i '/^crypt_style = sha512$/d' "$RLCH_CIS_5_4_1_4_LIBUSER"
    result=0; apply || result=$?; [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    result=0; rollback || result=$?; [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    [ "$(awk '/\[defaults\]/ {a=1;next} /\[other\]/ {a=0} a && /crypt_style/ {n++} END {print n+0}' "$RLCH_CIS_5_4_1_4_LIBUSER")" = 0 ]
}

@test "concurrent managed changes block rollback without overwriting either file" {
    sed -i 's/ENCRYPT_METHOD SHA512/ENCRYPT_METHOD MD5/' "$RLCH_CIS_5_4_1_4_LOGIN_DEFS"
    sed -i 's/^crypt_style = sha512$/crypt_style = md5/' "$RLCH_CIS_5_4_1_4_LIBUSER"
    result=0; apply || result=$?; [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    sed -i 's/^crypt_style = sha512$/crypt_style = yescrypt/' "$RLCH_CIS_5_4_1_4_LIBUSER"
    run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    grep -q '^ENCRYPT_METHOD SHA512 # rlch' "$RLCH_CIS_5_4_1_4_LOGIN_DEFS"
    sed -i 's/^crypt_style = yescrypt$/crypt_style = sha512/' "$RLCH_CIS_5_4_1_4_LIBUSER"
    sed -i 's/^ENCRYPT_METHOD SHA512 # rlch/ENCRYPT_METHOD SHA256 # rlch/' "$RLCH_CIS_5_4_1_4_LOGIN_DEFS"
    run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    [ -d "$RLCH_CIS_5_4_1_4_STATE" ]
}

@test "symlink and non-root refuse mutation" {
    sed -i 's/ENCRYPT_METHOD SHA512/ENCRYPT_METHOD MD5/' "$RLCH_CIS_5_4_1_4_LOGIN_DEFS"
    RLCH_TEST_EUID=1000
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    RLCH_TEST_EUID=0
    mv "$RLCH_CIS_5_4_1_4_LIBUSER" "$BATS_TEST_TMPDIR/real"
    ln -s "$BATS_TEST_TMPDIR/real" "$RLCH_CIS_5_4_1_4_LIBUSER"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    [ ! -e "$RLCH_CIS_5_4_1_4_STATE" ]
}

@test "failed post-write validation restores both defaults immediately" {
    sed -i 's/ENCRYPT_METHOD SHA512/ENCRYPT_METHOD MD5/' "$RLCH_CIS_5_4_1_4_LOGIN_DEFS"
    sed -i 's/^crypt_style = sha512$/crypt_style = md5/' "$RLCH_CIS_5_4_1_4_LIBUSER"
    eval "$(declare -f check | sed '1s/check/real_check/')"
    RLCH_TEST_CHECK_COUNT=0
    check() { RLCH_TEST_CHECK_COUNT=$((RLCH_TEST_CHECK_COUNT + 1)); if [ "$RLCH_TEST_CHECK_COUNT" -eq 2 ]; then return "$RLCH_MODULE_RESULT_ERROR"; fi; real_check; }
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    grep -q '^ENCRYPT_METHOD MD5$' "$RLCH_CIS_5_4_1_4_LOGIN_DEFS"
    grep -q '^crypt_style = md5$' "$RLCH_CIS_5_4_1_4_LIBUSER"
    [ ! -e "$RLCH_CIS_5_4_1_4_STATE" ]
}

@test "previous max/warn controls remain compliant and PAM files are untouched" {
    RLCH_CIS_5_4_1_1_LOGIN_DEFS="$RLCH_CIS_5_4_1_4_LOGIN_DEFS"
    RLCH_CIS_5_4_1_1_SHADOW="$BATS_TEST_TMPDIR/shadow"
    RLCH_CIS_5_4_1_3_LOGIN_DEFS="$RLCH_CIS_5_4_1_4_LOGIN_DEFS"
    RLCH_CIS_5_4_1_3_SHADOW="$BATS_TEST_TMPDIR/shadow"
    RLCH_CIS_5_3_3_4_3_AUTHSELECT="$BATS_TEST_TMPDIR/authselect"
    RLCH_CIS_5_3_3_4_3_PAM_DIR="$BATS_TEST_TMPDIR/pam.d"
    printf '#!/bin/sh\nexit 0\n' > "$RLCH_CIS_5_3_3_4_3_AUTHSELECT"
    chmod +x "$RLCH_CIS_5_3_3_4_3_AUTHSELECT"
    mkdir -p "$RLCH_CIS_5_3_3_4_3_PAM_DIR"
    for file in system-auth password-auth; do printf 'password sufficient pam_unix.so sha512 shadow\n' > "$RLCH_CIS_5_3_3_4_3_PAM_DIR/$file"; done
    pam_before="$(cat "$RLCH_CIS_5_3_3_4_3_PAM_DIR/system-auth")"
    sed -i 's/ENCRYPT_METHOD SHA512/ENCRYPT_METHOD MD5/' "$RLCH_CIS_5_4_1_4_LOGIN_DEFS"
    result=0; apply || result=$?; [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/4/1/1/module.sh"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/4/1/3/module.sh"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/3/3/4/3/module.sh"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    [ "$(cat "$RLCH_CIS_5_3_3_4_3_PAM_DIR/system-auth")" = "$pam_before" ]
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/4/1/4/module.sh"
    result=0; rollback || result=$?; [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
}

@test "all three login defaults apply sequentially and hashing rollback preserves aging" {
    RLCH_CIS_5_4_1_1_LOGIN_DEFS="$RLCH_CIS_5_4_1_4_LOGIN_DEFS"
    RLCH_CIS_5_4_1_1_SHADOW="$BATS_TEST_TMPDIR/shadow"
    RLCH_CIS_5_4_1_1_CHAGE="$BATS_TEST_TMPDIR/chage"
    RLCH_CIS_5_4_1_1_STATE="$BATS_TEST_TMPDIR/state-max"
    RLCH_CIS_5_4_1_3_LOGIN_DEFS="$RLCH_CIS_5_4_1_4_LOGIN_DEFS"
    RLCH_CIS_5_4_1_3_SHADOW="$BATS_TEST_TMPDIR/shadow"
    RLCH_CIS_5_4_1_3_CHAGE="$BATS_TEST_TMPDIR/chage"
    RLCH_CIS_5_4_1_3_STATE="$BATS_TEST_TMPDIR/state-warn"
    export RLCH_CIS_5_4_1_1_SHADOW
    cat > "$BATS_TEST_TMPDIR/chage" <<'EOF'
#!/usr/bin/env bash
case "$1" in -M) field=5;; --warndays) field=6;; *) exit 2;; esac
temp="${RLCH_CIS_5_4_1_1_SHADOW}.new"
awk -F: -v OFS=: -v field="$field" -v value="$2" -v account="$3" '$1==account {$field=value; found=1} {print} END {if (!found) exit 1}' "$RLCH_CIS_5_4_1_1_SHADOW" > "$temp" || exit 1
mv "$temp" "$RLCH_CIS_5_4_1_1_SHADOW"
EOF
    chmod +x "$BATS_TEST_TMPDIR/chage"
    sed -i 's/PASS_MAX_DAYS 365/PASS_MAX_DAYS 99999/;s/PASS_WARN_AGE 7/PASS_WARN_AGE 0/;s/ENCRYPT_METHOD SHA512/ENCRYPT_METHOD MD5/' "$RLCH_CIS_5_4_1_4_LOGIN_DEFS"
    sed -i '1s/:365:7:/:99999:0:/' "$BATS_TEST_TMPDIR/shadow"
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/4/1/1/module.sh"
    result=0; apply || result=$?; [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/4/1/3/module.sh"
    result=0; apply || result=$?; [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/4/1/4/module.sh"
    result=0; apply || result=$?; [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    result=0; rollback || result=$?; [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/4/1/1/module.sh"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/4/1/3/module.sh"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    [ "$(awk -F: '$1=="alice" {print $5 ":" $6}' "$BATS_TEST_TMPDIR/shadow")" = '365:7' ]
}
