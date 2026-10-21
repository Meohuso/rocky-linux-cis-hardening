#!/usr/bin/env bats
# shellcheck source-path=SCRIPTDIR
# shellcheck disable=SC2317 # Fault injection through sourced APIs.
# shellcheck disable=SC2030,SC2031 # Bats isolates tests; run sets status/output.
# shellcheck disable=SC2016 # Literal artificial credentials and inert names.
setup() {
    source "$BATS_TEST_DIRNAME/test_helper.bash"
    source "$BATS_TEST_DIRNAME/../lib/common.sh"
    source "$BATS_TEST_DIRNAME/../lib/module_api.sh"
    export RLCH_CIS_7_2_6_PASSWD="$BATS_TEST_TMPDIR/passwd"
    export RLCH_CIS_7_2_6_RPM="$BATS_TEST_TMPDIR/rpm"
    export PACKAGES="$BATS_TEST_TMPDIR/packages" FLAG="$BATS_TEST_TMPDIR/flag" COUNT="$BATS_TEST_TMPDIR/count"
    P="$RLCH_CIS_7_2_6_PASSWD"; N="$BATS_TEST_TMPDIR/nsswitch.conf"
    printf 'root:x:0:0::/:/bin/false\n' > "$P"; printf 'passwd: files\n' > "$N"; chmod 0644 "$P" "$N"
    printf 'RPM1|1|kernel-core|0|1|1|x86_64|END\n' > "$PACKAGES"
    printf '#!/usr/bin/env bash\n/usr/bin/cat "$PACKAGES"\n' > "$RLCH_CIS_7_2_6_RPM"; chmod 0700 "$RLCH_CIS_7_2_6_RPM"
    source "$BATS_TEST_DIRNAME/../modules/cis/7/2/6/module.sh"
}
dup() { printf 'root:x:42:7::/:/bin/bash\n' >> "$P"; }
uncertain() {
    run check; [ "$status" -eq 2 ]; [[ "$output" == *'cannot reliably evaluate'* ]]
    [[ "$output" != *PRIVATE* && "$output" != *SENTINEL* ]]; [ "${#output}" -lt 300 ]
}
@test "7.2.6 exact metadata Level 1 enabled no reboot and public functions" {
    source "$BATS_TEST_DIRNAME/../modules/cis/7/2/6/metadata.conf"
    [ "$RLCH_MODULE_ID" = 7.2.6 ]; [ "$RLCH_MODULE_LEVEL" = 1 ]; [ "$RLCH_MODULE_ENABLED" = true ]; [ "$RLCH_MODULE_REQUIRES_REBOOT" = false ]
    [ "$RLCH_MODULE_OPENSCAP_RULE" = xccdf_org.ssgproject.content_rule_account_unique_name ]
    validate_loaded_module_metadata 7.2.6; validate_loaded_module_functions
}
@test "7.2.6 framework loads after previous control" {
    source "$BATS_TEST_DIRNAME/../lib/modules.sh"
    RLCH_MODULE_ROOT="$BATS_TEST_DIRNAME/../modules"; RLCH_MODULE_NAMESPACE=cis
    RLCH_MODULE_METADATA_FILENAME=metadata.conf; RLCH_MODULE_IMPLEMENTATION_FILENAME=module.sh
    load_module "$BATS_TEST_DIRNAME/../modules/cis/7/2/5"; load_module "$BATS_TEST_DIRNAME/../modules/cis/7/2/6"
    [ "$RLCH_CURRENT_MODULE_ID" = 7.2.6 ]; run check; [ "$status" -eq 0 ]
}
@test "7.2.6 unique root system and user names comply" {
    printf 'daemon:x:1:1::/:/sbin/nologin\nuser:x:1000:1000::/:/bin/bash\n' >> "$P"
    run check; [ "$status" -eq 0 ]; [ -z "$output" ]
}
@test "7.2.6 two identical names are NON_COMPLIANT despite different UID and GID" {
    dup; run check; [ "$status" -eq 1 ]; [[ "$output" == *'2 selected local account entries have 1 distinct'* ]]
}
@test "7.2.6 three identical names are counted" {
    dup; printf 'root:x:77:88::/:/bin/false\n' >> "$P"; run check; [ "$status" -eq 1 ]; [[ "$output" == *'3 selected local account entries have 1 distinct'* ]]
}
@test "7.2.6 nonadjacent duplicate sets are counted globally" {
    printf 'a:x:1:7::/:/bin/false\nb:x:2:7::/:/bin/false\na:x:3:8::/:/bin/bash\nb:x:4:9::/:/bin/false\n' >> "$P"
    run check; [ "$status" -eq 1 ]; [[ "$output" == *'5 selected local account entries have 3 distinct'* ]]
}
@test "7.2.6 identical records are not silently deduplicated" {
    printf 'root:x:0:0::/:/bin/false\n' >> "$P"; run check; [ "$status" -eq 1 ]
}
@test "7.2.6 same name with same UID and different GID is a duplicate" {
    printf 'root:x:0:999::/:/bin/false\n' >> "$P"; run check; [ "$status" -eq 1 ]
}
@test "7.2.6 same name with different UID and same GID is a duplicate" {
    printf 'root:x:999:0::/:/bin/false\n' >> "$P"; run check; [ "$status" -eq 1 ]
}
@test "7.2.6 unique names may share UID GID and shell" {
    printf 'other:x:0:0::/:/bin/false\n' >> "$P"; run check; [ "$status" -eq 0 ]
}
@test "7.2.6 case is preserved without folding" {
    printf 'Alice:x:1:7::/:/bin/false\nalice:x:2:7::/:/bin/false\nALICE:x:3:7::/:/bin/false\n' > "$P"
    run check; [ "$status" -eq 0 ]; printf 'Alice:x:4:8::/:/bin/bash\n' >> "$P"; run check; [ "$status" -eq 1 ]
}
@test "7.2.6 leading trailing and internal spaces remain distinct" {
    printf 'a:x:1:7::/:/bin/false\n a:x:1:7::/:/bin/false\na :x:1:7::/:/bin/false\na  b:x:1:7::/:/bin/false\n' > "$P"
    run check; [ "$status" -eq 0 ]; printf 'a :x:2:8::/:/bin/false\n' >> "$P"; run check; [ "$status" -eq 1 ]
}
@test "7.2.6 numeric spellings and format-like names are distinct strings" {
    printf '01:x:1:7::/:/bin/false\n1:x:1:7::/:/bin/false\nSKIP:x:1:7::/:/bin/false\nNAME|a:x:1:7::/:/bin/false\n' > "$P"
    run check; [ "$status" -eq 0 ]; printf '01:x:8:9::/:/bin/false\n' >> "$P"; run check; [ "$status" -eq 1 ]
}
@test "7.2.6 Unicode names are exact without normalization" {
    printf 'élève:x:1:7::/:/bin/false\nÉlève:x:2:7::/:/bin/false\ne\314\201:x:3:7::/:/bin/false\né:x:4:7::/:/bin/false\n' > "$P"
    run check; [ "$status" -eq 0 ]; printf 'élève:x:5:7::/:/bin/false\n' >> "$P"; run check; [ "$status" -eq 1 ]
}
@test "7.2.6 empty first fields are unselected and not names" {
    printf ':PRIVATE_AUTH:1:7::/:/bin/false\n:PRIVATE_AUTH:2:8::/:/bin/false\n' >> "$P"; run check; [ "$status" -eq 0 ]
}
@test "7.2.6 no selected name abstains on unsupported empty collection semantics" {
    printf ':x:0:0::/:/bin/false\n' > "$P"; uncertain
}
@test "7.2.6 no UID GID shell or authentication filters are imported" {
    printf 'same::BAD:-1::/:/sbin/nologin\nsame:PRIVATE:999999999999999999:OTHER::/:/bin/false\n' > "$P"
    run check; [ "$status" -eq 1 ]; [[ "$output" != *PRIVATE* ]]
}
@test "7.2.6 plus minus comment-like and space names follow text selection" {
    printf '+:x:1:7::/:/bin/false\n-foo:x:1:7::/:/bin/false\n#name:x:1:7::/:/bin/false\n :x:1:7::/:/bin/false\n' > "$P"
    run check; [ "$status" -eq 0 ]; printf '+:x:2:7::/:/bin/false\n' >> "$P"; run check; [ "$status" -eq 1 ]
}
@test "7.2.6 shell metacharacters in names are inert data" {
    for name in '$(touch "$FLAG")' '`touch "$FLAG"`' 'a[$(touch "$FLAG")]' 'a";touch "$FLAG";#' 'a|b'; do
        printf '%s:x:1:7::/:/bin/false\n%s:x:2:8::/:/bin/bash\n' "$name" "$name" > "$P"
        run check; [ "$status" -eq 1 ]; [ ! -e "$FLAG" ]
    done
}
@test "7.2.6 long different length names are retained without truncation" {
    long="$(printf '%10000s' '' | tr ' ' a)"; printf 'a:x:1:7::/:/bin/false\n%s:x:1:7::/:/bin/false\n' "$long" > "$P"
    run check; [ "$status" -eq 0 ]; printf '%s:x:2:8::/:/bin/false\n' "$long" >> "$P"; run check; [ "$status" -eq 1 ]
}
@test "7.2.6 missing and empty source are ERROR" { rm "$P"; uncertain; : > "$P"; uncertain; }
@test "7.2.6 unreadable and unsafe permission modes are ERROR" {
    for mode in 0000 0666 0664; do chmod "$mode" "$P"; uncertain; done
}
@test "7.2.6 malformed later record overrides duplicate evidence" {
    dup; printf 'PRIVATE_BROKEN:x:BAD\n' >> "$P"; uncertain
    printf 'name:x:1:7::/:/bin/false:extra\n' > "$P"; uncertain
}
@test "7.2.6 unsupported blank or comment-only source lines are ERROR" {
    printf '\n' >> "$P"; uncertain; printf '# PRIVATE_COMMENT\n' > "$P"; uncertain
}
@test "7.2.6 invalid UTF-8 cannot produce SUCCESS" {
    printf 'PRIVATE\377:x:1:7::/:/bin/false\n' >> "$P"; uncertain
}
@test "7.2.6 symlink ancestor symlink and hardlink rejected" {
    mv "$P" "$P.real"; ln -s "$P.real" "$P"; uncertain; rm "$P"; mv "$P.real" "$P"
    ln "$P" "$P.alias"; uncertain; rm "$P.alias"
    mkdir "$BATS_TEST_TMPDIR/real"; mv "$P" "$BATS_TEST_TMPDIR/real/passwd"; ln -s real "$BATS_TEST_TMPDIR/alias"
    RLCH_CIS_7_2_6_PASSWD="$BATS_TEST_TMPDIR/alias/passwd"; uncertain
}
@test "7.2.6 directory and FIFO rejected without reading bodies" {
    rm "$P"; mkdir "$P"; uncertain; rmdir "$P"; mkfifo "$P"; uncertain
}
@test "7.2.6 complete-row truncation cannot hide duplicate name" {
    dup; rlch_identity_stream() { /usr/bin/head -n 1; }; uncertain
}
@test "7.2.6 two identical truncated observations cannot prove completeness" {
    dup; rlch_identity_stream() { /usr/bin/head -n 1; }; uncertain; uncertain
}
@test "7.2.6 mid-record and zero-byte truncation are ERROR" {
    rlch_identity_stream() { /usr/bin/head -c 5; }; uncertain; rlch_identity_stream() { :; }; uncertain
}
@test "7.2.6 producer failure and stderr discard prefix privately" {
    dup; rlch_identity_stream() { /usr/bin/cat; return 87; }; uncertain
    rlch_identity_stream() { /usr/bin/cat; printf PRIVATE_SENTINEL >&2; }; uncertain
}
@test "7.2.6 appended data and forged frame invalidate observation" {
    rlch_identity_stream() { /usr/bin/cat; printf 'later:x:1:7::/:/bin/false\n'; }; uncertain
    rlch_identity_stream() { /usr/bin/cat; printf 'RLCH-IDENTITY-END\n'; }; uncertain
}
@test "7.2.6 missing newline NUL and controls are ERROR" {
    printf 'root:x:0:0::/:/bin/false' > "$P"; uncertain
    printf 'root:PRIVATE\000:0:0::/:/bin/false\n' > "$P"; uncertain
    printf 'root:x:0:0:PRIVATE\r:/:/bin/false\n' > "$P"; uncertain
}
@test "7.2.6 line entry and aggregate byte bounds are enforced" {
    printf '%17000s:x:1:7::/:/bin/false\n' X > "$P"; uncertain
    awk 'BEGIN{for(i=0;i<65537;i++)print "same:x:1:7::/:/bin/false"}' > "$P"; uncertain
    awk 'BEGIN{for(i=0;i<500;i++){printf "same:";for(j=0;j<10000;j++)printf "x";print ":1:7::/:/bin/false"}}' > "$P"; uncertain
}
@test "7.2.6 maximum supported count preserves all duplicates" {
    awk 'BEGIN{for(i=0;i<65536;i++)print "same:x:1:7::/:/bin/false"}' > "$P"
    run check; [ "$status" -eq 1 ]; [[ "$output" == *'65536 selected local account entries have 1 distinct'* ]]
}
@test "7.2.6 content mutation during read is ERROR" {
    rlch_identity_stream() { /usr/bin/cat; printf 'later:x:1:7::/:/bin/false\n' >> "$P"; }; uncertain
}
@test "7.2.6 pathname replacement or link creation during read is ERROR" {
    rlch_identity_stream() { /usr/bin/cat; cp "$P" "$P.new"; mv "$P.new" "$P"; }; uncertain
    rlch_identity_stream() { /usr/bin/cat; ln "$P" "$P.alias"; }; uncertain
}
@test "7.2.6 changed projection and second-read failure have ERROR priority" {
    rlch_identity_user_names() { if [[ -f "$FLAG" ]]; then printf 'NAME|other\n'; else touch "$FLAG"; printf 'NAME|same\nNAME|same\n'; fi; }; uncertain
    rm "$FLAG"
    rlch_identity_user_names() { if [[ -f "$FLAG" ]]; then return 2; fi; touch "$FLAG"; printf 'NAME|same\nNAME|same\n'; }; uncertain
}
@test "7.2.6 changed outer metadata overrides matching projections" {
    rlch_identity_user_names() { printf 'NAME|same\n'; }
    rlch_identity_stamp() { if [[ -f "$FLAG" ]]; then printf changed; else touch "$FLAG"; printf before; fi; }; uncertain
}
@test "7.2.6 two real strict observations are required" {
    rlch_identity_stream() { printf 'read\n' >> "$COUNT"; /usr/bin/cat; }
    run check; [ "$status" -eq 0 ]; [ "$(wc -l < "$COUNT")" -eq 2 ]
}
@test "7.2.6 malformed projections cannot become findings" {
    for BAD in 'PRIVATE_SENTINEL' 'NAME|' 'NAME|bad:name' $'NAME|same\nNAME|same\nBROKEN' $'SKIP\nSKIP' $'NAME|bad\r'; do
        export BAD; rlch_identity_user_names() { printf '%s\n' "$BAD"; }; uncertain
    done
}
@test "7.2.6 projection row count length and aggregate bounds are checked" {
    rlch_identity_user_names() { printf 'NAME|%17000s\n' X; }; uncertain
    rlch_identity_user_names() { awk 'BEGIN{for(i=0;i<65537;i++)print "NAME|same"}'; }; uncertain
    rlch_identity_user_names() { printf '%4200000s\n' X; }; uncertain
}
@test "7.2.6 files mixed and external NSS do not alter local conformity" {
    for src in files 'files sss' 'sss files' ldap compat; do printf 'passwd: %s\n' "$src" > "$N"; run check; [ "$status" -eq 0 ]; done
}
@test "7.2.6 local duplicate remains finding independently of NSS" {
    dup; for src in files 'files sss' ldap; do printf 'passwd: %s\n' "$src" > "$N"; run check; [ "$status" -eq 1 ]; done
}
@test "7.2.6 absent ambiguous and unreadable NSS do not add prerequisites" {
    printf 'passwd: files\npasswd: sss\n' > "$N"; run check; [ "$status" -eq 0 ]
    chmod 0000 "$N"; run check; [ "$status" -eq 0 ]; rm "$N"; run check; [ "$status" -eq 0 ]
}
@test "7.2.6 no external enumeration or historical name reader is invoked" {
    for cmd in getent getpwent rlch_identity_rows rlch_identity_uid_values rlch_accounts_rows; do eval "${cmd}"'() { printf forbidden > "$FLAG"; return 99; }'; done
    check; [ ! -e "$FLAG" ]
}
@test "7.2.6 identity reader opens only selected local passwd fixture" {
    rlch_identity_stream() { [[ "$(readlink /proc/self/fd/0)" == "$P" ]] || return 99; /usr/bin/cat; }
    run check; [ "$status" -eq 0 ]
}
@test "7.2.6 local uncertainty overrides finding with external NSS" {
    dup; printf 'passwd: sss\n' > "$N"; rlch_identity_stream() { /usr/bin/head -n 1; }; uncertain
}
@test "7.2.6 RPM absence proves NOT_APPLICABLE without passwd access" {
    printf 'RPM1|1|bash|0|1|1|x86_64|END\n' > "$PACKAGES"; rm "$P"
    run check; [ "$status" -eq 3 ]; [ -z "$output" ]; run apply; [ "$status" -eq 3 ]
}
@test "7.2.6 failed empty malformed and noisy RPM inventory is ERROR" {
    : > "$PACKAGES"; uncertain; printf 'PRIVATE_BROKEN\n' > "$PACKAGES"; uncertain
    printf '#!/usr/bin/env bash\nexit 1\n' > "$RLCH_CIS_7_2_6_RPM"; uncertain
    printf '#!/usr/bin/env bash\nprintf PRIVATE_SENTINEL >&2\n' > "$RLCH_CIS_7_2_6_RPM"; uncertain
}
@test "7.2.6 applicability change across observation is ERROR" {
    rlch_rpm_package_status() { if [[ -f "$FLAG" ]]; then return 1; fi; touch "$FLAG"; return 0; }; uncertain
}
@test "7.2.6 kernel-bearing bootc is applicable without container heuristic" {
    printf 'RPM1|2|bootc|0|1|1|x86_64|END\n' >> "$PACKAGES"; run check; [ "$status" -eq 0 ]
}
@test "7.2.6 check and validate are fresh without cached result" {
    check; dup; run validate; [ "$status" -eq 1 ]; printf 'root:x:0:0::/:/bin/false\n' > "$P"; run check; [ "$status" -eq 0 ]
    rm "$P"; uncertain
}
@test "7.2.6 apply succeeds only for already conforming or inapplicable state" {
    run apply; [ "$status" -eq 0 ]; [ -z "$output" ]; dup
    run apply; [ "$status" -eq 2 ]; [[ "$output" == *'manual remediation required'* ]]
}
@test "7.2.6 apply preserves uncertainty and never claims CHANGED" {
    rm "$P"; run apply; [ "$status" -eq 2 ]; [[ "$output" == *'manual remediation required'* ]]
}
@test "7.2.6 rollback silent idempotent with missing source files" {
    rm "$P" "$N" "$PACKAGES"; run rollback; [ "$status" -eq 0 ]; [ -z "$output" ]; run rollback; [ "$status" -eq 0 ]; [ -z "$output" ]
}
@test "7.2.6 all public functions preserve fixtures metadata contents and file set" {
    before="$(stat -c '%i:%a:%u:%g:%Y:%Z:%s' "$P" "$N" "$PACKAGES")"; data="$(sha256sum "$P" "$N" "$PACKAGES")"; files="$(find "$BATS_TEST_TMPDIR" -type f | sort)"
    check; validate; apply; rollback; check
    [ "$before" = "$(stat -c '%i:%a:%u:%g:%Y:%Z:%s' "$P" "$N" "$PACKAGES")" ]; [ "$data" = "$(sha256sum "$P" "$N" "$PACKAGES")" ]
    [ "$files" = "$(find "$BATS_TEST_TMPDIR" -type f | sort)" ]
}
@test "7.2.6 findings and apply manual guidance preserve duplicate source" {
    dup; before="$(stat -c '%i:%a:%u:%g:%Y:%Z:%s' "$P")"; data="$(cat "$P")"
    run check; [ "$status" -eq 1 ]; run validate; [ "$status" -eq 1 ]; run apply; [ "$status" -eq 2 ]; rollback
    [ "$before" = "$(stat -c '%i:%a:%u:%g:%Y:%Z:%s' "$P")" ]; [ "$data" = "$(cat "$P")" ]
}
@test "7.2.6 account and ownership administration must never execute" {
    for cmd in usermod userdel useradd groupmod groupdel groupadd chown chgrp chmod setfacl; do eval "${cmd}"'() { printf forbidden > "$FLAG"; return 99; }'; done
    check; validate; apply; rollback; [ ! -e "$FLAG" ]
}
@test "7.2.6 diagnostics disclose no names identifiers hashes or other fields" {
    printf 'PRIVATE_NAME:$6$PRIVATE_SALT$PRIVATE_HASH:424242:737373:PRIVATE_GECOS:/PRIVATE_HOME:/PRIVATE_SHELL\nPRIVATE_NAME:PRIVATE_AUTH:1:7::/:/bin/false\n' > "$P"
    run check; [ "$status" -eq 1 ]; [[ "$output" != *PRIVATE* && "$output" != *424242* && "$output" != *737373* ]]; [ "${#output}" -lt 200 ]
    run apply; [ "$status" -eq 2 ]; [[ "$output" != *PRIVATE* ]]; [ "${#output}" -lt 400 ]
}
@test "7.2.6 aggregate diagnostics stay bounded with large duplicate sets" {
    awk 'BEGIN{for(i=0;i<1000;i++)print "PRIVATE_NAME:PRIVATE_AUTH:"i":7::/:/bin/false"}' > "$P"
    run check; [ "$status" -eq 1 ]; [ "${#output}" -lt 200 ]; [[ "$output" != *PRIVATE* ]]
}
@test "7.2.6 xtrace hides projections for success finding and ERROR preserving caller trace" {
    for mode in success finding error; do
        printf 'PRIVATE_NAME:PRIVATE_AUTH:1:7::/:/bin/false\n' > "$P"; expected=0
        if [[ "$mode" == finding ]]; then printf 'PRIVATE_NAME:PRIVATE_AUTH:2:8::/:/bin/false\n' >> "$P"; expected=1; fi
        if [[ "$mode" == error ]]; then printf 'PRIVATE_BROKEN\n' >> "$P"; expected=2; fi
        run bash -c 'source "$1"; source "$2"; set -x; rc=0; check || rc=$?; [[ $- == *x* ]] || exit 99; exit "$rc"' bash "$BATS_TEST_DIRNAME/../lib/module_api.sh" "$BATS_TEST_DIRNAME/../modules/cis/7/2/6/module.sh"
        [ "$status" -eq "$expected" ]; [[ "$output" != *PRIVATE* && "$output" != *'NAME|'* ]]
    done
}
@test "7.2.6 unexpected observer status is normalized to ERROR" {
    rlch_7_2_6_observe() { return 99; }; uncertain
}
