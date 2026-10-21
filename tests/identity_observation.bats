#!/usr/bin/env bats
# shellcheck source-path=SCRIPTDIR
# shellcheck disable=SC2317 # Fault injection through sourced API.
# shellcheck disable=SC2030,SC2031 # Bats isolates each test; run sets status/output.
# shellcheck disable=SC2016 # Artificial password strings contain literal dollars.
setup() {
    source "$BATS_TEST_DIRNAME/../lib/identity_observation.sh"
    P="$BATS_TEST_TMPDIR/passwd"; G="$BATS_TEST_TMPDIR/group"; N="$BATS_TEST_TMPDIR/nsswitch.conf"
    printf 'root:PRIVATE:0:0::/:/bin/bash\nuser:x:1001:1001::/:/bin/sh\n' > "$P"
    printf 'root:PRIVATE:0:member\nuser:x:1001:\n' > "$G"
    printf 'passwd: files\ngroup: files\n' > "$N"; chmod 0644 "$P" "$G" "$N"
}
unknown() { run rlch_identity_rows "$1" "$2"; [ "$status" -eq 2 ]; [ -z "$output" ]; }
@test "idobs projects only numeric UIDs" {
    run rlch_identity_rows "$P" passwd; [ "$status" -eq 0 ]; [ "$output" = $'0\n1001' ]; }
@test "idobs projects only numeric GIDs" {
    run rlch_identity_rows "$G" group; [ "$status" -eq 0 ]; [ "$output" = $'0\n1001' ]; }
@test "idobs absent UID and GID not invented" {
    run rlch_identity_rows "$P" passwd; [[ "$output" != *424242* ]]; run rlch_identity_rows "$G" group; [[ "$output" != *424242* ]]; }
@test "idobs NSS captures raw sources without completeness claim" {
    run rlch_identity_rows "$N" nss; [ "$status" -eq 0 ]; [ "$output" = $'passwd|files\ngroup|files' ]; }
@test "idobs NSS external sources remain explicit" {
    printf 'passwd: files sss\ngroup: files ldap\n' > "$N"; run rlch_identity_rows "$N" nss; [ "$status" -eq 0 ]; [[ "$output" == *sss* ]]; [[ "$output" == *ldap* ]]; }
@test "idobs altfiles capture retains CAS relevant spelling" {
    printf 'passwd: files\ngroup: altfiles files # note\n' > "$N"; run rlch_identity_rows "$N" nss; [ "$status" -eq 0 ]; [[ "$output" == *'altfiles files # note'* ]]; }
@test "idobs duplicate numeric IDs valid aliases" {
    printf 'alias:x:1001:1001::/:/bin/sh\n' >> "$P"; run rlch_identity_rows "$P" passwd; [ "$status" -eq 0 ]; [ "$output" = $'0\n1001\n1001' ]; }
@test "idobs duplicate names conservative error" {
    cat "$P" >> "$G"; unknown "$G" group; printf 'root:x:1002:1002::/:/bin/sh\n' >> "$P"; unknown "$P" passwd; }
@test "idobs malformed passwd field count" {
    printf 'bad:x:123:1\n' >> "$P"; unknown "$P" passwd; }
@test "idobs malformed group field count" {
    printf 'bad:x:123\n' >> "$G"; unknown "$G" group; }
@test "idobs UID bounds and syntax" {
    for uid in -1 bad 4294967295 999999999999; do printf 'bad:x:%s:0::/:/bin/sh\n' "$uid" > "$P"; unknown "$P" passwd; done; }
@test "idobs GID bounds and syntax" {
    for gid in -1 bad 4294967295 999999999999; do printf 'bad:x:%s:\n' "$gid" > "$G"; unknown "$G" group; done; }
@test "idobs leading zeros normalized numerically" {
    printf 'user:x:0001:0002::/:/bin/sh\n' > "$P"; run rlch_identity_rows "$P" passwd; [ "$status" -eq 0 ]; [ "$output" = 1 ]; }
@test "idobs empty bases rejected" {
    : > "$P"; : > "$G"; unknown "$P" passwd; unknown "$G" group; }
@test "idobs NUL bytes rejected" {
    printf 'bad\000row\n' >> "$P"; unknown "$P" passwd; }
@test "idobs control bytes rejected" {
    printf 'bad\r:x:1:\n' > "$G"; unknown "$G" group; }
@test "idobs missing last newline rejected" {
    printf 'root:x:0:0::/:/bin/sh' > "$P"; unknown "$P" passwd; }
@test "idobs NSS duplicate keys rejected" {
    printf 'passwd: files\n' >> "$N"; unknown "$N" nss; }
@test "idobs NSS missing keys rejected" {
    printf 'passwd: files\n' > "$N"; unknown "$N" nss; }
@test "idobs NSS unsupported syntax rejected" {
    printf 'passwd : files\ngroup: files\n' > "$N"; unknown "$N" nss; }
@test "idobs NSS comments tabs and other databases accepted" {
    printf '# comment\npasswd:\tfiles\ngroup: files\nhosts: files dns\n' > "$N"; run rlch_identity_rows "$N" nss; [ "$status" -eq 0 ]; }
@test "idobs compat inclusion entries rejected" {
    printf '+::::::\n' >> "$P"; unknown "$P" passwd; }
@test "idobs symlink base rejected" {
    ln -s "$P" "$BATS_TEST_TMPDIR/link"; unknown "$BATS_TEST_TMPDIR/link" passwd; }
@test "idobs symlink ancestor rejected" {
    mkdir "$BATS_TEST_TMPDIR/dir"; cp "$P" "$BATS_TEST_TMPDIR/dir/passwd"; ln -s dir "$BATS_TEST_TMPDIR/alias"; unknown "$BATS_TEST_TMPDIR/alias/passwd" passwd; }
@test "idobs writable or unreadable base rejected" {
    for mode in 0666 0664 0000; do chmod "$mode" "$P"; unknown "$P" passwd; done; }
@test "idobs missing base and directory rejected" {
    unknown "$P/missing" passwd; unknown "$BATS_TEST_TMPDIR" passwd; }
@test "idobs producer failure does not leak partial projection" {
    rlch_identity_stream() { /usr/bin/cat; return 99; }; unknown "$P" passwd; }
@test "idobs stream truncation rejected" {
    rlch_identity_stream() { /usr/bin/head -c 10; }; unknown "$P" passwd; }
@test "idobs record length limit" {
    printf '%17000s\n' x > "$G"; unknown "$G" group; }
@test "idobs line count limit" {
    awk 'BEGIN{for(i=0;i<65537;i++) print "u"i":x:"i":"}' > "$G"; unknown "$G" group; }
@test "idobs base mutation while reading detected" {
    rlch_identity_stream() { /usr/bin/cat; printf 'new:x:1002:1002::/:/bin/sh\n' >> "$P"; }; unknown "$P" passwd; }
@test "idobs fresh reads reflect identity addition and disappearance" {
    before="$(rlch_identity_rows "$P" passwd)"; printf 'new:x:1002:1002::/:/bin/sh\n' >> "$P"; after="$(rlch_identity_rows "$P" passwd)"; [ "$before" != "$after" ]; sed -i '$d' "$P"; [ "$before" = "$(rlch_identity_rows "$P" passwd)" ]; }
@test "idobs no secrets names or members in diagnostics" {
    printf 'BROKEN:VERYPRIVATE:BAD:\n' > "$G"; unknown "$G" group; }
@test "idobs no mutation and deterministic output" {
    before="$(stat -c '%i:%a:%u:%g:%Y:%Z' "$P")"; a="$(rlch_identity_rows "$P" passwd)"; b="$(rlch_identity_rows "$P" passwd)"; [ "$a" = "$b" ]; [ "$before" = "$(stat -c '%i:%a:%u:%g:%Y:%Z' "$P")" ]; [[ "$(cat "$P")" == *PRIVATE* ]]; }
@test "idobs unknown projection rejected" {
    unknown "$P" shadow; }
@test "idobs stderr even zero status invalidates evidence" {
    rlch_identity_stream() { /usr/bin/cat; printf 'PRIVATE\n' >&2; }; unknown "$P" passwd
}
@test "idobs aggregate byte volume limit" {
    awk 'BEGIN {for(i=0;i<500;i++) {printf "u%d:x:%d:",i,i;for(j=0;j<10000;j++) printf "a";print ""}}' > "$G"
    unknown "$G" group
}


# Additive literal-marker projection: artificial values only, never /etc data.
marker_row() { printf 'fixture:%s:1001:1001::/fixture:/bin/false\n' "$1" > "$P"; }
marker_error() {
    run rlch_identity_password_markers "$P"
    [ "$status" -eq 2 ]; [ -z "$output" ]
}
@test "idobs markers exact x classification" {
    marker_row x; run rlch_identity_password_markers "$P"; [ "$status" -eq 0 ]; [ "$output" = X ]
}
@test "idobs markers exact asterisk classification" {
    marker_row '*'; run rlch_identity_password_markers "$P"; [ "$status" -eq 0 ]; [ "$output" = STAR ]
}
@test "idobs markers other includes lock empty arbitrary and artificial hash forms" {
    for value in '!' '' '!!' '!x' '**' 'xx' 'X' 'xSENTINEL' 'SENTINEL' '$6$FAKE$SENTINEL' '$y$FAKE$SENTINEL' 'FAKEtraditionalSENTINEL'; do
        marker_row "$value"; run rlch_identity_password_markers "$P"
        [ "$status" -eq 0 ]; [ "$output" = OTHER ]
    done
}
@test "idobs markers retain input order without identity disclosure" {
    printf 'SECRETNAME:x:0:0::/:/bin/false\nsecond:*:1:1::/:/bin/false\nthird:SENTINEL:1:1::/:/bin/false\n' > "$P"
    run rlch_identity_password_markers "$P"; [ "$status" -eq 0 ]; [ "$output" = $'X\nSTAR\nOTHER' ]
}
@test "idobs markers do not alter historical public projection kinds" {
    unknown "$P" password_markers
    run rlch_identity_rows "$P" passwd; [ "$status" -eq 0 ]; [ "$output" = $'0\n1001' ]
    run rlch_identity_rows "$G" group; [ "$status" -eq 0 ]; [ "$output" = $'0\n1001' ]
    run rlch_identity_rows "$N" nss; [ "$status" -eq 0 ]; [ "$output" = $'passwd|files\ngroup|files' ]
}
@test "idobs markers reject malformed field counts without any output" {
    for row in 'fixture:SENTINEL:1:1' 'fixture:SENTINEL:1:1::/:/bin/false:extra'; do
        printf '%s\n' "$row" > "$P"; marker_error
    done
}
@test "idobs markers validate both numeric identifiers" {
    for value in bad -1 4294967295 999999999999; do
        printf 'fixture:SENTINEL:%s:1::/:/bin/false\n' "$value" > "$P"; marker_error
        printf 'fixture:SENTINEL:1:%s::/:/bin/false\n' "$value" > "$P"; marker_error
    done
}
@test "idobs markers reject duplicate names and compat entries" {
    cat "$P" > "$BATS_TEST_TMPDIR/copy"; cat "$BATS_TEST_TMPDIR/copy" >> "$P"; marker_error
    printf '+::::::\n' > "$P"; marker_error
}
@test "idobs markers accept duplicate IDs and non-CIS account names" {
    printf 'service$:x:0:0::/:/bin/false\nservice-two:*:0:0::/:/bin/false\n' > "$P"
    run rlch_identity_password_markers "$P"; [ "$status" -eq 0 ]; [ "$output" = $'X\nSTAR' ]
}
@test "idobs markers empty missing directory FIFO are errors" {
    : > "$P"; marker_error; rm "$P"; marker_error
    mkdir "$P"; marker_error; rmdir "$P"; mkfifo "$P"; marker_error
}
@test "idobs markers reject symlink and symlink ancestor" {
    mv "$P" "$P.real"; ln -s "$P.real" "$P"; marker_error
    rm "$P"; mkdir "$P.dir"; cp "$P.real" "$P.dir/passwd"
    ln -s "$P.dir" "$P"; P="$P/passwd"; marker_error
}
@test "idobs markers reject hardlinked bases without changing historical reader" {
    ln "$P" "$P.alias"; marker_error
    run rlch_identity_rows "$P" passwd; [ "$status" -eq 0 ]
}
@test "idobs markers reject unsafe permissions" {
    for mode in 0000 0664 0666; do chmod "$mode" "$P"; marker_error; done
}
@test "idobs markers reject NUL and controls anywhere" {
    for value in $'SENTINEL\r' $'SENTINEL\t'; do marker_row "$value"; marker_error; done
    printf 'fixture:SENTINEL\000:1:1::/:/bin/false\n' > "$P"; marker_error
}
@test "idobs markers reject missing final newline" {
    printf 'fixture:x:1:1::/:/bin/false' > "$P"; marker_error
}
@test "idobs markers reject mid-record silent truncation" {
    rlch_identity_stream() { /usr/bin/head -c 10; }; marker_error
}
@test "idobs markers reject complete-record silent truncation" {
    rlch_identity_stream() { /usr/bin/head -n 1; }; marker_error
}
@test "idobs markers reject zero byte silent truncation" {
    rlch_identity_stream() { :; }; marker_error
}
@test "idobs markers reject extra valid rows even with zero producer status" {
    rlch_identity_stream() { /usr/bin/cat; printf 'extra:x:1:1::/:/bin/false\n'; }; marker_error
}
@test "idobs markers reject producer errors after valid data" {
    rlch_identity_stream() { /usr/bin/cat; return 77; }; marker_error
}
@test "idobs markers suppress producer stderr including sentinels" {
    rlch_identity_stream() { /usr/bin/cat; printf 'SENTINEL-PRIVATE\n' >&2; }; marker_error
}
@test "idobs markers discard classifications on concurrent modification" {
    rlch_identity_stream() { /usr/bin/cat; printf 'extra:x:1:1::/:/bin/false\n' >> "$P"; }; marker_error
}
@test "idobs markers reject pathname replacement during read" {
    rlch_identity_stream() { /usr/bin/cat; cp "$P" "$P.new"; mv "$P.new" "$P"; }; marker_error
}
@test "idobs markers reject hardlink added during read" {
    rlch_identity_stream() { /usr/bin/cat; ln "$P" "$P.alias"; }; marker_error
}
@test "idobs markers reject forged end frame" {
    printf 'RLCH-IDENTITY-END\n' >> "$P"; marker_error
}
@test "idobs markers enforce line length limit" {
    awk 'BEGIN {printf "u:x:1:1:"; for(i=0;i<16400;i++) printf "a"; print ":/:/bin/false"}' > "$P"; marker_error
}
@test "idobs markers enforce entry count limit" {
    awk 'BEGIN {for(i=0;i<65537;i++) print "u"i":x:1:1::/:/bin/false"}' > "$P"; marker_error
}
@test "idobs markers enforce total bytes limit before publishing" {
    awk 'BEGIN {for(i=0;i<500;i++) {printf "u%d:x:1:1:",i; for(j=0;j<10000;j++) printf "a"; print ":/:/bin/false"}}' > "$P"; marker_error
}
@test "idobs markers stdout and stderr never contain raw sentinels" {
    marker_row '$6$FAKE$SENTINEL-PRIVATE'
    rlch_identity_password_markers "$P" > "$BATS_TEST_TMPDIR/out" 2> "$BATS_TEST_TMPDIR/err"
    [ "$(cat "$BATS_TEST_TMPDIR/out")" = OTHER ]; [ ! -s "$BATS_TEST_TMPDIR/err" ]
    printf 'BROKEN:SENTINEL-PRIVATE:bad:\n' > "$P"
    result=0; rlch_identity_password_markers "$P" > "$BATS_TEST_TMPDIR/out" 2> "$BATS_TEST_TMPDIR/err" || result=$?
    [ "$result" -eq 2 ]; [ ! -s "$BATS_TEST_TMPDIR/out" ]; [ ! -s "$BATS_TEST_TMPDIR/err" ]
}
@test "idobs markers deterministic fresh observation and preserved fixture" {
    before="$(stat -c '%i:%a:%u:%g:%s:%y:%z' "$P")"
    a="$(rlch_identity_password_markers "$P")"; b="$(rlch_identity_password_markers "$P")"; [ "$a" = "$b" ]
    [ "$before" = "$(stat -c '%i:%a:%u:%g:%s:%y:%z' "$P")" ]
    marker_row '*'; [ "$(rlch_identity_password_markers "$P")" = STAR ]
}
@test "idobs markers invalid invocation fails closed" {
    run rlch_identity_password_markers; [ "$status" -eq 2 ]; [ -z "$output" ]
    run rlch_identity_password_markers "$P" extra; [ "$status" -eq 2 ]; [ -z "$output" ]
}
@test "idobs markers suppress dependency diagnostics" {
    rlch_identity_stamp() { printf 'SENTINEL-PRIVATE\n' >&2; return 23; }; marker_error
}
@test "idobs markers classify a pipe in field without exposing it" {
    marker_row 'SENTINEL|X'; run rlch_identity_password_markers "$P"
    [ "$status" -eq 0 ]; [ "$output" = OTHER ]
}
@test "idobs markers accept largest allowed entry count" {
    awk 'BEGIN {for(i=0;i<65536;i++) print "u"i":x:1:1::/:/bin/false"}' > "$P"
    rlch_identity_password_markers "$P" > "$BATS_TEST_TMPDIR/result"
    [ "$(wc -l < "$BATS_TEST_TMPDIR/result")" -eq 65536 ]
    [ -z "$(/usr/bin/awk '$0!="X" {print "unexpected"}' "$BATS_TEST_TMPDIR/result")" ]
}
@test "idobs markers publication failure returns ERROR without diagnostics" {
    result=0; rlch_identity_password_markers "$P" > /dev/full 2> "$BATS_TEST_TMPDIR/err" || result=$?
    [ "$result" -eq 2 ]; [ ! -s "$BATS_TEST_TMPDIR/err" ]
}


# Additive shadow presence projection; exclusively artificial fixtures.
shadow_row() { printf 'fixture:%s:20000:0:99999:7:::\n' "$1" > "$P"; chmod 0600 "$P"; }
shadow_error() {
    run rlch_identity_shadow_password_presence "$P"
    [ "$status" -eq 2 ]; [ -z "$output" ]
}
@test "idobs shadow empty field has EMPTY token" {
    shadow_row ''; run rlch_identity_shadow_password_presence "$P"; [ "$status" -eq 0 ]; [ "$output" = EMPTY ]
}
@test "idobs shadow lock and zero values are NONEMPTY not truth tests" {
    for value in '!' '*' '!!' 0 00 0.0 ' ' ';' $'\\' x; do
        shadow_row "$value"; run rlch_identity_shadow_password_presence "$P"; [ "$status" -eq 0 ]; [ "$output" = NONEMPTY ]
    done
}
@test "idobs shadow arbitrary and artificial hash strings never escape" {
    for value in 'ARTIFICIAL_SENTINEL' '$6$FAKE_SALT$PRIVATE_SENTINEL' '$y$FAKE_SALT$PRIVATE_SENTINEL' 'FAKEtraditionalSENTINEL'; do
        shadow_row "$value"; run rlch_identity_shadow_password_presence "$P"; [ "$status" -eq 0 ]; [ "$output" = NONEMPTY ]
    done
}
@test "idobs shadow all entries retain order without names or ages" {
    printf 'SECRETNAME::20000:0:99999:7:::\nother:!:20000:0:99999:7:::\nthird:0:20000:0:99999:7:::\nlast::20000:0:99999:7:::\n' > "$P"
    run rlch_identity_shadow_password_presence "$P"; [ "$status" -eq 0 ]; [ "$output" = $'EMPTY\nNONEMPTY\nNONEMPTY\nEMPTY' ]
}
@test "idobs shadow optional numeric fields are allowed" {
    printf 'fixture:!:::::::\n' > "$P"; run rlch_identity_shadow_password_presence "$P"; [ "$status" -eq 0 ]; [ "$output" = NONEMPTY ]
}
@test "idobs shadow signed ages numeric boundaries and leading zeros" {
    printf 'fixture:!:-9223372036854775808:+0:9223372036854775807:-1:-2:0000:18446744073709551615\n' > "$P"
    run rlch_identity_shadow_password_presence "$P"; [ "$status" -eq 0 ]; [ "$output" = NONEMPTY ]
}
@test "idobs shadow malformed numeric fields are invalid not empty findings" {
    for n in bad 9223372036854775808 -9223372036854775809 '1 2'; do
        printf 'fixture:SENTINEL:%s:0:99999:7:::\n' "$n" > "$P"; shadow_error
    done
    printf 'fixture:!:20000:0:99999:7:::18446744073709551616\n' > "$P"; shadow_error
}
@test "idobs shadow wrong field counts and passwd format fail closed" {
    for row in 'fixture:!:1:1::/:/bin/false' 'fixture:!:1:0:99:7::' 'fixture:!:1:0:99:7::::extra'; do
        printf '%s\n' "$row" > "$P"; shadow_error
    done
}
@test "idobs shadow empty missing and special object rejected" {
    : > "$P"; shadow_error; rm "$P"; shadow_error
    mkdir "$P"; shadow_error; rmdir "$P"; mkfifo "$P"; shadow_error
}
@test "idobs shadow duplicate empty and compat names rejected" {
    shadow_row '!'; printf 'fixture::20000:0:99999:7:::\n' >> "$P"; shadow_error
    printf ':!:20000:0:99999:7:::\n' > "$P"; shadow_error
    printf '+:::::::0:\n' > "$P"; shadow_error
}
@test "idobs shadow symlink and ancestor aliases rejected" {
    shadow_row '!'; mv "$P" "$P.real"; ln -s "$P.real" "$P"; shadow_error
    rm "$P"; mkdir "$P.dir"; cp "$P.real" "$P.dir/shadow"; ln -s "$P.dir" "$P"; P="$P/shadow"; shadow_error
}
@test "idobs shadow hardlinks rejected" {
    shadow_row '!'; ln "$P" "$P.alias"; shadow_error
}
@test "idobs shadow unsafe writable modes rejected" {
    shadow_row '!'; for mode in 0664 0666; do chmod "$mode" "$P"; shadow_error; done
}
@test "idobs shadow mode zero depends on actual read authority without changing old stamp" {
    shadow_row '!'; chmod 0000 "$P"
    if [[ -r "$P" ]]; then
        run rlch_identity_shadow_password_presence "$P"; [ "$status" -eq 0 ]; [ "$output" = NONEMPTY ]
    else shadow_error; fi
    run rlch_identity_stamp "$P"; [ "$status" -eq 2 ]; [ -z "$output" ]
    chmod 0600 "$P"
}
@test "idobs shadow mode zero is ERROR if reader cannot open it" {
    shadow_row '!'; chmod 0000 "$P"
    # -r remains the real access decision; do not simulate privilege by EUID.
    if [[ ! -r "$P" ]]; then shadow_error; else
        rlch_identity_stream() { return 91; }; shadow_error
    fi
    chmod 0600 "$P"
}
@test "idobs shadow final newline required" {
    printf 'fixture:!:20000:0:99999:7:::' > "$P"; shadow_error
}
@test "idobs shadow NUL and controls withheld" {
    printf 'fixture:SENTINEL\000:20000:0:99999:7:::\n' > "$P"; shadow_error
    shadow_row $'SENTINEL\r'; shadow_error
    shadow_row $'SENTINEL\t'; shadow_error
}
@test "idobs shadow mid-record truncation rejected" {
    shadow_row '!'; rlch_identity_stream() { /usr/bin/head -c 10; }; shadow_error
}
@test "idobs shadow whole-record silent truncation rejected" {
    shadow_row '!'; printf 'second::20000:0:99999:7:::\n' >> "$P"
    rlch_identity_stream() { /usr/bin/head -n 1; }; shadow_error
}
@test "idobs shadow no producer bytes cannot become complete inventory" {
    shadow_row '!'; rlch_identity_stream() { :; }; shadow_error
}
@test "idobs shadow appended producer records rejected by exact byte count" {
    shadow_row '!'; rlch_identity_stream() { /usr/bin/cat; printf 'second:!:20000:0:99999:7:::\n'; }; shadow_error
}
@test "idobs shadow producer error with complete prefix returns no partial tokens" {
    shadow_row ''; rlch_identity_stream() { /usr/bin/cat; return 99; }; shadow_error
}
@test "idobs shadow producer stderr sentinel never escapes" {
    shadow_row ''; rlch_identity_stream() { /usr/bin/cat; printf 'PRIVATE_SALT_SENTINEL\n' >&2; }; shadow_error
}
@test "idobs shadow malformed later record withholds earlier empty classification" {
    shadow_row ''; printf 'BROKEN:PRIVATE_SENTINEL\n' >> "$P"; shadow_error
}
@test "idobs shadow mutation during read detected" {
    shadow_row ''; rlch_identity_stream() { /usr/bin/cat; printf 'second:!:20000:0:99999:7:::\n' >> "$P"; }; shadow_error
}
@test "idobs shadow path replacement detected" {
    shadow_row '!'; rlch_identity_stream() { /usr/bin/cat; cp "$P" "$P.new"; mv "$P.new" "$P"; }; shadow_error
}
@test "idobs shadow link count instability rejected" {
    shadow_row '!'; rlch_identity_stream() { /usr/bin/cat; ln "$P" "$P.alias"; }; shadow_error
}
@test "idobs shadow forged end frame rejected" {
    shadow_row '!'; printf 'RLCH-IDENTITY-END\n' >> "$P"; shadow_error
}
@test "idobs shadow line length bound" {
    awk 'BEGIN {printf "fixture:";for(i=0;i<16400;i++) printf "a";print ":20000:0:99999:7:::"}' > "$P"; shadow_error
}
@test "idobs shadow record count bound" {
    awk 'BEGIN {for(i=0;i<65537;i++) print "u"i":!:20000:0:99999:7:::"}' > "$P"; shadow_error
}
@test "idobs shadow total byte bound" {
    awk 'BEGIN {for(i=0;i<500;i++) {printf "u%d:",i;for(j=0;j<10000;j++) printf "a";print ":20000:0:99999:7:::"}}' > "$P"; shadow_error
}
@test "idobs shadow maximum valid entry count" {
    awk 'BEGIN {for(i=0;i<65536;i++) print "u"i":!:20000:0:99999:7:::"}' > "$P"
    rlch_identity_shadow_password_presence "$P" > "$BATS_TEST_TMPDIR/classifications"
    [ "$(wc -l < "$BATS_TEST_TMPDIR/classifications")" -eq 65536 ]
}
@test "idobs shadow output failure normalized without diagnostics" {
    shadow_row '!'; result=0
    rlch_identity_shadow_password_presence "$P" > /dev/full 2> "$BATS_TEST_TMPDIR/err" || result=$?
    [ "$result" -eq 2 ]; [ ! -s "$BATS_TEST_TMPDIR/err" ]
}
@test "idobs shadow stdout stderr and traces never include artificial salt or hash" {
    shadow_row '$6$PRIVATE_SALT$PRIVATE_SENTINEL'
    result=0
    # Isolate xtrace from Bats traps. Producer trace stderr invalidates evidence;
    # ERROR is intentional, and neither output channel may disclose the field.
    bash -c 'source "$1"; set -x; rc=0; rlch_identity_shadow_password_presence "$2" || rc=$?; set +x; exit "$rc"' bash \
        "$BATS_TEST_DIRNAME/../lib/identity_observation.sh" "$P" \
        > "$BATS_TEST_TMPDIR/out" 2> "$BATS_TEST_TMPDIR/err" || result=$?
    [ "$result" -eq 2 ]; [ ! -s "$BATS_TEST_TMPDIR/out" ]
    [[ "$(cat "$BATS_TEST_TMPDIR/err")" != *PRIVATE* ]]
}
@test "idobs shadow public API no argument and extra arguments are silent errors" {
    run rlch_identity_shadow_password_presence; [ "$status" -eq 2 ]; [ -z "$output" ]
    run rlch_identity_shadow_password_presence "$P" extra; [ "$status" -eq 2 ]; [ -z "$output" ]
}
@test "idobs shadow fresh deterministic observations preserve fixture" {
    shadow_row '$y$PRIVATE_SALT$PRIVATE_SENTINEL'; before="$(stat -c '%d:%i:%u:%g:%a:%s:%y:%z' "$P")"
    a="$(rlch_identity_shadow_password_presence "$P")"; b="$(rlch_identity_shadow_password_presence "$P")"; [ "$a" = "$b" ]
    [ "$before" = "$(stat -c '%d:%i:%u:%g:%a:%s:%y:%z' "$P")" ]
    shadow_row ''; [ "$(rlch_identity_shadow_password_presence "$P")" = EMPTY ]
}
@test "idobs shadow extension preserves prior kinds and exact marker API" {
    run rlch_identity_rows "$P" passwd; [ "$status" -eq 0 ]; [ "$output" = $'0\n1001' ]
    run rlch_identity_password_markers "$P"; [ "$status" -eq 0 ]; [ "$output" = $'OTHER\nX' ]
    unknown "$P" shadow_presence
    shadow_row '!'; run rlch_identity_password_markers "$P"; [ "$status" -eq 2 ]; [ -z "$output" ]
}


# Raw GID field projection; artificial passwd/group rows only.
gid_passwd() { printf 'PRIVATE_NAME:%s:%s:%s::/PRIVATE_HOME:/bin/false\n' "$1" "$2" "$3" > "$P"; }
gid_group() { printf 'PRIVATE_GROUP:%s:%s:PRIVATE_MEMBER\n' "$1" "$2" > "$G"; }
gid_error() { run rlch_identity_gid_fields "$1" "$2"; [ "$status" -eq 2 ]; [ -z "$output" ]; }
@test "idobs GID passwd projection is field four not UID" {
    gid_passwd PRIVATE_SENTINEL 11111 42
    run rlch_identity_gid_fields "$P" passwd; [ "$status" -eq 0 ]; [ "$output" = 'PRESENT|PRESENT|DECIMAL|42' ]
}
@test "idobs GID group projection is field three without members" {
    gid_group PRIVATE_SENTINEL 42
    run rlch_identity_gid_fields "$G" group; [ "$status" -eq 0 ]; [ "$output" = 'PRESENT|PRESENT|NA|42' ]
}
@test "idobs GID zero and leading zero spellings preserved" {
    for gid in 0 00 42 0042 000000000042; do
        gid_passwd x 1001 "$gid"; gid_group x "$gid"
        run rlch_identity_gid_fields "$P" passwd; [ "$status" -eq 0 ]; [ "$output" = "PRESENT|PRESENT|DECIMAL|$gid" ]
        run rlch_identity_gid_fields "$G" group; [ "$status" -eq 0 ]; [ "$output" = "PRESENT|PRESENT|NA|$gid" ]
    done
}
@test "idobs GID textual decimal capture is not an unsigned numeric conversion" {
    for gid in 4294967295 18446744073709551616 000429496729599999999999999999; do
        gid_passwd x 999999999999999999999 "$gid"; run rlch_identity_gid_fields "$P" passwd
        [ "$status" -eq 0 ]; [ "$output" = "PRESENT|PRESENT|DECIMAL|$gid" ]
    done
}
@test "idobs GID second field empty has only presence token" {
    gid_passwd '' 1001 42; gid_group '' 42
    run rlch_identity_gid_fields "$P" passwd; [ "$status" -eq 0 ]; [ "$output" = 'PRESENT|EMPTY|DECIMAL|42' ]
    run rlch_identity_gid_fields "$G" group; [ "$status" -eq 0 ]; [ "$output" = 'PRESENT|EMPTY|NA|42' ]
}
@test "idobs GID name presence is classification not name policy" {
    printf ':x:1001:42::/:/bin/false\n+:x:1002:42::/:/bin/false\n' > "$P"
    run rlch_identity_gid_fields "$P" passwd; [ "$status" -eq 0 ]; [ "$output" = $'EMPTY|PRESENT|DECIMAL|42\nPRESENT|PRESENT|DECIMAL|42' ]
}
@test "idobs GID nondecimal UID classification contains no raw value" {
    for uid in '' -1 +1 PRIVATE_SENTINEL ' 1'; do
        gid_passwd x "$uid" 42; run rlch_identity_gid_fields "$P" passwd
        [ "$status" -eq 0 ]; [ "$output" = 'PRESENT|PRESENT|OTHER|42' ]
    done
}
@test "idobs GID nondecimal group ID withheld as NONE" {
    for gid in '' -1 +42 PRIVATE_SENTINEL '42 '; do
        gid_passwd x 1001 "$gid"; gid_group x "$gid"
        run rlch_identity_gid_fields "$P" passwd; [ "$status" -eq 0 ]; [ "$output" = 'PRESENT|PRESENT|DECIMAL|NONE' ]
        run rlch_identity_gid_fields "$G" group; [ "$status" -eq 0 ]; [ "$output" = 'PRESENT|PRESENT|NA|NONE' ]
    done
}
@test "idobs GID aliases repeated names repeated rows and order retained" {
    printf 'same:x:1001:42::/:/bin/false\nsame:x:1002:0042::/:/bin/false\nother:x:1001:42::/:/bin/false\n' > "$P"
    printf 'same:x:42:\nsame:x:42:\nalias:x:0042:\n' > "$G"
    run rlch_identity_gid_fields "$P" passwd; [ "$status" -eq 0 ]; [ "$output" = $'PRESENT|PRESENT|DECIMAL|42\nPRESENT|PRESENT|DECIMAL|0042\nPRESENT|PRESENT|DECIMAL|42' ]
    run rlch_identity_gid_fields "$G" group; [ "$status" -eq 0 ]; [ "$output" = $'PRESENT|PRESENT|NA|42\nPRESENT|PRESENT|NA|42\nPRESENT|PRESENT|NA|0042' ]
}
@test "idobs GID passthrough invalid source framing is ERROR" {
    printf 'bad:PRIVATE:1\n' > "$P"; gid_error "$P" passwd
    printf 'bad:PRIVATE:1::extra\n' > "$G"; gid_error "$G" group
}
@test "idobs GID empty and absent bases ERROR" {
    : > "$P"; : > "$G"; gid_error "$P" passwd; gid_error "$G" group
    rm "$P" "$G"; gid_error "$P" passwd; gid_error "$G" group
}
@test "idobs GID unsafe permissions reject both sources" {
    chmod 0666 "$P" "$G"; gid_error "$P" passwd; gid_error "$G" group
    chmod 0000 "$P" "$G"; gid_error "$P" passwd; gid_error "$G" group
}
@test "idobs GID symlinks rejected on both sources" {
    mv "$P" "$P.real"; ln -s "$P.real" "$P"; gid_error "$P" passwd
    mv "$G" "$G.real"; ln -s "$G.real" "$G"; gid_error "$G" group
}
@test "idobs GID ancestor aliases rejected" {
    mkdir "$BATS_TEST_TMPDIR/dir"; cp "$P" "$BATS_TEST_TMPDIR/dir/passwd"
    ln -s "$BATS_TEST_TMPDIR/dir" "$BATS_TEST_TMPDIR/alias"; gid_error "$BATS_TEST_TMPDIR/alias/passwd" passwd
}
@test "idobs GID hardlinks rejected without tightening old projections" {
    ln "$P" "$P.alias"; ln "$G" "$G.alias"; gid_error "$P" passwd; gid_error "$G" group
    run rlch_identity_rows "$P" passwd; [ "$status" -eq 0 ]
}
@test "idobs GID directory and FIFO rejected without opening bodies" {
    rm "$P"; mkdir "$P"; gid_error "$P" passwd; rmdir "$P"; mkfifo "$P"; gid_error "$P" passwd
}
@test "idobs GID NUL and controls fail closed" {
    printf 'name:PRIVATE\000:1:42::/:/bin/false\n' > "$P"; gid_error "$P" passwd
    printf 'name:x:42:PRIVATE\r\n' > "$G"; gid_error "$G" group
}
@test "idobs GID missing final newline rejected" {
    printf 'name:x:1:42::/:/bin/false' > "$P"; gid_error "$P" passwd
}
@test "idobs GID complete-row truncation rejected for passwd and group" {
    printf 'second:x:42:\n' >> "$G"
    rlch_identity_stream() { /usr/bin/head -n 1; }
    gid_error "$P" passwd; gid_error "$G" group
}
@test "idobs GID strengthened byte check does not silently change old UID projection" {
    rlch_identity_stream() { /usr/bin/head -n 1; }
    run rlch_identity_rows "$P" passwd; [ "$status" -eq 0 ]; [ "$output" = 0 ]
    gid_error "$P" passwd
}
@test "idobs GID mid-row zero-byte and appended-record truncation rejected" {
    rlch_identity_stream() { /usr/bin/head -c 10; }; gid_error "$P" passwd
    rlch_identity_stream() { :; }; gid_error "$P" passwd
    rlch_identity_stream() { /usr/bin/cat; printf 'extra:x:1:42::/:/bin/false\n'; }; gid_error "$P" passwd
}
@test "idobs GID producer failure withholds partial projection" {
    rlch_identity_stream() { /usr/bin/cat; return 91; }; gid_error "$P" passwd; gid_error "$G" group
}
@test "idobs GID producer stderr withheld even on exit zero" {
    rlch_identity_stream() { /usr/bin/cat; printf 'PRIVATE_SALT_SENTINEL\n' >&2; }; gid_error "$P" passwd; gid_error "$G" group
}
@test "idobs GID malformed later record withholds prior projection" {
    printf 'BROKEN_PRIVATE_SENTINEL\n' >> "$P"; gid_error "$P" passwd
}
@test "idobs GID mutation during observation rejected" {
    rlch_identity_stream() { /usr/bin/cat; printf 'extra:x:1:42::/:/bin/false\n' >> "$P"; }; gid_error "$P" passwd
}
@test "idobs GID group mutation during observation rejected" {
    rlch_identity_stream() { /usr/bin/cat; printf 'extra:x:42:\n' >> "$G"; }; gid_error "$G" group
}
@test "idobs GID substitution and link changes detected" {
    rlch_identity_stream() { /usr/bin/cat; cp "$P" "$P.new"; mv "$P.new" "$P"; }; gid_error "$P" passwd
    rlch_identity_stream() { /usr/bin/cat; ln "$G" "$G.alias"; }; gid_error "$G" group
}
@test "idobs GID forged terminal frame rejected" {
    printf 'RLCH-IDENTITY-END\n' >> "$P"; gid_error "$P" passwd
}
@test "idobs GID size count and line bounds enforced" {
    awk 'BEGIN {printf "name:x:1:";for(i=0;i<16400;i++) printf "0";print "::/:/bin/false"}' > "$P"; gid_error "$P" passwd
    awk 'BEGIN {for(i=0;i<65537;i++) print "g"i":x:42:"}' > "$G"; gid_error "$G" group
    awk 'BEGIN {for(i=0;i<500;i++) {printf "u%d:x:1:42:",i;for(j=0;j<10000;j++) printf "a";print ":/:/bin/false"}}' > "$P"; gid_error "$P" passwd
}
@test "idobs GID maximum valid count retains duplicates" {
    awk 'BEGIN {for(i=0;i<65536;i++) print "same:x:0042:"}' > "$G"
    rlch_identity_gid_fields "$G" group > "$BATS_TEST_TMPDIR/result"; [ "$(wc -l < "$BATS_TEST_TMPDIR/result")" -eq 65536 ]
}
@test "idobs GID output failure returns silent ERROR" {
    result=0; rlch_identity_gid_fields "$P" passwd > /dev/full 2> "$BATS_TEST_TMPDIR/err" || result=$?
    [ "$result" -eq 2 ]; [ ! -s "$BATS_TEST_TMPDIR/err" ]
}
@test "idobs GID invalid calls and historical kinds remain closed" {
    run rlch_identity_gid_fields; [ "$status" -eq 2 ]; [ -z "$output" ]
    run rlch_identity_gid_fields "$P" shadow; [ "$status" -eq 2 ]; [ -z "$output" ]
    run rlch_identity_gid_fields "$P" passwd extra; [ "$status" -eq 2 ]; [ -z "$output" ]
    unknown "$P" gid_passwd; unknown "$G" gid_group
}
@test "idobs GID stdout stderr and xtrace do not expose private fields" {
    gid_passwd '$6$PRIVATE_SALT$PRIVATE_SENTINEL' 11111 0042
    rlch_identity_gid_fields "$P" passwd > "$BATS_TEST_TMPDIR/out" 2> "$BATS_TEST_TMPDIR/err"
    [ "$(cat "$BATS_TEST_TMPDIR/out")" = 'PRESENT|PRESENT|DECIMAL|0042' ]; [ ! -s "$BATS_TEST_TMPDIR/err" ]
    result=0
    bash -c 'source "$1"; set -x; rc=0; rlch_identity_gid_fields "$2" passwd || rc=$?; set +x; exit "$rc"' bash \
        "$BATS_TEST_DIRNAME/../lib/identity_observation.sh" "$P" > "$BATS_TEST_TMPDIR/out" 2> "$BATS_TEST_TMPDIR/err" || result=$?
    [ "$result" -eq 2 ]; [ ! -s "$BATS_TEST_TMPDIR/out" ]; [[ "$(cat "$BATS_TEST_TMPDIR/err")" != *PRIVATE* ]]
}
@test "idobs GID deterministic and fresh without fixture mutation" {
    gid_passwd PRIVATE_SENTINEL 11111 0042; before="$(stat -c '%d:%i:%a:%u:%g:%s:%y:%z' "$P")"
    a="$(rlch_identity_gid_fields "$P" passwd)"; b="$(rlch_identity_gid_fields "$P" passwd)"; [ "$a" = "$b" ]
    [ "$before" = "$(stat -c '%d:%i:%a:%u:%g:%s:%y:%z' "$P")" ]
    gid_passwd x 11111 42; [ "$(rlch_identity_gid_fields "$P" passwd)" != "$a" ]
}


# Additive UID/source observations: artificial account/configuration fixtures only.
uid_row() { printf 'fixture:x:%s:%s::/fixture:/bin/false\n' "$1" "$2" > "$P"; }
uid_fixture() {
    U_NSS="$BATS_TEST_TMPDIR/uid-nsswitch.conf"
    printf 'passwd: files\n' > "$U_NSS"; uid_row 42 7; chmod 0644 "$P" "$U_NSS"
}
uid_failure() {
    run rlch_identity_uid_values "$P" "$U_NSS"
    [ "$status" -eq 2 ]; [ -z "$output" ]
}
@test "idobs UID canonical values retain duplicate zero system and user UIDs" {
    uid_fixture
    printf 'a:x:0:0::/:/bin/false\nb:x:42:7::/:/bin/false\nc:x:0042:7::/:/bin/false\nd:x:1000:7::/:/bin/false\n' > "$P"
    run rlch_identity_uid_values "$P" "$U_NSS"; [ "$status" -eq 0 ]; [ "$output" = $'SOURCE|FILES\nUID|0\nUID|42\nUID|42\nUID|1000' ]
}
@test "idobs UID UID field is distinct from primary GID" {
    uid_fixture; uid_row 51 72
    run rlch_identity_uid_values "$P" "$U_NSS"; [ "$status" -eq 0 ]; [ "$output" = $'SOURCE|FILES\nUID|51' ]
}
@test "idobs UID arbitrary leading zero count canonicalizes without numeric overflow" {
    uid_fixture
    zeros="$(printf '%1000s' '' | tr ' ' 0)"; uid_row "${zeros}42" 7
    run rlch_identity_uid_values "$P" "$U_NSS"; [ "$status" -eq 0 ]; [[ "$output" == *'UID|42' ]]
}
@test "idobs UID maximum supported UID remains exact" {
    uid_fixture; uid_row 4294967294 4294967294
    run rlch_identity_uid_values "$P" "$U_NSS"; [ "$status" -eq 0 ]; [[ "$output" == *'UID|4294967294' ]]
}
@test "idobs UID invalid and unrepresentable UIDs fail closed" {
    uid_fixture
    for value in '' BAD -1 +42 1.0 4294967295 4294967296 999999999999999999999; do uid_row "$value" 7; uid_failure; done
}
@test "idobs UID invalid primary GID makes libc interpretation uncertain" {
    uid_fixture; uid_row 42 BAD; uid_failure
}
@test "idobs UID empty authentication marker is not an account exclusion" {
    uid_fixture; printf 'fixture::42:7::/:/bin/false\n' > "$P"
    run rlch_identity_uid_values "$P" "$U_NSS"; [ "$status" -eq 0 ]; [[ "$output" == *'UID|42' ]]
}
@test "idobs UID duplicate account names fail closed independently of UID policy" {
    uid_fixture; printf 'fixture:x:99:7::/:/bin/false\n' >> "$P"; uid_failure
}
@test "idobs UID compat and empty names fail closed" {
    uid_fixture
    for value in '+::::::' ':x:42:7::/:/bin/false' '-foo:x:42:7::/:/bin/false'; do printf '%s\n' "$value" > "$P"; uid_failure; done
}
@test "idobs UID passwd field framing rejected without partial projection" {
    uid_fixture
    for value in 'bad:x:42:7' 'bad:x:42:7::/:/bin/false:extra'; do printf '%s\n' "$value" >> "$P"; uid_failure; uid_row 42 7; done
}
@test "idobs UID explicit files source classification ignores unrelated databases" {
    uid_fixture
    printf 'hosts: files dns\npasswd:	files # local\ngroup: files sss\n' > "$U_NSS"
    run rlch_identity_uid_values "$P" "$U_NSS"; [ "$status" -eq 0 ]; [[ "$output" == SOURCE\|FILES* ]]
}
@test "idobs UID external and conditional sources are OTHER facts not CIS findings" {
    uid_fixture
    for value in 'files sss' 'sss files' ldap compat altfiles 'files [SUCCESS=return]' 'files files'; do
     printf 'passwd: %s\n' "$value" > "$U_NSS"; run rlch_identity_uid_values "$P" "$U_NSS"
     [ "$status" -eq 0 ]; [[ "$output" == SOURCE\|OTHER* && "$output" != *"$value"* ]]
    done
}
@test "idobs UID no explicit passwd source is insufficient" {
    uid_fixture; printf 'group: files\n' > "$U_NSS"; uid_failure
}
@test "idobs UID empty and comment-only passwd source invalid" {
    uid_fixture
    for value in 'passwd:' 'passwd: # absent'; do printf '%s\n' "$value" > "$U_NSS"; uid_failure; done
}
@test "idobs UID duplicate or ambiguous passwd declarations invalid" {
    uid_fixture
    for value in 'passwd : files' 'passwd files'; do printf '%s\n' "$value" > "$U_NSS"; uid_failure; done
    printf 'passwd: files\npasswd: files\n' > "$U_NSS"; uid_failure
}
@test "idobs UID both files must be nonempty and present" {
    uid_fixture; : > "$P"; uid_failure; uid_row 42 7; : > "$U_NSS"; uid_failure
    rm "$U_NSS"; uid_failure; uid_fixture; rm "$P"; uid_failure
}
@test "idobs UID symlinks in either source rejected" {
    uid_fixture
    mv "$P" "$P.real"; ln -s "$P.real" "$P"; uid_failure; rm "$P"; mv "$P.real" "$P"
    mv "$U_NSS" "$U_NSS.real"; ln -s "$U_NSS.real" "$U_NSS"; uid_failure
}
@test "idobs UID ancestor symlink rejected" {
    uid_fixture; mkdir "$BATS_TEST_TMPDIR/real"; mv "$P" "$BATS_TEST_TMPDIR/real/passwd"
    ln -s real "$BATS_TEST_TMPDIR/alias"; P="$BATS_TEST_TMPDIR/alias/passwd"; uid_failure
}
@test "idobs UID hardlinks in either source rejected" {
    uid_fixture; ln "$P" "$P.alias"; uid_failure; rm "$P.alias"
    ln "$U_NSS" "$U_NSS.alias"; uid_failure
}
@test "idobs UID unsafe permissions rejected in either source" {
    uid_fixture
    for file in "$P" "$U_NSS"; do for mode in 0666 0664 0000; do chmod "$mode" "$file"; uid_failure; done; chmod 0644 "$file"; done
}
@test "idobs UID special objects rejected without reading bodies" {
    uid_fixture; rm "$P"; mkfifo "$P"; uid_failure; rm "$P"; mkdir "$P"; uid_failure
}
@test "idobs UID producer errors discard complete prefix" {
    uid_fixture; rlch_identity_stream() { /usr/bin/cat; return 87; }; uid_failure
}
@test "idobs UID producer stderr is private and invalidates observation" {
    uid_fixture; rlch_identity_stream() { /usr/bin/cat; printf 'PRIVATE_SENTINEL\n' >&2; }; uid_failure
}
@test "idobs UID complete-row silent passwd truncation detected" {
    uid_fixture
    printf 'second:x:42:7::/:/bin/false\n' >> "$P"
    rlch_identity_stream() { /usr/bin/head -n 1; }; uid_failure
}
@test "idobs UID complete-row silent NSS truncation detected even after passwd declaration" {
    uid_fixture; printf 'group: files sss\n' >> "$U_NSS"
    rlch_identity_stream() { /usr/bin/head -n 1; }; uid_failure
}
@test "idobs UID identical truncated reads cannot become complete evidence" {
    uid_fixture; printf 'second:x:42:7::/:/bin/false\n' >> "$P"
    rlch_identity_stream() { /usr/bin/head -n 1; }; uid_failure; uid_failure
}
@test "idobs UID mid-record and zero-byte truncation rejected" {
    uid_fixture; rlch_identity_stream() { /usr/bin/head -c 10; }; uid_failure
    rlch_identity_stream() { :; }; uid_failure
}
@test "idobs UID missing final newline invalid in both sources" {
    uid_fixture; printf 'fixture:x:42:7::/:/bin/false' > "$P"; uid_failure; uid_row 42 7
    printf 'passwd: files' > "$U_NSS"; uid_failure
}
@test "idobs UID NUL and control bytes invalid in either source" {
    uid_fixture; printf 'fixture:PRIVATE\000:42:7::/:/bin/false\n' > "$P"; uid_failure; uid_row 42 7
    printf 'passwd: files\r\n' > "$U_NSS"; uid_failure
}
@test "idobs UID whole-record mutation detected" {
    uid_fixture
    rlch_identity_stream() { /usr/bin/cat; printf 'later:x:99:7::/:/bin/false\n' >> "$P"; }; uid_failure
}
@test "idobs UID hardlink added while reading detected" {
    uid_fixture
    rlch_identity_stream() { /usr/bin/cat; ln "$U_NSS" "$U_NSS.alias"; }; uid_failure
}
@test "idobs UID line size bound enforced" {
    uid_fixture; printf 'fixture:%17000s:42:7::/:/bin/false\n' X > "$P"; uid_failure
}
@test "idobs UID entry count bound enforced" {
    uid_fixture
    awk 'BEGIN{for(i=0;i<65537;i++) print "u"i":x:42:7::/:/bin/false"}' > "$P"; uid_failure
}
@test "idobs UID aggregate byte bound enforced" {
    uid_fixture
    awk 'BEGIN{for(i=0;i<500;i++){printf "u%d:",i;for(j=0;j<10000;j++)printf "x";print ":42:7::/:/bin/false"}}' > "$P"; uid_failure
}
@test "idobs UID maximum supported record count preserves every duplicate" {
    uid_fixture
    awk 'BEGIN{for(i=0;i<65536;i++) print "u"i":x:42:7::/:/bin/false"}' > "$P"
    rlch_identity_uid_values "$P" "$U_NSS" > "$BATS_TEST_TMPDIR/result"; [ "$(wc -l < "$BATS_TEST_TMPDIR/result")" -eq 65537 ]
}
@test "idobs UID exact byte limit guards appended or forged terminal data" {
    uid_fixture
    rlch_identity_stream() { /usr/bin/cat; printf 'RLCH-IDENTITY-END\n'; }; uid_failure
}
@test "idobs UID no secret name hash or member data escapes either output" {
    uid_fixture
    printf 'PRIVATE_ACCOUNT:$6$PRIVATE_SALT$PRIVATE_SENTINEL:42:7:PRIVATE_GECOS:/PRIVATE_HOME:/bin/false\n' > "$P"
    rlch_identity_uid_values "$P" "$U_NSS" > "$BATS_TEST_TMPDIR/out" 2> "$BATS_TEST_TMPDIR/err"
    [ "$(cat "$BATS_TEST_TMPDIR/out")" = $'SOURCE|FILES\nUID|42' ]; [ ! -s "$BATS_TEST_TMPDIR/err" ]
    bash -c 'source "$1"; set -x; rc=0; rlch_identity_uid_values "$2" "$3" || rc=$?; set +x; exit "$rc"' bash  "$BATS_TEST_DIRNAME/../lib/identity_observation.sh" "$P" "$U_NSS" > "$BATS_TEST_TMPDIR/trace" 2>&1 || :
    run /usr/bin/grep -q 'PRIVATE_' "$BATS_TEST_TMPDIR/trace"; [ "$status" -eq 1 ]
}
@test "idobs UID wrong argument counts rejected silently" {
    uid_fixture
    run rlch_identity_uid_values; [ "$status" -eq 2 ]; [ -z "$output" ]
    run rlch_identity_uid_values "$P"; [ "$status" -eq 2 ]; [ -z "$output" ]
    run rlch_identity_uid_values "$P" "$U_NSS" extra; [ "$status" -eq 2 ]; [ -z "$output" ]
}
@test "idobs UID deterministic fresh reads preserve content mode and ownership" {
    uid_fixture
    before="$(stat -c '%i:%a:%u:%g:%Y:%Z:%s' "$P" "$U_NSS")"
    a="$(rlch_identity_uid_values "$P" "$U_NSS")"; b="$(rlch_identity_uid_values "$P" "$U_NSS")"; [ "$a" = "$b" ]
    [ "$before" = "$(stat -c '%i:%a:%u:%g:%Y:%Z:%s' "$P" "$U_NSS")" ]
    uid_row 43 7; [ "$(rlch_identity_uid_values "$P" "$U_NSS")" != "$a" ]
}
@test "idobs UID output failure is ERROR rather than successful observation" {
    uid_fixture; result=0
    rlch_identity_uid_values "$P" "$U_NSS" > /dev/full 2> "$BATS_TEST_TMPDIR/err" || result=$?; [ "$result" -eq 2 ]
}

@test "idobs UID native blank comments and leading spaces do not invent accounts" {
    uid_fixture
    printf '\n# ignored:PRIVATE_SENTINEL:42:7::/:/bin/false\n  # ignored too\n  fixture:x:00042:7::/:/bin/false\n' > "$P"
    run rlch_identity_uid_values "$P" "$U_NSS"
    [ "$status" -eq 0 ]; [ "$output" = $'SOURCE|FILES\nUID|42' ]
    printf '# only comments\n\n' > "$P"; uid_failure
}


# Additive strict local username projection; artificial fixtures only.
name_row() { printf '%s:x:42:7::/fixture:/bin/false\n' "$1" > "$P"; }
name_failure() { run rlch_identity_user_names "$P"; [ "$status" -eq 2 ]; [ -z "$output" ]; }
@test "idobs names unique rows preserve exact input order" {
    printf 'root:x:0:0::/:/bin/false\nsystem:x:1:7::/:/sbin/nologin\nuser:x:1000:7::/:/bin/bash\n' > "$P"
    run rlch_identity_user_names "$P"; [ "$status" -eq 0 ]; [ "$output" = $'NAME|root\nNAME|system\nNAME|user' ]
}
@test "idobs names nonadjacent duplicates and identical rows are valid evidence" {
    printf 'same:x:0:0::/:/bin/false\nother:x:1:7::/:/bin/bash\nsame:x:2:8::/:/bin/false\nsame:x:2:8::/:/bin/false\n' > "$P"
    run rlch_identity_user_names "$P"; [ "$status" -eq 0 ]; [ "$output" = $'NAME|same\nNAME|other\nNAME|same\nNAME|same' ]
}
@test "idobs names case and leading trailing internal spaces remain exact" {
    printf 'Alice:x:1:7::/:/bin/false\nalice:x:2:7::/:/bin/false\n Alice :x:3:7::/:/bin/false\na  b:x:4:7::/:/bin/false\n' > "$P"
    run rlch_identity_user_names "$P"; [ "$status" -eq 0 ]; [ "$output" = $'NAME|Alice\nNAME|alice\nNAME| Alice \nNAME|a  b' ]
}
@test "idobs names numeric spellings and marker-like names are unambiguous" {
    printf '01:x:1:7::/:/bin/false\n1:x:1:7::/:/bin/false\nSKIP:x:1:7::/:/bin/false\nNAME|a:x:1:7::/:/bin/false\n' > "$P"
    run rlch_identity_user_names "$P"; [ "$status" -eq 0 ]; [ "$output" = $'NAME|01\nNAME|1\nNAME|SKIP\nNAME|NAME|a' ]
}
@test "idobs names Unicode bytes are retained without case or normalization changes" {
    printf 'élève:x:1:7::/:/bin/false\nÉlève:x:2:7::/:/bin/false\ne\314\201:x:3:7::/:/bin/false\né:x:4:7::/:/bin/false\n' > "$P"
    run rlch_identity_user_names "$P"; [ "$status" -eq 0 ]; [ "$output" = $'NAME|élève\nNAME|Élève\nNAME|e\314\201\nNAME|é' ]
}
@test "idobs names valid two three and four-byte UTF-8 survives projection" {
    printf '\302\242\342\202\254\360\237\230\200:x:1:7::/:/bin/false\n' > "$P"
    run rlch_identity_user_names "$P"; [ "$status" -eq 0 ]; [ "$output" = $'NAME|\302\242\342\202\254\360\237\230\200' ]
}
@test "idobs names invalid UTF-8 including overlong surrogate and out-of-range is ERROR" {
    for bytes in '\200' '\300\257' '\342\202' '\355\240\200' '\364\220\200\200' '\365\200\200\200'; do
        printf '%b:x:1:7::/:/bin/false\n' "$bytes" > "$P"; name_failure
    done
}
@test "idobs names UTF-8 validation covers unprojected source fields too" {
    printf 'user:x:1:7:PRIVATE\377:/:/bin/false\n' > "$P"; name_failure
}
@test "idobs names empty first field is SKIP and not a reader failure" {
    printf ':PRIVATE_AUTH:1:7::/:/bin/false\nuser:x:2:7::/:/bin/false\n' > "$P"
    run rlch_identity_user_names "$P"; [ "$status" -eq 0 ]; [ "$output" = $'SKIP\nNAME|user' ]
    printf ':x:1:7::/:/bin/false\n' > "$P"; run rlch_identity_user_names "$P"; [ "$status" -eq 0 ]; [ "$output" = SKIP ]
}
@test "idobs names no UID GID authentication or shell selection is imposed" {
    printf 'a::BAD:-1::/:/sbin/nologin\nb:PRIVATE:999999999999999999:OTHER::/:/bin/false\nc::::::\n' > "$P"
    run rlch_identity_user_names "$P"; [ "$status" -eq 0 ]; [ "$output" = $'NAME|a\nNAME|b\nNAME|c' ]
}
@test "idobs names plus minus comment-like and whitespace names are text captures" {
    printf '+:x:1:7::/:/bin/false\n-foo:x:1:7::/:/bin/false\n#name:x:1:7::/:/bin/false\n :x:1:7::/:/bin/false\n' > "$P"
    run rlch_identity_user_names "$P"; [ "$status" -eq 0 ]; [ "$output" = $'NAME|+\nNAME|-foo\nNAME|#name\nNAME| ' ]
}
@test "idobs names malformed field counts withhold an otherwise valid prefix" {
    for bad in 'PRIVATE_BROKEN:x:1' 'bad:x:1:7::/:/bin/false:extra'; do name_row good; printf '%s\n' "$bad" >> "$P"; name_failure; done
}
@test "idobs names blank and unsupported comment lines fail closed" {
    printf '\n' >> "$P"; name_failure; printf '# PRIVATE_COMMENT\n' > "$P"; name_failure
}
@test "idobs names empty missing directory and FIFO are ERROR" {
    : > "$P"; name_failure; rm "$P"; name_failure; mkdir "$P"; name_failure; rmdir "$P"; mkfifo "$P"; name_failure
}
@test "idobs names unsafe modes and unreadable-bit source rejected" {
    for mode in 0666 0664 0000; do chmod "$mode" "$P"; name_failure; done
}
@test "idobs names symlink and symlink ancestor rejected" {
    mv "$P" "$P.real"; ln -s "$P.real" "$P"; name_failure; rm "$P"
    mkdir "$P.dir"; cp "$P.real" "$P.dir/passwd"; ln -s "$P.dir" "$P"; P="$P/passwd"; name_failure
}
@test "idobs names hardlinks rejected" { ln "$P" "$P.alias"; name_failure; }
@test "idobs names relative or noncanonical path rejected" {
    P="$BATS_TEST_TMPDIR/./passwd"; name_failure; P=relative; name_failure
}
@test "idobs names complete-row truncation cannot hide later duplicate" {
    name_row same; printf 'same:x:9:8::/:/bin/false\n' >> "$P"
    rlch_identity_stream() { /usr/bin/head -n 1; }; name_failure
}
@test "idobs names two identically truncated reads do not prove completeness" {
    name_row same; printf 'same:x:9:8::/:/bin/false\n' >> "$P"
    rlch_identity_stream() { /usr/bin/head -n 1; }; name_failure; name_failure
}
@test "idobs names mid-record and zero-byte truncation are ERROR" {
    rlch_identity_stream() { /usr/bin/head -c 5; }; name_failure; rlch_identity_stream() { :; }; name_failure
}
@test "idobs names producer failure discards full prefix" {
    rlch_identity_stream() { /usr/bin/cat; return 87; }; name_failure
}
@test "idobs names producer stderr invalidates and remains private" {
    rlch_identity_stream() { /usr/bin/cat; printf 'PRIVATE_AUTH_SENTINEL\n' >&2; }; name_failure
}
@test "idobs names appended rows and forged frame are ERROR" {
    rlch_identity_stream() { /usr/bin/cat; printf 'extra:x:1:7::/:/bin/false\n'; }; name_failure
    rlch_identity_stream() { /usr/bin/cat; printf 'RLCH-IDENTITY-END\n'; }; name_failure
}
@test "idobs names missing final newline rejected" { printf 'name:x:1:7::/:/bin/false' > "$P"; name_failure; }
@test "idobs names NUL tabs and control bytes in any field rejected" {
    printf 'name:PRIVATE\000:1:7::/:/bin/false\n' > "$P"; name_failure
    printf 'na\tme:x:1:7::/:/bin/false\n' > "$P"; name_failure
    printf 'name:x:1:7:PRIVATE\r:/:/bin/false\n' > "$P"; name_failure
}
@test "idobs names mutation during reading is ERROR" {
    rlch_identity_stream() { /usr/bin/cat; printf 'later:x:1:7::/:/bin/false\n' >> "$P"; }; name_failure
}
@test "idobs names pathname replacement and link creation are ERROR" {
    rlch_identity_stream() { /usr/bin/cat; cp "$P" "$P.new"; mv "$P.new" "$P"; }; name_failure
    rlch_identity_stream() { /usr/bin/cat; ln "$P" "$P.alias"; }; name_failure
}
@test "idobs names line length bound applies to names and unprojected fields" {
    printf '%17000s:x:1:7::/:/bin/false\n' X > "$P"; name_failure
    printf 'name:%17000s:1:7::/:/bin/false\n' X > "$P"; name_failure
}
@test "idobs names entry count bound rejects complete oversized inventory" {
    awk 'BEGIN{for(i=0;i<65537;i++)print "same:x:1:7::/:/bin/false"}' > "$P"; name_failure
}
@test "idobs names aggregate bytes include unprojected authentication fields" {
    awk 'BEGIN{for(i=0;i<500;i++){printf "same:";for(j=0;j<10000;j++)printf "x";print ":1:7::/:/bin/false"}}' > "$P"; name_failure
}
@test "idobs names maximum supported count preserves every duplicate instance" {
    awk 'BEGIN{for(i=0;i<65536;i++)print "same:x:1:7::/:/bin/false"}' > "$P"
    rlch_identity_user_names "$P" > "$BATS_TEST_TMPDIR/result"; [ "$(wc -l < "$BATS_TEST_TMPDIR/result")" -eq 65536 ]
    [ "$(sort -u "$BATS_TEST_TMPDIR/result")" = 'NAME|same' ]
}
@test "idobs names only controlled name projection leaves parser" {
    printf 'VISIBLE_NAME:$6$PRIVATE_SALT$PRIVATE_HASH:424242:737373:PRIVATE_GECOS:/PRIVATE_HOME:/PRIVATE_SHELL\n' > "$P"
    rlch_identity_user_names "$P" > "$BATS_TEST_TMPDIR/out" 2> "$BATS_TEST_TMPDIR/err"
    [ "$(cat "$BATS_TEST_TMPDIR/out")" = 'NAME|VISIBLE_NAME' ]; [ ! -s "$BATS_TEST_TMPDIR/err" ]
}
@test "idobs names xtrace hides names and credentials and preserves caller trace state" {
    printf 'PRIVATE_NAME:$6$PRIVATE_SALT$PRIVATE_HASH:1:7::/:/bin/false\n' > "$P"
    run bash -c 'source "$1"; set -x; rlch_identity_user_names "$2" >/dev/null; [[ $- == *x* ]]' bash "$BATS_TEST_DIRNAME/../lib/identity_observation.sh" "$P"
    [ "$status" -eq 0 ]; [[ "$output" != *PRIVATE* ]]
}
@test "idobs names producer error under xtrace cannot reveal raw sentinels" {
    name_row PRIVATE_NAME
    run bash -c 'source "$1"; rlch_identity_stream() { /usr/bin/cat; printf PRIVATE_AUTH >&2; }; set -x; rlch_identity_user_names "$2"' bash "$BATS_TEST_DIRNAME/../lib/identity_observation.sh" "$P"
    [ "$status" -eq 2 ]; [[ "$output" != *PRIVATE* ]]
}
@test "idobs names stdout failure returns silent ERROR" {
    result=0; rlch_identity_user_names "$P" > /dev/full 2> "$BATS_TEST_TMPDIR/err" || result=$?
    [ "$result" -eq 2 ]; [ ! -s "$BATS_TEST_TMPDIR/err" ]
}
@test "idobs names wrong argument counts fail silently" {
    run rlch_identity_user_names; [ "$status" -eq 2 ]; [ -z "$output" ]
    run rlch_identity_user_names "$P" extra; [ "$status" -eq 2 ]; [ -z "$output" ]
}
@test "idobs names deterministic fresh observations preserve fixture metadata and content" {
    before="$(stat -c '%i:%a:%u:%g:%Y:%Z:%s' "$P")"; data="$(sha256sum "$P")"
    a="$(rlch_identity_user_names "$P")"; b="$(rlch_identity_user_names "$P")"; [ "$a" = "$b" ]
    [ "$before" = "$(stat -c '%i:%a:%u:%g:%Y:%Z:%s' "$P")" ]; [ "$data" = "$(sha256sum "$P")" ]
    name_row changed; [ "$a" != "$(rlch_identity_user_names "$P")" ]
}
@test "idobs names additive mode does not change old public kinds or duplicate rejection" {
    unknown "$P" user_names
    name_row same; printf 'same:x:9:8::/:/bin/false\n' >> "$P"
    run rlch_identity_rows "$P" passwd; [ "$status" -eq 2 ]
    run rlch_identity_gid_fields "$P" passwd; [ "$status" -eq 0 ]; [ "$output" = $'PRESENT|PRESENT|DECIMAL|7\nPRESENT|PRESENT|DECIMAL|8' ]
    printf 'passwd: files\n' > "$N"; run rlch_identity_uid_values "$P" "$N"; [ "$status" -eq 2 ]
    run rlch_identity_user_names "$P"; [ "$status" -eq 0 ]; [ "$output" = $'NAME|same\nNAME|same' ]
}
