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
