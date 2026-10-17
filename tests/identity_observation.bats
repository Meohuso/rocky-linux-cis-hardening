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
