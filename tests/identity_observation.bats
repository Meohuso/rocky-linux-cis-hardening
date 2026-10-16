#!/usr/bin/env bats
# shellcheck source-path=SCRIPTDIR
# shellcheck disable=SC2317 # Fault injection through sourced API.
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
