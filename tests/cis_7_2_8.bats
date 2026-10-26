#!/usr/bin/env bats
# shellcheck source-path=SCRIPTDIR
# shellcheck disable=SC2317 # Fault injection via sourced APIs.
# shellcheck disable=SC2030,SC2031 # Bats run isolates shell variables.
# shellcheck disable=SC2016 # Literal artificial credentials/hostile-looking data.
setup() {
    source "$BATS_TEST_DIRNAME/test_helper.bash"
    source "$BATS_TEST_DIRNAME/../lib/common.sh"
    source "$BATS_TEST_DIRNAME/../lib/module_api.sh"
    export RLCH_CIS_7_2_8_PASSWD="$BATS_TEST_TMPDIR/passwd" RLCH_CIS_7_2_8_RPM="$BATS_TEST_TMPDIR/rpm"
    export PACKAGES="$BATS_TEST_TMPDIR/packages" FLAG="$BATS_TEST_TMPDIR/flag" COUNT="$BATS_TEST_TMPDIR/count"
    P="$RLCH_CIS_7_2_8_PASSWD"; H="$BATS_TEST_TMPDIR/home"; J="$BATS_TEST_TMPDIR/other"; N="$BATS_TEST_TMPDIR/nsswitch.conf"
    mkdir "$H" "$J"; chmod 0750 "$H" "$J"
    U="$(id -u)"; UT="$(printf '%04d' "$U")"
    printf 'user:PRIVATE_AUTH:%s:7:PRIVATE_GECOS:%s:/bin/bash\n' "$UT" "$H" > "$P"; chmod 0644 "$P"
    printf 'RPM1|1|kernel-core|0|1|1|x86_64|END\n' > "$PACKAGES"
    printf '#!/usr/bin/env bash\n/usr/bin/cat "$PACKAGES"\n' > "$RLCH_CIS_7_2_8_RPM"; chmod 0700 "$RLCH_CIS_7_2_8_RPM"
    printf 'passwd: files\n' > "$N"
    source "$BATS_TEST_DIRNAME/../modules/cis/7/2/8/module.sh"
}
uncertain() {
    run check; [ "$status" -eq 2 ]; [[ "$output" == *'ERROR/ERROR/ERROR'* && "$output" != *PRIVATE* ]]; [ "${#output}" -lt 300 ]
}
row() { printf '%s:x:%s:7::%s:%s\n' "$1" "$2" "$3" "$4"; }
# Only policy fixtures substitute numeric st_uid: all metadata reads, framing,
# source completeness and real-I/O tests run the actual implementation.
policy_owners() {
    _rlch_identity_home_stat() {
        local data first rest dev ino uid
        data="$(/usr/bin/stat -c '%f|%d|%i|%u|%g|%a|%h|%y|%z' -- "$1" 2>/dev/null)" || return 2
        case "$1" in */home) uid="$OWNER_H";; */other) uid="$OWNER_J";; *) printf '%s\n' "$data"; return;; esac
        IFS='|' read -r first dev ino rest <<< "$data"
        rest="${rest#*|}"
        printf '%s|%s|%s|%s|%s\n' "$first" "$dev" "$ino" "$uid" "$rest"
    }
}
@test "7.2.8 metadata aggregate manual mapping and public lifecycle" {
    source "$BATS_TEST_DIRNAME/../modules/cis/7/2/8/metadata.conf"
    [ "$RLCH_MODULE_ID" = 7.2.8 ]; [ "$RLCH_MODULE_LEVEL" = 1 ]; [ "$RLCH_MODULE_ENABLED" = true ]; [ "$RLCH_MODULE_REQUIRES_REBOOT" = false ]; [ "$RLCH_MODULE_OPENSCAP_RULE" = manual ]
    validate_loaded_module_metadata 7.2.8; validate_loaded_module_functions
}
@test "7.2.8 framework loads after previous control" {
    source "$BATS_TEST_DIRNAME/../lib/modules.sh"
    RLCH_MODULE_ROOT="$BATS_TEST_DIRNAME/../modules"; RLCH_MODULE_NAMESPACE=cis; RLCH_MODULE_METADATA_FILENAME=metadata.conf; RLCH_MODULE_IMPLEMENTATION_FILENAME=module.sh
    load_module "$BATS_TEST_DIRNAME/../modules/cis/7/2/7"; load_module "$BATS_TEST_DIRNAME/../modules/cis/7/2/8"
    [ "$RLCH_CURRENT_MODULE_ID" = 7.2.8 ]; run check; [ "$status" -eq 0 ]
}
@test "7.2.8 one real local interactive home SUCCESS with traceable subresults" {
    run check; [ "$status" -eq 0 ]; [[ "$output" == *'SUCCESS/SUCCESS/SUCCESS'* && "$output" == *'home captures=1 distinct=1 existing=1'* ]]
}
@test "7.2.8 UID text 0001 0999 1000 and longer selects without numeric threshold" {
    for text in 0001 0999 1000 10000 0000000001; do
        row user "$text" "$H" /bin/bash > "$P"; run check; [ "$status" -eq 1 ]; [[ "$output" == *'SUCCESS/NON_COMPLIANT/SUCCESS'* && "$output" == *'home captures=1'* ]]
    done
}
@test "7.2.8 fewer than four UID digits do not initially select system accounts" {
    for text in 0 1 999; do row user "$text" "$H" /bin/bash > "$P"; run check; [ "$status" -eq 0 ]; [[ "$output" == *'home captures=0'* ]]; done
}
@test "7.2.8 nobody and nfsnobody exact exclusions only" {
    row nobody 65534 "$H" /bin/bash > "$P"; row nfsnobody 65534 "$J" /bin/bash >> "$P"
    run check; [ "$status" -eq 0 ]; [[ "$output" == *'home captures=0'* ]]
    row Nobody 65534 "$H" /bin/bash >> "$P"; run check; [ "$status" -eq 1 ]; [[ "$output" == *'home captures=1'* ]]
}
@test "7.2.8 four nologin false shell prefixes excluded exactly as macro" {
    for shell in /sbin/nologin /usr/sbin/nologin /bin/false /usr/bin/false /sbin/nologin.extra /bin/false.extra; do
        row user "$UT" "$H" "$shell" > "$P"; run check; [ "$status" -eq 0 ]; [[ "$output" == *'home captures=0'* ]]
    done
}
@test "7.2.8 unknown and empty shells remain selected without etc shells" {
    for shell in /PRIVATE_UNKNOWN ''; do row user "$UT" "$H" "$shell" > "$P"; run check; [ "$status" -eq 0 ]; [[ "$output" == *'home captures=1'* ]]; done
}
@test "7.2.8 empty home is absent from home captures as pinned extraction specifies" {
    row user "$UT" '' /bin/bash > "$P"; run check; [ "$status" -eq 0 ]; [[ "$output" == *'home captures=0 distinct=0 existing=0'* ]]
}
@test "7.2.8 no selected accounts is complete empty OVAL domain not fake NOT_APPLICABLE" {
    row root 0 /root /bin/bash > "$P"; run check; [ "$status" -eq 0 ]; [[ "$output" == *'SUCCESS/SUCCESS/SUCCESS'* && "$output" == *'home captures=0'* ]]
}
@test "7.2.8 dot matches another character and can select initially noninteractive row" {
    row a.b "$UT" '' /bin/bash > "$P"; row axb "$U" "$H" /bin/false >> "$P"
    # Noninteractive spelling for all UIDs, including four-digit CI EUID.
    sed -i "2s/:$U:/:000$U:/" "$P"
    run check; [ "$status" -eq 1 ]; [[ "$output" == *'SUCCESS/NON_COMPLIANT/SUCCESS'* && "$output" == *'home captures=1'* ]]
}
@test "7.2.8 overlapping dot patterns retain all capture multiplicities" {
    row a.b "$UT" "$H" /bin/bash > "$P"; row axb 1999 "$J" /bin/bash >> "$P"
    run check; [ "$status" -eq 1 ]; [[ "$output" == *'home captures=3 distinct=2 existing=2'* && "$output" == *'NON_COMPLIANT/NON_COMPLIANT/SUCCESS'* ]]
}
@test "7.2.8 literal dot name alone has one pattern and one subcapture" {
    row a.b "$UT" "$H" /bin/bash > "$P"; run check; [ "$status" -eq 0 ]; [[ "$output" == *'home captures=1'* ]]
}
@test "7.2.8 duplicate names preserved as text instances not silently excluded" {
    row user "$UT" "$H" /bin/bash >> "$P"; run check; [ "$status" -eq 1 ]; [[ "$output" == *'home captures=2 distinct=1 existing=1'* ]]
}
@test "7.2.8 unsupported capturing lookaround classes escapes alternation quantifiers ERROR" {
    for name in '(a)(b)' 'a(?=b)b' '(?<=a)b' '(?:a)' '[ab]' 'a|b' 'a\1' 'a+' 'a*' 'a?' 'a{2}' '^a' 'a$' '(?C"PRIVATE")' 'a['; do
        row "$name" "$UT" "$H" /bin/bash > "$P"; uncertain
    done
}
@test "7.2.8 unsupported names even in initially unselected accounts invalidate evidence" {
    row '(a)(b)' 0 '' /bin/false >> "$P"; uncertain
}
@test "7.2.8 Unicode in selected and unselected source always ERROR within ASCII domain" {
    row élève "$UT" "$H" /bin/bash > "$P"; uncertain
    row user "$UT" "$H" /bin/bash > "$P"; row système 0 '' /bin/false >> "$P"; uncertain
}
@test "7.2.8 invalid UTF-8 and malformed or blank source withhold all conclusions" {
    printf 'PRIVATE\377:x:1000:7::/fixture:/bin/bash\n' >> "$P"; uncertain
    printf 'PRIVATE_BROKEN:x:1\n' > "$P"; uncertain; printf '\n' > "$P"; uncertain
}
@test "7.2.8 bounded regex work budget rejected without incomplete selection" {
    awk -v h="$H" 'BEGIN{for(i=0;i<513;i++)print "user"i":x:1000:7::"h":/bin/bash"}' > "$P"; uncertain
}
@test "7.2.8 source bounds include ignored fields and source rows" {
    printf 'user:%17000s:%s:7::%s:/bin/bash\n' X "$UT" "$H" > "$P"; uncertain
    awk -v h="$H" 'BEGIN{for(i=0;i<65537;i++)print "root:x:0:7::"h":/bin/false"}' > "$P"; uncertain
}
@test "7.2.8 missing home yields existence NON_COMPLIANT only" {
    rmdir "$H"; run check; [ "$status" -eq 1 ]; [[ "$output" == *'NON_COMPLIANT/SUCCESS/SUCCESS'* && "$output" == *'existing=0'* ]]
}
@test "7.2.8 shared existing home counted once by file object" {
    row other 1999 "$H" /bin/bash >> "$P"; run check; [ "$status" -eq 1 ]; [[ "$output" == *'NON_COMPLIANT/SUCCESS/SUCCESS'* && "$output" == *'home captures=2 distinct=1 existing=1'* ]]
}
@test "7.2.8 relative home stays selected then safe observation is ERROR" {
    row user "$UT" relative /bin/bash > "$P"; uncertain
}
@test "7.2.8 noncanonical symlink dangling link FIFO and file homes ERROR" {
    row user "$UT" "$BATS_TEST_TMPDIR/./home" /bin/bash > "$P"; uncertain
    row user "$UT" "$H" /bin/bash > "$P"; mv "$H" "$H.real"; ln -s "$H.real" "$H"; uncertain
    rm "$H"; ln -s missing "$H"; uncertain; rm "$H"; mkfifo "$H"; uncertain; rm "$H"; : > "$H"; uncertain
}
@test "7.2.8 unsafe unobservable parent is ERROR rather than missing home finding" {
    row user "$UT" "$BATS_TEST_TMPDIR/missing-parent/home" /bin/bash > "$P"; uncertain
}
@test "7.2.8 source missing unreadable unsafe symlink or hardlink ERROR" {
    for mode in 0000 0664 0666; do chmod "$mode" "$P"; uncertain; done
    chmod 0644 "$P"; ln "$P" "$P.link"; uncertain; rm "$P.link"; mv "$P" "$P.real"; ln -s "$P.real" "$P"; uncertain; rm "$P"; uncertain
}
@test "7.2.8 whole-row identical repeated truncations cannot hide another account" {
    row other 1999 "$J" /bin/bash >> "$P"; rlch_identity_stream() { /usr/bin/head -n 1; }; uncertain; uncertain
}
@test "7.2.8 mid-record zero-byte producer error and stderr ERROR" {
    rlch_identity_stream() { /usr/bin/head -c 10; }; uncertain
    rlch_identity_stream() { :; }; uncertain
    rlch_identity_stream() { /usr/bin/cat; return 87; }; uncertain
    rlch_identity_stream() { /usr/bin/cat; printf PRIVATE_SENTINEL >&2; }; uncertain
}
@test "7.2.8 source NUL missing newline and forged terminal frame ERROR" {
    printf 'a:PRIVATE\000:1000:7::/fixture:/bin/bash\n' > "$P"; uncertain
    printf 'a:x:1000:7::/fixture:/bin/bash' > "$P"; uncertain
    row user "$UT" "$H" /bin/bash > "$P"; rlch_identity_stream() { /usr/bin/cat; printf 'RLCH-IDENTITY-END\n'; }; uncertain
}
@test "7.2.8 source mutation and path replacement have ERROR priority" {
    rlch_identity_stream() { /usr/bin/cat; row later 1999 "$J" /bin/bash >> "$P"; }; uncertain
    rlch_identity_stream() { /usr/bin/cat; cp "$P" "$P.new"; mv "$P.new" "$P"; }; uncertain
}
@test "7.2.8 second real source read failure overrides initial conformity" {
    rlch_identity_stream() { if [[ -f "$FLAG" ]]; then /usr/bin/head -c 5; else touch "$FLAG"; /usr/bin/cat; fi; }; uncertain
}
@test "7.2.8 two real independent source observations required" {
    rlch_identity_stream() { printf 'read\n' >> "$COUNT"; /usr/bin/cat; }
    run check; [ "$status" -eq 0 ]; [ "$(wc -l < "$COUNT")" -eq 2 ]
}
@test "7.2.8 changed directory permissions across metadata observations ERROR" {
    rlch_identity_stream() { /usr/bin/cat; if [[ -f "$FLAG" ]]; then chmod 0777 "$H"; else touch "$FLAG"; fi; }; uncertain
}
@test "7.2.8 replaced directory between complete observations ERROR" {
    rlch_identity_stream() { /usr/bin/cat; if [[ -f "$FLAG" ]]; then mv "$H" "$H.old"; mkdir "$H"; else touch "$FLAG"; fi; }; uncertain
}
@test "7.2.8 metadata collection error overrides known permission finding" {
    chmod 0777 "$H"; rlch_identity_home_metadata() { return 2; }; uncertain
}
@test "7.2.8 multiple correct owners satisfy all three rules" {
    row a 1000 "$H" /bin/bash > "$P"; row b 1001 "$J" /bin/bash >> "$P"; OWNER_H=1000; OWNER_J=1001; policy_owners
    run check; [ "$status" -eq 0 ]; [[ "$output" == *'SUCCESS/SUCCESS/SUCCESS'* ]]
}
@test "7.2.8 swapped owners intentionally satisfy pinned aggregate ownership OVAL" {
    row a 1000 "$H" /bin/bash > "$P"; row b 1001 "$J" /bin/bash >> "$P"; OWNER_H=1001; OWNER_J=1000; policy_owners
    run check; [ "$status" -eq 0 ]; [[ "$output" == *'SUCCESS/SUCCESS/SUCCESS'* ]]
}
@test "7.2.8 owner outside expected UID set NON_COMPLIANT" {
    row user 1999 "$H" /bin/bash > "$P"; run check; [ "$status" -eq 1 ]; [[ "$output" == *'SUCCESS/NON_COMPLIANT/SUCCESS'* ]]
}
@test "7.2.8 repeated directory owner violates uniqueness even if in expected set" {
    row a 1000 "$H" /bin/bash > "$P"; row b 1001 "$J" /bin/bash >> "$P"; OWNER_H=1000; OWNER_J=1000; policy_owners
    run check; [ "$status" -eq 1 ]; [[ "$output" == *'SUCCESS/NON_COMPLIANT/SUCCESS'* ]]
}
@test "7.2.8 repeated numeric UID captures violate only-one membership" {
    row a 0001 "$H" /bin/bash > "$P"; row b 00001 '' /bin/bash >> "$P"; OWNER_H=1; OWNER_J=2; policy_owners
    run check; [ "$status" -eq 1 ]; [[ "$output" == *'SUCCESS/NON_COMPLIANT/SUCCESS'* ]]
}
@test "7.2.8 every forbidden POSIX bit independently causes permission finding" {
    for bit in 04000 02000 01000 00020 00004 00002 00001; do
        chmod "$(printf '%o' "$((0700 | bit))")" "$H"; run check; [ "$status" -eq 1 ]; [[ "$output" == *'SUCCESS/SUCCESS/NON_COMPLIANT'* ]]
    done
}
@test "7.2.8 modes different from 0750 including 0000 remain acceptable" {
    for mode in 0000 0100 0200 0400 0700 0710 0740 0750; do chmod "$mode" "$H"; run check; [ "$status" -eq 0 ]; done; chmod 0750 "$H"
}
@test "7.2.8 missing kernel exempts existence only and still checks ownership permissions" {
    printf 'RPM1|1|bash|0|1|1|x86_64|END\n' > "$PACKAGES"; run check; [ "$status" -eq 0 ]; [[ "$output" == *'NOT_APPLICABLE/SUCCESS/SUCCESS'* ]]
    chmod 0777 "$H"; run check; [ "$status" -eq 1 ]; [[ "$output" == *'NOT_APPLICABLE/SUCCESS/NON_COMPLIANT'* ]]
}
@test "7.2.8 applicability absence does not bypass incomplete passwd" {
    printf 'RPM1|1|bash|0|1|1|x86_64|END\n' > "$PACKAGES"; rm "$P"; uncertain
}
@test "7.2.8 uncertain failed empty and noisy RPM inventories ERROR" {
    : > "$PACKAGES"; uncertain; printf PRIVATE_BROKEN > "$PACKAGES"; uncertain
    printf '#!/bin/bash\nprintf PRIVATE >&2\n' > "$RLCH_CIS_7_2_8_RPM"; uncertain
}
@test "7.2.8 applicability change across observation ERROR" {
    rlch_rpm_package_status() { if [[ -f "$FLAG" ]]; then return 1; fi; touch "$FLAG"; return 0; }; uncertain
}
@test "7.2.8 aggregator prioritizes ERROR then finding and all-NA only defensively" {
    run rlch_7_2_8_result 3 3 3; [ "$status" -eq 3 ]
    run rlch_7_2_8_result 3 0 0; [ "$status" -eq 0 ]
    run rlch_7_2_8_result 3 1 0; [ "$status" -eq 1 ]
    run rlch_7_2_8_result 1 2 0; [ "$status" -eq 2 ]
    run rlch_7_2_8_result 0 0 99; [ "$status" -eq 2 ]
}
@test "7.2.8 all NSS configurations leave local observation unchanged" {
    for src in files 'files sss' 'sss files' ldap compat; do printf 'passwd: %s\n' "$src" > "$N"; run check; [ "$status" -eq 0 ]; done
}
@test "7.2.8 NSS enumeration and recursive filesystem walkers never invoked" {
    getent() { touch "$FLAG"; return 99; }; getpwent() { touch "$FLAG"; return 99; }; rlch_fs_observe() { touch "$FLAG"; return 99; }; find() { touch "$FLAG"; return 99; }
    mkfifo "$H/never-open"; run check; [ "$status" -eq 0 ]; [ ! -e "$FLAG" ]
}
@test "7.2.8 shell and path metacharacters are inert data" {
    row user "$UT" "$H" '\$(touch PRIVATE_FLAG)' > "$P"; run check; [ "$status" -eq 0 ]; [ ! -e PRIVATE_FLAG ]
    K="$BATS_TEST_TMPDIR/\$(touch PRIVATE_FLAG)[*]"; mkdir "$K"; chmod 0750 "$K"; row user "$UT" "$K" /bin/bash > "$P"; run check; [ "$status" -eq 0 ]; [ ! -e PRIVATE_FLAG ]
}
@test "7.2.8 check validate and apply use fresh observations without cache" {
    check; chmod 0777 "$H"; run validate; [ "$status" -eq 1 ]; chmod 0750 "$H"; run check; [ "$status" -eq 0 ]
    rm "$P"; run apply; [ "$status" -eq 2 ]
}
@test "7.2.8 apply observation-only conforms or returns manual ERROR without CHANGED" {
    run apply; [ "$status" -eq 0 ]; chmod 0777 "$H"; run apply; [ "$status" -eq 2 ]; [[ "$output" == *'manual remediation required'* ]]
}
@test "7.2.8 rollback silent idempotent with missing inputs" {
    rm "$P" "$PACKAGES"; run rollback; [ "$status" -eq 0 ]; [ -z "$output" ]; run rollback; [ "$status" -eq 0 ]; [ -z "$output" ]
}
@test "7.2.8 all lifecycle operations preserve fixtures modes contents and file set" {
    printf PRIVATE_CONTENT > "$H/file"; before="$(stat -c '%i:%a:%u:%g:%Y:%Z:%s' "$P" "$H" "$H/file")"; data="$(sha256sum "$P" "$H/file")"; files="$(find "$BATS_TEST_TMPDIR" -type f | sort)"
    check; validate; apply; rollback; check
    [ "$before" = "$(stat -c '%i:%a:%u:%g:%Y:%Z:%s' "$P" "$H" "$H/file")" ]; [ "$data" = "$(sha256sum "$P" "$H/file")" ]; [ "$files" = "$(find "$BATS_TEST_TMPDIR" -type f | sort)" ]
}
@test "7.2.8 administration commands never execute" {
    chown() { touch "$FLAG"; return 99; }; chgrp() { touch "$FLAG"; return 99; }; chmod() { touch "$FLAG"; return 99; }
    setfacl() { touch "$FLAG"; return 99; }; chcon() { touch "$FLAG"; return 99; }; usermod() { touch "$FLAG"; return 99; }
    check; validate; apply; rollback; [ ! -e "$FLAG" ]
}
@test "7.2.8 diagnostics and xtrace never expose internal identities paths UID shells hashes" {
    for scenario in success finding error; do
        row PRIVATE_NAME "$UT" "$H" /PRIVATE_SHELL > "$P"; expected=0
        if [[ "$scenario" == finding ]]; then chmod 0777 "$H"; expected=1; fi
        if [[ "$scenario" == error ]]; then printf 'PRIVATE_BROKEN\n' >> "$P"; expected=2; fi
        run bash -c 'source "$1"; source "$2"; set -x; rc=0; check || rc=$?; [[ $- == *x* ]] || exit 99; exit "$rc"' bash "$BATS_TEST_DIRNAME/../lib/module_api.sh" "$BATS_TEST_DIRNAME/../modules/cis/7/2/8/module.sh"
        [ "$status" -eq "$expected" ]; [[ "$output" != *PRIVATE* && "$output" != *"$H"* && "$output" != *'ROW|'* ]]; chmod 0750 "$H"
    done
}
@test "7.2.8 malformed defensive projections and unexpected observer RC normalize ERROR" {
    rlch_7_2_8_captures() { printf 'CAPTURES|1|1|1|1\nUID|1|1\nHOME|1|relative\n'; }; uncertain
    rlch_7_2_8_observe() { printf PRIVATE; return 99; }; uncertain
}
@test "7.2.8 accepted fixtures reproduce complete sole captures with GNU PCRE reference" {
    for fixture in simple dot duplicate overlap; do
        case "$fixture" in
            simple) row abc 1000 "$H" /bin/bash > "$P"; patterns=(abc) ;;
            dot) row a.b 1000 '' /bin/bash > "$P"; row axb 999 "$H" /bin/false >> "$P"; patterns=(a.b) ;;
            duplicate) row abc 1000 "$H" /bin/bash > "$P"; row abc 1000 "$H" /bin/bash >> "$P"; patterns=(abc) ;;
            overlap) row a.b 1000 "$H" /bin/bash > "$P"; row axb 1001 "$J" /bin/bash >> "$P"; patterns=(a.b axb) ;;
        esac
        : > "$BATS_TEST_TMPDIR/ref-home"; : > "$BATS_TEST_TMPDIR/ref-uid"
        for pattern in "${patterns[@]}"; do
            # Grammar excludes dynamic groups. Moving the fixed suffix into a
            # lookahead and placing \K before the sole capture changes only
            # the emitted whole-match span, not the captured value/instances.
            LC_ALL=C /usr/bin/grep -Po "^(?:${pattern}):(?:[^:]*:){4}\\K([^:]+)(?=:[^:]*$)" "$P" >> "$BATS_TEST_TMPDIR/ref-home" || [[ "$?" -eq 1 ]]
            LC_ALL=C /usr/bin/grep -Po "^(?:${pattern}:)(?:[^:]*:)\\K([^:]+)(?=:(?:[^:]*:){3}[^:]*$)" "$P" >> "$BATS_TEST_TMPDIR/ref-uid" || [[ "$?" -eq 1 ]]
        done
        rlch_identity_home_rows "$P" | rlch_7_2_8_captures > "$BATS_TEST_TMPDIR/actual"
        IFS='|' read -r kind selected all homes unique < "$BATS_TEST_TMPDIR/actual"
        [ "$selected" -eq "${#patterns[@]}" ]; [ "$all" -eq "$(wc -l < "$BATS_TEST_TMPDIR/ref-uid")" ]; [ "$homes" -eq "$(wc -l < "$BATS_TEST_TMPDIR/ref-home")" ]
        [ "$unique" -eq "$(sort -u "$BATS_TEST_TMPDIR/ref-home" | wc -l)" ]
        awk -F '|' '$1=="HOME"{print $3}' "$BATS_TEST_TMPDIR/actual" | sort > "$BATS_TEST_TMPDIR/actual-home"
        sort -u "$BATS_TEST_TMPDIR/ref-home" > "$BATS_TEST_TMPDIR/expected-home"; cmp "$BATS_TEST_TMPDIR/actual-home" "$BATS_TEST_TMPDIR/expected-home"
        awk '{sub(/^0+/,"");if($0=="")$0="0";n["u:"$0]++}END{for(k in n)print substr(k,3)"|"n[k]}' "$BATS_TEST_TMPDIR/ref-uid" | sort > "$BATS_TEST_TMPDIR/expected-uid"
        awk -F '|' '$1=="UID"{print $2"|"$3}' "$BATS_TEST_TMPDIR/actual" | sort > "$BATS_TEST_TMPDIR/actual-uid"; cmp "$BATS_TEST_TMPDIR/expected-uid" "$BATS_TEST_TMPDIR/actual-uid"
    done
}
@test "7.2.8 later unobservable home overrides earlier permission finding" {
    chmod 0777 "$H"; row other 1999 "$BATS_TEST_TMPDIR/absent-parent/home" /bin/bash >> "$P"; uncertain
}
@test "7.2.8 incomplete extraction metadata and inconsistent subresults cannot certify" {
    rlch_7_2_8_captures() { printf 'CAPTURES|1|1|1|1\n'; }; uncertain
    unset -f rlch_7_2_8_captures
    source "$BATS_TEST_DIRNAME/../modules/cis/7/2/8/module.sh"
    rlch_identity_home_metadata() { printf 'PRESENT|41ed|1\n'; }; uncertain
    rlch_7_2_8_observe() { printf 'RULES|0|0|0|1|1|1\n'; return 1; }
    run check; [ "$status" -eq 2 ]; [[ "$output" == *'evidence rejected'* ]]
}
