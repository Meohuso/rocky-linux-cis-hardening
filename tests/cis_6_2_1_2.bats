#!/usr/bin/env bats
setup() {
    source "$BATS_TEST_DIRNAME/test_helper.bash"
    source "$BATS_TEST_DIRNAME/../lib/module_api.sh"
    export RLCH_CIS_6_2_1_2_ROOT="$BATS_TEST_TMPDIR/root"
    export RLCH_CIS_6_2_1_2_TMPFILES="$BATS_TEST_TMPDIR/tmpfiles"
    export RLCH_CIS_6_2_1_2_GETFACL="$BATS_TEST_TMPDIR/getfacl"
    export JA_STATE="$BATS_TEST_TMPDIR/state" JA_CALLS="$BATS_TEST_TMPDIR/calls"
    mkdir -p "$JA_STATE" "$RLCH_CIS_6_2_1_2_ROOT"/{etc/tmpfiles.d,run/tmpfiles.d,usr/local/lib/tmpfiles.d,usr/lib/tmpfiles.d}
    export JA_ID=0123456789abcdef0123456789abcdef
    printf '%s\n' "$JA_ID" > "$RLCH_CIS_6_2_1_2_ROOT/etc/machine-id"
    export JA_VENDOR="$RLCH_CIS_6_2_1_2_ROOT/usr/lib/tmpfiles.d/systemd.conf"
    printf 'z /var/log/journal/%%m/system.journal 0640 root systemd-journal - -\n' > "$JA_VENDOR"
    cat > "$RLCH_CIS_6_2_1_2_TMPFILES" <<'MOCK'
#!/usr/bin/env bash
printf 'tmpfiles %s\n' "$*" >> "$JA_CALLS"
[[ "$1" == --cat-config && "$2" == --no-pager && "$3" == "--root=$RLCH_CIS_6_2_1_2_ROOT" && $# == 3 && "$LC_ALL" == C ]] || exit 3
[[ ! -e "$JA_STATE/tmp-error" ]] || { echo SECRET >&2; exit 1; }
if [[ -e "$JA_STATE/program" ]]; then cat "$JA_STATE/program"; exit; fi
[[ ! -e "$JA_STATE/nul" ]] || { printf 'z /var/log/journal/%%m/system.journal 0640\0\n'; exit; }
[[ ! -e "$JA_STATE/large" ]] || { printf '%9000s\n' ' '; exit; }
if [[ -e "$JA_STATE/real" ]]; then exec /usr/bin/systemd-tmpfiles "$@"; fi
shopt -s nullglob
# Fixture models concatenation; production delegates selection to the tool.
declare -A selected=()
for dir in etc/tmpfiles.d run/tmpfiles.d usr/local/lib/tmpfiles.d usr/lib/tmpfiles.d; do
  for file in "$RLCH_CIS_6_2_1_2_ROOT/$dir"/*.conf; do name="${file##*/}"; [[ -v 'selected[$name]' ]] || selected[$name]="$file"; done
done
for name in $(printf '%s\n' "${!selected[@]}" | LC_ALL=C sort); do
  file="${selected[$name]}"; printf '# %s\n' "$file"; [[ -L "$file" ]] || cat "$file"
done
if [[ -e "$JA_STATE/config-race" ]]; then printf '# changed\n' >> "$JA_VENDOR"; fi
MOCK
    cat > "$RLCH_CIS_6_2_1_2_GETFACL" <<'MOCK'
#!/usr/bin/env bash
printf 'getfacl %s\n' "$*" >> "$JA_CALLS"
[[ "$1" == -c && "$2" == -n && "$3" == -E && "$4" == -P && "$5" == -- && $# == 6 && "$LC_ALL" == C ]] || exit 3
[[ ! -e "$JA_STATE/acl-error" ]] || { echo SECRET >&2; exit 1; }
if [[ -e "$JA_STATE/acl-nul" ]]; then printf 'user::rw-\0\ngroup::r--\nother::---\n'; exit; fi
if [[ -e "$JA_STATE/acl" ]]; then cat "$JA_STATE/acl"; else printf 'user::rw-\ngroup::r--\nother::---\n'; fi
if [[ -e "$JA_STATE/rotate-once" ]]; then touch "$RLCH_CIS_6_2_1_2_ROOT/run/log/journal/new.journal"; chmod 0640 "$RLCH_CIS_6_2_1_2_ROOT/run/log/journal/new.journal"; rm "$JA_STATE/rotate-once"; fi
if [[ -e "$JA_STATE/rotate-always" ]]; then touch "$RLCH_CIS_6_2_1_2_ROOT/run/log/journal/new-$RANDOM.journal"; fi
if [[ -e "$JA_STATE/mode-race" && "$6" == *.journal ]]; then chmod 0600 "$6"; rm "$JA_STATE/mode-race"; fi
if [[ -e "$JA_STATE/inode-race" && "$6" == *.journal ]]; then mv "$6" "$JA_STATE/old-inode"; touch "$6"; chmod 0640 "$6"; rm "$JA_STATE/inode-race"; fi
MOCK
    chmod 0755 "$RLCH_CIS_6_2_1_2_TMPFILES" "$RLCH_CIS_6_2_1_2_GETFACL"
    source "$BATS_TEST_DIRNAME/../modules/cis/6/2/1/2/module.sh"
}
expect() { run check; [ "$status" -eq "$1" ]; [[ "$output" != *SECRET* ]]; }
rule() { printf '%s\n' "$1" > "$JA_VENDOR"; }
journal() { mkdir -p "$RLCH_CIS_6_2_1_2_ROOT/${1%/*}"; touch "$RLCH_CIS_6_2_1_2_ROOT/$1"; chmod "$2" "$RLCH_CIS_6_2_1_2_ROOT/$1"; }
base_acl() { printf 'user::rw-\ngroup::r--\nother::---\n' > "$JA_STATE/acl"; }
@test "6212 metadata manual exact Level 1 enabled no reboot" {
    source "$BATS_TEST_DIRNAME/../modules/cis/6/2/1/2/metadata.conf"
    [ "$RLCH_MODULE_ID" = 6.2.1.2 ]; [ "$RLCH_MODULE_OPENSCAP_RULE" = manual ]; [ "$RLCH_MODULE_LEVEL" = 1 ]; [ "$RLCH_MODULE_ENABLED" = true ]; [ "$RLCH_MODULE_REQUIRES_REBOOT" = false ]
}
@test "6212 both journal trees absent is observable PASS" {
    expect 0;
}
@test "6212 bitwise accepted modes 640 600 400 000" {
    for mode in 640 600 400 000 0640 0600 0400 0000; do run rlch_journal_mode "$mode" 0640; [ "$status" -eq 0 ]; done
}
@test "6212 bitwise rejected modes 660 644 664 666 650 740 1640" {
    for mode in 660 644 664 666 650 740 1640 2640 4640 7640; do run rlch_journal_mode "$mode" 0640; [ "$status" -eq 1 ]; done
}
@test "6212 invalid modes ERROR" {
    for mode in 64 888 10000 bad 0x640 - +640 '640 ' ' 640'; do run rlch_journal_mode "$mode" 0640; [ "$status" -eq 2 ]; done
}
@test "6212 restrictive literal policy preserved PASS" {
    for mode in 0600 0400 0000; do rule "z /var/log/journal/%m/system.journal $mode root systemd-journal - -"; expect 0; done
}
@test "6212 permissive literal policy NON COMPLIANT" {
    for mode in 0660 0644 0664 0666 0650 0740 1640; do rule "z /var/log/journal/%m/system.journal $mode root systemd-journal - -"; expect 1; done
}
@test "6212 malformed policy modes ERROR" {
    for mode in invalid 8888 64 10000; do rule "z /var/log/journal/%m/system.journal $mode root systemd-journal - -"; expect 2; done
}
@test "6212 missing policy NON COMPLIANT" {
    rule '# none'; expect 1;
}
@test "6212 unchanged mode dash cannot establish policy" {
    rule 'z /var/log/journal/%m/system.journal - root systemd-journal - -'; expect 1;
}
@test "6212 literal machine ID supported" {
    rule "z /var/log/journal/$JA_ID/system.journal 0640 root systemd-journal - -"; expect 0;
}
@test "6212 other machine ID does not establish local policy" {
    rule 'z /var/log/journal/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/system.journal 0640 root systemd-journal - -'; expect 1;
}
@test "6212 invalid machine ID ERROR" {
    for value in '' uninitialized abc 00000000000000000000000000000000 0123456789ABCDEF0123456789ABCDEF; do printf '%s\n' "$value" > "$RLCH_CIS_6_2_1_2_ROOT/etc/machine-id"; expect 2; done
}
@test "6212 missing machine ID ERROR" {
    rm "$RLCH_CIS_6_2_1_2_ROOT/etc/machine-id"; expect 2;
}
@test "6212 unknown specifier ERROR" {
    rule 'z /var/log/journal/%b/system.journal 0640 root systemd-journal - -'; expect 2;
}
@test "6212 directory modes do not add file requirements" {
    printf 'z /var/log/journal 2755 root systemd-journal - -\nd /run/log/journal 2755 root systemd-journal - -\nD /var/log/journal/%%m 2755 root systemd-journal - -\n' >> "$JA_VENDOR"; expect 0
}
@test "6212 recursive Z category mask tilde 2750 allows 0640 file effect" {
    printf 'Z /run/log/journal/%%m ~2750 root systemd-journal - -\n' >> "$JA_VENDOR"; expect 0;
}
@test "6212 recursive Z without tilde 2750 is file NON COMPLIANT" {
    printf 'Z /run/log/journal/%%m 2750 root systemd-journal - -\n' >> "$JA_VENDOR"; expect 1;
}
@test "6212 tilde is category masking not bitwise intersection" {
    rule 'z /var/log/journal/%m/system.journal ~0740 root systemd-journal - -'; expect 0;
}
@test "6212 tilde retains unsafe group write" {
    rule 'z /var/log/journal/%m/system.journal ~0770 root systemd-journal - -'; expect 1;
}
@test "6212 mode creation colon unsupported ERROR" {
    rule 'z /var/log/journal/%m/system.journal :0640 root systemd-journal - -'; expect 2;
}
@test "6212 operation modifiers unsupported ERROR" {
    for op in 'z!' 'z+' 'Z~' f w r; do rule "$op /var/log/journal/%m/system.journal 0640 root systemd-journal - -"; expect 2; done
}
@test "6212 relevant ACL a a+ A A+ requires manual ERROR" {
    for op in a a+ A A+; do printf '%s /var/log/journal/%%m - - - - u:4:r--\n' "$op" >> "$JA_VENDOR"; expect 2; done
}
@test "6212 broad ancestor recursive rule ERROR" {
    printf 'Z /var/log 0640 root root - -\n' >> "$JA_VENDOR"; expect 2;
}
@test "6212 broad glob recursive rule ERROR" {
    printf 'Z /var/log/* 0640 root root - -\n' >> "$JA_VENDOR"; expect 2;
}
@test "6212 journal glob unsupported ERROR" {
    printf 'z /var/log/journal/*/*.journal 0640 root root - -\n' >> "$JA_VENDOR"; expect 2;
}
@test "6212 traversal path ERROR" {
    rule 'z /var/log/journal/../system.journal 0640 root root - -'; expect 2;
}
@test "6212 quoted path ERROR" {
    rule 'z "/var/log/journal/%m/system.journal" 0640 root root - -'; expect 2;
}
@test "6212 unsupported fields ERROR" {
    for line in 'z /var/log/journal/%m/system.journal' 'z /var/log/journal/%m/system.journal 0640 root root 1d -' 'z /var/log/journal/%m/system.journal 0640 root root - arbitrary' 'z /var/log/journal/%m/system.journal 0640 root root - - extra'; do rule "$line"; expect 2; done
}
@test "6212 unrelated vendor rules ignored" {
    printf 'f /etc/unrelated 0644 root root - data\nZ /home/user 0755 root root - -\n' >> "$JA_VENDOR"; expect 0;
}
@test "6212 etc same basename overrides permissive vendor" {
    cp "$JA_VENDOR" "$RLCH_CIS_6_2_1_2_ROOT/etc/tmpfiles.d/systemd.conf"; rule 'z /var/log/journal/%m/system.journal 0666 root root - -'; expect 0
}
@test "6212 run same basename overrides vendor" {
    cp "$JA_VENDOR" "$RLCH_CIS_6_2_1_2_ROOT/run/tmpfiles.d/systemd.conf"; rule 'z /var/log/journal/%m/system.journal 0666 root root - -'; expect 0
}
@test "6212 etc takes precedence over run" {
    cp "$JA_VENDOR" "$RLCH_CIS_6_2_1_2_ROOT/etc/tmpfiles.d/systemd.conf"; printf 'z /var/log/journal/%%m/system.journal 0666 root root - -\n' > "$RLCH_CIS_6_2_1_2_ROOT/run/tmpfiles.d/systemd.conf"; expect 0
}
@test "6212 different basenames sort lexicographically first literal wins" {
    printf 'z /var/log/journal/%%m/system.journal 0666 root root - -\n' > "$RLCH_CIS_6_2_1_2_ROOT/usr/lib/tmpfiles.d/00-first.conf"; expect 1
    printf 'z /var/log/journal/%%m/system.journal 0600 root root - -\n' > "$RLCH_CIS_6_2_1_2_ROOT/usr/lib/tmpfiles.d/00-first.conf"; expect 0
}
@test "6212 duplicate literal same file deterministic first wins" {
    printf 'z /var/log/journal/%%m/system.journal 0666 root root - -\n' >> "$JA_VENDOR"; expect 0;
}
@test "6212 documented dev null mask prevents vendor policy" {
    ln -s /dev/null "$RLCH_CIS_6_2_1_2_ROOT/etc/tmpfiles.d/systemd.conf"; expect 1;
}
@test "6212 actual systemd cat config selection is read only" {
    [ -x /usr/bin/systemd-tmpfiles ] || skip 'systemd-tmpfiles unavailable'
    touch "$JA_STATE/real"; cp "$JA_VENDOR" "$RLCH_CIS_6_2_1_2_ROOT/etc/tmpfiles.d/systemd.conf"; rule 'z /var/log/journal/%m/system.journal 0666 root root - -'; expect 0
}
@test "6212 local lib inventory preserved and included by authoritative output" {
    printf 'z /var/log/journal/%%m/system.journal 0666 root root - -\n' > "$RLCH_CIS_6_2_1_2_ROOT/usr/local/lib/tmpfiles.d/00-local.conf"; expect 1
}
@test "6212 tmpfiles query failure and missing tool ERROR no stderr leak" {
    touch "$JA_STATE/tmp-error"; expect 2; rm "$JA_STATE/tmp-error"; RLCH_CIS_6_2_1_2_TMPFILES=/nonexistent; expect 2;
}
@test "6212 tmpfiles binary NUL and large lines ERROR" {
    touch "$JA_STATE/nul"; expect 2; rm "$JA_STATE/nul"; touch "$JA_STATE/large"; expect 2;
}
@test "6212 configuration drift ERROR" {
    touch "$JA_STATE/config-race"; expect 2;
}
@test "6212 unsafe configuration symlink ERROR" {
    ln -s "$JA_VENDOR" "$RLCH_CIS_6_2_1_2_ROOT/etc/tmpfiles.d/other.conf"; expect 2;
}
@test "6212 configuration FIFO ERROR without blocking" {
    mkfifo "$RLCH_CIS_6_2_1_2_ROOT/etc/tmpfiles.d/other.conf"; expect 2;
}
@test "6212 unreadable config mode ERROR even privileged" {
    chmod 0000 "$JA_VENDOR"; expect 2;
}
@test "6212 oversized config ERROR" {
    truncate -s 1048577 "$JA_VENDOR"; expect 2;
}
@test "6212 configuration parent symlink ERROR" {
    mv "$RLCH_CIS_6_2_1_2_ROOT/etc/tmpfiles.d" "$JA_STATE/config-dir"; ln -s "$JA_STATE/config-dir" "$RLCH_CIS_6_2_1_2_ROOT/etc/tmpfiles.d"; expect 2;
}
@test "6212 runtime journals accepted without persistent tree" {
    journal run/log/journal/system.journal 0640; expect 0;
}
@test "6212 persistent journals accepted without runtime tree" {
    journal "var/log/journal/$JA_ID/system.journal" 0600; expect 0;
}
@test "6212 both trees user archives and damaged suffix included" {
    journal "run/log/journal/$JA_ID/user-1000.journal" 0640; journal "var/log/journal/$JA_ID/system@old.journal" 0400; journal "var/log/journal/$JA_ID/user-1000.journal~" 0000; expect 0
}
@test "6212 existing modes tested independently from good configuration" {
    journal run/log/journal/system.journal 0660; expect 1; chmod 0644 "$RLCH_CIS_6_2_1_2_ROOT/run/log/journal/system.journal"; expect 1
}
@test "6212 existing special bits NON COMPLIANT" {
    journal run/log/journal/system.journal 1640; expect 1;
}
@test "6212 zero journal mode does not require content read" {
    journal run/log/journal/system.journal 0000; expect 0;
}
@test "6212 non journal regular file mode outside policy preserved" {
    journal run/log/journal/README 0666; expect 0;
}
@test "6212 empty present trees PASS with base ACL" {
    mkdir -p "$RLCH_CIS_6_2_1_2_ROOT/run/log/journal" "$RLCH_CIS_6_2_1_2_ROOT/var/log/journal"; expect 0;
}
@test "6212 journal symlink outside tree ERROR" {
    mkdir -p "$RLCH_CIS_6_2_1_2_ROOT/run/log/journal"; ln -s "$JA_VENDOR" "$RLCH_CIS_6_2_1_2_ROOT/run/log/journal/system.journal"; expect 2;
}
@test "6212 journal symlink inside tree ERROR" {
    journal run/log/journal/target.journal 0640; ln -s target.journal "$RLCH_CIS_6_2_1_2_ROOT/run/log/journal/system.journal"; expect 2;
}
@test "6212 journal directory symlink ERROR" {
    mkdir -p "$RLCH_CIS_6_2_1_2_ROOT/run/log" "$JA_STATE/external"; ln -s "$JA_STATE/external" "$RLCH_CIS_6_2_1_2_ROOT/run/log/journal"; expect 2;
}
@test "6212 journal FIFO ERROR" {
    mkdir -p "$RLCH_CIS_6_2_1_2_ROOT/run/log/journal"; mkfifo "$RLCH_CIS_6_2_1_2_ROOT/run/log/journal/system.journal"; expect 2;
}
@test "6212 unavailable ACL tool ERROR when tree exists" {
    journal run/log/journal/system.journal 0640; RLCH_CIS_6_2_1_2_GETFACL=/missing; expect 2;
}
@test "6212 ACL command failure ERROR" {
    journal run/log/journal/system.journal 0640; touch "$JA_STATE/acl-error"; expect 2;
}
@test "6212 base ACL PASS" {
    journal run/log/journal/system.journal 0640; base_acl; expect 0;
}
@test "6212 named user effective read requires site review ERROR" {
    journal run/log/journal/system.journal 0640; base_acl; printf 'user:1000:r--\nmask::r--\n' >> "$JA_STATE/acl"; expect 2;
}
@test "6212 named group effective read requires site review ERROR" {
    journal run/log/journal/system.journal 0640; base_acl; printf 'group:1000:r--\nmask::r--\n' >> "$JA_STATE/acl"; expect 2;
}
@test "6212 named zero effective grant PASS" {
    journal run/log/journal/system.journal 0640; base_acl; printf 'user:1000:rwx\nmask::---\n' >> "$JA_STATE/acl"; expect 0;
}
@test "6212 directory inherited default named grant requires review ERROR" {
    journal run/log/journal/system.journal 0640; base_acl; printf 'default:user::rwx\ndefault:group::r-x\ndefault:other::---\ndefault:user:1000:r--\ndefault:mask::r-x\n' >> "$JA_STATE/acl"; expect 2;
}
@test "6212 malformed duplicate incomplete ACL ERROR" {
    journal run/log/journal/system.journal 0640
    for text in 'user::rw-' 'not-an-acl' 'user::rw-\nuser::rw-\ngroup::r--\nother::---' 'user::rw-\ngroup::r--\nother::---\ndefault:user::rwx'; do printf '%b\n' "$text" > "$JA_STATE/acl"; expect 2; done
}
@test "6212 ACL raw NUL rejected before substitution" {
    journal run/log/journal/system.journal 0640; touch "$JA_STATE/acl-nul"; expect 2;
}
@test "6212 ACL excessive output ERROR" {
    journal run/log/journal/system.journal 0640; printf '%70000s\n' x > "$JA_STATE/acl"; expect 2;
}
@test "6212 mode changes during ACL observation ERROR" {
    journal run/log/journal/system.journal 0640; touch "$JA_STATE/mode-race"; expect 2;
}
@test "6212 inode replaced during observation ERROR" {
    journal run/log/journal/system.journal 0640; touch "$JA_STATE/inode-race"; expect 2;
}
@test "6212 new journal completed rotation stabilizes with third snapshot" {
    journal run/log/journal/system.journal 0640; touch "$JA_STATE/rotate-once"; expect 0;
}
@test "6212 continuously changing journal set ERROR" {
    journal run/log/journal/system.journal 0640; touch "$JA_STATE/rotate-always"; expect 2;
}
@test "6212 apply repeated compliant SUCCESS rollback repeated SUCCESS unchanged" {
    journal run/log/journal/system.journal 0640; before="$(sha256sum "$JA_VENDOR")"
    for n in 1 2; do run apply; [ "$status" -eq 0 ]; run validate; [ "$status" -eq 0 ]; run rollback; [ "$status" -eq 0 ]; done
    [ "$(sha256sum "$JA_VENDOR")" = "$before" ]; [ "$(stat -c %a "$RLCH_CIS_6_2_1_2_ROOT/run/log/journal/system.journal")" = 640 ]
}
@test "6212 apply deficient manual ERROR repeated preserves policy mode and content" {
    journal run/log/journal/system.journal 0666; echo retained > "$RLCH_CIS_6_2_1_2_ROOT/run/log/journal/system.journal"
    for n in 1 2; do run apply; [ "$status" -eq 2 ]; [[ "$output" == *manual* ]]; run rollback; [ "$status" -eq 0 ]; done
    [ "$(stat -c %a "$RLCH_CIS_6_2_1_2_ROOT/run/log/journal/system.journal")" = 666 ]; [ "$(cat "$RLCH_CIS_6_2_1_2_ROOT/run/log/journal/system.journal")" = retained ]
}
@test "6212 apply ambiguous ERROR preserves administrator ACL" {
    journal run/log/journal/system.journal 0640; base_acl; printf 'user:1000:r--\nmask::r--\n' >> "$JA_STATE/acl"; before="$(sha256sum "$JA_STATE/acl")"; run apply; [ "$status" -eq 2 ]; [ "$(sha256sum "$JA_STATE/acl")" = "$before" ];
}
@test "6212 previous controls state and journald config untouched" {
    mkdir -p "$RLCH_CIS_6_2_1_2_ROOT"/{etc/aide,etc/cron.d,var/lib/aide,etc/systemd,var/lib/rlch}
    for path in etc/aide/aide.conf etc/cron.d/aide var/lib/aide/aide.db etc/systemd/journald.conf var/lib/rlch/6.1.3.journal; do printf 'preserved\n' > "$RLCH_CIS_6_2_1_2_ROOT/$path"; done
    before="$(find "$RLCH_CIS_6_2_1_2_ROOT" -type f -exec sha256sum {} + | sort)"; run apply; [ "$status" -eq 0 ]; run rollback; [ "$status" -eq 0 ]; [ "$(find "$RLCH_CIS_6_2_1_2_ROOT" -type f -exec sha256sum {} + | sort)" = "$before" ]
    ! rg --quiet -- '--create|--clean|--remove|chmod|systemctl|dnf' "$JA_CALLS"
}
@test "6212 effective output drift with unchanged source files ERROR" {
    cat > "$RLCH_CIS_6_2_1_2_TMPFILES" <<'MOCK'
#!/usr/bin/env bash
if [[ -e "$JA_STATE/queried" ]]; then mode=0600; else mode=0640; touch "$JA_STATE/queried"; fi
printf 'z /var/log/journal/%%m/system.journal %s root systemd-journal - -\n' "$mode"
MOCK
    expect 2
}
@test "6212 unsupported relevant escaped path ERROR" {
    rule 'z /var/log/journal/space\x20name/system.journal 0640 root root - -'; expect 2
}
@test "6212 unreadable journal directory ERROR even privileged" {
    journal run/log/journal/system.journal 0640; chmod 0000 "$RLCH_CIS_6_2_1_2_ROOT/run/log/journal"; expect 2
}
@test "6212 configuration changes between stamp and descriptor open ERROR" {
    eval "$(declare -f rlch_tmout_file_stamp | sed '1s/rlch_tmout_file_stamp/ja_original_file_stamp/')"
    rlch_tmout_file_stamp() {
        ja_original_file_stamp "$1" || return 2
        if [[ "$1" == "$JA_VENDOR" ]]; then chmod 0600 "$1"; fi
    }
    expect 2
}
@test "6212 reported ownership drift during object observation ERROR" {
    journal run/log/journal/system.journal 0640
    eval "$(declare -f rlch_journal_object_stamp | sed '1s/rlch_journal_object_stamp/ja_original_object_stamp/')"
    rlch_journal_object_stamp() {
        local observed
        observed="$(ja_original_object_stamp "$1")" || return 2
        if [[ "$1" == *.journal && ! -e "$JA_STATE/owner-observed" ]]; then
            touch "$JA_STATE/owner-observed"; observed="$(awk -F: 'BEGIN{OFS=":"}{$4=987654;print}' <<< "$observed")"
        fi
        printf '%s\n' "$observed"
    }
    expect 2
}
@test "6212 ACL carriage return rejected" {
    journal run/log/journal/system.journal 0640; printf 'user::rw-\r\ngroup::r--\nother::---\n' > "$JA_STATE/acl"; expect 2
}
@test "6212 masked default named grant accepted with complete base entries" {
    journal run/log/journal/system.journal 0640; base_acl
    printf 'default:user::rwx\ndefault:group::r-x\ndefault:other::---\ndefault:user:1000:rwx\ndefault:mask::---\n' >> "$JA_STATE/acl"; expect 0
}
teardown() {
    # Restore traversal only on this fixture for Bats temporary-directory cleanup.
    if [[ -d "$RLCH_CIS_6_2_1_2_ROOT/run/log/journal" && ! -L "$RLCH_CIS_6_2_1_2_ROOT/run/log/journal" ]]; then
        chmod u+rwx "$RLCH_CIS_6_2_1_2_ROOT/run/log/journal"
    fi
}
@test "6212 etc restrictive override preserved and permissive override NON COMPLIANT" {
    local override="$RLCH_CIS_6_2_1_2_ROOT/etc/tmpfiles.d/systemd.conf"
    printf 'z /var/log/journal/%%m/system.journal 0600 root systemd-journal - -\n' > "$override"; expect 0
    printf 'z /var/log/journal/%%m/system.journal 0666 root systemd-journal - -\n' > "$override"; expect 1
    [ "$(cat "$override")" = 'z /var/log/journal/%m/system.journal 0666 root systemd-journal - -' ]
}
@test "6212 comments whitespace and tabs accepted" {
    printf '# journal policy\n\n  z\t/var/log/journal/%%m/system.journal\t0640\troot\tsystemd-journal\t-\t-\n' > "$JA_VENDOR"; expect 0
}
@test "6212 unexpected socket object ERROR without opening" {
    mkdir -p "$RLCH_CIS_6_2_1_2_ROOT/run/log/journal"
    if ! python3 - "$RLCH_CIS_6_2_1_2_ROOT/run/log/journal/unexpected" 2>/dev/null <<'PY'
import socket, sys
s=socket.socket(socket.AF_UNIX); s.bind(sys.argv[1]); s.close()
PY
    then skip 'Unix socket creation denied by execution environment'; fi
    expect 2
}
@test "6212 mixed z Z exact target conflict requires review ERROR" {
    printf 'Z /var/log/journal/%%m/system.journal 0666 root systemd-journal - -\n' >> "$JA_VENDOR"; expect 2
}
@test "6212 malformed relevant directory mode ERROR" {
    printf 'z /var/log/journal invalid root systemd-journal - -\n' >> "$JA_VENDOR"; expect 2
}
@test "6212 control byte configuration filename ERROR" {
    cp "$JA_VENDOR" "$RLCH_CIS_6_2_1_2_ROOT/etc/tmpfiles.d/"$'bad\nname.conf'; expect 2
}
