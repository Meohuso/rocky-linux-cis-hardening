#!/usr/bin/env bats
# shellcheck source-path=SCRIPTDIR
# shellcheck disable=SC2317,SC2030,SC2031 # Fault injection and Bats run isolation.
# shellcheck disable=SC2016 # Inert hostile fixture names.
setup() {
    source "$BATS_TEST_DIRNAME/test_helper.bash"
    source "$BATS_TEST_DIRNAME/../lib/common.sh"
    source "$BATS_TEST_DIRNAME/../lib/module_api.sh"
    export RLCH_CIS_7_2_9_PASSWD="$BATS_TEST_TMPDIR/passwd" RLCH_CIS_7_2_9_NSS="$BATS_TEST_TMPDIR/nsswitch.conf"
    export RLCH_CIS_7_2_9_RPM="$BATS_TEST_TMPDIR/rpm" RLCH_CIS_7_2_9_MOUNTINFO="$BATS_TEST_TMPDIR/mountinfo"
    export RLCH_CIS_7_2_9_HOME="$BATS_TEST_TMPDIR/base" RLCH_CIS_7_2_9_ROOT="$BATS_TEST_TMPDIR/root" RLCH_CIS_7_2_9_ETC="$BATS_TEST_TMPDIR/etc"
    export PACKAGES="$BATS_TEST_TMPDIR/packages" FLAG="$BATS_TEST_TMPDIR/flag"
    P="$RLCH_CIS_7_2_9_PASSWD"; N="$RLCH_CIS_7_2_9_NSS"; M="$RLCH_CIS_7_2_9_MOUNTINFO"
    H="$RLCH_CIS_7_2_9_HOME/user"; J="$RLCH_CIS_7_2_9_HOME/other"
    mkdir -p "$H" "$J" "$RLCH_CIS_7_2_9_ROOT" "$RLCH_CIS_7_2_9_ETC"; chmod 0755 "$H" "$J"
    U="$(id -u)"; G="$(id -g)"; UT="$(printf '%04d' "$U")"
    if (( U<1000 )); then row owner "$UT" '' /bin/bash > "$P"; row user 1000 "$H" /bin/bash >> "$P"
    else row user "$UT" "$H" /bin/bash > "$P"
    fi
    chmod 0644 "$P"; printf 'passwd: files\ngroup: files sss\n' > "$N"; chmod 0644 "$N"
    printf PRIVATE_BODY > "$H/.bashrc"; chmod 0600 "$H/.bashrc"
    packages kernel-core bash
    printf '#!/usr/bin/env bash\n/usr/bin/cat "$PACKAGES"\n' > "$RLCH_CIS_7_2_9_RPM"; chmod 0700 "$RLCH_CIS_7_2_9_RPM"
    dev="$(stat -c %d "$H")"; DEVICE="$(( (dev>>8 &4095)|(dev>>32 &4294963200) )):$(( (dev&255)|(dev>>12 &4294967040) ))"
    printf '10 0 %s / / rw - ext4 /dev/fixture rw\n' "$DEVICE" > "$M"
    : > "$FLAG"
    source "$BATS_TEST_DIRNAME/../modules/cis/7/2/9/module.sh"
}
row() { printf '%s:PRIVATE_AUTH:%s:%s:PRIVATE_GECOS:%s:%s\n' "$1" "$2" "$G" "$3" "$4"; }
packages() { local i=0 p; : > "$PACKAGES"; for p in "$@"; do i=$((i+1)); printf 'RPM1|%s|%s|0|1|1|x86_64|END\n' "$i" "$p" >> "$PACKAGES"; done; }
expect_rule() { [[ "$output" == *"$1=$2"* ]]; }
history() { : > "$H/.bash_history"; chmod "$1" "$H/.bash_history"; }
save_snapshot_reader() { eval "$(declare -f rlch_729_read_snapshot | sed '1s/rlch_729_read_snapshot/real_729_read_snapshot/')"; }
# Isolated policy fixtures alter returned owner IDs AFTER a real complete API
# observation, allowing non-root CI to test membership/swaps without chown.
policy_owners() {
    save_snapshot_reader
    rlch_729_read_snapshot() {
        real_729_read_snapshot "$@" || return 2
        local -n policy_rows="$4"
        local i
        for ((i=12;i<${#policy_rows[@]};i+=12)); do
            [[ "${policy_rows[i+1]}" != d ]] || continue
            case "${policy_rows[i]}" in
                "$H/"*) policy_rows[i+5]="$OWNER_H"; policy_rows[i+6]="$GROUP_H";;
                "$J/"*) policy_rows[i+5]="$OWNER_J"; policy_rows[i+6]="$GROUP_J";;
            esac
        done
    }
}
@test "7.2.9 metadata exact aggregate mapping and lifecycle" {
    source "$BATS_TEST_DIRNAME/../modules/cis/7/2/9/metadata.conf"
    [ "$RLCH_MODULE_ID" = 7.2.9 ]; [ "$RLCH_MODULE_LEVEL" = 1 ]; [ "$RLCH_MODULE_OPENSCAP_RULE" = manual ]; [ "$RLCH_MODULE_REQUIRES_REBOOT" = false ]
    validate_loaded_module_metadata 7.2.9; validate_loaded_module_functions
}
@test "7.2.9 complete compliant local observation SUCCESS" {
    run check; [ "$status" -eq 0 ]; expect_rule file_permission_user_init_files SUCCESS; expect_rule accounts_user_dot_user_ownership SUCCESS; expect_rule no_rsh_trust_files NOT_APPLICABLE
}
@test "7.2.9 group ownership membership is NON_COMPLIANT for unexpected GID" {
    OWNER_H="$U"; OWNER_J="$U"; GROUP_H=4294967000; GROUP_J="$G"; policy_owners
    run check; [ "$status" -eq 1 ]; expect_rule accounts_user_dot_group_ownership NON_COMPLIANT
}
@test "7.2.9 user ownership membership is NON_COMPLIANT for unexpected UID" {
    OWNER_H=4294967000; OWNER_J="$U"; GROUP_H="$G"; GROUP_J="$G"; policy_owners
    run check; [ "$status" -eq 1 ]; expect_rule accounts_user_dot_user_ownership NON_COMPLIANT
}
@test "7.2.9 UID capture multiplicity is retained" {
    row duplicate "$UT" "$H" /bin/bash >> "$P"
    run check; [ "$status" -eq 1 ]; expect_rule accounts_user_dot_user_ownership NON_COMPLIANT; expect_rule accounts_user_dot_group_ownership SUCCESS
}
@test "7.2.9 duplicate numeric GIDs are deduplicated" {
    row another 2000 "$H" /bin/bash >> "$P"
    run check; [ "$status" -eq 0 ]; expect_rule accounts_user_dot_group_ownership SUCCESS
}
@test "7.2.9 swapped owners and groups pass the literal collection comparison" {
    G=2000; row alpha 1000 "$H" /bin/bash > "$P"; G=2001; row beta 1001 "$J" /bin/bash >> "$P"
    : > "$J/.profile"; chmod 0600 "$J/.profile"
    OWNER_H=1001; OWNER_J=1000; GROUP_H=2001; GROUP_J=2000; policy_owners
    run check; [ "$status" -eq 0 ]; expect_rule accounts_user_dot_user_ownership SUCCESS; expect_rule accounts_user_dot_group_ownership SUCCESS
}
@test "7.2.9 general permissions reject group write" {
    chmod 0620 "$H/.bashrc"; run check; [ "$status" -eq 1 ]; expect_rule file_permission_user_init_files NON_COMPLIANT
}
@test "7.2.9 general permissions allow owner execute and group read" {
    chmod 0740 "$H/.bashrc"; run check; [ "$status" -eq 0 ]
}
@test "7.2.9 general mask 07037 rejects each forbidden bit" {
    for mode in 4600 2600 1600 0620 0610 0604 0602 0601; do chmod "$mode" "$H/.bashrc"; run check; [ "$status" -eq 1 ]; expect_rule file_permission_user_init_files NON_COMPLIANT; done
}
@test "7.2.9 all_dotfiles includes profile bashrc and ordinary names" {
    for name in .profile .bashrc '.dot file' .dot-file .dot_file; do : > "$H/$name"; chmod 0620 "$H/$name"; run check; [ "$status" -eq 1 ]; chmod 0600 "$H/$name"; done
}
@test "7.2.9 all_dotfiles excludes extra dots and punctuation exactly" {
    for name in .a.b '.a+b' '..' ordinary; do [[ "$name" != .. ]] || continue; : > "$H/$name"; chmod 0666 "$H/$name"; done
    run check; [ "$status" -eq 0 ]; expect_rule file_permission_user_init_files SUCCESS
}
@test "7.2.9 ownership includes dotted names outside all_dotfiles" {
    : > "$H/.a.b"; OWNER_H=4294967000; OWNER_J="$U"; GROUP_H="$G"; GROUP_J="$G"; policy_owners
    run check; [ "$status" -eq 1 ]; expect_rule accounts_user_dot_user_ownership NON_COMPLIANT; expect_rule file_permission_user_init_files SUCCESS
}
@test "7.2.9 ownership recurses one directory level but permissions do not" {
    mkdir -p "$H/sub/deeper"; : > "$H/sub/.profile"; chmod 0666 "$H/sub/.profile"
    run check; [ "$status" -eq 0 ]; expect_rule file_permission_user_init_files SUCCESS
    OWNER_H=4294967000; OWNER_J="$U"; GROUP_H="$G"; GROUP_J="$G"; policy_owners
    run check; [ "$status" -eq 1 ]; expect_rule accounts_user_dot_user_ownership NON_COMPLIANT
}
@test "7.2.9 deeper ownership files excluded by exact bounded depth" {
    rm "$H/.bashrc"; mkdir -p "$H/sub/deeper"; : > "$H/sub/deeper/.profile"
    OWNER_H=4294967000; OWNER_J="$U"; GROUP_H="$G"; GROUP_J="$G"; policy_owners
    run check; [ "$status" -eq 0 ]
}
@test "7.2.9 forward unanchored start matches prefixed name" {
    : > "$H/prefix.forward"; chmod 0600 "$H/prefix.forward"
    run check; [ "$status" -eq 1 ]; expect_rule no_forward_files NON_COMPLIANT
}
@test "7.2.9 forward only configured interactive homes" {
    : > "$J/.forward"; run check; [ "$status" -eq 0 ]
}
@test "7.2.9 forward absent and empty file handled by existence" {
    run check; [ "$status" -eq 0 ]; : > "$H/.forward"; chmod 0600 "$H/.forward"; run check; [ "$status" -eq 1 ]; expect_rule no_forward_files NON_COMPLIANT
}
@test "7.2.9 netrc scans fixed home tree even without matching account" {
    : > "$J/.netrc"; chmod 0600 "$J/.netrc"; run check; [ "$status" -eq 1 ]; expect_rule no_netrc_files NON_COMPLIANT
}
@test "7.2.9 netrc includes root of home and immediate subdirectories" {
    : > "$RLCH_CIS_7_2_9_HOME/.netrc"; run check; [ "$status" -eq 1 ]; expect_rule no_netrc_files NON_COMPLIANT
}
@test "7.2.9 netrc excludes deeper paths and prefixed names" {
    mkdir "$J/sub"; : > "$J/sub/.netrc"; : > "$J/prefix.netrc"; run check; [ "$status" -eq 0 ]
}
@test "7.2.9 netrc scans other filesystems under all policy" {
    : > "$J/.netrc"; printf '20 10 %s / %s rw - nfs server:/share rw\n' "$DEVICE" "$J" >> "$M"
    run check; [ "$status" -eq 1 ]; expect_rule no_netrc_files NON_COMPLIANT
}
@test "7.2.9 rsh package absence applies only to rsh rule" {
    : > "$RLCH_CIS_7_2_9_ROOT/.rhosts"; : > "$RLCH_CIS_7_2_9_ETC/hosts.equiv"; run check; [ "$status" -eq 0 ]; expect_rule no_rsh_trust_files NOT_APPLICABLE
}
@test "7.2.9 rsh detects root trust file" {
    packages kernel-core bash rsh-server; : > "$RLCH_CIS_7_2_9_ROOT/.rhosts"; run check; [ "$status" -eq 1 ]; expect_rule no_rsh_trust_files NON_COMPLIANT
}
@test "7.2.9 rsh detects home trust file" {
    packages kernel-core bash rsh-server; : > "$J/.rhosts"; run check; [ "$status" -eq 1 ]; expect_rule no_rsh_trust_files NON_COMPLIANT
}
@test "7.2.9 rsh detects hosts equiv independently of users" {
    packages kernel-core bash rsh-server; : > "$RLCH_CIS_7_2_9_ETC/hosts.equiv"; run check; [ "$status" -eq 1 ]; expect_rule no_rsh_trust_files NON_COMPLIANT
}
@test "7.2.9 history absent accepted" { run check; [ "$status" -eq 0 ]; expect_rule file_permission_user_bash_history SUCCESS; }
@test "7.2.9 history 0600 accepted" { history 0600; run check; [ "$status" -eq 0 ]; }
@test "7.2.9 history 0400 accepted" { history 0400; run check; [ "$status" -eq 0 ]; }
@test "7.2.9 history 0200 accepted" { history 0200; run check; [ "$status" -eq 0 ]; }
@test "7.2.9 history 0000 accepted without reading contents" { history 0000; run check; [ "$status" -eq 0 ]; }
@test "7.2.9 history 0640 rejected while general permissions pass" { history 0640; run check; [ "$status" -eq 1 ]; expect_rule file_permission_user_bash_history NON_COMPLIANT; expect_rule file_permission_user_init_files SUCCESS; }
@test "7.2.9 history 0700 rejected while general permissions pass" { history 0700; run check; [ "$status" -eq 1 ]; expect_rule file_permission_user_bash_history NON_COMPLIANT; expect_rule file_permission_user_init_files SUCCESS; }
@test "7.2.9 history 0660 rejected" { history 0660; run check; [ "$status" -eq 1 ]; expect_rule file_permission_user_bash_history NON_COMPLIANT; }
@test "7.2.9 history 0601 rejected" { history 0601; run check; [ "$status" -eq 1 ]; expect_rule file_permission_user_bash_history NON_COMPLIANT; }
@test "7.2.9 history each special bit rejected" {
    for mode in 4600 2600 1600; do history "$mode"; run check; [ "$status" -eq 1 ]; expect_rule file_permission_user_bash_history NON_COMPLIANT; done
}
@test "7.2.9 history symlink excluded only from complement" {
    ln -s missing "$H/.bash_history"; run check; [ "$status" -eq 1 ]; expect_rule file_permission_user_bash_history SUCCESS; expect_rule file_permission_user_init_files NON_COMPLIANT
}
@test "7.2.9 history FIFO is selected without regular-file filter" {
    mkfifo "$H/.bash_history"; chmod 0640 "$H/.bash_history"; run check; [ "$status" -eq 1 ]; expect_rule file_permission_user_bash_history NON_COMPLIANT
}
@test "7.2.9 directory named bash history is not emitted by filename collector" {
    mkdir "$H/.bash_history"; chmod 0755 "$H/.bash_history"; run check; [ "$status" -eq 0 ]; expect_rule file_permission_user_bash_history SUCCESS
}
@test "7.2.9 history package applicability is independent" {
    packages kernel-core; history 0640; run check; [ "$status" -eq 0 ]; expect_rule file_permission_user_bash_history NOT_APPLICABLE; expect_rule file_permission_user_init_files SUCCESS
}
@test "7.2.9 history shared homes evaluated without per-user ownership pairing" {
    row second 2000 "$H" /bin/bash >> "$P"; history 0640; run check; [ "$status" -eq 1 ]; expect_rule file_permission_user_bash_history NON_COMPLIANT
}
@test "7.2.9 missing configured home is complete absence not automatic error" {
    rm -r "$H"; run check; [ "$status" -eq 0 ]; expect_rule file_permission_user_bash_history SUCCESS
}
@test "7.2.9 inaccessible configured home is ERROR" {
    chmod 0000 "$H"; run check; [ "$status" -eq 2 ]; expect_rule file_permission_user_bash_history ERROR; chmod 0755 "$H"
}
@test "7.2.9 nonabsolute configured home is ERROR not silently skipped" {
    row user 1000 relative /bin/bash > "$P"; run check; [ "$status" -eq 2 ]
}
@test "7.2.9 symlink home cannot expose outside paths" {
    mv "$H" "$H.real"; ln -s "$H.real" "$H"; run check; [ "$status" -eq 2 ]; expect_rule file_permission_user_bash_history ERROR
}
@test "7.2.9 hardlinked dotfiles preserve every selected name" {
    ln "$H/.bashrc" "$H/.bash_history"; chmod 0640 "$H/.bash_history"; run check; [ "$status" -eq 1 ]; expect_rule file_permission_user_bash_history NON_COMPLIANT
}
@test "7.2.9 nobody exclusions and numeric NSS threshold preserved" {
    row nobody 65534 "$H" /bin/bash > "$P"; row nfsnobody 65534 "$H" /bin/bash >> "$P"; row low 0999 "$H" /bin/bash >> "$P"
    history 0640; run check; [ "$status" -eq 1 ]; expect_rule file_permission_user_bash_history SUCCESS; expect_rule accounts_user_dot_user_ownership NON_COMPLIANT
}
@test "7.2.9 exact NSS shell differs from local prefix exclusion" {
    row user 1000 "$H" /bin/false.extra > "$P"; history 0640; run check; [ "$status" -eq 1 ]; expect_rule accounts_user_dot_user_ownership SUCCESS; expect_rule file_permission_user_bash_history NON_COMPLIANT
}
@test "7.2.9 exact false shell excludes password population" {
    row user 1000 "$H" /bin/false > "$P"; history 0640; run check; [ "$status" -eq 0 ]; expect_rule file_permission_user_bash_history SUCCESS
}
@test "7.2.9 dotted dynamic names reproduce wildcard overlap and UID multiplicity" {
    row a.b "$UT" "$H" /bin/bash > "$P"; row axb "$UT" "$H" /bin/bash >> "$P"
    run check; [ "$status" -eq 1 ]; expect_rule accounts_user_dot_user_ownership NON_COMPLIANT
}
@test "7.2.9 unsupported dynamic PCRE syntax causes ERROR" {
    for name in '(a)' 'a(?=b)' 'a|b' 'a\1' 'a+' '[ab]' 'élève'; do row "$name" 1000 "$H" /bin/bash > "$P"; run check; [ "$status" -eq 2 ]; done
}
@test "7.2.9 files-only NSS optional comment accepted and external group irrelevant" {
    printf ' # fixture\npasswd: files # local\ngroup: sss files\n' > "$N"; run check; [ "$status" -eq 0 ]
}
@test "7.2.9 external NSS yields ERROR only for dependent rules" {
    printf 'passwd: sss\n' > "$N"; run check; [ "$status" -eq 2 ]; expect_rule file_permission_user_init_files ERROR; expect_rule accounts_user_dot_user_ownership SUCCESS; expect_rule no_netrc_files SUCCESS
}
@test "7.2.9 mixed conditional and unknown NSS services fail closed" {
    for services in 'files sss' 'files [SUCCESS=return]' unknown 'compat' ''; do printf 'passwd: %s\n' "$services" > "$N"; run check; [ "$status" -eq 2 ]; expect_rule file_permission_user_init_files ERROR; done
}
@test "7.2.9 duplicate or malformed passwd NSS key rejected" {
    for text in $'passwd: files\npasswd: files' 'passwd : files' 'passwd files'; do printf '%s\n' "$text" > "$N"; run check; [ "$status" -eq 2 ]; done
}
@test "7.2.9 inaccessible and symlink NSS configuration rejected" {
    chmod 0000 "$N"; run check; [ "$status" -eq 2 ]; chmod 0644 "$N"
    mv "$N" "$N.real"; ln -s "$N.real" "$N"; run check; [ "$status" -eq 2 ]
}
@test "7.2.9 fixed path findings survive NSS ERROR in individual results" {
    printf 'passwd: sss\n' > "$N"; : > "$J/.netrc"; run check; [ "$status" -eq 2 ]; expect_rule no_netrc_files NON_COMPLIANT; expect_rule file_permission_user_init_files ERROR
}
@test "7.2.9 rsh fixed paths independent of NSS" {
    packages kernel-core bash rsh-server; printf 'passwd: sss\n' > "$N"; : > "$RLCH_CIS_7_2_9_ETC/hosts.equiv"
    run check; [ "$status" -eq 2 ]; expect_rule no_rsh_trust_files NON_COMPLIANT
}
@test "7.2.9 no external identity enumeration occurs" {
    getent() { printf PRIVATE >&2; return 99; }; run check; [ "$status" -eq 0 ]
}
@test "7.2.9 complete-line repeated passwd truncations cannot produce success" {
    rlch_identity_stream() { /usr/bin/head -n 1; }; run check; [ "$status" -eq 2 ]; run check; [ "$status" -eq 2 ]; expect_rule no_netrc_files SUCCESS
}
@test "7.2.9 malformed passwd and nonnumeric GID are ERROR" {
    printf 'user:x:1000:bad::%s:/bin/bash\n' "$H" > "$P"; run check; [ "$status" -eq 2 ]
}
@test "7.2.9 producer I/O error invalidates projection" {
    rlch_identity_stream() { /usr/bin/cat; return 87; }; run check; [ "$status" -eq 2 ]; [[ "$output" != *PRIVATE* ]]
}
@test "7.2.9 silently partial filesystem enumeration cannot produce success" {
    _rlch_fs_snapshot_names_stream() { :; }; run check; [ "$status" -eq 2 ]
}
@test "7.2.9 file mutation across rule observations invalidates shared evidence" {
    save_snapshot_reader
    rlch_729_read_snapshot() { real_729_read_snapshot "$@" || return 2; if [[ ! -s "$FLAG" ]]; then printf 1 > "$FLAG"; chmod 0640 "$H/.bashrc"; fi; }
    run check; [ "$status" -eq 2 ]; expect_rule accounts_user_dot_user_ownership ERROR
}
@test "7.2.9 NSS mutation invalidates only dependent observations" {
    save_snapshot_reader
    rlch_729_read_snapshot() { real_729_read_snapshot "$@" || return 2; if [[ ! -s "$FLAG" ]]; then printf 1 > "$FLAG"; printf 'passwd: sss\n' > "$N"; fi; }
    run check; [ "$status" -eq 2 ]; expect_rule file_permission_user_init_files ERROR; expect_rule no_netrc_files SUCCESS
}
@test "7.2.9 later I/O error overrides earlier NON_COMPLIANT" {
    history 0640; chmod 0000 "$J"; run check; [ "$status" -eq 2 ]; expect_rule file_permission_user_bash_history NON_COMPLIANT; expect_rule no_netrc_files ERROR; chmod 0755 "$J"
}
@test "7.2.9 ERROR within one rule cannot be overwritten by later finding" {
    row extra 2000 "$J" /bin/bash >> "$P"; chmod 0000 "$H"; : > "$J/.bash_history"; chmod 0640 "$J/.bash_history"
    run check; [ "$status" -eq 2 ]; expect_rule file_permission_user_bash_history ERROR; chmod 0755 "$H"
}
@test "7.2.9 kernel absence does not exempt permissions or history" {
    packages bash; history 0640; run check; [ "$status" -eq 1 ]; expect_rule accounts_user_dot_user_ownership NOT_APPLICABLE; expect_rule no_netrc_files NOT_APPLICABLE; expect_rule file_permission_user_bash_history NON_COMPLIANT
}
@test "7.2.9 uncertain package applicability returns ERROR" {
    printf '#!/usr/bin/env bash\nexit 87\n' > "$RLCH_CIS_7_2_9_RPM"; run check; [ "$status" -eq 2 ]; expect_rule no_rsh_trust_files ERROR
}
@test "7.2.9 aggregation all NA supported but not invented from kernel absence" {
    run rlch_729_result 3 3 3 3 3 3 3; [ "$status" -eq 3 ]
    packages unrelated; run check; [ "$status" -eq 0 ]; expect_rule file_permission_user_init_files SUCCESS
}
@test "7.2.9 aggregation ERROR priority over any finding" { run rlch_729_result 1 0 2 3 0 0 0; [ "$status" -eq 2 ]; }
@test "7.2.9 check and validate independently observe changes" {
    run check; [ "$status" -eq 0 ]; history 0640; run validate; [ "$status" -eq 1 ]; chmod 0600 "$H/.bash_history"; run check; [ "$status" -eq 0 ]
}
@test "7.2.9 repeated validate is fresh and idempotent" { run validate; [ "$status" -eq 0 ]; run validate; [ "$status" -eq 0 ]; }
@test "7.2.9 apply observation only never calls account or permission administration" {
    for command in chmod chown chgrp usermod useradd userdel groupmod groupadd groupdel setfacl chcon restorecon; do eval "$command() { return 99; }"; done
    run apply; [ "$status" -eq 0 ]
}
@test "7.2.9 apply findings require manual action without CHANGED" { history 0640; run apply; [ "$status" -eq 2 ]; [[ "$output" == *'observation only'* ]]; }
@test "7.2.9 rollback silent idempotent and no observation" {
    rlch_729_observe() { return 99; }; run rollback; [ "$status" -eq 0 ]; [ -z "$output" ]; run rollback; [ "$status" -eq 0 ]; [ -z "$output" ]
}
@test "7.2.9 checks and apply preserve contents metadata and file set" {
    before="$(stat -c '%i:%a:%u:%g:%s:%Y:%Z' "$P" "$N" "$H" "$H/.bashrc")"; bodies="$(sha256sum "$P" "$N" "$H/.bashrc")"; files="$(find "$RLCH_CIS_7_2_9_HOME" -print | sort)"
    run check; [ "$status" -eq 0 ]; run apply; [ "$status" -eq 0 ]; run rollback; [ "$status" -eq 0 ]
    [ "$before" = "$(stat -c '%i:%a:%u:%g:%s:%Y:%Z' "$P" "$N" "$H" "$H/.bashrc")" ]; [ "$bodies" = "$(sha256sum "$P" "$N" "$H/.bashrc")" ]; [ "$files" = "$(find "$RLCH_CIS_7_2_9_HOME" -print | sort)" ]
}
@test "7.2.9 diagnostics never disclose source data names shells UID or paths" {
    history 0640; run check; [ "$status" -eq 1 ]; [[ "$output" != *PRIVATE* && "$output" != *"$H"* && "$output" != *'/bin/bash'* && "$output" != *'ROW|'* ]]; [ "${#output}" -lt 1500 ]
}
@test "7.2.9 error diagnostics remain private" {
    _rlch_fs_snapshot_stat() { printf PRIVATE_AUTH >&2; return 2; }; run check; [ "$status" -eq 2 ]; [[ "$output" != *PRIVATE* && "$output" != *"$H"* ]]
}
@test "7.2.9 caller xtrace does not expose internal observations" {
    run bash -c 'source "$1/lib/common.sh"; source "$1/lib/module_api.sh"; source "$1/modules/cis/7/2/9/module.sh"; set -x; check; rc=$?; [[ $- == *x* ]] || exit 99; exit "$rc"' bash "$BATS_TEST_DIRNAME/.."
    [ "$status" -eq 0 ]; [[ "$output" != *PRIVATE* && "$output" != *"$H"* && "$output" != *'ROW|'* ]]
}
@test "7.2.9 unsupported Unicode tab newline and non UTF8 filenames ERROR" {
    for name in '.élève' $'.tab\tname' $'.line\nname' $'.bad\377'; do : > "$H/$name"; run check; [ "$status" -eq 2 ]; rm "$H/$name"; done
}
@test "7.2.9 printable shell metacharacters remain inert" {
    : > "$H/\$(touch PRIVATE_FLAG)"; run check; [ "$status" -eq 0 ]; [ ! -e PRIVATE_FLAG ]
}
@test "7.2.9 nonlocal ownership source fails conservatively without suppressing fixed findings" {
    printf '20 10 %s / %s rw - nfs server:/share rw\n' "$DEVICE" "$H" >> "$M"; : > "$J/.netrc"
    run check; [ "$status" -eq 2 ]; expect_rule accounts_user_dot_user_ownership ERROR; expect_rule no_netrc_files NON_COMPLIANT
}

# OVAL unique(text) followed by only-one(integer); policy owner substitutions
# occur only AFTER actual complete filesystem observations, as above.
gid_case() {
    local observed="$1" expected="$2" raw index=0 uid projection kind value matches gid_matches=0
    shift 2
    : > "$P"
    for raw in "$@"; do
        G="$raw"; uid="$UT"
        if (( index>0 )); then uid="$((100000+index))"; fi
        row "gid$index" "$uid" "$H" /bin/bash >> "$P"
        index=$((index+1))
    done
    projection="$(printf '%s\n%s\n' "$(rlch_identity_home_rows "$P")" "$(rlch_identity_gid_fields "$P" passwd)" | rlch_729_populations)"
    while IFS='|' read -r kind value matches; do
        if [[ "$kind" == GID && "$value" == "$observed" ]]; then gid_matches="$matches"; fi
    done <<< "$projection"
    [ "$gid_matches" -eq "$expected" ]
    OWNER_H="$U"; OWNER_J="$U"; GROUP_H="$observed"; GROUP_J="$observed"; policy_owners
    run check
    if [[ "$expected" -eq 1 ]]; then [ "$status" -eq 0 ]; expect_rule accounts_user_dot_group_ownership SUCCESS
    else [ "$status" -eq 1 ]; expect_rule accounts_user_dot_group_ownership NON_COMPLIANT
    fi
    expect_rule accounts_user_dot_user_ownership SUCCESS
    [[ "$output" != *'0042'* && "$output" != *'00042'* && "$output" != *'GID|'* ]]
}
@test "7.2.9 GID text unique 42 42 gives one numeric match" { gid_case 42 1 42 42; }
@test "7.2.9 GID false SUCCESS regression 42 0042 gives two numeric matches" { gid_case 42 2 42 0042; }
@test "7.2.9 GID text unique 42 0042 00042 gives three numeric matches" { gid_case 42 3 42 0042 00042; }
@test "7.2.9 GID text unique 42 43 observed 42 gives one numeric match" { gid_case 42 1 42 43; }
@test "7.2.9 GID text unique 42 43 observed 44 gives zero numeric matches" { gid_case 44 0 42 43; }
@test "7.2.9 GID text unique 0042 0042 gives one numeric match" { gid_case 42 1 0042 0042; }
@test "7.2.9 GID text unique 0042 42 0042 gives two numeric matches" { gid_case 42 2 0042 42 0042; }
@test "7.2.9 exact previously observed false SUCCESS fixture now NON_COMPLIANT" {
    G="000$G"; row extra 2000 "$H" /bin/bash >> "$P"
    run check; [ "$status" -eq 1 ]; expect_rule accounts_user_dot_group_ownership NON_COMPLIANT; expect_rule accounts_user_dot_user_ownership SUCCESS
}
@test "7.2.9 corrected projection exposes only counts for distinct raw GID spellings" {
    data="$(printf 'ROW|a|1000|/fixture|/bin/bash\nROW|b|1001|/fixture|/bin/bash\nROW|c|1002|/fixture|/bin/bash\nPRESENT|PRESENT|DECIMAL|0042\nPRESENT|PRESENT|DECIMAL|42\nPRESENT|PRESENT|DECIMAL|0042\n' | rlch_729_populations)"
    [[ "$data" == *'GID|42|2'* && "$data" != *'0042'* ]]
}
@test "7.2.9 GID conversion rejects unsupported signs range and nondecimal values" {
    for raw in -42 +42 4.2 0x2a 4294967295 999999999999999999999999999999999; do
        G="$raw"; row user 1000 "$H" /bin/bash > "$P"; run check; [ "$status" -eq 2 ]; expect_rule accounts_user_dot_group_ownership ERROR
    done
}
@test "7.2.9 GID zero spellings also retain only-one comparison multiplicity" { gid_case 0 2 0 0000; }
@test "7.2.9 GID accepted maximum and 32 digit spelling compare exactly" { gid_case 4294967294 1 00000000000000000000004294967294; }
