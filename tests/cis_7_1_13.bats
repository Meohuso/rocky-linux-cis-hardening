#!/usr/bin/env bats
# shellcheck source-path=SCRIPTDIR
# shellcheck disable=SC2016,SC2317 # Literal attack names and injected faults.
setup() {
    source "$BATS_TEST_DIRNAME/test_helper.bash"
    source "$BATS_TEST_DIRNAME/../lib/common.sh"
    source "$BATS_TEST_DIRNAME/../lib/modules.sh"
    source "$BATS_TEST_DIRNAME/../lib/module_api.sh"
    export RLCH_CIS_7_1_13_ROOT="$BATS_TEST_TMPDIR/root" RLCH_CIS_7_1_13_MOUNTINFO="$BATS_TEST_TMPDIR/mountinfo"
    RLCH_CIS_7_1_13_EMIT_INVENTORY=false
    R="$RLCH_CIS_7_1_13_ROOT"; M="$RLCH_CIS_7_1_13_MOUNTINFO"; CALLS="$BATS_TEST_TMPDIR/calls"
    mkdir "$R"; chmod 0755 "$R"
    # Inert plain files; tests never create or execute a privileged executable.
    printf 'artificial data only\n' > "$R/file"; chmod 0600 "$R/file"
    dev="$(stat -c %d "$R")"
    DEVICE="$(( (dev>>8 & 4095) | (dev>>32 & 4294963200) )):$(( (dev & 255) | (dev>>12 & 4294967040) ))"
    printf '10 0 %s / / rw - ext4 /dev/fixture rw\n' "$DEVICE" > "$M"
    source "$BATS_TEST_DIRNAME/../modules/cis/7/1/13/module.sh"
    eval "$(declare -f rlch_fs_find | sed '1s/rlch_fs_find/real_suid_find/')"
}
expect() { run "$1"; [ "$status" -eq 2 ]; [[ "$output" == *'human review required and unverified'* ]]; }
unknown() {
    RLCH_CIS_7_1_13_EMIT_INVENTORY=true
    run check; [ "$status" -eq 2 ]; [[ "$output" == 'CIS 7.1.13: ERROR; partial-scope inventory unavailable:'* ]]; [[ "$output" != *'BEGIN CIS_'* ]];
}
emit() { RLCH_CIS_7_1_13_EMIT_INVENTORY=true; run check; [ "$status" -eq 2 ]; [[ "$output" == 'BEGIN CIS_7_1_13_INVENTORY '* ]]; [[ "$output" == *'observation=COMPLETE review=UNVERIFIED conformity=UNDEMONSTRATED'* ]]; }
encode() { ENCODED="$1"; ENCODED="${ENCODED//\\/\\134}"; ENCODED="${ENCODED// /\\040}"; ENCODED="${ENCODED//$'\t'/\\011}"; ENCODED="${ENCODED//$'\n'/\\012}"; }
add_mount() {
    local id="$1" parent="$2" target="$3" source="$4" fs="${5:-ext4}" root="${6:-/}" encodedtarget encodedroot
    encode "$target"; encodedtarget="$ENCODED"; encode "$root"; encodedroot="$ENCODED"
    printf '%s %s %s %s %s rw - %s %s rw\n' "$id" "$parent" "$DEVICE" "$encodedroot" "$encodedtarget" "$fs" "$source" >> "$M"
}
snapshot() { (find "$R" -printf '%p|%y|%i|%n|%m|%U|%G|%T@|%C@|%l\n' | LC_ALL=C sort; find "$R" -type f -exec sha256sum -- {} + | LC_ALL=C sort); }
@test "7113 metadata honest Manual related rules no primary automation" {
    source "$BATS_TEST_DIRNAME/../modules/cis/7/1/13/metadata.conf"
    [ "$RLCH_MODULE_ID" = 7.1.13 ]; [ "$RLCH_MODULE_LEVEL" = 1 ]; [ "$RLCH_MODULE_ENABLED" = true ]
    [ "$RLCH_MODULE_REQUIRES_REBOOT" = false ]; [ "$RLCH_MODULE_OPENSCAP_RULE" = manual ]; [[ "$RLCH_MODULE_DESCRIPTION" == *Manual* ]]
    validate_loaded_module_metadata 7.1.13; validate_loaded_module_functions
}
@test "7113 framework loads after 7112" {
    RLCH_MODULE_ROOT="$RLCH_TEST_REPOSITORY_ROOT/modules"; RLCH_MODULE_NAMESPACE=cis
    RLCH_MODULE_METADATA_FILENAME=metadata.conf; RLCH_MODULE_IMPLEMENTATION_FILENAME=module.sh
    load_module "$RLCH_TEST_REPOSITORY_ROOT/modules/cis/7/1/12"; load_module "$RLCH_TEST_REPOSITORY_ROOT/modules/cis/7/1/13"
    [ "$RLCH_CURRENT_MODULE_ID" = 7.1.13 ]; expect check
}
@test "7113 ordinary file never false SUCCESS all APIs" {
    expect check; expect validate; expect apply; [[ "$output" == *'(0 files)'* ]]; }
@test "7113 empty artificial tree never proves human review" {
    rm "$R/file"; emit; [[ "$output" == *'files=0 mounts=1'* ]]; }
@test "7113 SUID regular file is inventory not NON_COMPLIANT" {
    chmod 4600 "$R/file"; emit; [[ "$output" == *'mode=4600'* ]]; [[ "$output" == *'suid=1 sgid=0'* ]]; [[ "$output" == *'files=1 '* ]]; }
@test "7113 SGID regular file recorded separately" {
    chmod 2600 "$R/file"; emit; [[ "$output" == *'suid=0 sgid=1'* ]]; }
@test "7113 both bits recorded once" {
    chmod 6600 "$R/file"; emit; [[ "$output" == *'suid=1 sgid=1'* ]]; [[ "$output" == *'files=1 '* ]]; }
@test "7113 sticky bit alone never SUID or SGID evidence" {
    chmod 1600 "$R/file"; emit; [[ "$output" == *'files=0 '* ]]; }
@test "7113 sticky with SUID SGID does not hide either" {
    chmod 7600 "$R/file"; emit; [[ "$output" == *'suid=1 sgid=1'* ]]; }
@test "7113 execute permission not required by technical bit criterion" {
    chmod 4600 "$R/file"; [ ! -x "$R/file" ]; emit; [[ "$output" == *'files=1 '* ]]; }
@test "7113 multiple files each bit included" {
    touch "$R/sgid" "$R/both"; chmod 4600 "$R/file"; chmod 2600 "$R/sgid"; chmod 6600 "$R/both"
    emit; [[ "$output" == *'files=3 '* ]]; }
@test "7113 symlink to privileged inert fixture not followed" {
    printf 'external artificial\n' > "$BATS_TEST_TMPDIR/external"; chmod 4600 "$BATS_TEST_TMPDIR/external"
    ln -s "$BATS_TEST_TMPDIR/external" "$R/link"; ln -s / "$R/host"; ln -s missing "$R/dangling"; ln -s . "$R/cycle"
    emit; [[ "$output" == *'files=0 '* ]]; }
@test "7113 hardlinks each path retained with nlink identity" {
    chmod 4600 "$R/file"; ln "$R/file" "$R/alias"; emit; [[ "$output" == *'files=2 '* ]]; [[ "$output" == *'nlink=2 '* ]]; }
@test "7113 directories SGID and FIFO bits not regular file evidence" {
    mkdir "$R/directory"; chmod 2600 "$R/directory"; chmod 2700 "$R/directory"
    mkfifo "$R/pipe"; chmod 6600 "$R/pipe"; emit; [[ "$output" == *'files=0 '* ]]; }
@test "7113 arbitrary paths escaped to one display line without execution" {
    for name in 'space name' $'line\nname' $'end\n' $'tab\tname' $'control\001name' $'nonutf\377' '$(touch BAD)' 'glob[*?]' 'pipe|name'; do
        touch "$R/$name"; chmod 4600 "$R/$name"
    done
    emit; [[ "$output" == *'files=9 '* ]]; [[ "$output" == *'\nname'* ]]; [[ "$output" == *'\377'* ]]; [ ! -e BAD ]
    [ "$(printf '%s\n' "$output" | awk '/^FILE /{n++} END{print n}')" -eq 9 ]
}
@test "7113 paths omitted by default even when found" {
    chmod 4600 "$R/file"; run check; [ "$status" -eq 2 ]; [[ "$output" != *'path='* ]]; [[ "$output" != *'/file'* ]]; [[ "$output" == *'(1 files)'* ]]; }
@test "7113 output flag exact bool invalid fails without scan" {
    RLCH_CIS_7_1_13_EMIT_INVENTORY=YES; rlch_fs_find() { touch "$CALLS"; return 99; }
    run check; [ "$status" -eq 2 ]; [[ "$output" == *'invalid inventory output setting'* ]]; [ ! -e "$CALLS" ]
}
@test "7113 report includes numeric identity metadata and mount evidence" {
    chmod 4600 "$R/file"; emit
    for key in 'MOUNT id=10 parent=0 device=' 'root=/' 'target=/' 'source=/dev/fixture' 'fstype=ext4' 'FILE mount_id=10 path=/file type=f device=' 'inode=' 'nlink=' 'uid=' 'gid=' 'ctime='; do [[ "$output" == *"$key"* ]]; done
}
@test "7113 selected nested mount maps to nearest mount ID" {
    mkdir -p "$R/data/nested"; touch "$R/data/nested/file"; chmod 4600 "$R/data/nested/file"
    add_mount 20 10 /data /dev/data; add_mount 30 20 /data/nested /dev/nested; emit
    [[ "$output" == *'FILE mount_id=30 path=/data/nested/file '* ]]; [[ "$output" == *'files=1 mounts=3'* ]]
}
@test "7113 same device bind distinct mount identity" {
    mkdir "$R/bind"; touch "$R/bind/file"; chmod 2600 "$R/bind/file"; add_mount 20 10 /bind /dev/fixture ext4 /original
    emit; [[ "$output" == *'MOUNT id=20 '* ]]; [[ "$output" == *'root=/original target=/bind'* ]]; [[ "$output" == *'FILE mount_id=20 path=/bind/file '* ]]
}
@test "7113 excluded same device bind subtree not inventoried" {
    mkdir "$R/excluded"; touch "$R/excluded/file"; chmod 4600 "$R/excluded/file"; add_mount 20 10 /excluded tmpfs tmpfs
    emit; [[ "$output" == *'files=0 mounts=1'* ]]; [[ "$output" != *'path=/excluded'* ]]
}
@test "7113 selected descendant below excluded ancestor" {
    mkdir -p "$R/net/local"; touch "$R/net/local/file"; chmod 4600 "$R/net/local/file"
    add_mount 20 10 /net host:/share nfs; add_mount 30 20 /net/local /dev/local; emit
    [[ "$output" == *'FILE mount_id=30 path=/net/local/file '* ]]
}
@test "7113 ordinary network proc overlay tmpfs excluded technical scope" {
    for spec in 'nfs host:/share' 'proc proc' 'overlay overlay' 'tmpfs tmpfs'; do
        read -r fs src <<< "$spec"; mkdir "$R/excluded"; touch "$R/excluded/file"; chmod 4600 "$R/excluded/file"; add_mount 20 10 /excluded "$src" "$fs"
        emit; [[ "$output" == *'files=0 '* ]]; rm -r "$R/excluded"; head -1 "$M" > "$M.new"; mv "$M.new" "$M"
    done
}
@test "7113 tmpfs tmp addition from SCE not imported" {
    mkdir "$R/tmp"; touch "$R/tmp/file"; chmod 4600 "$R/tmp/file"; add_mount 20 10 /tmp tmpfs tmpfs; emit; [[ "$output" == *'files=0 '* ]]; }
@test "7113 dev backed distributed FS and read only volume included" {
    chmod 4600 "$R/file"; sed -i 's/ext4/ceph/;s/ rw/ ro/g' "$M"; emit; [[ "$output" == *'files=1 '* ]]; [[ "$output" == *'fstype=ceph vfs=ro'* ]]; }
@test "7113 exact sysroot subtree excluded both bits" {
    mkdir "$R/sysroot"; touch "$R/sysroot/suid" "$R/sysroot/sgid"; chmod 4600 "$R/sysroot/suid"; chmod 2600 "$R/sysroot/sgid"; emit; [[ "$output" == *'files=0 '* ]]; }
@test "7113 similarly named sysroot sibling not excluded" {
    touch "$R/sysroot-file"; chmod 4600 "$R/sysroot-file"; emit; [[ "$output" == *'path=/sysroot-file '* ]]; }
@test "7113 sysroot newline exception ambiguity returns ERROR no inventory" {
    mkdir "$R/sysroot"; touch "$R/sysroot/line"$'\n'; chmod 4600 "$R/sysroot/line"$'\n'; unknown; }
@test "7113 no unrelated selinux exception imported" {
    mkdir "$R/selinux"; touch "$R/selinux/member"; chmod 4600 "$R/selinux/member"; emit; [[ "$output" == *'path=/selinux/member '* ]]; }
@test "7113 missing or malformed mount evidence never emits inventory" {
    printf 'bad\n' > "$M"; unknown; rm "$M"; unknown; }
@test "7113 no eligible devices not vacuous reviewed success" {
    sed -i 's@/dev/fixture@overlay@' "$M"; unknown; }
@test "7113 newline mount source ambiguous rejected" {
    sed -i 's@/dev/fixture@/dev/fixture\\012tail@' "$M"; unknown; }
@test "7113 arbitrary mount name display escaped and ID retained" {
    name=$'literal[*?]\n\377'; mkdir "$R/$name"; touch "$R/$name/file"; chmod 4600 "$R/$name/file"; add_mount 20 10 "/$name" /dev/data
    emit; [[ "$output" == *'FILE mount_id=20 '* ]]; [[ "$output" == *'files=1 mounts=2'* ]]
}
@test "7113 interrupted find output never emitted" {
    chmod 4600 "$R/file"; rlch_fs_find() { real_suid_find "$@"; return 124; }; unknown; }
@test "7113 zero status warning invalidates inventory" {
    rlch_fs_find() { real_suid_find "$@"; printf 'PRIVATE PATH\n' >&2; }; unknown; [[ "$output" != *PRIVATE* ]]; }
@test "7113 malformed metadata rejected" {
    rlch_fs_find() { real_suid_find "$@" | awk -v RS='\0' '{if(NR==8)$0="8888";printf "%s%c",$0,0}'; }; unknown; }
@test "7113 truncated tuple rejected" {
    rlch_fs_find() { printf '%s\0f\0' "$R"; }; unknown; }
@test "7113 missing final NUL rejected" {
    rlch_fs_find() { real_suid_find "$@" | head -c -1; }; unknown; }
@test "7113 inaccessible later mount suppresses earlier collected evidence" {
    chmod 4600 "$R/file"; add_mount 20 10 /missing /dev/missing; unknown; }
@test "7113 filesystem change between traversals invalidates entire inventory" {
    rlch_fs_find() { real_suid_find "$@"; if [[ ! -e "$CALLS" ]]; then touch "$CALLS"; chmod 4600 "$R/file"; fi; }; unknown; }
@test "7113 mount graph change invalidates entire inventory" {
    chmod 4600 "$R/file"; rlch_fs_find() { real_suid_find "$@"; if [[ ! -e "$CALLS" ]]; then touch "$CALLS"; mkdir "$R/new"; add_mount 20 10 /new proc proc; fi; }; unknown; }
@test "7113 fixture contents permissions and atime preserved by public APIs" {
    chmod 4600 "$R/file"; touch -a -d '2001-01-01 UTC' "$R/file"; before="$(stat -c '%i:%n:%a:%u:%g:%s:%X:%Y:%Z' "$R/file")"
    expect check; expect validate; expect apply; [ "$before" = "$(stat -c '%i:%n:%a:%u:%g:%s:%X:%Y:%Z' "$R/file")" ]; [ "$(cat "$R/file")" = 'artificial data only' ]
}
@test "7113 fresh validate and apply no cached records" {
    emit; [[ "$output" == *'files=0 '* ]]; chmod 4600 "$R/file"; run validate; [ "$status" -eq 2 ]; [[ "$output" == *'files=1 '* ]]; chmod 0600 "$R/file"; run apply; [ "$status" -eq 2 ]; [[ "$output" == *'files=0 '* ]]
}
@test "7113 repeat inventory deterministic without false review" {
    chmod 4600 "$R/file"; emit; first="$output"; emit; [ "$first" = "$output" ]; [[ "$output" != *'review=VERIFIED'* ]]; }
@test "7113 rollback silent repeatable no state" {
    before="$(snapshot)"; for n in 1 2; do [ "$n" -gt 0 ]; run rollback; [ "$status" -eq 0 ]; [ -z "$output" ]; done; [ "$before" = "$(snapshot)" ]; }
@test "7113 no human approval inferred from arbitrary flags" {
    export RLCH_CIS_7_1_13_REVIEWED=true RLCH_CIS_7_1_13_APPROVED=true
    expect check; expect validate; expect apply
}
@test "7113 framework records ERROR not COMPLIANT or NON_COMPLIANT" {
    source "$BATS_TEST_DIRNAME/../lib/execution.sh"
    RLCH_CURRENT_MODULE_ID=7.1.13; RLCH_CURRENT_MODULE_ENABLED=true
    result=0; execute_current_module_action check || result=$?
    [ "$result" -eq 2 ]; [ "$RLCH_EXECUTION_STATUS" = error ]
}
@test "7113 diagnostics bounded redacted and stdout empty by default" {
    chmod 4600 "$R/file"; result=0; check > "$BATS_TEST_TMPDIR/out" 2> "$BATS_TEST_TMPDIR/err" || result=$?
    [ "$result" -eq 2 ]; [ ! -s "$BATS_TEST_TMPDIR/out" ]; [ "$(wc -c < "$BATS_TEST_TMPDIR/err")" -lt 512 ]; [[ "$(cat "$BATS_TEST_TMPDIR/err")" != *"$R"* ]]
}
@test "7113 no package lookup hash content execution or mutation command" {
    chmod 4600 "$R/file"
    for cmd in cat sha256sum rpm getent chmod chown chgrp cp mv rm systemctl service; do eval "$cmd() { printf '%s\n' '$cmd' >> '$CALLS'; return 99; }"; done
    emit; [ ! -e "$CALLS" ]; unset -f cat sha256sum rpm getent chmod chown chgrp cp mv rm systemctl service
}
@test "7113 output write failure returns ERROR with fixed guidance" {
    RLCH_CIS_7_1_13_EMIT_INVENTORY=true; result=0
    check > /dev/full 2> "$BATS_TEST_TMPDIR/err" || result=$?
    [ "$result" -eq 2 ]; [[ "$(cat "$BATS_TEST_TMPDIR/err")" == *'inventory output failed'* ]]
}
@test "7113 broken pipe cannot terminate evaluator with SIGPIPE status" {
    RLCH_CIS_7_1_13_EMIT_INVENTORY=true
    bash -c 'source "$1"; source "$2"; RLCH_CIS_7_1_13_ROOT="$3"; RLCH_CIS_7_1_13_MOUNTINFO="$4"; RLCH_CIS_7_1_13_EMIT_INVENTORY=true; set -o pipefail; check 2>/dev/null | head -c 0; exit "${PIPESTATUS[0]}"' \
        _ "$BATS_TEST_DIRNAME/../lib/module_api.sh" "$BATS_TEST_DIRNAME/../modules/cis/7/1/13/module.sh" "$R" "$M" && result=0 || result=$?
    [ "$result" -eq 2 ]
}
@test "7113 inventory count cap never truncates to apparently complete output" {
    for ((i=0;i<4097;i++)); do printf 'artificial\n' > "$R/f$i"; chmod 4600 "$R/f$i"; done
    unknown
}
@test "7113 inventory byte cap enforced before publication" {
    # Direct callback boundary: scan evidence is supplied by the library; this
    # test stresses the separate module report budget without a huge host scan.
    RLCH_7113_TEXT="$(printf '%8388608s' x)"; RLCH_7113_MOUNTS=(); RLCH_7113_SELECTED=()
    # shellcheck disable=SC2034 # Read indirectly through the selector nameref.
    local -a sample_mounts=(10 0 "$DEVICE" / / /dev/fixture ext4 rw rw '')
    run rlch_7_1_13_select sample_mounts 0; [ "$status" -eq 2 ]
}
@test "7113 filesystem-specific mount options not disclosed even opt in" {
    sed -i 's@/dev/fixture rw$@/dev/fixture rw,secret=PRIVATE@' "$M"; emit
    [[ "$output" != *PRIVATE* ]]; [[ "$output" != *fs_options=* ]]
}
@test "7113 nosuid not treated as human approval or bit absence" {
    chmod 4600 "$R/file"; sed -i 's@ / / rw @ / / rw,nosuid @' "$M"; emit
    printf -v displayed %q rw,nosuid; [[ "$output" == *"vfs=$displayed"* ]]; [[ "$output" == *'files=1 '* ]]
}
@test "7113 newline frame text in filename never forges end frame" {
    name=$'x\nEND CIS_7_1_13_INVENTORY files=0'; touch "$R/$name"; chmod 4600 "$R/$name"; emit
    [ "$(printf '%s\n' "$output" | awk '/^END CIS_7_1_13_INVENTORY /{n++} END{print n}')" -eq 1 ]
    [[ "$output" == *'files=1 '* ]]
}
