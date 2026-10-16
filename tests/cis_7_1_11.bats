#!/usr/bin/env bats
# shellcheck source-path=SCRIPTDIR
# shellcheck disable=SC2016,SC2317 # Literal attack names; mocks invoked by sourced APIs.
setup() {
    source "$BATS_TEST_DIRNAME/test_helper.bash"
    source "$BATS_TEST_DIRNAME/../lib/common.sh"
    source "$BATS_TEST_DIRNAME/../lib/modules.sh"
    source "$BATS_TEST_DIRNAME/../lib/module_api.sh"
    export RLCH_CIS_7_1_11_ROOT="$BATS_TEST_TMPDIR/root" RLCH_CIS_7_1_11_MOUNTINFO="$BATS_TEST_TMPDIR/mountinfo"
    R="$RLCH_CIS_7_1_11_ROOT"; M="$RLCH_CIS_7_1_11_MOUNTINFO"; CALLS="$BATS_TEST_TMPDIR/calls"
    mkdir -p "$R/etc"; chmod 0755 "$R" "$R/etc"
    for name in passwd passwd- group group- shadow shadow- gshadow gshadow- shells; do printf 'artificial preservation content\n' > "$R/etc/$name"; chmod 0644 "$R/etc/$name"; done
    dev="$(stat -c %d "$R")"; DEVICE_NUMBER="$dev"
    DEVICE="$(( (dev>>8 & 4095) | (dev>>32 & 4294963200) )):$(( (dev & 255) | (dev>>12 & 4294967040) ))"
    printf '10 0 %s / / rw - ext4 /dev/fixture rw\n' "$DEVICE" > "$M"
    source "$BATS_TEST_DIRNAME/../modules/cis/7/1/11/module.sh"
    eval "$(declare -f rlch_7_1_11_find | sed '1s/rlch_7_1_11_find/real_ww_find/')"
}
expect() { run "$1"; [ "$status" -eq "$2" ]; [[ "$output" == 'CIS 7.1.11:'* ]]; }
unknown() { expect check 2; expect validate 2; expect apply 2; }
encode() { ENCODED="$1"; ENCODED="${ENCODED//\\/\\134}"; ENCODED="${ENCODED// /\\040}"; ENCODED="${ENCODED//$'\t'/\\011}"; ENCODED="${ENCODED//$'\n'/\\012}"; }
add_mount() {
    local id="$1" parent="$2" target="$3" source="$4" fs="${5:-ext4}" root="${6:-/}" encodedtarget encodedroot
    encode "$target"; encodedtarget="$ENCODED"; encode "$root"; encodedroot="$ENCODED"
    printf '%s %s %s %s %s rw - %s %s rw\n' "$id" "$parent" "$DEVICE" "$encodedroot" "$encodedtarget" "$fs" "$source" >> "$M"
}
snapshot() {
    (set -o pipefail; find "$R" -printf '%p|%y|%D|%i|%n|%m|%U|%G|%T@|%C@|%l\n' | LC_ALL=C sort
     find "$R" -type f -perm /0444 -exec sha256sum -- {} + | LC_ALL=C sort)
}
@test "7111 exact L1 metadata two-rule manual scalar" {
    source "$BATS_TEST_DIRNAME/../modules/cis/7/1/11/metadata.conf"
    [ "$RLCH_MODULE_ID" = 7.1.11 ]; [ "$RLCH_MODULE_TITLE" = 'Ensure world writable files and directories are secured' ]
    [ "$RLCH_MODULE_LEVEL" = 1 ]; [ "$RLCH_MODULE_ENABLED" = true ]; [ "$RLCH_MODULE_REQUIRES_REBOOT" = false ]; [ "$RLCH_MODULE_OPENSCAP_RULE" = manual ]
    validate_loaded_module_metadata 7.1.11; validate_loaded_module_functions
}
@test "7111 framework loads after opasswd and binds fresh API" {
    RLCH_MODULE_ROOT="$RLCH_TEST_REPOSITORY_ROOT/modules"; RLCH_MODULE_NAMESPACE=cis
    RLCH_MODULE_METADATA_FILENAME=metadata.conf; RLCH_MODULE_IMPLEMENTATION_FILENAME=module.sh
    load_module "$RLCH_TEST_REPOSITORY_ROOT/modules/cis/7/1/10"; load_module "$RLCH_TEST_REPOSITORY_ROOT/modules/cis/7/1/11"
    [ "$RLCH_CURRENT_MODULE_ID" = 7.1.11 ]; expect check 0
}
@test "7111 compliant files check validate apply unchanged" {
    before="$(snapshot)"; expect check 0; expect validate 0; expect apply 0; [ "$before" = "$(snapshot)" ]; }
@test "7111 world writable regular file deficit" {
    chmod 0666 "$R/etc/passwd"; expect check 1; expect validate 1; expect apply 2; }
@test "7111 regular sticky bit does not excuse world write" {
    chmod 1666 "$R/etc/passwd"; expect check 1; }
@test "7111 sticky world writable directories accepted" {
    mkdir "$R/public"; chmod 1777 "$R/public"; expect check 0; expect apply 0; }
@test "7111 world writable directory without sticky deficit" {
    mkdir "$R/public"; chmod 0777 "$R/public"; expect check 1; expect apply 2; }
@test "7111 directory sticky not required without other write" {
    mkdir "$R/shared"; for mode in 0755 0770 2770 4770 1770; do chmod "$mode" "$R/shared"; expect check 0; done; }
@test "7111 directory suid sgid do not replace sticky" {
    mkdir "$R/public"; for mode in 2777 4777 6777; do chmod "$mode" "$R/public"; expect check 1; done; }
@test "7111 directory sticky plus other special bits allowed" {
    mkdir "$R/public"; for mode in 3777 5777 7777; do chmod "$mode" "$R/public"; expect check 0; done; }
@test "7111 regular suid sgid execute otherwise outside criterion" {
    for mode in 0755 0644 0600 0000 4755 2755 6755; do chmod "$mode" "$R/etc/passwd"; expect check 0; done; }
@test "7111 simultaneous file directory deficits all APIs preserve" {
    chmod 0666 "$R/etc/group"; mkdir "$R/public"; chmod 0777 "$R/public"; before="$(snapshot)"
    expect check 1; expect validate 1; expect apply 2; run rollback; [ "$status" -eq 0 ]; [ "$before" = "$(snapshot)" ]
}
@test "7111 truly empty artificial tree valid" {
    rm -r "${R:?}/etc"; expect check 0; }
@test "7111 hidden nested world writable file found" {
    mkdir -p "$R/.hidden/.nested"; touch "$R/.hidden/.nested/.bad"; chmod 0602 "$R/.hidden/.nested/.bad"; expect check 1; }
@test "7111 arbitrary file names spaces newline control nonutf8 and shell syntax" {
    for name in 'space name' $'line\nname' $'tab\tname' $'control\001name' $'nonutf\377' '$(touch BAD)' 'pipe|name' 'glob[*?]'; do
        printf 'artificial\n' > "$R/$name"; chmod 0644 "$R/$name"; expect check 0; chmod 0666 "$R/$name"; expect check 1; rm "$R/$name"
    done
    [ ! -e BAD ]
}
@test "7111 directory names arbitrary bytes remain literal" {
    for name in 'space name' $'line\nname' $'nonutf\377' '$(touch BAD)'; do mkdir "$R/$name"; chmod 1777 "$R/$name"; expect check 0; chmod 0777 "$R/$name"; expect check 1; rmdir "$R/$name"; done
    [ ! -e BAD ]
}
@test "7111 symlinks dangling and cycles not followed" {
    ln -s / "$R/host"; ln -s missing "$R/dangling"; ln -s . "$R/loop"; expect check 0; }
@test "7111 symlink to artificial external world writable file not followed" {
    printf 'artificial\n' > "$BATS_TEST_TMPDIR/external"; chmod 0666 "$BATS_TEST_TMPDIR/external"; ln -s "$BATS_TEST_TMPDIR/external" "$R/external"; expect check 0
}
@test "7111 hardlinks valid and world writable aliases deficient not ERROR" {
    ln "$R/etc/group" "$R/alias"; expect check 0; chmod 0666 "$R/alias"; expect check 1; }
@test "7111 FIFO not opened or classified as regular file" {
    mkfifo "$R/pipe"; chmod 0666 "$R/pipe"; expect check 0; }
@test "7111 inaccessible directory ERROR even when root could bypass mode" {
    mkdir "$R/closed"; chmod 0000 "$R/closed"; unknown; chmod 0755 "$R/closed"; }
@test "7111 missing selected mount root ERROR" {
    add_mount 20 10 /missing /dev/fixture; unknown; }
@test "7111 selected file mount unsupported ERROR instead of omitted" {
    touch "$R/file-mount"; add_mount 20 10 /file-mount /dev/fixture; unknown; }
@test "7111 symlink selected mount root ERROR" {
    mkdir "$R/actual"; ln -s actual "$R/alias"; add_mount 20 10 /alias /dev/fixture; unknown; }
@test "7111 root symlink dot segments or relative injection ERROR" {
    for path in relative "$R/../root"; do RLCH_CIS_7_1_11_ROOT="$path"; unknown; done; }
@test "7111 nested selected mount own traversal finds deficit" {
    mkdir "$R/data"; touch "$R/data/bad"; chmod 0666 "$R/data/bad"; add_mount 20 10 /data /dev/data; expect check 1; }
@test "7111 same device bind mount not hidden by xdev" {
    mkdir "$R/bind"; touch "$R/bind/bad"; chmod 0666 "$R/bind/bad"; add_mount 20 10 /bind /dev/fixture ext4 /original; expect check 1; }
@test "7111 excluded network pseudo tmpfs overlay scopes explicitly pruned" {
    for spec in 'nfs host:/share' 'proc proc' 'tmpfs tmpfs' 'overlay overlay'; do read -r fs source <<< "$spec"; mkdir "$R/excluded"; touch "$R/excluded/bad"; chmod 0666 "$R/excluded/bad"; add_mount 20 10 /excluded "$source" "$fs"; expect check 0; rm -r "$R/excluded"; head -1 "$M" > "$M.new"; mv "$M.new" "$M"; done
}
@test "7111 excluded ancestor still allows separately selected nested local mount" {
    mkdir -p "$R/net/local"; touch "$R/net/local/bad"; chmod 0666 "$R/net/local/bad"; add_mount 20 10 /net host:/share nfs; add_mount 30 20 /net/local /dev/local; expect check 1; }
@test "7111 local dev backed distributed FS included by literal CAS selection" {
    mkdir "$R/ceph"; touch "$R/ceph/bad"; chmod 0666 "$R/ceph/bad"; add_mount 20 10 /ceph /dev/rbd0 ceph; expect check 1; }
@test "7111 readonly option not a conformity exemption" {
    chmod 0666 "$R/etc/group"; sed -i 's/ rw/ ro/g' "$M"; expect check 1; }
@test "7111 no eligible mounts ERROR never vacuous global success" {
    sed -i 's@/dev/fixture@overlay@' "$M"; unknown; }
@test "7111 major minor mismatch ERROR" {
    sed -i "s/$DEVICE/4294:1234/" "$M"; unknown; }
@test "7111 selected mountpoint names newline space nonutf8 and glob literal" {
    for name in 'space name' $'line\nname' $'nonutf\377' 'literal[*?]'; do
        mkdir "$R/$name"; touch "$R/$name/bad"; chmod 0666 "$R/$name/bad"; add_mount 20 10 "/$name" /dev/data; expect check 1
        rm -r "${R:?}/$name"; head -1 "$M" > "$M.new"; mv "$M.new" "$M"
    done
}
@test "7111 excluded glob mount name does not prune similarly named sibling" {
    mkdir "$R/[x]*?" "$R/xx"; touch "$R/[x]*?/bad" "$R/xx/bad"; chmod 0666 "$R/[x]*?/bad" "$R/xx/bad"; add_mount 20 10 '/[x]*?' proc proc; expect check 1; chmod 0644 "$R/xx/bad"; expect check 0; }
@test "7111 file sysroot exception does not exempt directories" {
    mkdir -p "$R/sysroot"; touch "$R/sysroot/bad"; chmod 0666 "$R/sysroot/bad"; expect check 0; chmod 0777 "$R/sysroot"; expect check 1; }
@test "7111 exact six selinux file exceptions not siblings or directories" {
    mkdir "$R/selinux"
    for name in member user relabel create access context; do touch "$R/selinux/$name"; chmod 0666 "$R/selinux/$name"; done
    expect check 0; touch "$R/selinux/other"; chmod 0666 "$R/selinux/other"; expect check 1
    rm "$R/selinux/other" "$R/selinux/member"; mkdir "$R/selinux/member"; chmod 0777 "$R/selinux/member"; expect check 1
}
@test "7111 find failure after plausible full output ERROR" {
    rlch_7_1_11_find() { real_ww_find "$@"; return 99; }; unknown; }
@test "7111 interrupted scan ERROR" {
    rlch_7_1_11_find() { return 124; }; unknown; }
@test "7111 empty output with success ERROR" {
    rlch_7_1_11_find() { return 0; }; unknown; }
@test "7111 incomplete malformed fields ERROR" {
    for data in '' 'bad' $'/tmp\000f\000'; do rlch_7_1_11_find() { printf '%s' "$data"; }; unknown; done
}
@test "7111 all malformed metadata fields rejected" {
    for spec in '2=Z' '3=-1' '4=0' '5=0' '6=00' '7=4294967295' '8=8888' '9=garbage' '10=1025'; do
        rlch_7_1_11_find() { real_ww_find "$@" | LC_ALL=C awk -v RS='\0' -v spec="$spec" 'BEGIN{split(spec,a,"=")} {if(NR==a[1]) $0=a[2];printf "%s%c",$0,0}'; }; unknown
    done
}
@test "7111 duplicate records ERROR instead of claimed complete scan" {
    rlch_7_1_11_find() { real_ww_find "$@"; real_ww_find "$@"; }; unknown; }
@test "7111 malformed root stat controls NUL high raw bits rejected" {
    for evidence in 'bad' "$dev|ffff41ed" "$dev|ffff8000"; do rlch_7_1_11_root_stat() { printf '%s\n' "$evidence"; }; unknown; done
    rlch_7_1_11_root_stat() { printf '%s|41ed\000\n' "$DEVICE_NUMBER"; }; unknown
}
@test "7111 ERROR priority over detected world writable deficit" {
    chmod 0666 "$R/etc/group"; mkdir "$R/closed"; chmod 0000 "$R/closed"; unknown; chmod 0755 "$R/closed"; }
@test "7111 actual creation between traversals ERROR" {
    rlch_7_1_11_find() { real_ww_find "$@"; if [[ ! -e "$CALLS" ]]; then : > "$CALLS"; touch "$R/new"; fi; }
    expect check 2
}
@test "7111 actual disappearance between traversals ERROR" {
    rlch_7_1_11_find() { real_ww_find "$@"; if [[ ! -e "$CALLS" ]]; then : > "$CALLS"; rm "$R/etc/group"; fi; }
    expect check 2
}
@test "7111 actual replacement mode or hardlink count changes ERROR" {
    rlch_7_1_11_find() { real_ww_find "$@"; if [[ ! -e "$CALLS" ]]; then : > "$CALLS"; mv "$R/etc/group" "$BATS_TEST_TMPDIR/old"; touch "$R/etc/group"; fi; }
    expect check 2
}
@test "7111 metadata change between complete scans ERROR even for stable deficit" {
    chmod 0666 "$R/etc/group"; : > "$CALLS"
    rlch_7_1_11_find() { real_ww_find "$@" | LC_ALL=C awk -v RS='\0' -v n="$(wc -l < "$CALLS")" '{if(n && NR==4) $0+=1;printf "%s%c",$0,0}'; printf 'call\n' >> "$CALLS"; }
    expect check 2
}
@test "7111 inventory changes between scans ERROR" {
    rlch_7_1_11_find() { real_ww_find "$@"; if [[ ! -e "$CALLS" ]]; then : > "$CALLS"; mkdir "$R/new-mount"; add_mount 20 10 /new-mount proc proc; fi; }
    expect check 2
}
@test "7111 invalid inventory or missing file ERROR" {
    printf 'bad\n' > "$M"; unknown; rm "$M"; unknown; }
@test "7111 selected device source newline ambiguous ERROR" {
    sed -i 's@/dev/fixture@/dev/fixture\\012name@' "$M"; unknown; }
@test "7111 fresh validate observes compliant then deficit" {
    expect check 0; chmod 0666 "$R/etc/group"; expect validate 1; }
@test "7111 fresh apply observes deficit then repair without cache" {
    chmod 0666 "$R/etc/group"; expect apply 2; chmod 0644 "$R/etc/group"; expect apply 0; }
@test "7111 check apply validate rollback sequence idempotent no state" {
    before="$(snapshot)"; for n in 1 2; do expect check 0; expect apply 0; expect validate 0; run rollback; [ "$status" -eq 0 ]; [ -z "$output" ]; done; [ "$before" = "$(snapshot)" ]
}
@test "7111 rollback silent repeatable without tree or inventory" {
    rm -r "$R"; rm "$M"; for n in 1 2; do run rollback; [ "$status" -eq 0 ]; [ -z "$output" ]; done; }
@test "7111 no content NSS mutation packages network or service commands" {
    probe() (
        local cmd api
        for cmd in cat grep sed sha256sum getent id rpm dnf curl systemctl service chmod chown chgrp cp mv rm mkdir touch ln mount umount; do eval "$cmd() { printf '%s\n' '$cmd' >> '$CALLS'; return 99; }"; done
        for api in check validate apply rollback; do "$api" >/dev/null 2>/dev/null || return 1; done
    )
    run probe; [ "$status" -eq 0 ]; [ ! -e "$CALLS" ]
}
@test "7111 artificial contents neighbors and metadata preserved for deficit too" {
    chmod 0666 "$R/etc/group"; before="$(snapshot)"; expect check 1; expect validate 1; expect apply 2; run rollback; [ "$status" -eq 0 ]; [ "$before" = "$(snapshot)" ]; }
@test "7111 file atime mtime ctime preserved without hashing" {
    before="$(stat -c '%n|%d|%i|%h|%u|%g|%a|%x|%y|%z' "$R/etc/"*)"
    expect check 0; expect validate 0; expect apply 0
    [ "$before" = "$(stat -c '%n|%d|%i|%h|%u|%g|%a|%x|%y|%z' "$R/etc/"*)" ]
}
@test "7111 diagnostics bounded redacted stderr no stdout" {
    chmod 0666 "$R/etc/group"
    for api in check validate apply; do result=0; "$api" > "$BATS_TEST_TMPDIR/out" 2> "$BATS_TEST_TMPDIR/err" || result=$?
        [[ "$result" == 1 || "$result" == 2 ]]; [ ! -s "$BATS_TEST_TMPDIR/out" ]; [ "$(wc -c < "$BATS_TEST_TMPDIR/err")" -lt 1024 ]; ! grep -F "$R" "$BATS_TEST_TMPDIR/err"
    done
}
@test "7111 reasonable 500-object artificial tree completes" {
    mkdir "$R/many"; for ((n=0;n<500;n++)); do : > "$R/many/file$n"; done; expect check 0; }
@test "7111 selected mount names raw control and carriage return preserve bytes" {
    for name in $'control-\001-name' $'return-\r-name'; do
        mkdir "$R/$name"; add_mount 20 10 "/$name" /dev/data; expect check 0
        rm -r "${R:?}/$name"; head -1 "$M" > "$M.new"; mv "$M.new" "$M"
    done
}
@test "7111 newline bearing CAS exception path fails closed instead of shell widening" {
    mkdir "$R/sysroot"; touch "$R/sysroot/"$'bad\nname'; chmod 0666 "$R/sysroot/"$'bad\nname'; unknown
}
@test "7111 producer object and field limits ERROR never partial success" {
    rlch_7_1_11_find() { LC_ALL=C awk 'BEGIN{for(i=0;i<1000010;i++) printf "x%c",0}'; }
    run rlch_7_1_11_frame; [ "$status" -eq 2 ]
    rlch_7_1_11_find() { printf '%04097d\000' 0; }
    unknown
}
@test "7111 metadata device inode links uid gid mode ctime transitions all ERROR" {
    for field in 3 4 5 6 7 8 9; do
        : > "$CALLS"
        rlch_7_1_11_find() {
            real_ww_find "$@" | LC_ALL=C awk -v RS='\0' -v f="$field" -v n="$(wc -l < "$CALLS")" '{if(n && NR==f){if(f==9) $0="1.0000000000";else if(f==8) $0="700";else $0+=1}printf "%s%c",$0,0}'
            printf 'call\n' >> "$CALLS"
        }
        expect check 2
    done
}
