#!/usr/bin/env bats
# shellcheck source-path=SCRIPTDIR
# shellcheck disable=SC2016,SC2317,SC2030,SC2031 # Literal attack names and injected boundaries.
setup() {
    source "$BATS_TEST_DIRNAME/../lib/filesystem_observation.sh"
    R="$BATS_TEST_TMPDIR/root"; M="$BATS_TEST_TMPDIR/mountinfo"; CALLS="$BATS_TEST_TMPDIR/calls"
    mkdir "$R"; chmod 0755 "$R"
    dev="$(stat -c %d "$R")"
    DEVICE="$(( (dev>>8 & 4095) | (dev>>32 & 4294963200) )):$(( (dev & 255) | (dev>>12 & 4294967040) ))"
    printf '10 0 %s / / rw - ext4 /dev/fixture rw\n' "$DEVICE" > "$M"
    eval "$(declare -f rlch_fs_find | sed '1s/rlch_fs_find/real_fs_find/')"
    OBSERVED=()
}
select_dev() { local -n inv="$1"; [[ "${inv[$2+5]}" == /dev/* ]]; }
collect() { local -n rows="$1"; local i; for ((i=0;i<${#rows[@]};i+=10)); do OBSERVED+=("${rows[i]}" "${rows[i+1]}"); done; }
observe() { rlch_fs_observe "$R" "$M" select_dev collect; }
unknown() { run observe; [ "$status" -eq 2 ]; [ -z "$output" ]; }
encode() { ENCODED="$1"; ENCODED="${ENCODED//\\/\\134}"; ENCODED="${ENCODED// /\\040}"; ENCODED="${ENCODED//$'\t'/\\011}"; ENCODED="${ENCODED//$'\n'/\\012}"; }
add_mount() {
    local id="$1" parent="$2" target="$3" source="$4" fs="${5:-ext4}" root="${6:-/}" encodedtarget encodedroot
    encode "$target"; encodedtarget="$ENCODED"; encode "$root"; encodedroot="$ENCODED"
    printf '%s %s %s %s %s rw - %s %s rw\n' "$id" "$parent" "$DEVICE" "$encodedroot" "$encodedtarget" "$fs" "$source" >> "$M"
}
@test "fsobs empty tree complete and no diagnostics" {
    run observe; [ "$status" -eq 0 ]; [ -z "$output" ]; }
@test "fsobs caller receives validated metadata" {
    touch "$R/file"; observe; [ "${#OBSERVED[@]}" -eq 4 ]; [ "${OBSERVED[0]}" = "$R" ]; [ "${OBSERVED[1]}" = d ]; [ "${OBSERVED[3]}" = f ]; }
@test "fsobs content and file atime preserved" {
    printf 'body\n' > "$R/file"; touch -a -d '2001-01-01 UTC' "$R/file"
    before="$(stat -c '%a:%u:%g:%i:%s:%X:%Y:%Z' "$R/file")"; observe
    [ "$before" = "$(stat -c '%a:%u:%g:%i:%s:%X:%Y:%Z' "$R/file")" ]; [ "$(cat "$R/file")" = body ]; }
@test "fsobs symlinks dangling and cycle never followed" {
    ln -s / "$R/host"; ln -s nowhere "$R/dangling"; ln -s . "$R/loop"; observe; [ "${#OBSERVED[@]}" -eq 8 ]; }
@test "fsobs FIFO not opened" {
    mkfifo "$R/fifo"; observe; [ "${OBSERVED[3]}" = p ]; }
@test "fsobs hardlink aliases accepted" {
    touch "$R/a"; ln "$R/a" "$R/b"; observe; [ "${#OBSERVED[@]}" -eq 6 ]; }
@test "fsobs arbitrary byte names" {
    for name in 'space name' $'line\nname' $'trailing\n' $'tab\tname' $'control\001name' $'nonutf\377' '$(touch BAD)' 'glob[*?]' 'pipe|name'; do touch "$R/$name"; done
    observe; [ "${#OBSERVED[@]}" -eq 20 ]; [ ! -e BAD ]; }
@test "fsobs nested selected mounts traversed exactly once" {
    mkdir -p "$R/a/b"; touch "$R/a/b/file"; add_mount 20 10 /a /dev/a; add_mount 30 20 /a/b /dev/b
    observe; [ "${#OBSERVED[@]}" -eq 8 ]; }
@test "fsobs same device bind own traversal" {
    mkdir "$R/bind"; touch "$R/bind/file"; add_mount 20 10 /bind /dev/fixture ext4 /original
    observe; [ "${#OBSERVED[@]}" -eq 6 ]; }
@test "fsobs excluded same device bind is pruned" {
    mkdir "$R/excluded"; touch "$R/excluded/file"; add_mount 20 10 /excluded tmpfs tmpfs
    observe; [ "${#OBSERVED[@]}" -eq 2 ]; }
@test "fsobs selected below excluded ancestor" {
    mkdir -p "$R/net/local"; touch "$R/net/local/file"; add_mount 20 10 /net host:/share nfs; add_mount 30 20 /net/local /dev/local
    observe; [ "${#OBSERVED[@]}" -eq 6 ]; }
@test "fsobs generic selector may include tmpfs" {
    select_dev() { return 0; }
    mkdir "$R/tmp"; add_mount 20 10 /tmp tmpfs tmpfs; observe; [ "${#OBSERVED[@]}" -eq 4 ]; }
@test "fsobs literal mount patterns and sibling" {
    mkdir "$R/[x]*?" "$R/xx"; touch "$R/xx/file"; add_mount 20 10 '/[x]*?' proc proc
    observe; [ "${#OBSERVED[@]}" -eq 6 ]; }
@test "fsobs mount names newline space nonutf8" {
    for name in 'space name' $'line\nname' $'nonutf\377'; do mkdir "$R/$name"; done
    add_mount 20 10 '/space name' /dev/a; add_mount 30 10 $'/line\nname' /dev/b; add_mount 40 10 $'/nonutf\377' /dev/c
    observe; [ "${#OBSERVED[@]}" -eq 8 ]; }
@test "fsobs producer nonzero after full data rejected" {
    rlch_fs_find() { real_fs_find "$@"; return 99; }; unknown; }
@test "fsobs producer interrupted rejected" {
    rlch_fs_find() { return 124; }; unknown; }
@test "fsobs zero status empty stream rejected" {
    rlch_fs_find() { return 0; }; unknown; }
@test "fsobs stderr even zero status rejected" {
    rlch_fs_find() { real_fs_find "$@"; printf 'private\n' >&2; }; unknown; }
@test "fsobs missing final NUL rejected" {
    rlch_fs_find() { real_fs_find "$@" | head -c -1; }; unknown; }
@test "fsobs clipped tuple rejected" {
    rlch_fs_find() { printf '%s\0f\0' "$R"; }; unknown; }
@test "fsobs duplicate tuples rejected" {
    rlch_fs_find() { real_fs_find "$@"; real_fs_find "$@"; }; unknown; }
@test "fsobs malformed fields all rejected" {
    for spec in '1=relative' '2=Z' '3=-1' '4=0' '5=0' '6=00' '7=4294967295' '8=8888' '9=bad' '10=1025' '3=9999999999999999999' '4=99999999999999999999' '5=99999999999999999999'; do
        rlch_fs_find() { real_fs_find "$@" | LC_ALL=C awk -v RS='\0' -v spec="$spec" 'BEGIN{split(spec,a,"=")} {if(NR==a[1]) $0=a[2];printf "%s%c",$0,0}'; }; unknown
    done
}
@test "fsobs field length bounded" {
    rlch_fs_find() { printf '%5000s\0' x; }; unknown; }
@test "fsobs object count bounded" {
    rlch_fs_find() { real_fs_find "$@" | awk -v RS='\0' '{a[NR]=$0} END{for(i=0;i<100001;i++) for(j=1;j<=10;j++) printf "%s%c",a[j],0}'; }; unknown; }
@test "fsobs root device mismatch rejected" {
    sed -i "s/$DEVICE/123:456/" "$M"; unknown; }
@test "fsobs malformed root stat rejected" {
    rlch_fs_root_stat() { printf '%s|ffff41ed\n' "$dev"; }; unknown; }
@test "fsobs missing root rejected" {
    R="$R/missing"; unknown; }
@test "fsobs symlink root rejected" {
    ln -s "$R" "$BATS_TEST_TMPDIR/alias"; R="$BATS_TEST_TMPDIR/alias"; unknown; }
@test "fsobs file mount root unsupported" {
    touch "$R/file"; add_mount 20 10 /file /dev/a; unknown; }
@test "fsobs unreadable directory rejected even privileged" {
    mkdir "$R/closed"; chmod 0000 "$R/closed"; unknown; chmod 0755 "$R/closed"; }
@test "fsobs no selected mounts rejected" {
    select_dev() { return 1; }; unknown; }
@test "fsobs selector error rejected" {
    select_dev() { return 2; }; unknown; }
@test "fsobs visitor failure rejected" {
    collect() { return 1; }; unknown; }
@test "fsobs malformed inventory rejected" {
    printf 'bad\n' > "$M"; unknown; }
@test "fsobs inventory mutation detected" {
    rlch_fs_find() { real_fs_find "$@"; if [[ ! -e "$CALLS" ]]; then touch "$CALLS"; mkdir "$R/new"; add_mount 20 10 /new proc proc; fi; }; unknown; }
@test "fsobs creation between scans detected" {
    rlch_fs_find() { real_fs_find "$@"; if [[ ! -e "$CALLS" ]]; then touch "$CALLS" "$R/new"; fi; }; unknown; }
@test "fsobs removal between scans detected" {
    touch "$R/file"; rlch_fs_find() { real_fs_find "$@"; if [[ ! -e "$CALLS" ]]; then touch "$CALLS"; rm "$R/file"; fi; }; unknown; }
@test "fsobs metadata replacement detected" {
    touch "$R/file"; rlch_fs_find() { real_fs_find "$@"; if [[ ! -e "$CALLS" ]]; then touch "$CALLS"; chmod 0600 "$R/file"; fi; }; unknown; }
@test "fsobs fresh repeat observes added file" {
    observe; [ "${#OBSERVED[@]}" -eq 2 ]; OBSERVED=(); touch "$R/file"; observe; [ "${#OBSERVED[@]}" -eq 4 ]; }
@test "fsobs error category bounded without names" {
    select_dev() { return 2; }; result=0; observe || result=$?; [ "$result" -eq 2 ]; [ "$RLCH_FS_OBSERVATION_ERROR" = selection ]; }
@test "fsobs historical public mount API retained" {
    declare -F mount_runtime_entry; declare -F mount_check_option; declare -F mount_inventory; }
@test "fsobs aggregate byte volume limit" {
    rlch_fs_find() { awk 'BEGIN{for(i=0;i<18000;i++){printf "%04000d%c",i,0}}'; }; unknown
}
@test "fsobs root tuple device inconsistent with inventory" {
    rlch_fs_find() { real_fs_find "$@" | awk -v RS='\0' '{if((NR-1)%10==2) $0=1;printf "%s%c",$0,0}'; }; unknown
}
@test "fsobs visitor earlier finding cannot mask later failure" {
    mkdir "$R/later"; add_mount 20 10 /later /dev/later
    collect() { OBSERVED+=(finding); }
    rlch_fs_find() { case "$2" in */later) return 99;; *) real_fs_find "$@";; esac; }
    result=0; observe || result=$?; [ "$result" -eq 2 ]; [ "${OBSERVED[0]}" = finding ]
}

@test "fsobs root stat failure diagnostics remain private" {
    rlch_fs_root_stat() { printf 'PRIVATE PATH\n' >&2; return 2; }; unknown
}
