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

# Additive snapshot contract; all preceding tests remain byte-for-byte intact.
snapshot() {
    local fd pid rc=0
    SNAPSHOT=()
    exec {fd}< <(rlch_fs_snapshot "${S_PATH:-$R}" "${S_DEPTH:-2}" "${S_POLICY:-all}" "$M"); pid=$!
    mapfile -d '' -t SNAPSHOT <&"$fd" || rc=2
    exec {fd}<&-
    wait "$pid" || rc=2
    return "$rc"
}
snapshot_error() { run snapshot; [ "$status" -eq 2 ]; [ -z "$output" ]; }
save_names_producer() {
    eval "$(declare -f _rlch_fs_snapshot_names_stream | sed '1s/_rlch_fs_snapshot_names_stream/real_snapshot_names/')"
}
@test "fs snapshot empty directory is one complete root tuple" {
    snapshot; [ "${#SNAPSHOT[@]}" -eq 12 ]; [ "${SNAPSHOT[0]}" = "$R" ]; [ "${SNAPSHOT[1]}" = d ]; [ "${SNAPSHOT[11]}" = 0 ]
}
@test "fs snapshot stable file metadata and zero depth" {
    printf PRIVATE > "$R/file"; chmod 0640 "$R/file"; S_PATH="$R/file"; S_DEPTH=0
    snapshot; [ "${#SNAPSHOT[@]}" -eq 12 ]; [ "${SNAPSHOT[1]}" = f ]; [ "${SNAPSHOT[5]}" = "$(id -u)" ]; [ "${SNAPSHOT[6]}" = "$(id -g)" ]; [ "${SNAPSHOT[7]}" = 640 ]
}
@test "fs snapshot depths zero one and two preserve populations" {
    mkdir -p "$R/child/grandchild"; touch "$R/child/file" "$R/child/grandchild/deeper"
    S_DEPTH=0; snapshot; [ "${#SNAPSHOT[@]}" -eq 12 ]
    S_DEPTH=1; snapshot; [ "${#SNAPSHOT[@]}" -eq 24 ]
    S_DEPTH=2; snapshot; [ "${#SNAPSHOT[@]}" -eq 48 ]
}
@test "fs snapshot missing leaf reliably differs from failure" {
    S_PATH="$R/missing"; snapshot; [ "${SNAPSHOT[1]}" = a ]; [ "${SNAPSHOT[0]}" = "$S_PATH" ]
}
@test "fs snapshot missing ancestor produces reliable empty target observation" {
    S_PATH="$R/missing/deeper"; snapshot; [ "${#SNAPSHOT[@]}" -eq 12 ]; [ "${SNAPSHOT[1]}" = a ]
}
@test "fs snapshot symlink leaf dangling link and cycle never followed" {
    ln -s / "$R/link"; ln -s missing "$R/dangling"; ln -s . "$R/cycle"
    snapshot; [ "${#SNAPSHOT[@]}" -eq 48 ]; [ "${SNAPSHOT[13]}" = l ]; [ "${SNAPSHOT[25]}" = l ]; [ "${SNAPSHOT[37]}" = l ]
}
@test "fs snapshot symlink ancestors are rejected" {
    mkdir "$R/real"; ln -s "$R/real" "$R/alias"; S_PATH="$R/alias/file"; snapshot_error
}
@test "fs snapshot hardlinks retained as separate directory entries" {
    touch "$R/a"; ln "$R/a" "$R/b"; snapshot; [ "${#SNAPSHOT[@]}" -eq 36 ]; [ "${SNAPSHOT[15]}" = "${SNAPSHOT[27]}" ]; [ "${SNAPSHOT[16]}" = 2 ]
}
@test "fs snapshot FIFO metadata without content read" {
    mkfifo "$R/fifo"; snapshot; [ "${SNAPSHOT[13]}" = p ]
}
@test "fs snapshot arbitrary byte and hostile names are inert and retained" {
    for name in 'space name' $'tab\tname' $'line\nname' $'trailing\n' 'élève' $'nonutf\377' '$(touch PRIVATE_FLAG)' '-leading' 'glob[*?]' 'pipe|name'; do : > "$R/$name"; done
    snapshot; [ "${#SNAPSHOT[@]}" -eq 132 ]; [ ! -e PRIVATE_FLAG ]
}
@test "fs snapshot newline-containing root retained exactly" {
    mkdir "$R/line"$'\n'; S_PATH="$R/line"$'\n'; snapshot; [ "${SNAPSHOT[0]}" = "$S_PATH" ]
}
@test "fs snapshot long valid names retained" {
    name="$(printf '%240s' '' | tr ' ' a)"; : > "$R/$name"; snapshot; [ "${SNAPSHOT[12]}" = "$R/$name" ]
}
@test "fs snapshot relative aliases and unsupported depths rejected" {
    for S_PATH in relative "$R/" "$R/./file" "$R/../file" "$R//file"; do snapshot_error; done
    unset S_PATH; for S_DEPTH in -1 9 01 x; do snapshot_error; done
}
@test "fs snapshot overlong path and excessive components rejected" {
    S_PATH="$(printf '/%4100s' X)"; snapshot_error
    S_PATH="$R"; for ((i=0;i<65;i++)); do S_PATH+="/a"; mkdir -p "$S_PATH"; done; snapshot_error
}
@test "fs snapshot unreadable directory fail closed even privileged" {
    chmod 0000 "$R"; snapshot_error; chmod 0755 "$R"
}
@test "fs snapshot zero mode final directory observable at depth zero" {
    chmod 0000 "$R"; S_DEPTH=0; snapshot; [ "${SNAPSHOT[7]}" = 0 ]; chmod 0755 "$R"
}
@test "fs snapshot inaccessible ancestor is not absence" {
    mkdir -p "$R/closed/child"; chmod 0000 "$R/closed"; S_PATH="$R/closed/child/missing"; snapshot_error; chmod 0755 "$R/closed"
}
@test "fs snapshot complete-boundary silent truncation rejected repeatedly" {
    touch "$R/a" "$R/b"; _rlch_fs_snapshot_names_stream() { printf 'a\0'; }; snapshot_error; snapshot_error
}
@test "fs snapshot zero bytes and unterminated producer data rejected" {
    touch "$R/a"; _rlch_fs_snapshot_names_stream() { :; }; snapshot_error
    _rlch_fs_snapshot_names_stream() { printf a; }; snapshot_error
}
@test "fs snapshot producer error after otherwise complete enumeration rejected" {
    save_names_producer; touch "$R/a"; _rlch_fs_snapshot_names_stream() { real_snapshot_names "$@"; return 87; }; snapshot_error
}
@test "fs snapshot producer stderr remains private and invalidates success" {
    save_names_producer; _rlch_fs_snapshot_names_stream() { real_snapshot_names "$@"; printf PRIVATE_PATH >&2; }; snapshot_error
}
@test "fs snapshot duplicate and forged trailer records rejected" {
    _rlch_fs_snapshot_names_stream() { printf 'RLCH-SNAPSHOT-END\0RLCH-SNAPSHOT-END\0'; }; snapshot_error
    touch "$R/a"; _rlch_fs_snapshot_names_stream() { printf 'a\0a\0'; }; snapshot_error
}
@test "fs snapshot real file equal to trailer token is not lost" {
    touch "$R/RLCH-SNAPSHOT-END"; snapshot; [ "${#SNAPSHOT[@]}" -eq 24 ]; [ "${SNAPSHOT[12]}" = "$R/RLCH-SNAPSHOT-END" ]
}
@test "fs snapshot observable creation and source replacement rejected" {
    save_names_producer; : > "$CALLS"
    _rlch_fs_snapshot_names_stream() { real_snapshot_names "$@"; if [[ ! -s "$CALLS" ]]; then printf 1 > "$CALLS"; touch "$R/new"; fi; }; snapshot_error
}
@test "fs snapshot observable file permission mutation rejected" {
    save_names_producer; : > "$CALLS"; touch "$R/a"; chmod 0644 "$R/a"
    _rlch_fs_snapshot_names_stream() { real_snapshot_names "$@"; if [[ -s "$CALLS" ]]; then chmod 0600 "$R/a"; else printf 1 > "$CALLS"; fi; }; snapshot_error
}
@test "fs snapshot directory replacement after open rejected" {
    save_names_producer; : > "$CALLS"
    _rlch_fs_snapshot_names_stream() { real_snapshot_names "$@"; if [[ ! -s "$CALLS" ]]; then printf 1 > "$CALLS"; mv "$R" "$R.old"; mkdir "$R"; fi; }; snapshot_error
}
@test "fs snapshot stat failure cannot become reliable absence" {
    touch "$R/PRIVATE"; _rlch_fs_snapshot_stat() { printf PRIVATE_PATH >&2; return 2; }; snapshot_error
}
@test "fs snapshot malformed metadata rejected" {
    _rlch_fs_snapshot_stat() { printf '0|0|0|0|0|0|0|0|0|0000\n'; }; snapshot_error
}
@test "fs snapshot mounted subtree all versus local policy" {
    mkdir "$R/remote"; touch "$R/remote/file"; add_mount 20 10 "$R/remote" server:/share nfs
    S_POLICY=all; snapshot; [ "${#SNAPSHOT[@]}" -eq 36 ]
    S_POLICY=local; snapshot_error
}
@test "fs snapshot unknown local filesystem is ERROR not skipped" {
    sed -i 's/ ext4 / unknownfs /' "$M"; S_POLICY=local; snapshot_error
}
@test "fs snapshot autofs is rejected before traversal" {
    add_mount 20 10 "$R/autofs" map autofs; _rlch_fs_snapshot_names_stream() { printf PRIVATE >&2; return 99; }; snapshot_error
}
@test "fs snapshot mount inventory mutation rejected" {
    save_names_producer; : > "$CALLS"
    _rlch_fs_snapshot_names_stream() { real_snapshot_names "$@"; if [[ ! -s "$CALLS" ]]; then printf 1 > "$CALLS"; printf '\n' >> "$M"; fi; }; snapshot_error
}
@test "fs snapshot malformed inventory rejected" {
    printf 'bad\n' > "$M"; snapshot_error
}
@test "fs snapshot entry limit rejects a complete oversized directory" {
    for ((i=0;i<16384;i++)); do : > "$R/$i"; done; snapshot_error
}
@test "fs snapshot injected byte overflow rejected without output" {
    _rlch_fs_snapshot_names_stream() { /usr/bin/awk 'BEGIN{for(i=0;i<2200;i++)printf "%04096d%c",i,0}'; }; snapshot_error
}
@test "fs snapshot metadata observation leaves content mode and file atime unchanged" {
    printf PRIVATE > "$R/file"; touch -a -d '2001-01-01 UTC' "$R/file"; before="$(stat -c '%i:%a:%u:%g:%s:%X:%Y:%Z' "$R/file")"
    snapshot; [ "$before" = "$(stat -c '%i:%a:%u:%g:%s:%X:%Y:%Z' "$R/file")" ]; [ "$(cat "$R/file")" = PRIVATE ]
}
@test "fs snapshot fresh calls observe new names" {
    snapshot; [ "${#SNAPSHOT[@]}" -eq 12 ]; touch "$R/new"; snapshot; [ "${#SNAPSHOT[@]}" -eq 24 ]
}
@test "fs snapshot caller descriptors and shell options unchanged" {
    before=(/proc/$$/fd/*); old="$(shopt -p nullglob dotglob failglob || true)"; snapshot; after=(/proc/$$/fd/*)
    [ "${before[*]}" = "${after[*]}" ]; [ "$old" = "$(shopt -p nullglob dotglob failglob || true)" ]
}
@test "fs snapshot private values untraced caller trace preserved" {
    run bash -c 'source "$1"; set -x; rc=0; rlch_fs_snapshot "$2" 1 all "$3" >/dev/null || rc=$?; [[ $- == *x* ]] || exit 99; exit "$rc"' bash "$BATS_TEST_DIRNAME/../lib/filesystem_observation.sh" "$R" "$M"
    [ "$status" -eq 0 ]; [[ "$output" != *RLCH-SNAPSHOT-END* && "$output" != *'_rlch_fs_snapshot_walk '* ]]
}
@test "fs snapshot wrong arity and output device failure return ERROR" {
    run rlch_fs_snapshot; [ "$status" -eq 2 ]; [ -z "$output" ]
    result=0; rlch_fs_snapshot "$R" 1 all "$M" > /dev/full || result=$?; [ "$result" -eq 2 ]
}
@test "fs snapshot unrelated ancestor sibling creation does not invalidate intact path" {
    save_names_producer; : > "$CALLS"
    _rlch_fs_snapshot_names_stream() { real_snapshot_names "$@"; if [[ ! -s "$CALLS" ]]; then printf 1 > "$CALLS"; : > "$BATS_TEST_TMPDIR/unrelated"; fi; }
    snapshot
}
