#!/usr/bin/env bats
# shellcheck source-path=SCRIPTDIR
# shellcheck disable=SC2016,SC2317 # Literal attack names; mocks invoked by sourced APIs.
setup() {
    source "$BATS_TEST_DIRNAME/test_helper.bash"
    source "$BATS_TEST_DIRNAME/../lib/module_api.sh"
    source "$BATS_TEST_DIRNAME/../lib/mount.sh"
    M="$BATS_TEST_TMPDIR/mountinfo"; export M
    printf '10 0 8:1 / / rw - ext4 /dev/root rw\n' > "$M"
    declare -ga result=()
}
read_inventory() { mount_inventory result "$M"; }
invalid() { result=(old); code=0; read_inventory || code=$?; [ "$code" -eq 2 ]; [ "${#result[@]}" -eq 0 ]; }
@test "MI simple ten-field contract no stdout" {
    read_inventory; [ "${#result[@]}" -eq 10 ]; [ "${result[0]}" = 10 ]; [ "${result[4]}" = / ]; [ "${result[5]}" = /dev/root ]; [ "${result[9]}" = '' ]
    run read_inventory; [ "$status" -eq 0 ]; [ -z "$output" ]
}
@test "MI nested mounts sorted numerically regardless of row order" {
    printf '30 20 8:3 / /data/nested rw - xfs /dev/three rw\n20 10 8:2 / /data rw - xfs /dev/two rw\n' >> "$M"
    read_inventory; [ "${#result[@]}" -eq 30 ]; [ "${result[10]}" = 20 ]; [ "${result[21]}" = 20 ]
    first=("${result[@]}"); tac "$M" > "$M.new"; mv "$M.new" "$M"; read_inventory
    [ "${first[*]}" = "${result[*]}" ]
}
@test "MI same device bind retains root target parent identity" {
    printf '20 10 8:1 /original /bind rw - ext4 /dev/root rw\n' >> "$M"
    read_inventory; [ "${result[12]}" = 8:1 ]; [ "${result[13]}" = /original ]; [ "${result[14]}" = /bind ]; [ "${result[11]}" = 10 ]
}
@test "MI network pseudo overlay tmpfs and readonly preserved not silently excluded" {
    for row in '20 10 0:2 / /net rw - nfs host:/export rw' '30 10 0:3 / /proc rw - proc proc rw' '40 10 0:4 / /tmp rw - tmpfs tmpfs rw' '50 10 0:5 / /overlay rw - overlay overlay rw' '60 10 8:2 / /ro ro - ext4 /dev/ro ro'; do printf '%s\n' "$row" >> "$M"; done
    read_inventory; [ "${#result[@]}" -eq 60 ]; [ "${result[55]}" = /dev/ro ]; [ "${result[57]}" = ro ]
}
@test "MI spaces tabs newlines backslash special and non UTF8 byte transport" {
    printf '20 10 8:1 /root\\040space /space\\040name rw - ext4 /dev/disk\\134name rw\n30 10 8:1 / /line\\012name rw - ext4 /dev/root rw\n40 10 8:1 / /tab\\011name rw - ext4 /dev/root rw\n50 10 8:1 / /special[*?] rw - ext4 /dev/root rw\n60 10 8:1 / /nonutf-\377 rw - ext4 /dev/root rw\n' >> "$M"
    read_inventory; [ "${result[13]}" = '/root space' ]; [ "${result[14]}" = '/space name' ]; [ "${result[15]}" = '/dev/disk\name' ]
    [ "${result[24]}" = $'/line\nname' ]; [ "${result[34]}" = $'/tab\tname' ]; [ "${result[44]}" = '/special[*?]' ]; [ "${result[54]}" = $'/nonutf-\377' ]
}
@test "MI escape decoded only once" {
    printf '20 10 8:1 / /literal\\134040 rw - ext4 /dev/root rw\n' >> "$M"
    read_inventory; [ "${result[14]}" = '/literal\040' ]
}
@test "MI optional propagation fields retained" {
    printf '10 0 8:1 / / rw shared:1 master:2 propagate_from:3 - ext4 /dev/root rw\n' > "$M"
    read_inventory; [ "${result[9]}" = 'shared:1 master:2 propagate_from:3' ]
}
@test "MI root parent outside namespace or self accepted" {
    for parent in 0 99 10; do printf '10 %s 8:1 / / rw - ext4 /dev/root rw\n' "$parent" > "$M"; read_inventory; done
}
@test "MI duplicate IDs and stacked target fail closed" {
    printf '10 10 8:1 / /other rw - ext4 /dev/root rw\n' >> "$M"; invalid
    printf '10 0 8:1 / / rw - ext4 /dev/root rw\n20 10 8:2 / / rw - ext4 /dev/two rw\n' > "$M"; invalid
}
@test "MI absent root empty input missing source separator or options ERROR" {
    for row in '' '20 0 8:1 / /data rw - ext4 /dev/root rw' '10 0 8:1 / / rw ext4 /dev/root rw' '10 0 8:1 / / rw - ext4' '10 0 8:1 / / rw - ext4 /dev/root'; do printf '%s\n' "$row" > "$M"; invalid; done
}
@test "MI invalid IDs parent device and optional fields ERROR" {
    for row in '0 0 8:1 / / rw - ext4 /dev/root rw' '01 0 8:1 / / rw - ext4 /dev/root rw' '10 -1 8:1 / / rw - ext4 /dev/root rw' '10 0 x:1 / / rw - ext4 /dev/root rw' '10 0 8:01 / / rw - ext4 /dev/root rw' '10 0 8:1 / / unknown - ext4 /dev/root rw' '10 0 8:1 / / rw future:1 - ext4 /dev/root rw' '10 0 8:1 / / rw shared:1 shared:2 - ext4 /dev/root rw'; do printf '%s\n' "$row" > "$M"; invalid; done
}
@test "MI missing parent cycles incompatible ancestry ERROR" {
    for rows in $'20 99 8:1 / /data rw - ext4 /dev/root rw' $'20 30 8:1 / /data rw - ext4 /dev/root rw\n30 20 8:1 / /other rw - ext4 /dev/root rw' $'20 10 8:1 / /data rw - ext4 /dev/root rw\n30 20 8:1 / /other rw - ext4 /dev/root rw'; do
        printf '10 0 8:1 / / rw - ext4 /dev/root rw\n%s\n' "$rows" > "$M"; invalid
    done
}
@test "MI invalid escapes NUL and raw controls ERROR without output" {
    for target in '/bad\999' '/bad\04' '/bad\000' '/dot/../path' '/double//path' '/trailing/'; do printf '10 0 8:1 / %s rw - ext4 /dev/root rw\n' "$target" > "$M"; invalid; done
    printf '10 0 8:1 / / rw - ext4 /dev/root rw\000\n' > "$M"; invalid
    printf '10 0 8:1 / / rw - ext4 /dev/root rw\t\n' > "$M"; invalid
}
@test "MI producer status not lost for plausible complete output" {
    _mount_inventory_stream() { /usr/bin/cat "$M"; return 99; }; invalid
}
@test "MI missing input ERROR" { rm "$M"; invalid; }
@test "MI resource count line and total byte limits ERROR" {
    for ((n=20;n<4120;n++)); do printf '%s 10 8:1 / /d%s rw - ext4 /dev/root rw\n' "$n" "$n"; done >> "$M"; invalid
    printf '%016385d\n' 0 > "$M"; invalid
}
@test "MI private transport missing or truncated trailer ERROR" {
    _mount_inventory_frame() { printf 'RLCH-MOUNTS-1\00010\000'; }; invalid
}
@test "MI invalid destination name rejected without executing code" {
    run mount_inventory 'x[$(touch BAD)]' "$M"; [ "$status" -eq 2 ]; [ ! -e BAD ]
    run mount_inventory _rlch_mi_frame "$M"; [ "$status" -eq 2 ]
}
@test "MI legacy target and option contracts remain unchanged" {
    run mount_is_valid_target /audit; [ "$status" -eq 0 ]
    run mount_is_valid_target $'/audit\nname'; [ "$status" -eq 1 ]
    run mount_option_list_contains rw,nodev nodev; [ "$status" -eq 0 ]
    run mount_option_list_contains rw,nodevice nodev; [ "$status" -eq 1 ]
}
@test "MI raw nonseparator controls in names preserved as kernel byte data" {
    printf '20 10 8:1 / /control-\001-name rw - ext4 /dev/root rw\n30 10 8:1 / /return-\r-name rw - ext4 /dev/root rw\n' >> "$M"
    read_inventory; [ "${result[14]}" = $'/control-\001-name' ]; [ "${result[24]}" = $'/return-\r-name' ]
}
@test "MI total byte resource bound rejects otherwise complete rows" {
    filler=$(printf '%01200d' 0)
    for ((n=20;n<4020;n++)); do printf '%s 10 8:1 / /d%s%s rw - ext4 /dev/root rw\n' "$n" "$n" "$filler"; done >> "$M"
    invalid
}
@test "MI unterminated last kernel record is truncated evidence ERROR" {
    printf '10 0 8:1 / / rw - ext4 /dev/root rw' > "$M"; invalid
}
@test "MI hidden or incorrect nearest parent relation ERROR" {
    printf '20 10 8:1 / /data rw - ext4 /dev/root rw\n30 10 8:1 / /data/nested rw - ext4 /dev/root rw\n' >> "$M"; invalid
}
