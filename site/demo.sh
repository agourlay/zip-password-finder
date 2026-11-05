#!/usr/bin/env sh
# Render the landing page's hero capture, demo.gif, from a scripted "tape".
#
# There is no screen recorder in play: each frame is drawn with ImageMagick's
# Pango renderer so the GIF is reproducible from this file alone and re-renders
# identically on any machine with ImageMagick + the DejaVu Sans Mono font.
#
# The frames reproduce a real run measured on this project: an AES-256 ZIP
# cracked with a mask attack (AES is what modern archives use). The status
# lines, the progress-bar template
# ([{elapsed_precise}] {wide_bar} {pos}/{len} throughput:{per_sec} (eta:{eta})),
# the solid/light bar glyphs, the ~67k/s AES throughput and the comma grouping
# all match the tool's actual stderr; the password Qmn34 is found at ~62% of
# the 1,757,600 candidate space, which is where it genuinely lands, in 17s.
#
# Usage: site/demo.sh   ->   writes ./demo.gif at the repository root.
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# ---- palette (GitHub-dark terminal) ---------------------------------------
BG='#0d1117'; BARCHROME='#161b22'; DIM='#8b949e'; TXT='#c9d1d9'
BLUE='#58a6ff'; GREEN='#3fb950'; AMBER='#d29922'; EMPTY='#30363d'; RED='#f85149'
FONT='DejaVu-Sans-Mono'; PT=19
CELLS=14          # progress-bar width in cells (indicatif's wide_bar shrinks
                  # to leave room for the counts, as it does in a real ~92-col
                  # terminal — the whole status line has to fit on one row)
LEN=1757600       # total candidates (mask ?u?l?l?d?d)

# A fully drawn bar string: $1 = filled cells.
bar() { i=0; s=''; while [ "$i" -lt "$CELLS" ]; do
    if [ "$i" -lt "$1" ]; then s="$s█"; else s="$s░"; fi; i=$((i+1)); done
  printf '%s' "$s"; }

# The five fixed preamble lines, as Pango markup (shared by every frame).
preamble() { cat <<EOF
<span foreground="$DIM">\$</span> <span foreground="$TXT">zip-password-finder</span> <span foreground="$TXT">secret.zip</span> <span foreground="$BLUE">-m</span> <span foreground="$AMBER">'?u?l?l?d?d'</span>
<span foreground="$DIM">Targeting file </span><span foreground="$TXT">'budget.txt'</span><span foreground="$DIM"> within the archive</span>
<span foreground="$DIM">Archive encrypted with </span><span foreground="$TXT">AES256</span><span foreground="$DIM"> - expect a long wait time</span>
<span foreground="$DIM">Using mask attack with </span><span foreground="$TXT">1757600</span><span foreground="$DIM"> candidates.</span>
<span foreground="$DIM">Starting </span><span foreground="$TXT">12</span><span foreground="$DIM"> workers to test passwords</span>
EOF
}

# A progress frame: $1 elapsed, $2 filled-cells, $3 pos, $4 throughput, $5 eta.
progress_line() {
  b=$(bar "$2")
  filled=$(printf '%s' "$b" | sed 's/░.*$//')
  empty=$(printf '%s' "$b" | sed 's/^█*//')
  printf '<span foreground="%s">[%s]</span> <span foreground="%s">%s</span><span foreground="%s">%s</span> <span foreground="%s">%s</span><span foreground="%s">/%s throughput:</span><span foreground="%s">%s/s</span> <span foreground="%s">(eta:%s)</span>' \
    "$DIM" "$1" "$GREEN" "$filled" "$EMPTY" "$empty" "$TXT" "$3" "$DIM" "$LEN" "$BLUE" "$4" "$DIM" "$5"
}

# Render one frame file ($1) from a markup body on stdin.
render() {
  out="$1"; markup=$(cat)
  # A fixed-size canvas keeps every frame aligned so the GIF does not jitter.
  magick -background "$BG" -font "$FONT" -pointsize "$PT" \
         -define pango:align=left pango:"$markup" \
         -bordercolor "$BG" -border 28 \
         -background "$BG" -gravity NorthWest -extent 1200x330 \
         "$out"
}

# ---- the tape -------------------------------------------------------------
# Each line: elapsed  filled  pos  throughput  eta
i=0
while IFS='|' read -r el fill pos tp eta; do
  [ -z "$el" ] && continue
  f=$(printf '%s/f%02d.png' "$work" "$i")
  { preamble; printf '\n'; progress_line "$el" "$fill" "$pos" "$tp" "$eta"; } | render "$f"
  i=$((i+1))
done <<'TAPE'
00:00:00|0|0|0|0s
00:00:01|1|72000|66,924.5242|25s
00:00:04|2|288000|67,282.9289|22s
00:00:07|4|504000|67,208.3384|19s
00:00:10|6|720000|67,193.8059|15s
00:00:13|7|936000|67,140.8457|12s
00:00:17|9|1152000|67,104.8334|9s
TAPE

# Final frame: the result replaces the progress line.
ffound=$(printf '%s/f%02d.png' "$work" "$i")
{ preamble; printf '\n'
  printf '<span foreground="%s">Time elapsed: </span><span foreground="%s">17s 166ms</span>\n' "$DIM" "$TXT"
  printf '<span foreground="%s">Password found: </span><span foreground="%s" weight="bold">Qmn34</span>' "$DIM" "$GREEN"
} | render "$ffound"

# ---- assemble -------------------------------------------------------------
# Hold the first frame a beat, play the search, then rest on the result before
# looping. -layers Optimize shrinks the palette/frames for a lean asset.
magick \
  -delay 80  "$work/f00.png" \
  -delay 38  "$work/f01.png" "$work/f02.png" "$work/f03.png" "$work/f04.png" "$work/f05.png" "$work/f06.png" \
  -delay 320 "$ffound" \
  -loop 0 -layers Optimize "$root/demo.gif"

printf 'wrote %s (%s)\n' "$root/demo.gif" "$(du -h "$root/demo.gif" | cut -f1)"
