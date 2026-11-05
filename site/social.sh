#!/usr/bin/env sh
# Render the link preview card, site/social.png (1200x630), with ImageMagick.
#
# No browser or external font: the card is composited from shapes and Pango
# text so it renders identically anywhere ImageMagick and DejaVu Sans / Sans
# Mono are present. The palette matches the landing page. Run it after editing
# the card and commit the PNG; the Pages workflow only copies the PNG.
#
#   site/social.sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
out="$root/site/social.png"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

BG='#0d1117'; LIFT='#161b22'; DEEP='#010409'; TXT='#e6edf3'; DIM='#8b949e'
GREEN='#3fb950'; LINE='rgba(255,255,255,0.10)'
MONO='DejaVu-Sans-Mono'; SANS='DejaVu-Sans'

# Base: a soft top-to-bottom gradient with a faint dot field, the same texture
# the page draws behind its headline.
magick -size 1200x630 gradient:"$LIFT"-"$BG" "$work/base.png"
magick -size 20x20 xc:none -fill 'rgba(255,255,255,0.05)' \
  -draw 'circle 3,3 3,4.3' "$work/dot.png"
magick "$work/base.png" -size 1200x630 tile:"$work/dot.png" \
  -compose over -composite "$work/bg.png"

# The terminal panel: dark rounded rectangle with a title bar and three dots.
magick "$work/bg.png" \
  -fill "$DEEP" -stroke "$LINE" -strokewidth 1 \
  -draw 'roundrectangle 80,372 1120,556 14,14' \
  -fill "$LIFT" -stroke none \
  -draw 'roundrectangle 81,373 1119,422 14,14' \
  -fill "$DEEP" -draw 'rectangle 81,404 1119,422' \
  -fill '#ff5f56' -draw 'circle 108,398 108,405' \
  -fill '#ffbd2e' -draw 'circle 136,398 136,405' \
  -fill '#27c93f' -draw 'circle 164,398 164,405' \
  "$work/panel.png"

# Text blocks, each rendered transparent then composited at a fixed point.
magick -background none -font "$MONO" -pointsize 66 -fill "$TXT" \
  label:'zip-password-finder' "$work/title.png"
magick -background none -font "$SANS" -pointsize 34 -fill "$DIM" \
  -size 760x caption:'Recover protected ZIP & 7z passwords. Fast, multi-threaded Rust.' \
  "$work/tag.png"
magick -background none -font "$MONO" -pointsize 26 \
  pango:"<span foreground=\"$DIM\">\$</span> <span foreground=\"$TXT\">zip-password-finder secret.zip</span> <span foreground=\"$DIM\">--mask '?u?l?l?d?d'</span>" \
  "$work/cmd.png"
magick -background none -font "$MONO" -pointsize 26 \
  pango:"<span foreground=\"$DIM\">Password found: </span><span foreground=\"$GREEN\" weight=\"bold\">Qmn34</span>" \
  "$work/found.png"

magick "$work/panel.png" \
  "$work/title.png" -geometry +78+96  -compose over -composite \
  -fill "$GREEN" -draw 'roundrectangle 80,196 170,202 3,3' \
  "$work/tag.png"   -geometry +80+226  -compose over -composite \
  "$work/cmd.png"   -geometry +108+446 -compose over -composite \
  "$work/found.png" -geometry +108+492 -compose over -composite \
  "$out"

printf 'wrote %s (%s)\n' "$out" "$(identify -format '%wx%h' "$out")"
