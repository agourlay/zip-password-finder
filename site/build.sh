#!/usr/bin/env sh
# Assemble the landing page into ./_site, ready to serve or publish.
#
# The demo capture lives at the repository root, where the README can point at
# it, and is copied in so the published site has its own copy at a path that
# does not climb out of the site root. It is produced by site/demo.sh.
#
# The link preview card is site/social.png, rendered from site/social.html by
# site/social.sh; only the PNG is published.
#
# Used by .github/workflows/pages.yml and by hand:
#
#   site/build.sh && python3 -m http.server -d _site
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
out="$root/_site"

rm -rf "$out"
mkdir -p "$out"

cp "$root/site/index.html" "$root/site/style.css" "$root/site/social.png" \
   "$root/site/install.sh" "$root/site/install.ps1" "$out/"
cp "$root/demo.gif" "$out/"

# Stamp the stylesheet link with a digest of the stylesheet.
#
# Pages serves everything with `cache-control: max-age=600`, and the page and
# its styles expire independently, so for up to ten minutes after a deploy a
# browser can hold new markup against the old stylesheet: markup written for
# a rule that is not there yet falls back to default layout. Naming the file
# after its contents means new markup always asks for a URL no cache has.
v=$(cksum "$out/style.css" | cut -d' ' -f1)
sed "s|href=\"style.css\"|href=\"style.css?v=$v\"|" "$out/index.html" > "$out/index.html.tmp"
mv "$out/index.html.tmp" "$out/index.html"

# Pages runs Jekyll over a branch unless told not to, which would drop any
# file or directory whose name begins with an underscore.
touch "$out/.nojekyll"

printf 'built %s\n' "$out"
