#!/usr/bin/env bash
# Builds the file to upload to the Chrome Web Store, Firefox Add-ons and Edge Add-ons:
#   dist/grilled-phish-<version>.zip
# Only the files the extension needs are included, and the result is checked:
# no private keys, no test pages or tools, every file the manifest names is present.
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="$(node -p "require('./manifest.json').version")"
OUT="dist/grilled-phish-${VERSION}.zip"
INCLUDE=(manifest.json background.js LICENSE lib content popup options learn warn _locales
         icons/icon-16.png icons/icon-32.png icons/icon-48.png icons/icon-128.png data/known-sites.txt)

echo "Running tests…"
node --test test/*.test.js >/dev/null || { echo "Tests failed: not packaging." >&2; exit 1; }

# The shipped well-known sites list must be correctly signed.
node -e "
  const L = require('./lib/list-verify.js'), keys = require('./lib/list-public-key.js');
  L.verifySignedList(require('fs').readFileSync('data/known-sites.txt', 'utf8'), keys)
    .then((ok) => { if (!ok) { console.error('data/known-sites.txt is not correctly signed'); process.exit(1); } });"

mkdir -p dist
rm -f "$OUT"
zip -q -r -X "$OUT" "${INCLUDE[@]}" -x '*.DS_Store' -x '*/.*'

# Checks on what actually went into the zip.
LIST="$(unzip -Z1 "$OUT")"
if grep -E '\.(pem|key|zip|xpi|crx|sh|md)$|(^|/)(test|tools|node_modules|\.github|store|dist)/' <<<"$LIST"; then
  echo "Unexpected files in the package (above)." >&2; exit 1
fi
if unzip -p "$OUT" | grep -a -q -E 'BEGIN (EC |RSA |ENCRYPTED )?PRIVATE KEY'; then
  echo "A private key is inside the package!" >&2; exit 1
fi
node -e "
  const m = require('./manifest.json'), have = new Set(process.argv[1].split('\n'));
  const named = [m.background.service_worker, ...m.background.scripts, m.action.default_popup, m.options_ui.page,
    ...Object.values(m.icons), ...Object.values(m.action.default_icon), ...m.content_scripts.flatMap((c) => c.js)];
  const missing = named.filter((f) => !have.has(f));
  if (missing.length) { console.error('Missing from package:', missing.join(', ')); process.exit(1); }" "$LIST"

echo "Built $OUT ($(du -h "$OUT" | cut -f1), $(wc -l <<<"$LIST") files)."
